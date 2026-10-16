/* rules.c - filter images: flash A/B slots, updates, custom rules (see rules.h). */
#include "rules.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "app_config.h"
#include "dc_port.h"
#include "dc_util.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "fl_filter.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "net.h"

static const char *TAG = "rules";

#define SEC 4096u
#define BLOCK 65536u
#define MAX_LIST_BYTES (24u << 20)
#define RETRY_FAIL_S 1800

static dns_server_t *g_srv;
static SemaphoreHandle_t g_flash_mu;
static SemaphoreHandle_t g_img_mu; /* g_custom / g_subs / set rebuild */
static SemaphoreHandle_t g_unmapped; /* given when the flash-mapped image is released */
static fl_image_t *g_custom, *g_subs;
static const esp_partition_t *g_slot[2], *g_staging;
static int g_active = -1;
static TaskHandle_t g_task;
static volatile bool g_trigger, g_force, g_running;
static fl_stats_t g_custom_stats;

static struct {
    char phase[24];
    char current[64];
    uint32_t bytes;
    uint32_t started;
    char error[160];
    uint32_t last_ok;       /* wall time of the last successful build/check (0 = clock not set) */
    uint32_t last_ok_up;    /* uptime (s) + 1 of the same, 0 = none yet */
    uint32_t last_attempt;  /* uptime (s) */
    uint32_t last_ms;
    uint32_t next_due;      /* uptime (s) */
} g_st;

void flash_lock(void) { xSemaphoreTakeRecursive(g_flash_mu, portMAX_DELAY); }
void flash_unlock(void) { xSemaphoreGiveRecursive(g_flash_mu); }

static uint32_t uptime_s(void) { return (uint32_t)(dc_time_us() / 1000000u); }

/* ---- flash store (fl_store_t over a partition) ----------------------------------- */

typedef struct {
    fl_store_t st;
    const esp_partition_t *p;
    uint8_t *ready; /* per 4 KiB sector: erased and open for writing */
    uint32_t nsec;
} fstore_t;

static int fs_write(fl_store_t *s, uint32_t off, const void *buf, size_t len) {
    fstore_t *f = (fstore_t *)s->ctx;
    if ((uint64_t)off + len > f->p->size) return FL_ERR_FULL;
    for (uint32_t sec = off / SEC; sec <= (off + (uint32_t)len - 1) / SEC && len; sec++) {
        if (f->ready[sec]) continue;
        /* erase a whole 64 KiB block when none of it is in use: much faster */
        uint32_t b0 = sec & ~15u;
        bool whole = (sec & 15u) == 0 && b0 + 16 <= f->nsec;
        for (uint32_t k = b0; whole && k < b0 + 16; k++)
            if (f->ready[k]) whole = false;
        if (whole) {
            if (esp_partition_erase_range(f->p, b0 * SEC, BLOCK) != ESP_OK) return FL_ERR_IO;
            memset(f->ready + b0, 1, 16);
        } else {
            if (esp_partition_erase_range(f->p, sec * SEC, SEC) != ESP_OK) return FL_ERR_IO;
            f->ready[sec] = 1;
        }
    }
    return esp_partition_write(f->p, off, buf, len) == ESP_OK ? 0 : FL_ERR_IO;
}

static int fs_read(fl_store_t *s, uint32_t off, void *buf, size_t len) {
    fstore_t *f = (fstore_t *)s->ctx;
    return esp_partition_read(f->p, off, buf, len) == ESP_OK ? 0 : FL_ERR_IO;
}

static void fs_discard(fl_store_t *s, uint32_t off, size_t len) {
    fstore_t *f = (fstore_t *)s->ctx;
    for (uint32_t sec = off / SEC; sec < (off + (uint32_t)len) / SEC && sec < f->nsec; sec++) f->ready[sec] = 0;
}

static bool fs_open(fstore_t *f, const esp_partition_t *p, bool run_store) {
    memset(f, 0, sizeof(*f));
    f->p = p;
    f->nsec = p->size / SEC;
    f->ready = calloc(f->nsec, 1);
    if (!f->ready) return false;
    f->st.write = fs_write;
    f->st.read = fs_read;
    f->st.discard = run_store ? fs_discard : NULL;
    f->st.capacity = p->size & ~(SEC - 1);
    f->st.ctx = f;
    return true;
}

static void fs_close(fstore_t *f) { free(f->ready); }

/* ---- image sets ------------------------------------------------------------------ */

static void publish_set(void) {
    fl_image_t *imgs[2];
    unsigned n = 0;
    if (g_custom) imgs[n++] = g_custom;
    if (g_subs) imgs[n++] = g_subs;
    static uint32_t gen;
    fl_set_t *set = n ? fl_set_new(imgs, n, ++gen) : NULL;
    dns_server_set_filters(g_srv, set);
    if (set) fl_set_unref(set);
}

typedef struct {
    esp_partition_mmap_handle_t h;
} mmap_rel_t;

static void mmap_release(const uint8_t *data, void *arg) {
    mmap_rel_t *r = (mmap_rel_t *)arg;
    esp_partition_munmap(r->h);
    free(r);
    xSemaphoreGive(g_unmapped);
}

/* Loads slot `s`: flash-mapped first (immediately active), then PSRAM. */
static esp_err_t activate_slot(int s) {
    const esp_partition_t *p = g_slot[s];
    fstore_t f;
    if (!fs_open(&f, p, false)) return ESP_ERR_NO_MEM;
    uint32_t len = 0, gen = 0;
    int rc = fl_image_probe(&f.st, &len, &gen);
    fs_close(&f);
    if (rc) return ESP_ERR_NOT_FOUND;
    flash_lock(); /* no flash writes while the image is read through the cache */
    const void *ptr;
    mmap_rel_t *rel = calloc(1, sizeof(*rel));
    if (!rel || esp_partition_mmap(p, 0, len, ESP_PARTITION_MMAP_DATA, &ptr, &rel->h) != ESP_OK) {
        free(rel);
        flash_unlock();
        return ESP_FAIL;
    }
    fl_image_t *mimg;
    rc = fl_image_load_ex((const uint8_t *)ptr, len, true, mmap_release, rel, &mimg);
    if (rc) {
        esp_partition_munmap(rel->h);
        free(rel);
        flash_unlock();
        ESP_LOGE(TAG, "slot %c: image invalid (%d)", 'a' + s, rc);
        return ESP_ERR_INVALID_CRC;
    }
    xSemaphoreTake(g_img_mu, portMAX_DELAY);
    fl_image_t *old = g_subs;
    g_subs = mimg;
    publish_set();
    xSemaphoreGive(g_img_mu);
    if (old) fl_image_unref(old);
    /* the old PSRAM copy is released once in-flight queries drop it */
    uint8_t *copy = NULL;
    for (int i = 0; i < 40 && !copy; i++) {
        copy = dc_malloc_ext(len);
        if (!copy) vTaskDelay(pdMS_TO_TICKS(50));
    }
    /* still no room: give memory from the response cache to the filters */
    for (int i = 0; i < 4 && !copy; i++) {
        dns_config_t *dc = malloc(sizeof(*dc));
        if (dc) dns_server_get_config(g_srv, dc); /* (the running values) */
        if (!dc || dc->cache_bytes <= 256 * 1024) {
            free(dc);
            break;
        }
        dc->cache_bytes /= 2;
        ESP_LOGW(TAG, "PSRAM short: response cache reduced to %u KiB", (unsigned)(dc->cache_bytes / 1024));
        dns_server_reconfigure(g_srv, dc);
        free(dc);
        copy = dc_malloc_ext(len);
    }
    fl_image_t *pimg = NULL;
    if (copy) {
        memcpy(copy, ptr, len);
        if (fl_image_load(copy, len, false, &pimg)) {
            dc_free(copy);
            pimg = NULL;
        }
    }
    /* Flash-mapped data must not be read while flash is written: without a
     * PSRAM copy the lists are switched off rather than risk that. */
    xSemaphoreTake(g_img_mu, portMAX_DELAY);
    g_subs = pimg;
    publish_set();
    xSemaphoreGive(g_img_mu);
    xSemaphoreTake(g_unmapped, 0);
    fl_image_unref(mimg); /* unmapped when the last query is done with it */
    /* flash stays locked until nothing reads the mapping any more */
    if (xSemaphoreTake(g_unmapped, pdMS_TO_TICKS(30000)) != pdTRUE) ESP_LOGW(TAG, "flash mapping still in use");
    flash_unlock();
    if (!pimg) {
        ESP_LOGE(TAG, "not enough PSRAM for the filter image (%u KiB): lists disabled", (unsigned)(len / 1024));
        snprintf(g_st.error, sizeof(g_st.error), "not enough PSRAM for the filter image (%u KiB)",
                 (unsigned)(len / 1024));
        return ESP_ERR_NO_MEM;
    }
    g_active = s;
    const fl_stats_t *st = fl_image_stats(pimg);
    ESP_LOGI(TAG, "filter image slot %c active: %.2f MiB, %u keys, %u generic rules, generation %u", 'a' + s,
             len / 1048576.0, st->keys, st->generic, (unsigned)gen);
    return ESP_OK;
}

/* ---- custom rules / local records -------------------------------------------------- */

static int compile_custom(const char *text, size_t len, fl_image_t **out, fl_stats_t *stats, char *err,
                          size_t errlen) {
    fl_memstore_t runs, sink;
    fl_memstore_init(&runs, 8u << 20);
    fl_memstore_init(&sink, 8u << 20);
    fl_compile_opts_t o;
    memset(&o, 0, sizeof(o));
    o.runs = &runs.st;
    o.chunk_bytes = 128 * 1024;
    fl_compiler_t *c = fl_compile_new(&o);
    int rc = c ? 0 : FL_ERR_NOMEM;
    if (!rc) {
        fl_compile_begin_source(c, "custom", 0);
        fl_compile_feed(c, text, len);
        fl_compile_line(c, "", 0);
        fl_compile_end_source(c);
        int n = fl_compile_finish(c, &sink.st, stats);
        if (n < 0) {
            rc = n;
            snprintf(err, errlen, "%s", fl_compile_error(c));
        } else {
            uint8_t *d = dc_malloc_ext((size_t)n);
            if (!d) {
                rc = FL_ERR_NOMEM;
            } else {
                memcpy(d, sink.buf.data, (size_t)n);
                rc = fl_image_load(d, (size_t)n, false, out);
                if (rc) dc_free(d);
            }
        }
    }
    if (c) fl_compile_free(c);
    fl_memstore_free(&runs);
    fl_memstore_free(&sink);
    return rc;
}

static void load_custom(const char *text, size_t len) {
    fl_image_t *img = NULL;
    fl_stats_t st;
    char err[96];
    memset(&st, 0, sizeof(st));
    bool empty = true;
    for (size_t i = 0; i < len && empty; i++)
        if (text[i] != ' ' && text[i] != '\n' && text[i] != '\r' && text[i] != '\t') empty = false;
    if (!empty && compile_custom(text, len, &img, &st, err, sizeof(err)) != 0) {
        ESP_LOGE(TAG, "custom rules: %s", err);
        img = NULL;
    }
    xSemaphoreTake(g_img_mu, portMAX_DELAY);
    fl_image_t *old = g_custom;
    g_custom = img;
    g_custom_stats = st;
    publish_set();
    xSemaphoreGive(g_img_mu);
    if (old) fl_image_unref(old);
}

esp_err_t rules_set_custom(const char *text, size_t len, char *err, size_t errlen) {
    if (len > APP_RULES_MAX) {
        snprintf(err, errlen, "custom rules too large (max %u KiB)", APP_RULES_MAX / 1024);
        return ESP_ERR_INVALID_SIZE;
    }
    flash_lock();
    esp_err_t e = app_blob_save("rules", text, len);
    flash_unlock();
    if (e != ESP_OK) {
        snprintf(err, errlen, "saving failed: %s", esp_err_to_name(e));
        return e;
    }
    load_custom(text, len);
    return ESP_OK;
}

static dns_local_t *parse_local(const char *text, char *err, size_t errlen) {
    dns_local_t *l = dns_local_new();
    if (!l) return NULL;
    const char *p = text;
    int ln = 0;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        ln++;
        char line[512];
        if (n >= sizeof(line)) n = sizeof(line) - 1;
        memcpy(line, p, n);
        line[n] = 0;
        p = e ? e + 1 : p + n;
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        size_t sl = strlen(s);
        while (sl && (s[sl - 1] == '\r' || s[sl - 1] == ' ' || s[sl - 1] == '\t')) s[--sl] = 0;
        if (!*s || *s == '#') continue;
        char *dom = s;
        while (*s && *s != ' ' && *s != '\t') s++;
        if (*s) *s++ = 0;
        while (*s == ' ' || *s == '\t') s++;
        char *type = s;
        while (*s && *s != ' ' && *s != '\t') s++;
        if (*s) *s++ = 0;
        while (*s == ' ' || *s == '\t') s++;
        char *val = s;
        if (!*dom || !*type || !*val) {
            snprintf(err, errlen, "line %d: expected 'domain TYPE value'", ln);
            dns_local_free(l);
            return NULL;
        }
        unsigned ttl = 300;
        char *t = strstr(val, " ttl=");
        if (t) {
            ttl = (unsigned)atoi(t + 5);
            *t = 0;
        }
        const char *e2;
        if (dns_local_add(l, dom, type, ttl, val, &e2) < 0) {
            snprintf(err, errlen, "line %d: %s", ln, e2);
            dns_local_free(l);
            return NULL;
        }
    }
    return l;
}

esp_err_t rules_set_local(const char *text, size_t len, char *err, size_t errlen) {
    if (len > APP_LOCAL_MAX) {
        snprintf(err, errlen, "too large (max %u KiB)", APP_LOCAL_MAX / 1024);
        return ESP_ERR_INVALID_SIZE;
    }
    dns_local_t *l = parse_local(text, err, errlen);
    if (!l) return ESP_ERR_INVALID_ARG;
    flash_lock();
    esp_err_t e = app_blob_save("local", text, len);
    flash_unlock();
    if (e != ESP_OK) {
        dns_local_free(l);
        snprintf(err, errlen, "saving failed: %s", esp_err_to_name(e));
        return e;
    }
    dns_server_set_local(g_srv, dns_local_count(l) ? l : NULL);
    if (!dns_local_count(l)) dns_local_free(l);
    return ESP_OK;
}

/* ---- subscription status --------------------------------------------------------------- */

static cJSON *substat_load(void) {
    size_t n;
    char *s = app_blob_load("substat", &n);
    cJSON *j = s ? cJSON_ParseWithLength(s, n) : NULL;
    free(s);
    if (!cJSON_IsObject(j)) {
        cJSON_Delete(j);
        j = cJSON_CreateObject();
    }
    if (!cJSON_GetObjectItem(j, "lists")) cJSON_AddItemToObject(j, "lists", cJSON_CreateArray());
    return j;
}

static bool substat_save(cJSON *j) {
    char *s = cJSON_PrintUnformatted(j);
    if (!s) return false;
    flash_lock();
    esp_err_t e = app_blob_save("substat", s, strlen(s));
    flash_unlock();
    cJSON_free(s);
    if (e != ESP_OK) ESP_LOGE(TAG, "saving subscription status failed: %s", esp_err_to_name(e));
    return e == ESP_OK;
}

static cJSON *substat_find(cJSON *j, const char *url, bool create) {
    cJSON *lists = cJSON_GetObjectItem(j, "lists"), *e;
    cJSON_ArrayForEach(e, lists) {
        cJSON *u = cJSON_GetObjectItem(e, "url");
        if (cJSON_IsString(u) && !strcmp(u->valuestring, url)) return e;
    }
    if (!create) return NULL;
    e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "url", url);
    cJSON_AddItemToArray(lists, e);
    return e;
}

static void jset_str(cJSON *o, const char *k, const char *v) {
    cJSON_DeleteItemFromObject(o, k);
    cJSON_AddStringToObject(o, k, v ? v : "");
}
static void jset_num(cJSON *o, const char *k, double v) {
    cJSON_DeleteItemFromObject(o, k);
    cJSON_AddNumberToObject(o, k, v);
}
static const char *jget_str(const cJSON *o, const char *k) {
    cJSON *v = o ? cJSON_GetObjectItem(o, k) : NULL;
    return cJSON_IsString(v) ? v->valuestring : "";
}
static double jget_num(const cJSON *o, const char *k) {
    cJSON *v = o ? cJSON_GetObjectItem(o, k) : NULL;
    return cJSON_IsNumber(v) ? v->valuedouble : 0;
}

/* identity of the enabled list set: a change forces a rebuild */
static uint32_t lists_signature(const app_config_t *c) {
    uint32_t h = 0x811c9dc5u;
    for (unsigned i = 0; i < c->nsubs; i++) {
        if (!c->subs[i].enabled) continue;
        h = dc_crc32(h, c->subs[i].url, strlen(c->subs[i].url));
        h = dc_crc32(h, c->subs[i].allowlist ? "A" : "B", 1);
        h = dc_crc32(h, c->subs[i].name, strlen(c->subs[i].name));
    }
    return h;
}

/* Remove records from removed or disabled sources only AFTER successfully
 * switching to a new image. These are NVS metadata records, not separate
 * downloaded files: subscription bodies are streamed straight to staging. */
static void prune_inactive_substat(cJSON *ss, const app_config_t *cfg) {
    cJSON *lists = cJSON_GetObjectItem(ss, "lists");
    if (!cJSON_IsArray(lists)) return;
    for (int i = cJSON_GetArraySize(lists) - 1; i >= 0; --i) {
        cJSON *e = cJSON_GetArrayItem(lists, i);
        cJSON *u = cJSON_GetObjectItem(e, "url");
        bool keep = false;
        if (cJSON_IsString(u)) {
            for (unsigned k = 0; k < cfg->nsubs; ++k) {
                if (cfg->subs[k].enabled && !strcmp(u->valuestring, cfg->subs[k].url)) {
                    keep = true;
                    break;
                }
            }
        }
        if (!keep) cJSON_DeleteItemFromArray(lists, i);
    }
}

/* Delete obsolete rule DATA, not just the old image header. This is
 * deliberately done only after the current image and its NVS metadata have
 * been committed: a failed download/compile must retain the old rules.
 *
 * Erase in small aligned batches and yield so a full 8.5 MiB cleanup does
 * not hold the updater CPU continuously. Neither partition is used for an
 * active MMAP image here: activate_slot() copied it to PSRAM and unmapped it.
 */
static bool erase_old_partition(const esp_partition_t *p, const char *label) {
    if (!p || (p->size % SEC) != 0) return false;
    size_t off = 0;
    while (off < p->size) {
        /* Invalidate the 4 KiB image header first: reboot in the middle of
         * erasure must never revive the obsolete, now partly erased image. */
        size_t step = (off % BLOCK == 0 && p->size - off >= BLOCK) ? BLOCK : SEC;
        if (off == 0) step = SEC;
        flash_lock();
        esp_err_t err = esp_partition_erase_range(p, off, step);
        flash_unlock();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "erasing obsolete %s at %u failed: %s", label,
                     (unsigned)off, esp_err_to_name(err));
            return false;
        }
        off += step;
        vTaskDelay(1);
    }
    return true;
}

/* A committed cleanup marker avoids erasing the same empty partitions every
 * 30 minutes and also makes an OTA from v1.0.1 clean up legacy contents on
 * the first successful unchanged-list check. The generation changes after
 * each rebuild, so the other A/B slot can be retired safely next time. */
static bool obsolete_flash_is_clean(const cJSON *ss, int active) {
    const cJSON *slot = cJSON_GetObjectItem(ss, "flash_gc_slot");
    const cJSON *gen = cJSON_GetObjectItem(ss, "flash_gc_gen");
    return cJSON_IsNumber(slot) && cJSON_IsNumber(gen) &&
           slot->valueint == active &&
           (uint32_t)gen->valuedouble == (uint32_t)jget_num(ss, "gen");
}

static bool cleanup_obsolete_flash(cJSON *ss, int active) {
    if (active != -1 && active != g_active) {
        ESP_LOGE(TAG, "refusing obsolete flash cleanup: active slot changed");
        return false;
    }
    if (obsolete_flash_is_clean(ss, active)) return true;
    snprintf(g_st.phase, sizeof(g_st.phase), "cleanup");
    /* Active means the CURRENT persistent slot; do not touch its bytes. When
     * there are no enabled subscriptions, both slots may be erased. */
    for (int i = 0; i < 2; i++) {
        if (i == active) continue;
        if (!erase_old_partition(g_slot[i], i ? "rules_b" : "rules_a")) return false;
    }
    /* staging only contains temporary sorting runs, never live DNS rules. */
    if (!erase_old_partition(g_staging, "staging")) return false;
    jset_num(ss, "flash_gc_slot", active);
    jset_num(ss, "flash_gc_gen", jget_num(ss, "gen"));
    if (!substat_save(ss)) return false;
    ESP_LOGI(TAG, "obsolete rule flash erased; active slot %d", active);
    return true;
}

/* ---- download ----------------------------------------------------------------------------- */

typedef struct {
    char etag[96];
    char lm[48];
} hdrs_t;

static esp_err_t http_ev(esp_http_client_event_t *e) {
    hdrs_t *h = (hdrs_t *)e->user_data;
    if (e->event_id == HTTP_EVENT_ON_HEADER && h) {
        if (!strcasecmp(e->header_key, "ETag")) snprintf(h->etag, sizeof(h->etag), "%s", e->header_value);
        if (!strcasecmp(e->header_key, "Last-Modified")) snprintf(h->lm, sizeof(h->lm), "%s", e->header_value);
    }
    return ESP_OK;
}

/* GET url.  With etag/lm set the request is conditional (returns 304).
 * The body is fed to the compiler when c != NULL.  Returns the HTTP status
 * (200, 304) or -1 with err. */
static int http_get(const char *url, const char *etag, const char *lm, fl_compiler_t *c, uint32_t *bytes,
                    uint32_t *crc, hdrs_t *hd, char *err, size_t errlen) {
    esp_http_client_config_t hc;
    memset(&hc, 0, sizeof(hc));
    hc.url = url;
    hc.crt_bundle_attach = esp_crt_bundle_attach;
    hc.timeout_ms = 30000;
    hc.buffer_size = 4096;
    hc.buffer_size_tx = 1024;
    hc.max_redirection_count = 5;
    hc.user_agent = "esp32s3-dns/1.0";
    hc.event_handler = http_ev;
    hc.user_data = hd;
    esp_http_client_handle_t cl = esp_http_client_init(&hc);
    if (!cl) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    if (etag && etag[0]) esp_http_client_set_header(cl, "If-None-Match", etag);
    if (lm && lm[0]) esp_http_client_set_header(cl, "If-Modified-Since", lm);
    int status = -1;
    int64_t clen = 0;
    for (int redir = 0; redir < 6; redir++) {
        esp_err_t e = esp_http_client_open(cl, 0);
        if (e != ESP_OK) {
            snprintf(err, errlen, "connection failed: %s", esp_err_to_name(e));
            goto out;
        }
        clen = esp_http_client_fetch_headers(cl);
        status = esp_http_client_get_status_code(cl);
        if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
            esp_http_client_set_redirection(cl);
            esp_http_client_close(cl);
            status = -1;
            continue;
        }
        break;
    }
    if (status == 304) goto out;
    if (status != 200) {
        snprintf(err, errlen, status < 0 ? "too many redirects" : "HTTP status %d", status);
        status = -1;
        goto out;
    }
    if (c) {
        char *buf = malloc(4096);
        uint32_t total = 0, h = 0;
        int n = 0;
        uint64_t last_yield = dc_time_us();
        while (buf && (n = esp_http_client_read(cl, buf, 4096)) > 0) {
            total += (uint32_t)n;
            h = dc_crc32(h, buf, (size_t)n);
            g_st.bytes += (uint32_t)n;
            if (total > MAX_LIST_BYTES) {
                snprintf(err, errlen, "list larger than %u MiB", MAX_LIST_BYTES >> 20);
                n = -1;
                break;
            }
            int rc = fl_compile_feed(c, buf, (size_t)n);
            if (rc) {
                if (rc == FL_ERR_HTML || (rc == FL_ERR_BINARY && !fl_compile_error(c)[0]))
                    snprintf(err, errlen, "not a filter list (%s)", rc == FL_ERR_HTML ? "HTML page" : "binary data");
                else
                    snprintf(err, errlen, "compiler: %s", fl_compile_error(c));
                n = -1;
                break;
            }
            if (dc_time_us() - last_yield > 50000) { /* let lower priority tasks run */
                vTaskDelay(1);
                last_yield = dc_time_us();
            }
        }
        free(buf);
        if (n < 0 && !err[0]) snprintf(err, errlen, "download interrupted");
        if (n == 0 && clen > 0 && total != (uint64_t)clen) {
            snprintf(err, errlen, "truncated download (%u of %lld bytes)", (unsigned)total, (long long)clen);
            n = -1;
        }
        if (n == 0 && clen <= 0 && !esp_http_client_is_complete_data_received(cl)) {
            snprintf(err, errlen, "incomplete download");
            n = -1;
        }
        if (n < 0) status = -1;
        if (bytes) *bytes = total;
        if (crc) *crc = h;
    }
out:
    esp_http_client_close(cl);
    esp_http_client_cleanup(cl);
    return status;
}

/* ---- update ------------------------------------------------------------------------------------ */

static bool progress_cb(void *arg, const char *phase, uint32_t done, uint32_t total) {
    static uint64_t last;
    snprintf(g_st.phase, sizeof(g_st.phase), "%s", phase);
    uint64_t now = dc_time_us();
    if (now - last > 50000) {
        vTaskDelay(1);
        last = now;
    }
    return true;
}

static void set_error(const char *fmt, const char *a, const char *b) {
    snprintf(g_st.error, sizeof(g_st.error), fmt, a, b);
    ESP_LOGE(TAG, "%s", g_st.error);
}

static void run_update(bool force) {
    app_config_t *cfg = app_config_get();
    if (!cfg) return;
    uint64_t t0 = dc_time_us();
    g_st.error[0] = 0;
    g_st.bytes = 0;
    g_st.current[0] = 0;
    g_st.started = uptime_s();
    g_st.last_attempt = uptime_s();
    snprintf(g_st.phase, sizeof(g_st.phase), "check");
    cJSON *ss = substat_load();
    if (!ss) {
        set_error("subscription metadata allocation failed%s%s", "", "");
        goto done;
    }
    uint32_t sig = lists_signature(cfg);
    unsigned nen = 0;
    for (unsigned i = 0; i < cfg->nsubs; i++) nen += cfg->subs[i].enabled;

    if (!nen) { /* no subscriptions: drop the image */
        if (g_subs) {
            xSemaphoreTake(g_img_mu, portMAX_DELAY);
            fl_image_t *old = g_subs;
            g_subs = NULL;
            publish_set();
            xSemaphoreGive(g_img_mu);
            fl_image_unref(old);
        }
        g_active = -1;
        jset_num(ss, "slot", -1);
        jset_num(ss, "sig", sig);
        prune_inactive_substat(ss, cfg);
        if (substat_save(ss)) {
            /* Both retired rule slots and the staging runs are now obsolete.
             * Do the full erase only once per committed generation. */
            if (!cleanup_obsolete_flash(ss, -1))
                set_error("empty-list flash cleanup incomplete%s%s", "", "");
        } else {
            set_error("saving empty subscription set failed%s%s", "", "");
        }
        goto done;
    }

    /* unchanged lists (conditional requests) need no rebuild */
    if (!force && g_subs && (uint32_t)jget_num(ss, "sig") == sig) {
        bool changed = false, failed = false;
        for (unsigned i = 0; i < cfg->nsubs && !changed; i++) {
            if (!cfg->subs[i].enabled) continue;
            cJSON *st = substat_find(ss, cfg->subs[i].url, false);
            const char *et = jget_str(st, "etag"), *lm = jget_str(st, "lm");
            if (!et[0] && !lm[0]) {
                changed = true;
                break;
            }
            snprintf(g_st.current, sizeof(g_st.current), "%s", cfg->subs[i].name);
            hdrs_t hd = {{0}, {0}};
            char err[128] = "";
            int status = http_get(cfg->subs[i].url, et, lm, NULL, NULL, NULL, &hd, err, sizeof(err));
            if (status == 200) changed = true;
            if (status < 0) {
                failed = true;
                jset_str(st, "error", err);
                jset_num(st, "err_time", dc_wall_time());
                set_error("%s: %s", cfg->subs[i].name, err);
            }
        }
        if (!changed) {
            if (!failed) {
                g_st.last_ok = dc_wall_time();
                g_st.last_ok_up = uptime_s() + 1;
            }
            ESP_LOGI(TAG, "filter lists unchanged");
            if (!substat_save(ss))
                set_error("saving subscription status failed%s%s", "", "");
            else if (!cleanup_obsolete_flash(ss, g_active))
                set_error("old rule flash cleanup incomplete%s%s", "", "");
            goto done;
        }
    }

    /* A full rebuild needs working memory. Release both cache levels before
     * any compiler allocation; live DNS and filtering stay enabled. */
    dns_server_cache_build_mode(g_srv, true);
    bool cache_paused = true;
    int target = g_active == 0 ? 1 : 0;
    fstore_t runs, sink;
    if (!fs_open(&runs, g_staging, true)) {
        set_error("cannot allocate staging sector map%s%s", "", "");
        goto restore_cache;
    }
    if (!fs_open(&sink, g_slot[target], false)) {
        fs_close(&runs);
        set_error("cannot allocate image sector map%s%s", "", "");
        goto restore_cache;
    }
    uint32_t gen = (uint32_t)jget_num(ss, "gen") + 1;
    fl_compile_opts_t o;
    memset(&o, 0, sizeof(o));
    o.runs = &runs.st;
    o.chunk_bytes = 192u * 1024u; /* smaller peak arena + offsets, more flash runs */
    o.generation = gen;
    o.progress = progress_cb;
    fl_compiler_t *c = fl_compile_new(&o);
    bool ok = c != NULL;
    if (!ok) set_error("cannot allocate filter compiler%s%s", "", "");
    unsigned ok_cnt = 0;
    for (unsigned i = 0; i < cfg->nsubs && ok; i++) {
        app_sub_t *sub = &cfg->subs[i];
        if (!sub->enabled) continue;
        snprintf(g_st.phase, sizeof(g_st.phase), "download");
        snprintf(g_st.current, sizeof(g_st.current), "%s", sub->name);
        ESP_LOGI(TAG, "downloading %s", sub->url);
        cJSON *st = substat_find(ss, sub->url, true);
        /* (ok_time stays 0 while the clock is not set) */
        /* first install and subsequent failures are handled consistently */
        int src = fl_compile_begin_source(c, sub->name, sub->allowlist ? FL_SRC_ALLOWLIST : 0);
        hdrs_t hd = {{0}, {0}};
        char err[128] = "";
        uint32_t bytes = 0, crc = 0;
        int status = src < 0 ? -1 : http_get(sub->url, NULL, NULL, c, &bytes, &crc, &hd, err, sizeof(err));
        if (src < 0) snprintf(err, sizeof(err), "too many lists");
        int erc = fl_compile_end_source(c);
        if (status == 200 && erc < 0)
            snprintf(err, sizeof(err), "not a filter list (%s)", erc == FL_ERR_HTML ? "HTML page" : "binary data");
        if (status != 200 || erc < 0) {
            jset_str(st, "error", err);
            jset_num(st, "err_time", dc_wall_time());
            set_error("%s: %s", sub->name, err);
            /* Preserve existing image: first-boot download failure is not success. */
            ok = false;
            continue;
        }
        ok_cnt++;
        const fl_stats_t *ps = fl_compile_source_stats(c, src);
        jset_str(st, "error", "");
        jset_str(st, "etag", hd.etag);
        jset_str(st, "lm", hd.lm);
        jset_num(st, "ok", 1);
        jset_num(st, "ok_time", dc_wall_time());
        jset_num(st, "bytes", bytes);
        jset_num(st, "crc", crc);
        jset_num(st, "lines", ps ? ps->lines : 0);
        jset_num(st, "rules", ps ? ps->host_rules + ps->net_rules : 0);
        jset_num(st, "invalid", ps ? ps->invalid : 0);
        jset_num(st, "unsupported", ps ? ps->unsupported : 0);
        jset_num(st, "client_skipped", ps ? ps->client_skipped : 0);
    }
    if (ok && !ok_cnt) ok = false;
    fl_stats_t stats;
    int len = -1;
    if (ok) {
        snprintf(g_st.phase, sizeof(g_st.phase), "compile");
        g_st.current[0] = 0;
        len = fl_compile_finish(c, &sink.st, &stats);
        if (len < 0) {
            set_error("compile failed: %s%s", fl_compile_error(c),
                      len == FL_ERR_FULL ? " (lists too large for the flash slots)" : "");
            ok = false;
        }
    }
    if (c) fl_compile_free(c);
    fs_close(&runs);
    fs_close(&sink);
    if (ok) {
        /* If configuration changed while downloading, do not activate a
         * snapshot containing a recently disabled/removed subscription. */
        app_config_t *latest = app_config_get();
        if (!latest || lists_signature(latest) != sig) {
            set_error("subscription settings changed during update%s%s", "", "");
            ok = false;
        }
        free(latest);
    }
    if (ok) {
        snprintf(g_st.phase, sizeof(g_st.phase), "activate");
        if (activate_slot(target) != ESP_OK) {
            /* The previous Flash slot is still intact. An OOM during the
             * mmap -> PSRAM handoff can leave the active filter unset;
             * best-effort reload the previously committed image before
             * making DNS queries run without subscription filtering. */
            if (g_active >= 0 && g_active != target && activate_slot(g_active) != ESP_OK)
                ESP_LOGE(TAG, "could not restore the previous filter image");
            set_error("activating the new image failed%s%s", "", "");
            ok = false;
        }
    }
    if (ok) {
        jset_num(ss, "slot", target);
        jset_num(ss, "gen", gen);
        jset_num(ss, "sig", sig);
        jset_num(ss, "built", dc_wall_time());
        prune_inactive_substat(ss, cfg);
        if (substat_save(ss)) {
            g_st.last_ok = dc_wall_time();
            g_st.last_ok_up = uptime_s() + 1;
            /* The new image has been committed; DNS cache can resume while
             * the obsolete Flash partitions are erased in the background.
             * Avoid stretching the cache-disabled period over large erases. */
            if (cache_paused) {
                dns_server_cache_build_mode(g_srv, false);
                cache_paused = false;
            }
            /* Physical cleanup, not just a 4 KiB header invalidation:
             * erase the entire retired A/B image and staging runs. The
             * cleanup marker is committed separately, so power loss causes
             * a retry without endangering the newly active image. */
            if (!cleanup_obsolete_flash(ss, target))
                set_error("old rule flash cleanup incomplete%s%s", "", "");
            ESP_LOGI(TAG, "update done: %.2f MiB image, %u keys, %u ms", len / 1048576.0, stats.keys,
                     (unsigned)((dc_time_us() - t0) / 1000));
        } else {
            set_error("saving new rule slot failed%s%s", "", "");
        }
    } else {
        /* Retain the previous committed signature if compilation fails.
         * Keep error details for individual sources when possible. */
        substat_save(ss);
    }
restore_cache:
    if (cache_paused) dns_server_cache_build_mode(g_srv, false);
done:
    g_st.last_ms = (uint32_t)((dc_time_us() - t0) / 1000);
    snprintf(g_st.phase, sizeof(g_st.phase), "%s", g_st.error[0] ? "failed" : "idle");
    g_st.current[0] = 0;
    cJSON_Delete(ss);
    free(cfg);
}

static void updater_task(void *arg) {
    net_wait_up(portMAX_DELAY);
    /* first check soon after boot (cheap when nothing changed) */
    g_st.next_due = uptime_s() + (g_subs ? 120 : 5);
    for (;;) {
        uint32_t now = uptime_s();
        if (g_trigger || now >= g_st.next_due) {
            if (net_is_up()) {
                bool force = g_force;
                g_trigger = g_force = false;
                g_running = true;
                run_update(force);
                g_running = false;
                app_config_t *cfg = app_config_get();
                uint32_t hours = cfg ? cfg->update_hours : 24;
                free(cfg);
                uint32_t next = g_st.error[0] ? RETRY_FAIL_S : hours ? hours * 3600u : 0x7FFFFFFFu;
                g_st.next_due = uptime_s() + next;
            } else {
                g_st.next_due = now + 60;
            }
        }
        now = uptime_s();
        uint32_t wait = g_st.next_due > now ? g_st.next_due - now : 1;
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS((wait > 3600 ? 3600 : wait) * 1000u));
    }
}

void rules_trigger_update(bool force) {
    if (force) g_force = true;
    g_trigger = true;
    /* Retry task allocation on explicit user action if boot was short on RAM. */
    if (!g_task) rules_start_updater();
    if (g_task) xTaskNotifyGive(g_task);
}

bool rules_update_running(void) { return g_running; }

/* ---- init --------------------------------------------------------------------------------------- */

void rules_init(dns_server_t *srv) {
    g_srv = srv;
    g_flash_mu = xSemaphoreCreateRecursiveMutex();
    g_img_mu = xSemaphoreCreateMutex();
    g_unmapped = xSemaphoreCreateBinary();
    g_slot[0] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "rules_a");
    g_slot[1] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "rules_b");
    g_staging = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x41, "staging");
    if (!g_slot[0] || !g_slot[1] || !g_staging) ESP_LOGE(TAG, "rule partitions missing (partitions.csv)");
    snprintf(g_st.phase, sizeof(g_st.phase), "idle");

    size_t n = 0;
    char *t = app_blob_load("rules", &n);
    if (t) {
        load_custom(t, n);
        free(t);
    }
    t = app_blob_load("local", &n);
    if (t) {
        char err[96];
        dns_local_t *l = parse_local(t, err, sizeof(err));
        if (l && dns_local_count(l))
            dns_server_set_local(g_srv, l);
        else if (l)
            dns_local_free(l);
        free(t);
    }
    /* the stored slot, else whichever slot holds a valid image */
    cJSON *ss = substat_load();
    int slot = (int)jget_num(ss, "slot");
    cJSON *sv = cJSON_GetObjectItem(ss, "slot");
    cJSON_Delete(ss);
    if (!sv) slot = 0;
    if (g_slot[0] && g_slot[1] && slot >= 0) {
        if (activate_slot(slot) != ESP_OK && activate_slot(1 - slot) != ESP_OK)
            ESP_LOGW(TAG, "no stored filter image: lists will be downloaded");
    }
}

void rules_start_updater(void) {
    /* stack must live in internal DRAM because updater_task writes flash and calls esp_partition_mmap */
    if (!g_task && g_staging &&
        xTaskCreatePinnedToCoreWithCaps(updater_task, "rules-upd", 16384, NULL, 2, &g_task, 0,
                                        MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) != pdPASS) {
        g_task = NULL;
        ESP_LOGE(TAG, "rule update task allocation failed (internal RAM)");
        snprintf(g_st.error, sizeof(g_st.error), "cannot allocate rule update task");
    }
}

/* ---- status / diagnostics ------------------------------------------------------------------------ */

cJSON *rules_status_json(void) {
    cJSON *r = cJSON_CreateObject();
    cJSON *u = cJSON_AddObjectToObject(r, "update");
    cJSON_AddBoolToObject(u, "running", g_running);
    cJSON_AddStringToObject(u, "phase", g_st.phase);
    cJSON_AddStringToObject(u, "current", g_st.current);
    cJSON_AddNumberToObject(u, "bytes", g_st.bytes);
    cJSON_AddStringToObject(u, "error", g_st.error);
    cJSON_AddNumberToObject(u, "last_ok", g_st.last_ok);
    cJSON_AddNumberToObject(u, "last_ok_ago_s", g_st.last_ok_up ? (double)(uptime_s() + 1 - g_st.last_ok_up) : -1);
    cJSON_AddNumberToObject(u, "last_duration_ms", g_st.last_ms);
    cJSON_AddNumberToObject(u, "next_in_s", g_st.next_due > uptime_s() ? g_st.next_due - uptime_s() : 0);

    xSemaphoreTake(g_img_mu, portMAX_DELAY);
    cJSON *im = cJSON_AddObjectToObject(r, "image");
    if (g_subs) {
        const fl_stats_t *st = fl_image_stats(g_subs);
        cJSON_AddNumberToObject(im, "slot", g_active);
        cJSON_AddNumberToObject(im, "generation", fl_image_generation(g_subs));
        cJSON_AddNumberToObject(im, "bytes", fl_image_size(g_subs));
        cJSON_AddNumberToObject(im, "keys", st->keys);
        cJSON_AddNumberToObject(im, "plain", st->plain);
        cJSON_AddNumberToObject(im, "complex", st->complex_domain);
        cJSON_AddNumberToObject(im, "generic", st->generic);
        cJSON_AddNumberToObject(im, "regex", st->regex);
        cJSON_AddNumberToObject(im, "badfilter", st->badfilter);
        cJSON_AddNumberToObject(im, "dnsrewrite", st->dnsrewrite);
        cJSON_AddNumberToObject(im, "invalid", st->invalid);
        cJSON_AddNumberToObject(im, "unsupported", st->unsupported);
        cJSON_AddNumberToObject(im, "client_skipped", st->client_skipped);
        cJSON_AddNumberToObject(im, "not_dns", st->not_dns + st->cosmetic);
        cJSON_AddNumberToObject(im, "compile_ms", st->compile_ms);
    }
    cJSON *cu = cJSON_AddObjectToObject(r, "custom");
    cJSON_AddBoolToObject(cu, "loaded", g_custom != NULL);
    cJSON_AddNumberToObject(cu, "rules", g_custom_stats.host_rules + g_custom_stats.net_rules);
    cJSON_AddNumberToObject(cu, "invalid", g_custom_stats.invalid);
    cJSON_AddNumberToObject(cu, "unsupported", g_custom_stats.unsupported);
    cJSON_AddNumberToObject(cu, "client_skipped", g_custom_stats.client_skipped);
    xSemaphoreGive(g_img_mu);

    cJSON *ss = substat_load();
    cJSON *lists = cJSON_DetachItemFromObject(ss, "lists");
    cJSON_AddItemToObject(r, "lists", lists ? lists : cJSON_CreateArray());
    cJSON_AddNumberToObject(r, "built", jget_num(ss, "built"));
    cJSON_Delete(ss);
    return r;
}

typedef struct {
    cJSON *arr;
} explain_t;

static void explain_cb(void *arg, const char *rule, const char *source, const char *effect) {
    explain_t *x = (explain_t *)arg;
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "rule", rule);
    cJSON_AddStringToObject(o, "source", source);
    cJSON_AddStringToObject(o, "effect", effect);
    cJSON_AddItemToArray(x->arr, o);
}

cJSON *rules_check_json(const char *host, uint16_t qtype) {
    cJSON *r = cJSON_CreateObject();
    char h[256];
    size_t n = 0;
    for (const char *p = host; *p && n < sizeof(h) - 1; p++) h[n++] = (char)dc_lower((uint8_t)*p);
    while (n && h[n - 1] == '.') n--;
    h[n] = 0;
    fl_req_t rq = {h, (uint16_t)n, qtype, 0, NULL};
    fl_set_t *set = dns_server_get_filters(g_srv);
    fl_result_t res;
    memset(&res, 0, sizeof(res));
    cJSON *arr = cJSON_AddArrayToObject(r, "matches");
    if (set) {
        fl_match(set, &rq, &res);
        explain_t x = {arr};
        fl_explain(set, &rq, explain_cb, &x);
        char *text = malloc(800);
        if (text) {
            char *src = text + 600;
            if (res.has_rule && fl_rule_text(set, &res.rule, h, text, 600, src, 200)) {
                cJSON_AddStringToObject(r, "rule", text);
                cJSON_AddStringToObject(r, "source", src);
            }
            free(text);
        }
        fl_set_unref(set);
    }
    static const char *verdicts[] = {"none", "allowed", "allowlisted", "blocked", "rewritten"};
    cJSON_AddStringToObject(r, "verdict", res.verdict < 5 ? verdicts[res.verdict] : "?");
    if (res.verdict == FL_V_BLOCK && res.n_ips) {
        cJSON *ips = cJSON_AddArrayToObject(r, "hosts_ips");
        for (unsigned i = 0; i < res.n_ips; i++) {
            char b[48];
            dc_ip_format(&res.ips[i], b, sizeof(b));
            cJSON_AddItemToArray(ips, cJSON_CreateString(b));
        }
    }
    if (res.verdict == FL_V_REWRITE && res.rw_kind == FL_RW_CNAME && res.cname) {
        char b[300];
        if (fl_name_from_wire(res.cname, 256, b, sizeof(b)) > 0) cJSON_AddStringToObject(r, "cname", b);
    }
    return r;
}
