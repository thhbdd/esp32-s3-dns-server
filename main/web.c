/*
 * web.c - web UI, REST API, DNS-over-HTTPS (RFC 8484 via esp_https_server),
 * TLS certificate management, Prometheus metrics, OTA.
 *
 * Authentication: HTTP Basic against the admin password (none until one is
 * set in the UI).  Verified credentials are remembered for 10 minutes so the
 * deliberately slow password hash is not paid on every request.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "app.h"
#include "dc_util.h"
#include "dot_server.h"
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#ifdef CONFIG_ESP_HTTPS_SERVER_ENABLE
#include "esp_https_server.h"
#endif
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "fl_filter.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/version.h"
#if MBEDTLS_VERSION_MAJOR >= 4
#include "psa/crypto.h"
#else
#include "mbedtls/sha256.h"
#endif
#include "mbedtls/x509_crt.h"
#include "net.h"
#include "rules.h"
#include "upstream_tls.h"

static const char *TAG = "web";

/* DoH input bound: matches the DNS core's 4096-byte message limit. */
#define DOH_MAX_WIRE_MSG 4096u

extern const uint8_t index_html_gz_start[] asm("_binary_index_html_gz_start");
extern const uint8_t index_html_gz_end[] asm("_binary_index_html_gz_end");

static dns_server_t *g_srv;
static httpd_handle_t g_httpd;
static httpd_handle_t g_httpsd;
static uint16_t g_http_port = 80;
static uint16_t g_https_port = 443;
static char *g_https_cert;
static char *g_https_key;
static SemaphoreHandle_t g_auth_mu;
static volatile bool g_ota_running;

/* ---- helpers ----------------------------------------------------------------------- */

static esp_err_t send_json(httpd_req_t *req, cJSON *j) {
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return httpd_resp_send_500(req);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t e = httpd_resp_send(req, s, HTTPD_RESP_USE_STRLEN);
    cJSON_free(s);
    return e;
}

static esp_err_t send_err(httpd_req_t *req, const char *status, const char *msg) {
    httpd_resp_set_status(req, status);
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "error", msg);
    return send_json(req, j);
}

static esp_err_t send_ok(httpd_req_t *req) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddBoolToObject(j, "ok", true);
    return send_json(req, j);
}

/* Receives up to `len` bytes; a client that stops sending is given up after
 * 3 receive timeouts (30 s). */
static int recv_some(httpd_req_t *req, char *buf, size_t len) {
    for (int timeouts = 0; timeouts < 3; timeouts++) {
        int n = httpd_req_recv(req, buf, len);
        if (n != HTTPD_SOCK_ERR_TIMEOUT) return n > 0 ? n : -1;
    }
    return -1;
}

static bool recv_all(httpd_req_t *req, char *buf, size_t len) {
    for (size_t got = 0; got < len;) {
        int n = recv_some(req, buf + got, len - got);
        if (n < 0) return false;
        got += (size_t)n;
    }
    return true;
}

/* reads the whole body (max bytes); NUL terminated, caller frees */
static char *read_body(httpd_req_t *req, size_t max, size_t *len) {
    if (req->content_len > max) return NULL;
    char *b = malloc(req->content_len + 1);
    if (!b) return NULL;
    if (!recv_all(req, b, req->content_len)) {
        free(b);
        return NULL;
    }
    b[req->content_len] = 0;
    if (len) *len = req->content_len;
    return b;
}

static cJSON *read_json(httpd_req_t *req, size_t max) {
    size_t n;
    char *b = read_body(req, max, &n);
    if (!b) return NULL;
    cJSON *j = cJSON_ParseWithLength(b, n);
    free(b);
    return j;
}

static bool query_param(httpd_req_t *req, const char *key, char *out, size_t cap) {
    size_t qlen = httpd_req_get_url_query_len(req);
    out[0] = 0;
    if (!qlen || qlen >= 1200) return false;
    char *q = malloc(qlen + 1);
    if (!q) return false;
    bool ok = httpd_req_get_url_query_str(req, q, qlen + 1) == ESP_OK &&
              httpd_query_key_value(q, key, out, cap) == ESP_OK;
    free(q);
    return ok;
}

static void url_decode(char *s) {
    char *o = s;
    for (char *p = s; *p; p++) {
        if (*p == '%' && p[1] && p[2]) {
            char h[3] = {p[1], p[2], 0};
            *o++ = (char)strtol(h, NULL, 16);
            p += 2;
        } else {
            *o++ = *p == '+' ? ' ' : *p;
        }
    }
    *o = 0;
}

static void peer_ip(httpd_req_t *req, dc_ip_t *ip, uint16_t *port) {
    struct sockaddr_storage sa;
    socklen_t sl = sizeof(sa);
    memset(ip, 0, sizeof(*ip));
    *port = 0;
    int fd = httpd_req_to_sockfd(req);
    if (getpeername(fd, (struct sockaddr *)&sa, &sl) != 0) return;
    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&sa;
        ip->family = 4;
        memcpy(ip->addr, &a->sin_addr, 4);
        *port = ntohs(a->sin_port);
    } else if (sa.ss_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&sa;
        ip->family = 6;
        memcpy(ip->addr, &a->sin6_addr, 16);
        *port = ntohs(a->sin6_port);
        dc_ip_unmap4(ip);
    }
}

/* ---- authentication --------------------------------------------------------------------- */

static struct {
    uint8_t digest[32];
    int64_t until;
} g_auth_cache[4];

static bool authorized(httpd_req_t *req) {
    if (!app_auth_required()) return true;
    char hdr[200];
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) != ESP_OK ||
        strncmp(hdr, "Basic ", 6) != 0)
        return false;
    uint8_t dg[32];
#if MBEDTLS_VERSION_MAJOR >= 4
    size_t dg_len = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)hdr, strlen(hdr), dg,
                         sizeof(dg), &dg_len) != PSA_SUCCESS || dg_len != sizeof(dg))
        return false;
#else
    if (mbedtls_sha256((const uint8_t *)hdr, strlen(hdr), dg, 0) != 0) return false;
#endif
    int64_t now = esp_timer_get_time();
    xSemaphoreTake(g_auth_mu, portMAX_DELAY);
    for (int i = 0; i < 4; i++)
        if (g_auth_cache[i].until > now && !memcmp(g_auth_cache[i].digest, dg, 32)) {
            xSemaphoreGive(g_auth_mu);
            return true;
        }
    xSemaphoreGive(g_auth_mu);
    unsigned char dec[150];
    size_t dl = 0;
    if (mbedtls_base64_decode(dec, sizeof(dec) - 1, &dl, (const unsigned char *)hdr + 6, strlen(hdr + 6)) != 0)
        return false;
    dec[dl] = 0;
    char *colon = strchr((char *)dec, ':');
    if (!colon) return false;
    *colon = 0;
    if (!app_auth_check((char *)dec, colon + 1)) {
        vTaskDelay(pdMS_TO_TICKS(500)); /* slow down guessing */
        return false;
    }
    xSemaphoreTake(g_auth_mu, portMAX_DELAY);
    int slot = 0;
    for (int i = 1; i < 4; i++)
        if (g_auth_cache[i].until < g_auth_cache[slot].until) slot = i;
    memcpy(g_auth_cache[slot].digest, dg, 32);
    g_auth_cache[slot].until = now + 600 * 1000000LL;
    xSemaphoreGive(g_auth_mu);
    return true;
}

static bool same_origin(httpd_req_t *req) {
    if (req->method == HTTP_GET) return true;
    char origin[128], host[128];
    size_t ol = httpd_req_get_hdr_value_len(req, "Origin");
    if (!ol) return true;
    if (ol >= sizeof(origin) || httpd_req_get_hdr_value_str(req, "Origin", origin, sizeof(origin)) != ESP_OK ||
        httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK)
        return false;
    const char *o = strstr(origin, "://");
    return o && !strcasecmp(o + 3, host);
}

static void auth_cache_clear(void) {
    xSemaphoreTake(g_auth_mu, portMAX_DELAY);
    memset(g_auth_cache, 0, sizeof(g_auth_cache));
    xSemaphoreGive(g_auth_mu);
}

#define REQUIRE_AUTH(req)                                                                                      \
    do {                                                                                                       \
        if (!same_origin(req)) return send_err(req, "403 Forbidden", "cross-site request refused");            \
        if (!authorized(req)) {                                                                                \
            httpd_resp_set_status(req, "401 Unauthorized");                                                    \
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"ESP32 DNS\"");                          \
            return httpd_resp_send(req, "authentication required", HTTPD_RESP_USE_STRLEN);                     \
        }                                                                                                      \
    } while (0)

/* ---- TLS certificate inspection & management ------------------------------------------- */

#if MBEDTLS_VERSION_MAJOR < 4
static int rng_cb(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}
#endif

static bool validate_tls_pair(const char *cert_pem, size_t cert_len, const char *key_pem, size_t key_len,
                              char *err, size_t errlen) {
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&pk);
    int rc = mbedtls_x509_crt_parse(&crt, (const unsigned char *)cert_pem, cert_len + 1);
    if (rc != 0) {
        snprintf(err, errlen, "invalid PEM certificate (-0x%04x)", (unsigned)-rc);
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pk);
        return false;
    }
#if MBEDTLS_VERSION_MAJOR >= 4
    rc = mbedtls_pk_parse_key(&pk, (const unsigned char *)key_pem, key_len + 1, NULL, 0);
#else
    rc = mbedtls_pk_parse_key(&pk, (const unsigned char *)key_pem, key_len + 1, NULL, 0, rng_cb, NULL);
#endif
    if (rc != 0) {
        snprintf(err, errlen, "invalid PEM private key (-0x%04x)", (unsigned)-rc);
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&pk);
        return false;
    }
#if MBEDTLS_VERSION_MAJOR >= 4
    rc = mbedtls_pk_check_pair(&crt.pk, &pk);
#else
    rc = mbedtls_pk_check_pair(&crt.pk, &pk, rng_cb, NULL);
#endif
    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&pk);
    if (rc != 0) {
        snprintf(err, errlen, "certificate and private key do not match (-0x%04x)", (unsigned)-rc);
        return false;
    }
    return true;
}

static cJSON *tls_status_json(void) {
    cJSON *r = cJSON_CreateObject();
    size_t clen = 0, klen = 0;
    char *cert = app_blob_load("tls_cert", &clen);
    char *key = app_blob_load("tls_key", &klen);
    bool configured = cert && key && clen > 0 && klen > 0;
    cJSON_AddBoolToObject(r, "configured", configured);
    cJSON_AddBoolToObject(r, "https_running", g_httpsd != NULL);
    cJSON_AddBoolToObject(r, "dot_running", dot_server_running());
    cJSON_AddNumberToObject(r, "https_port", g_https_port);
    if (configured) {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        if (mbedtls_x509_crt_parse(&crt, (const unsigned char *)cert, clen + 1) == 0) {
            char subj[160] = "", iss[160] = "", exp[48] = "";
            mbedtls_x509_dn_gets(subj, sizeof(subj), &crt.subject);
            mbedtls_x509_dn_gets(iss, sizeof(iss), &crt.issuer);
            snprintf(exp, sizeof(exp), "%04d-%02d-%02d %02d:%02d UTC", crt.valid_to.year, crt.valid_to.mon,
                     crt.valid_to.day, crt.valid_to.hour, crt.valid_to.min);
            cJSON_AddStringToObject(r, "subject", subj);
            cJSON_AddStringToObject(r, "issuer", iss);
            cJSON_AddStringToObject(r, "valid_until", exp);
        }
        mbedtls_x509_crt_free(&crt);
    }
    free(cert);
    free(key);
    return r;
}

static esp_err_t h_tls(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    if (req->method == HTTP_GET) return send_json(req, tls_status_json());
    if (req->method == HTTP_DELETE) {
        flash_lock();
        app_blob_save("tls_cert", NULL, 0);
        app_blob_save("tls_key", NULL, 0);
        flash_unlock();
        app_reboot_later(1200); /* safely reload listeners outside their own HTTP task */
        return send_json(req, tls_status_json());
    }
    cJSON *j = read_json(req, APP_TLS_MAX * 2 + 1024);
    if (!j) return send_err(req, "400 Bad Request", "invalid JSON or payload too large");
    cJSON *jc = cJSON_GetObjectItemCaseSensitive(j, "cert");
    cJSON *jk = cJSON_GetObjectItemCaseSensitive(j, "key");
    if (!cJSON_IsString(jc) || !cJSON_IsString(jk) || !jc->valuestring[0] || !jk->valuestring[0]) {
        cJSON_Delete(j);
        return send_err(req, "400 Bad Request", "both PEM certificate and private key are required");
    }
    size_t clen = strlen(jc->valuestring), klen = strlen(jk->valuestring);
    if (clen > APP_TLS_MAX || klen > APP_TLS_MAX) {
        cJSON_Delete(j);
        return send_err(req, "413 Payload Too Large", "certificate or key exceeds 16 KiB");
    }
    char err[160];
    if (!validate_tls_pair(jc->valuestring, clen, jk->valuestring, klen, err, sizeof(err))) {
        cJSON_Delete(j);
        return send_err(req, "400 Bad Request", err);
    }
    flash_lock();
    esp_err_t e1 = app_blob_save("tls_cert", jc->valuestring, clen);
    esp_err_t e2 = app_blob_save("tls_key", jk->valuestring, klen);
    flash_unlock();
    cJSON_Delete(j);
    if (e1 != ESP_OK || e2 != ESP_OK) return send_err(req, "500 Internal Server Error", "saving certificate to NVS failed");
    app_reboot_later(1200); /* never stop httpd_ssl from its own request callback */
    return send_json(req, tls_status_json());
}

/* ---- UI ------------------------------------------------------------------------------------ */

static esp_err_t h_index(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    return httpd_resp_send(req, (const char *)index_html_gz_start, index_html_gz_end - index_html_gz_start);
}

/* ---- status / statistics ------------------------------------------------------------------- */

static const char *reset_reason(void) {
    switch (esp_reset_reason()) {
    case ESP_RST_POWERON: return "power-on";
    case ESP_RST_SW: return "software";
    case ESP_RST_PANIC: return "panic";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT: return "watchdog";
    case ESP_RST_BROWNOUT: return "brownout";
    case ESP_RST_DEEPSLEEP: return "deep sleep";
    default: return "other";
    }
}

static void add_hist(cJSON *o, const char *k, const dns_hist_t *h) {
    cJSON *x = cJSON_AddObjectToObject(o, k);
    cJSON_AddNumberToObject(x, "count", h->count);
    cJSON_AddNumberToObject(x, "mean_us", dns_hist_mean(h));
    cJSON_AddNumberToObject(x, "p50_us", dns_hist_percentile(h, 50));
    cJSON_AddNumberToObject(x, "p90_us", dns_hist_percentile(h, 90));
    cJSON_AddNumberToObject(x, "p99_us", dns_hist_percentile(h, 99));
}

static cJSON *stats_json(void) {
    dns_stats_t *st = malloc(sizeof(dns_stats_t));
    cJSON *r = cJSON_CreateObject();
    if (!st) return r;
    dns_server_get_stats(g_srv, st);
    const struct {
        const char *k;
        uint32_t v;
    } f[] = {{"queries", st->queries},     {"udp", st->udp},
             {"tcp", st->tcp},             {"dot", st->dot},
             {"doh", st->doh},             {"blocked", st->blocked},
             {"resp_blocked", st->resp_blocked}, {"rewritten", st->rewritten},
             {"local", st->local},         {"allowed", st->allowed},
             {"cached", st->cached},       {"forwarded", st->forwarded},
             {"failed", st->failed},       {"refused", st->refused},
             {"dropped", st->dropped},     {"ratelimited", st->ratelimited},
             {"malformed", st->malformed}, {"truncated", st->truncated},
             {"stale_served", st->stale_served}, {"coalesced", st->coalesced},
             {"qtype_a", st->qtype_a},     {"qtype_aaaa", st->qtype_aaaa},
             {"qtype_https", st->qtype_https}, {"qtype_other", st->qtype_other},
             {"pending", st->pending}};
    for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++) cJSON_AddNumberToObject(r, f[i].k, f[i].v);
    cJSON *lat = cJSON_AddObjectToObject(r, "latency");
    add_hist(lat, "local", &st->local_us);
    add_hist(lat, "cached", &st->cached_us);
    add_hist(lat, "forwarded", &st->forward_us);
    cJSON *c = cJSON_AddObjectToObject(r, "cache");
    cJSON_AddNumberToObject(c, "entries", st->cache.entries);
    cJSON_AddNumberToObject(c, "bytes_used", st->cache.bytes_used);
    cJSON_AddNumberToObject(c, "bytes_total", st->cache.bytes_total);
    cJSON_AddNumberToObject(c, "l1_hits", st->cache.l1_hits);
    cJSON_AddNumberToObject(c, "l2_hits", st->cache.l2_hits);
    cJSON_AddNumberToObject(c, "stale_hits", st->cache.stale_hits);
    cJSON_AddNumberToObject(c, "misses", st->cache.misses);
    cJSON_AddNumberToObject(c, "evictions", st->cache.evictions);
    cJSON *ups = cJSON_AddArrayToObject(r, "upstreams");
    for (unsigned i = 0; i < st->nup; i++) {
        cJSON *u = cJSON_CreateObject();
        cJSON_AddStringToObject(u, "address", st->up[i].text);
        cJSON_AddNumberToObject(u, "sent", st->up[i].sent);
        cJSON_AddNumberToObject(u, "ok", st->up[i].ok);
        cJSON_AddNumberToObject(u, "timeouts", st->up[i].timeouts);
        cJSON_AddNumberToObject(u, "errors", st->up[i].errors);
        cJSON_AddNumberToObject(u, "rtt_ms", st->up[i].rtt_us / 1000.0);
        cJSON_AddBoolToObject(u, "healthy", st->up[i].healthy);
        cJSON_AddItemToArray(ups, u);
    }
    free(st);
    return r;
}

static esp_err_t h_status(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    cJSON *r = cJSON_CreateObject();
    const esp_app_desc_t *d = esp_app_get_description();
    cJSON_AddStringToObject(r, "version", d->version);
    cJSON_AddStringToObject(r, "idf", d->idf_ver);
    cJSON_AddStringToObject(r, "build", d->date);
    cJSON_AddNumberToObject(r, "uptime", (double)(esp_timer_get_time() / 1000000));
    cJSON_AddNumberToObject(r, "time", net_time_synced() ? (double)time(NULL) : 0);
    cJSON_AddStringToObject(r, "reset_reason", reset_reason());
    cJSON_AddBoolToObject(r, "password_set", app_auth_required());
    cJSON *h = cJSON_AddObjectToObject(r, "memory");
    cJSON_AddNumberToObject(h, "internal_free", heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(h, "internal_min", heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(h, "psram_total", heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(h, "psram_free", heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(h, "psram_largest", heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));
    net_info_t ni;
    net_get_info(&ni);
    cJSON *n = cJSON_AddObjectToObject(r, "network");
    cJSON_AddBoolToObject(n, "connected", ni.sta_connected);
    cJSON_AddStringToObject(n, "ssid", ni.ssid);
    cJSON_AddNumberToObject(n, "rssi", ni.rssi);
    cJSON_AddNumberToObject(n, "channel", ni.channel);
    cJSON_AddStringToObject(n, "ip", ni.ip);
    cJSON_AddStringToObject(n, "netmask", ni.netmask);
    cJSON_AddStringToObject(n, "gateway", ni.gateway);
    cJSON *v6 = cJSON_AddArrayToObject(n, "ipv6");
    for (int i = 0; i < 3; i++)
        if (ni.ip6[i][0]) cJSON_AddItemToArray(v6, cJSON_CreateString(ni.ip6[i]));
    cJSON_AddBoolToObject(n, "configured", ni.configured);
    cJSON_AddNumberToObject(n, "last_reason", ni.last_reason);
    cJSON_AddBoolToObject(n, "ap_active", ni.ap_active);
    cJSON_AddBoolToObject(n, "ap_closing", ni.ap_closing);
    cJSON_AddStringToObject(n, "ap_ssid", ni.ap_ssid);
    cJSON_AddStringToObject(n, "ap_ip", ni.ap_ip);
    cJSON_AddStringToObject(n, "mac", ni.mac);
    cJSON_AddNumberToObject(n, "reconnects", ni.reconnects);
    cJSON_AddItemToObject(r, "dns", stats_json());
    cJSON_AddItemToObject(r, "filters", rules_status_json());
    cJSON_AddItemToObject(r, "tls", tls_status_json());
    return send_json(req, r);
}

static esp_err_t h_stats(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    if (req->method == HTTP_POST) {
        dns_server_reset_stats(g_srv);
        return send_ok(req);
    }
    return send_json(req, stats_json());
}

static esp_err_t h_history(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    return send_json(req, app_history_json());
}

static const char *qtype_name(uint16_t t, char *b) {
    switch (t) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    case 255: return "ANY";
    default: sprintf(b, "TYPE%u", t); return b;
    }
}

/* JSON string body (names are printable ASCII in presentation format) */
static void json_esc(const char *s, char *out, size_t cap) {
    size_t o = 0;
    for (; *s && o + 2 < cap; s++) {
        if (*s == '"' || *s == '\\') out[o++] = '\\';
        out[o++] = (unsigned char)*s < 0x20 ? '?' : *s;
    }
    out[o] = 0;
}

static esp_err_t h_querylog(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    char v[96];
    unsigned limit = 200;
    if (query_param(req, "limit", v, sizeof(v))) limit = (unsigned)atoi(v);
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;
    char search[96] = "";
    if (query_param(req, "q", search, sizeof(search))) url_decode(search);
    for (char *p = search; *p; p++) *p = (char)dc_lower((uint8_t)*p);
    int result = -1;
    if (query_param(req, "result", v, sizeof(v))) result = atoi(v);
    dns_qlog_t *e = malloc(sizeof(dns_qlog_t) * 1000 + 1024 + 400);
    if (!e) return httpd_resp_send_500(req);
    char *buf = (char *)(e + 1000);
    char *item = buf + 1024;
    unsigned n = dns_server_qlog(g_srv, e, 1000);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    size_t bl = 0;
    buf[bl++] = '[';
    unsigned out = 0;
    for (unsigned i = 0; i < n && out < limit; i++) {
        char ip[48], tb[12];
        dc_ip_format(&e[i].client, ip, sizeof(ip));
        if (search[0] && !strstr(e[i].name, search) && !strstr(ip, search)) continue;
        if (result >= 0 && e[i].result != result) continue;
        char name[2 * sizeof(e[i].name)];
        json_esc(e[i].name, name, sizeof(name));
        int k = snprintf(item, 400,
                         "%s{\"t\":%u,\"us\":%u,\"client\":\"%s\",\"name\":\"%s\",\"type\":\"%s\",\"result\":%u,"
                         "\"rcode\":%u,\"up\":%d}",
                         out ? "," : "", (unsigned)e[i].time, (unsigned)e[i].elapsed_us, ip, name,
                         qtype_name(e[i].qtype, tb), e[i].result, e[i].rcode,
                         e[i].upstream == 0xFF ? -1 : e[i].upstream);
        if (k <= 0 || (size_t)k >= 400) continue;
        if (bl + (size_t)k > 1024 - 2) {
            httpd_resp_send_chunk(req, buf, (ssize_t)bl);
            bl = 0;
        }
        memcpy(buf + bl, item, (size_t)k);
        bl += (size_t)k;
        out++;
    }
    buf[bl++] = ']';
    httpd_resp_send_chunk(req, buf, (ssize_t)bl);
    free(e);
    return httpd_resp_send_chunk(req, NULL, 0);
}

/* ---- configuration --------------------------------------------------------------------------- */

static esp_err_t h_config(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    if (req->method == HTTP_GET) {
        app_config_t *c = app_config_get();
        if (!c) return httpd_resp_send_500(req);
        cJSON *j = app_config_to_json(c, false);
        free(c);
        return send_json(req, j);
    }
    cJSON *j = read_json(req, 32768);
    if (!j) return send_err(req, "400 Bad Request", "invalid JSON");
    cJSON *sys = cJSON_GetObjectItem(j, "system"); /* never through this endpoint */
    if (sys) {
        cJSON_DeleteItemFromObject(sys, "pass_hash");
        cJSON_DeleteItemFromObject(sys, "pass_salt");
    }
    app_config_t *old = app_config_get();
    app_config_t *c = app_config_edit_begin();
    if (!old || !c) {
        free(old);
        if (c) app_config_edit_abort(c);
        cJSON_Delete(j);
        return httpd_resp_send_500(req);
    }
    char err[160];
    if (!app_config_apply_json(c, j, err, sizeof(err))) {
        app_config_edit_abort(c);
        free(old);
        cJSON_Delete(j);
        return send_err(req, "400 Bad Request", err);
    }
    cJSON_Delete(j);
    app_config_t *cur = malloc(sizeof(app_config_t));
    if (!cur) {
        app_config_edit_abort(c);
        free(old);
        return httpd_resp_send_500(req);
    }
    memcpy(cur, c, sizeof(*c));
    flash_lock();
    esp_err_t e = app_config_edit_commit(c);
    flash_unlock();
    if (e != ESP_OK) {
        free(old);
        free(cur);
        return send_err(req, "500 Internal Server Error", "saving failed");
    }
    bool restart = false;
    if (cur) app_apply_config(old, cur, &restart);
    free(old);
    free(cur);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    cJSON_AddBoolToObject(r, "restart_required", restart);
    return send_json(req, r);
}

static esp_err_t h_password(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req, 1024);
    cJSON *u = j ? cJSON_GetObjectItem(j, "username") : NULL, *p = j ? cJSON_GetObjectItem(j, "password") : NULL;
    if (!cJSON_IsString(p) || (u && !cJSON_IsString(u))) {
        cJSON_Delete(j);
        return send_err(req, "400 Bad Request", "expected {username, password}");
    }
    if (strlen(p->valuestring) > 64 || (p->valuestring[0] && strlen(p->valuestring) < 4)) {
        cJSON_Delete(j);
        return send_err(req, "400 Bad Request", "password: 4..64 characters (empty = no password)");
    }
    app_config_t *c = app_config_edit_begin();
    if (!c) {
        cJSON_Delete(j);
        return httpd_resp_send_500(req);
    }
    if (u && u->valuestring[0]) snprintf(c->username, sizeof(c->username), "%s", u->valuestring);
    app_password_set(c, p->valuestring);
    cJSON_Delete(j);
    flash_lock();
    esp_err_t e = app_config_edit_commit(c);
    flash_unlock();
    auth_cache_clear();
    return e == ESP_OK ? send_ok(req) : send_err(req, "500 Internal Server Error", "saving failed");
}

static esp_err_t text_get(httpd_req_t *req, const char *key) {
    size_t n = 0;
    char *t = app_blob_load(key, &n);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t e = httpd_resp_send(req, t ? t : "", t ? (ssize_t)n : 0);
    free(t);
    return e;
}

static esp_err_t h_rules(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    if (req->method == HTTP_GET) return text_get(req, "rules");
    size_t n;
    char *b = read_body(req, APP_RULES_MAX, &n);
    if (!b) return send_err(req, "413 Payload Too Large", "custom rules too large or upload failed");
    char err[160];
    esp_err_t e = rules_set_custom(b, n, err, sizeof(err));
    free(b);
    if (e != ESP_OK) return send_err(req, "400 Bad Request", err);
    return send_json(req, rules_status_json());
}

static esp_err_t h_local(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    if (req->method == HTTP_GET) return text_get(req, "local");
    size_t n;
    char *b = read_body(req, APP_LOCAL_MAX, &n);
    if (!b) return send_err(req, "413 Payload Too Large", "too large or upload failed");
    char err[160];
    esp_err_t e = rules_set_local(b, n, err, sizeof(err));
    free(b);
    return e == ESP_OK ? send_ok(req) : send_err(req, "400 Bad Request", err);
}

static esp_err_t h_filters(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    return send_json(req, rules_status_json());
}

static esp_err_t h_filters_update(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    char v[8];
    bool force = query_param(req, "force", v, sizeof(v)) && v[0] == '1';
    rules_trigger_update(force);
    return send_ok(req);
}

static esp_err_t h_cache_flush(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    dns_server_cache_flush(g_srv);
    return send_ok(req);
}

/* name check: rule diagnostics + a real resolution through the server */
static esp_err_t h_check(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    char name[260], type[16] = "A";
    if (!query_param(req, "name", name, sizeof(name)) || !name[0])
        return send_err(req, "400 Bad Request", "name required");
    url_decode(name);
    query_param(req, "type", type, sizeof(type));
    uint16_t qt = fl_rr_type_code(type);
    if (!qt) qt = 1;
    cJSON *r = rules_check_json(name, qt);
    /* resolve */
    uint8_t q[300];
    int nl = fl_name_to_wire(name, strlen(name), q + 12, 256);
    typedef struct {
        dns_resp_t rr;
        char val[300];
        uint8_t nm[256];
    } chk_ws_t;
    uint8_t *out = malloc(DNS_QUERY_BUF + sizeof(chk_ws_t));
    if (nl > 0 && out) {
        chk_ws_t *ws = (chk_ws_t *)(out + DNS_QUERY_BUF);
        memset(q, 0, 12);
        dc_wbe16(q, (uint16_t)esp_random());
        dc_wbe16(q + 2, 0x0100);
        dc_wbe16(q + 4, 1);
        dc_wbe16(q + 12 + nl, qt);
        dc_wbe16(q + 14 + nl, 1);
        dns_peer_t peer;
        memset(&peer, 0, sizeof(peer));
        peer.transport = DNS_TR_INTERNAL;
        int64_t t0 = esp_timer_get_time();
        size_t n = dns_server_query(g_srv, &peer, q, (size_t)nl + 16, out, DNS_QUERY_BUF);
        cJSON *a = cJSON_AddObjectToObject(r, "answer");
        cJSON_AddNumberToObject(a, "ms", (double)(esp_timer_get_time() - t0) / 1000.0);
        if (n && dns_parse_response(out, n, &ws->rr) == 0) {
            static const char *rc[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
            cJSON_AddStringToObject(a, "rcode", ws->rr.rcode < 6 ? rc[ws->rr.rcode] : "?");
            cJSON *recs = cJSON_AddArrayToObject(a, "records");
            size_t off = ws->rr.an_off;
            for (unsigned i = 0; i < ws->rr.ancount; i++) {
                if (dns_skip_name(out, n, &off) || off + 10 > n) break;
                uint16_t t = dc_be16(out + off), rdl = dc_be16(out + off + 8);
                uint32_t ttl = dc_be32(out + off + 4);
                size_t rd = off + 10;
                off = rd + rdl;
                if (off > n) break;
                char *val = ws->val, tb[12];
                val[0] = 0;
                if ((t == 1 && rdl == 4) || (t == 28 && rdl == 16)) {
                    dc_ip_t ip;
                    memset(&ip, 0, sizeof(ip));
                    ip.family = t == 1 ? 4 : 6;
                    memcpy(ip.addr, out + rd, rdl);
                    dc_ip_format(&ip, val, sizeof(ws->val));
                } else if (t == 5) {
                    size_t p = rd;
                    int l = dns_read_name(out, n, &p, ws->nm, false);
                    if (l > 0) fl_name_from_wire(ws->nm, (size_t)l, val, sizeof(ws->val));
                } else {
                    snprintf(val, sizeof(ws->val), "(%u bytes)", rdl);
                }
                cJSON *o = cJSON_CreateObject();
                cJSON_AddStringToObject(o, "type", qtype_name(t, tb));
                cJSON_AddNumberToObject(o, "ttl", ttl);
                cJSON_AddStringToObject(o, "value", val);
                cJSON_AddItemToArray(recs, o);
            }
        } else {
            cJSON_AddStringToObject(a, "rcode", "no answer");
        }
    }
    free(out);
    return send_json(req, r);
}

static esp_err_t h_scan(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    return send_json(req, net_scan_json());
}

/* ---- backup / restore ------------------------------------------------------------------------- */

static esp_err_t h_backup(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    app_config_t *c = app_config_get();
    if (!c) return httpd_resp_send_500(req);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "type", "esp32s3-dns-backup");
    cJSON_AddNumberToObject(r, "version", 1);
    cJSON_AddItemToObject(r, "config", app_config_to_json(c, true));
    free(c);
    size_t n;
    char *t = app_blob_load("rules", &n);
    cJSON_AddStringToObject(r, "rules", t ? t : "");
    free(t);
    t = app_blob_load("local", &n);
    cJSON_AddStringToObject(r, "local", t ? t : "");
    free(t);
    t = app_blob_load("tls_cert", &n);
    cJSON_AddStringToObject(r, "tls_cert", t ? t : "");
    free(t);
    t = app_blob_load("tls_key", &n);
    cJSON_AddStringToObject(r, "tls_key", t ? t : "");
    free(t);
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"esp32-dns-backup.json\"");
    return send_json(req, r);
}

static esp_err_t h_restore(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req, APP_RULES_MAX + APP_LOCAL_MAX + APP_TLS_MAX * 2 + 65536);
    cJSON *cfgj = j ? cJSON_GetObjectItem(j, "config") : NULL;
    cJSON *type = j ? cJSON_GetObjectItem(j, "type") : NULL;
    if (!cJSON_IsObject(cfgj) || !cJSON_IsString(type) || strcmp(type->valuestring, "esp32s3-dns-backup") != 0) {
        cJSON_Delete(j);
        return send_err(req, "400 Bad Request", "not a backup file");
    }
    app_config_t *c = app_config_edit_begin();
    if (!c) {
        cJSON_Delete(j);
        return httpd_resp_send_500(req);
    }
    app_config_defaults(c);
    char err[160];
    if (!app_config_apply_json(c, cfgj, err, sizeof(err))) {
        app_config_edit_abort(c);
        cJSON_Delete(j);
        return send_err(req, "400 Bad Request", err);
    }
    flash_lock();
    esp_err_t e = app_config_edit_commit(c);
    flash_unlock();
    cJSON *rules = cJSON_GetObjectItem(j, "rules"), *local = cJSON_GetObjectItem(j, "local");
    cJSON *tcert = cJSON_GetObjectItem(j, "tls_cert"), *tkey = cJSON_GetObjectItem(j, "tls_key");
    if (e == ESP_OK && cJSON_IsString(rules)) e = rules_set_custom(rules->valuestring, strlen(rules->valuestring), err, sizeof(err));
    if (e == ESP_OK && cJSON_IsString(local)) e = rules_set_local(local->valuestring, strlen(local->valuestring), err, sizeof(err));
    if (e == ESP_OK && cJSON_IsString(tcert) && cJSON_IsString(tkey)) {
        flash_lock();
        e = app_blob_save("tls_cert", tcert->valuestring, strlen(tcert->valuestring));
        if (e == ESP_OK)
            e = app_blob_save("tls_key", tkey->valuestring, strlen(tkey->valuestring));
        flash_unlock();
    }
    cJSON_Delete(j);
    if (e != ESP_OK) return send_err(req, "500 Internal Server Error", "restore failed");
    app_reboot_later(1500);
    return send_ok(req);
}

/* ---- system ----------------------------------------------------------------------------------------- */

static esp_err_t h_reboot(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    app_reboot_later(500);
    return send_ok(req);
}

static esp_err_t h_factory(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    flash_lock();
    app_config_factory_reset();
    flash_unlock();
    app_reboot_later(500);
    return send_ok(req);
}

static bool same_project(const esp_app_desc_t *d) {
    return d->magic_word == ESP_APP_DESC_MAGIC_WORD &&
           !strncmp(d->project_name, esp_app_get_description()->project_name, sizeof(d->project_name));
}

static esp_err_t h_ota_upload(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    if (g_ota_running) return send_err(req, "409 Conflict", "an update is already running");
    const esp_partition_t *p = esp_ota_get_next_update_partition(NULL);
    if (!p || req->content_len < 1024 || req->content_len > p->size)
        return send_err(req, "400 Bad Request", "invalid firmware size");
    char *buf = malloc(4096);
    if (!buf) return httpd_resp_send_500(req);
    g_ota_running = true;
    esp_ota_handle_t h = 0;
    const char *err = NULL;
    bool begun = false;
    const size_t desc_off = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    size_t n = desc_off + sizeof(esp_app_desc_t), got = 0;
    if (!recv_all(req, buf, n))
        err = "upload interrupted";
    else if (!same_project((const esp_app_desc_t *)(buf + desc_off)))
        err = "not a firmware for this device";
    if (!err) {
        flash_lock();
        esp_err_t e = esp_ota_begin(p, OTA_WITH_SEQUENTIAL_WRITES, &h);
        flash_unlock();
        if (e != ESP_OK) err = "cannot start the update";
        begun = e == ESP_OK;
        ESP_LOGI(TAG, "OTA: writing %u bytes to %s (version %.32s)", (unsigned)req->content_len, p->label,
                 ((const esp_app_desc_t *)(buf + desc_off))->version);
    }
    while (!err) {
        flash_lock();
        esp_err_t e = esp_ota_write(h, buf, n);
        flash_unlock();
        if (e != ESP_OK) {
            err = "flash write failed";
            break;
        }
        got += n;
        if (got >= req->content_len) break;
        int k = recv_some(req, buf, req->content_len - got < 4096 ? req->content_len - got : 4096);
        if (k < 0) err = "upload interrupted";
        n = k > 0 ? (size_t)k : 0;
    }
    free(buf);
    if (!err) {
        if (esp_ota_end(h) != ESP_OK)
            err = "image verification failed";
        else if (esp_ota_set_boot_partition(p) != ESP_OK)
            err = "cannot select the new firmware";
        begun = false;
    }
    if (begun) esp_ota_abort(h);
    g_ota_running = false;
    if (err) return send_err(req, "400 Bad Request", err);
    ESP_LOGI(TAG, "OTA done, restarting");
    app_reboot_later(1000);
    return send_ok(req);
}

static void ota_url_task(void *arg) {
    char *url = (char *)arg;
    esp_http_client_config_t hc;
    memset(&hc, 0, sizeof(hc));
    hc.url = url;
    hc.crt_bundle_attach = esp_crt_bundle_attach;
    hc.timeout_ms = 30000;
    hc.keep_alive_enable = true;
    esp_https_ota_config_t oc;
    memset(&oc, 0, sizeof(oc));
    oc.http_config = &hc;
    ESP_LOGI(TAG, "OTA from %s", url);
    esp_https_ota_handle_t h = NULL;
    flash_lock();
    esp_err_t e = esp_https_ota_begin(&oc, &h);
    flash_unlock();
    esp_app_desc_t nd;
    if (e == ESP_OK && (esp_https_ota_get_img_desc(h, &nd) != ESP_OK || !same_project(&nd))) {
        ESP_LOGE(TAG, "OTA: not a firmware for this device");
        e = ESP_ERR_INVALID_VERSION;
    }
    while (e == ESP_OK) {
        flash_lock();
        esp_err_t r = esp_https_ota_perform(h);
        flash_unlock();
        if (r != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
            e = r;
            break;
        }
    }
    if (e == ESP_OK && !esp_https_ota_is_complete_data_received(h)) e = ESP_ERR_INVALID_SIZE;
    if (h) {
        flash_lock();
        if (e == ESP_OK)
            e = esp_https_ota_finish(h);
        else
            esp_https_ota_abort(h);
        flash_unlock();
    }
    free(url);
    g_ota_running = false;
    if (e == ESP_OK) {
        ESP_LOGI(TAG, "OTA done, restarting");
        app_reboot_later(500);
    } else {
        ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(e));
    }
    vTaskDeleteWithCaps(NULL);
}

static esp_err_t h_ota_url(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    cJSON *j = read_json(req, 1024);
    cJSON *u = j ? cJSON_GetObjectItem(j, "url") : NULL;
    if (!cJSON_IsString(u) || strncmp(u->valuestring, "https://", 8) != 0) {
        cJSON_Delete(j);
        return send_err(req, "400 Bad Request", "https:// URL required");
    }
    if (g_ota_running) {
        cJSON_Delete(j);
        return send_err(req, "409 Conflict", "an update is already running");
    }
    g_ota_running = true;
    char *url = strdup(u->valuestring);
    cJSON_Delete(j);
    if (!url || xTaskCreateWithCaps(ota_url_task, "ota", 12288, url, 3, NULL, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) != pdPASS) {
        free(url);
        g_ota_running = false;
        return httpd_resp_send_500(req);
    }
    return send_ok(req);
}

/* ---- DNS over HTTPS (RFC 8484) ---------------------------------------------------------------- */

static volatile bool g_doh_enabled = true;
void web_set_doh(bool on) { g_doh_enabled = on; }

static esp_err_t h_doh(httpd_req_t *req) {
    if (!g_doh_enabled) return httpd_resp_send_404(req);
    if (req->method == HTTP_OPTIONS) {
        httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
        httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type, Accept");
        httpd_resp_set_hdr(req, "Access-Control-Max-Age", "86400");
        return httpd_resp_send(req, NULL, 0);
    }
    uint8_t *out = malloc(DNS_QUERY_BUF + DOH_MAX_WIRE_MSG);
    if (!out) return httpd_resp_send_500(req);
    uint8_t *q = out + DNS_QUERY_BUF;
    size_t ql = 0;
    if (req->method == HTTP_GET) {
        char *b64 = (char *)out; /* reuse out (16 KiB) as temporary base64url buffer */
        if (!query_param(req, "dns", b64, 1200) || !b64[0]) {
            free(out);
            return send_err(req, "400 Bad Request", "dns parameter missing");
        }
        url_decode(b64);
        size_t l = strlen(b64);
        for (size_t i = 0; i < l; i++) b64[i] = b64[i] == '-' ? '+' : b64[i] == '_' ? '/' : b64[i];
        while (l % 4 && l < 1199) b64[l++] = '=';
        b64[l] = 0;
        if (mbedtls_base64_decode(q, DOH_MAX_WIRE_MSG, &ql, (const unsigned char *)b64, l) != 0 || ql < DNS_HDR_LEN) {
            free(out);
            return send_err(req, "400 Bad Request", "invalid base64url DNS message");
        }
    } else if (req->method == HTTP_POST) {
        char ct[64];
        if (httpd_req_get_hdr_value_str(req, "Content-Type", ct, sizeof(ct)) != ESP_OK ||
            (strncasecmp(ct, "application/dns-message", 23) != 0 ||
             (ct[23] != '\0' && ct[23] != ';' && ct[23] != ' '))) {
            free(out);
            return send_err(req, "415 Unsupported Media Type", "expected application/dns-message");
        }
        if (req->content_len > DOH_MAX_WIRE_MSG || req->content_len < DNS_HDR_LEN) {
            free(out);
            return send_err(req, "413 Payload Too Large", "invalid DNS message size");
        }
        if (!recv_all(req, (char *)q, req->content_len)) {
            free(out);
            return ESP_FAIL;
        }
        ql = req->content_len;
    } else {
        free(out);
        return send_err(req, "405 Method Not Allowed", "use GET or POST");
    }
    dns_peer_t peer;
    peer_ip(req, &peer.ip, &peer.port);
    peer.transport = DNS_TR_DOH;
    size_t n = dns_server_query(g_srv, &peer, q, ql, out, DNS_QUERY_BUF);
    if (!n) {
        free(out);
        return send_err(req, "403 Forbidden", "query refused");
    }
    dns_resp_t r;
    uint32_t maxage = 0;
    if (dns_parse_response(out, n, &r) == 0 && r.min_ttl != 0xFFFFFFFFu) maxage = r.min_ttl;
    char cc[40];
    snprintf(cc, sizeof(cc), "max-age=%u", (unsigned)maxage);
    httpd_resp_set_type(req, "application/dns-message");
    httpd_resp_set_hdr(req, "Cache-Control", cc);
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    esp_err_t e = httpd_resp_send(req, (const char *)out, (ssize_t)n);
    free(out);
    return e;
}

/* ---- Prometheus metrics -------------------------------------------------------------------------- */

static esp_err_t h_metrics(httpd_req_t *req) {
    REQUIRE_AUTH(req);
    dns_stats_t *st = malloc(sizeof(dns_stats_t));
    char *b = malloc(4096);
    if (!st || !b) {
        free(st);
        free(b);
        return httpd_resp_send_500(req);
    }
    dns_server_get_stats(g_srv, st);
    size_t o = 0;
#define M(...)                                                \
    do {                                                      \
        if (o < 4096) {                                       \
            int k_ = snprintf(b + o, 4096 - o, __VA_ARGS__);  \
            if (k_ > 0) o += (size_t)k_;                      \
        }                                                     \
    } while (0)
    M("# TYPE dns_queries_total counter\n");
    M("dns_queries_total{result=\"forwarded\"} %u\n", (unsigned)(st->forwarded));
    M("dns_queries_total{result=\"cached\"} %u\n", (unsigned)(st->cached));
    M("dns_queries_total{result=\"blocked\"} %u\n", (unsigned)(st->blocked));
    M("dns_queries_total{result=\"resp_blocked\"} %u\n", (unsigned)(st->resp_blocked));
    M("dns_queries_total{result=\"rewritten\"} %u\n", (unsigned)(st->rewritten));
    M("dns_queries_total{result=\"local\"} %u\n", (unsigned)(st->local));
    M("dns_queries_total{result=\"allowed\"} %u\n", (unsigned)(st->allowed));
    M("dns_queries_total{result=\"failed\"} %u\n", (unsigned)(st->failed));
    M("dns_queries_total{result=\"refused\"} %u\n", (unsigned)(st->refused));
    M("dns_transport_queries_total{proto=\"udp\"} %u\n", (unsigned)(st->udp));
    M("dns_transport_queries_total{proto=\"tcp\"} %u\n", (unsigned)(st->tcp));
    M("dns_transport_queries_total{proto=\"dot\"} %u\n", (unsigned)(st->dot));
    M("dns_transport_queries_total{proto=\"doh\"} %u\n", (unsigned)(st->doh));
    M("dns_dropped_total %u\n", (unsigned)(st->dropped + st->ratelimited));
    M("dns_cache_entries %u\n", (unsigned)(st->cache.entries));
    M("dns_cache_hits_total %u\n", (unsigned)(st->cache.l1_hits + st->cache.l2_hits + st->cache.stale_hits));
    M("dns_cache_misses_total %u\n", (unsigned)(st->cache.misses));
    M("dns_pending %u\n", (unsigned)(st->pending));
    M("dns_latency_us{path=\"cached\",q=\"0.5\"} %u\n", (unsigned)dns_hist_percentile(&st->cached_us, 50));
    M("dns_latency_us{path=\"cached\",q=\"0.99\"} %u\n", (unsigned)dns_hist_percentile(&st->cached_us, 99));
    M("dns_latency_us{path=\"forwarded\",q=\"0.5\"} %u\n", (unsigned)dns_hist_percentile(&st->forward_us, 50));
    M("dns_latency_us{path=\"forwarded\",q=\"0.99\"} %u\n", (unsigned)dns_hist_percentile(&st->forward_us, 99));
    M("dns_latency_us{path=\"local\",q=\"0.5\"} %u\n", (unsigned)dns_hist_percentile(&st->local_us, 50));
    for (unsigned i = 0; i < st->nup && o < 3600; i++) {
        M("dns_upstream_rtt_us{upstream=\"%s\"} %u\n", st->up[i].text, (unsigned)st->up[i].rtt_us);
        M("dns_upstream_requests_total{upstream=\"%s\",status=\"ok\"} %u\n", st->up[i].text, (unsigned)st->up[i].ok);
        M("dns_upstream_requests_total{upstream=\"%s\",status=\"timeout\"} %u\n", st->up[i].text,
          (unsigned)st->up[i].timeouts);
    }
    M("esp_heap_internal_free_bytes %u\n", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    M("esp_heap_psram_free_bytes %u\n", (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    M("esp_uptime_seconds %u\n", (unsigned)(esp_timer_get_time() / 1000000));
#undef M
    if (o > 4095) o = 4095;
    httpd_resp_set_type(req, "text/plain; version=0.0.4");
    esp_err_t e = httpd_resp_send(req, b, (ssize_t)o);
    free(st);
    free(b);
    return e;
}

/* ---- setup hotspot captive portal ----------------------------------------------------------------- */

static volatile bool g_captive;
static char g_captive_url[40] = "http://192.168.4.1/";

void web_set_captive(bool on, const char *ap_ip) {
    if (on && ap_ip) snprintf(g_captive_url, sizeof(g_captive_url), "http://%s/", ap_ip);
    g_captive = on;
}

static esp_err_t h_not_found(httpd_req_t *req, httpd_err_code_t err) {
    if (g_captive) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", g_captive_url);
        httpd_resp_set_hdr(req, "Cache-Control", "no-store");
        return httpd_resp_send(req, NULL, 0);
    }
    return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
}

/* ---- registration ---------------------------------------------------------------------------------- */

static void reg_on(httpd_handle_t hd, const char *uri, httpd_method_t m, esp_err_t (*fn)(httpd_req_t *)) {
    httpd_uri_t u = {.uri = uri, .method = m, .handler = fn, .user_ctx = NULL};
    if (httpd_register_uri_handler(hd, &u) != ESP_OK) ESP_LOGE(TAG, "cannot register %s", uri);
}

static void register_all_handlers(httpd_handle_t hd) {
    reg_on(hd, "/", HTTP_GET, h_index);
    reg_on(hd, "/index.html", HTTP_GET, h_index);
    reg_on(hd, "/api/status", HTTP_GET, h_status);
    reg_on(hd, "/api/stats", HTTP_GET, h_stats);
    reg_on(hd, "/api/stats", HTTP_POST, h_stats);
    reg_on(hd, "/api/history", HTTP_GET, h_history);
    reg_on(hd, "/api/querylog", HTTP_GET, h_querylog);
    reg_on(hd, "/api/config", HTTP_GET, h_config);
    reg_on(hd, "/api/config", HTTP_PUT, h_config);
    reg_on(hd, "/api/config", HTTP_POST, h_config);
    reg_on(hd, "/api/password", HTTP_POST, h_password);
    reg_on(hd, "/api/tls", HTTP_GET, h_tls);
    reg_on(hd, "/api/tls", HTTP_PUT, h_tls);
    reg_on(hd, "/api/tls", HTTP_POST, h_tls);
    reg_on(hd, "/api/tls", HTTP_DELETE, h_tls);
    reg_on(hd, "/api/rules", HTTP_GET, h_rules);
    reg_on(hd, "/api/rules", HTTP_PUT, h_rules);
    reg_on(hd, "/api/rules", HTTP_POST, h_rules);
    reg_on(hd, "/api/local", HTTP_GET, h_local);
    reg_on(hd, "/api/local", HTTP_PUT, h_local);
    reg_on(hd, "/api/local", HTTP_POST, h_local);
    reg_on(hd, "/api/filters", HTTP_GET, h_filters);
    reg_on(hd, "/api/filters/update", HTTP_POST, h_filters_update);
    reg_on(hd, "/api/cache/flush", HTTP_POST, h_cache_flush);
    reg_on(hd, "/api/check", HTTP_GET, h_check);
    reg_on(hd, "/api/wifi/scan", HTTP_GET, h_scan);
    reg_on(hd, "/api/backup", HTTP_GET, h_backup);
    reg_on(hd, "/api/restore", HTTP_POST, h_restore);
    reg_on(hd, "/api/reboot", HTTP_POST, h_reboot);
    reg_on(hd, "/api/factory-reset", HTTP_POST, h_factory);
    reg_on(hd, "/api/ota", HTTP_POST, h_ota_upload);
    reg_on(hd, "/api/ota/url", HTTP_POST, h_ota_url);
    /* RFC 8484 DNS-over-HTTPS must only be offered over TLS. */
    if (hd == g_httpsd) {
        reg_on(hd, "/dns-query", HTTP_GET, h_doh);
        reg_on(hd, "/dns-query", HTTP_POST, h_doh);
        reg_on(hd, "/dns-query", HTTP_OPTIONS, h_doh);
    }
    reg_on(hd, "/metrics", HTTP_GET, h_metrics);
    httpd_register_err_handler(hd, HTTPD_404_NOT_FOUND, h_not_found);
}

void web_reload_https(void) {
#ifdef CONFIG_ESP_HTTPS_SERVER_ENABLE
    if (g_httpsd) {
        httpd_ssl_stop(g_httpsd);
        g_httpsd = NULL;
    }
    free(g_https_cert);
    free(g_https_key);
    g_https_cert = NULL;
    g_https_key = NULL;
    size_t clen = 0, klen = 0;
    g_https_cert = app_blob_load("tls_cert", &clen);
    g_https_key = app_blob_load("tls_key", &klen);
    if (!g_https_cert || !g_https_key || !clen || !klen) {
        free(g_https_cert);
        free(g_https_key);
        g_https_cert = g_https_key = NULL;
        ESP_LOGI(TAG, "HTTPS server inactive (no TLS certificate uploaded)");
        return;
    }
    httpd_ssl_config_t sc = HTTPD_SSL_CONFIG_DEFAULT();
    sc.httpd.server_port = g_https_port ? g_https_port : 443;
    /* HTTPS defaults to its own control port; do not override the IDF default. */
    sc.httpd.max_uri_handlers = 40;
    sc.httpd.stack_size = 16384;
    sc.httpd.lru_purge_enable = true;
    sc.httpd.max_open_sockets = 4;
    sc.httpd.recv_wait_timeout = 10;
    sc.httpd.send_wait_timeout = 10;
    sc.httpd.task_priority = 4;
    sc.httpd.task_caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
    sc.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    sc.servercert = (const uint8_t *)g_https_cert;
    sc.servercert_len = clen + 1;
    sc.prvtkey_pem = (const uint8_t *)g_https_key;
    sc.prvtkey_len = klen + 1;
    if (httpd_ssl_start(&g_httpsd, &sc) != ESP_OK) {
        ESP_LOGE(TAG, "HTTPS server failed to start on port %u", sc.httpd.server_port);
        g_httpsd = NULL;
        return;
    }
    register_all_handlers(g_httpsd);
    ESP_LOGI(TAG, "HTTPS server & DoH (/dns-query, RFC 8484) active on port %u", sc.httpd.server_port);
#endif
}

void web_start(dns_server_t *srv, uint16_t http_port, uint16_t https_port) {
    g_srv = srv;
    g_http_port = http_port ? http_port : 80;
    g_https_port = https_port ? https_port : 443;
    g_auth_mu = xSemaphoreCreateMutex();
    if (!g_auth_mu) {
        ESP_LOGE(TAG, "cannot allocate web authentication mutex");
        return;
    }
    httpd_config_t hc = HTTPD_DEFAULT_CONFIG();
    hc.server_port = g_http_port;
    hc.max_uri_handlers = 40;
    hc.stack_size = 12288; /* heavy rule buffers are heap-allocated */
    hc.lru_purge_enable = true;
    hc.max_open_sockets = 6;
    hc.recv_wait_timeout = 10;
    hc.send_wait_timeout = 10;
    hc.task_priority = 4;
    hc.task_caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
    if (httpd_start(&g_httpd, &hc) != ESP_OK) {
        ESP_LOGE(TAG, "web server failed to start on port %u", hc.server_port);
    } else {
        register_all_handlers(g_httpd);
        ESP_LOGI(TAG, "web UI on HTTP port %u", hc.server_port);
    }
    web_reload_https();
}
