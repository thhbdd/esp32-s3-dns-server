/* app_config.c - persistent configuration (see app_config.h). */
#include "app_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dc_net.h"
#include "esp_log.h"
#include "esp_random.h"
#include "fl_filter.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/version.h"
#if MBEDTLS_VERSION_MAJOR >= 4
#include "psa/crypto.h"
#else
#include "mbedtls/sha256.h"
#endif
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

static const char *TAG = "config";
#define PART "cfg"
#define NS "app"

static app_config_t *g_cfg;
static SemaphoreHandle_t g_mu;   /* protects g_cfg contents */
static SemaphoreHandle_t g_edit; /* serializes read-modify-write cycles */

/* ---- defaults ------------------------------------------------------------------- */

static void add_sub(app_config_t *c, const char *name, const char *url, bool en) {
    if (c->nsubs >= APP_MAX_SUBS) return;
    app_sub_t *s = &c->subs[c->nsubs++];
    snprintf(s->name, sizeof(s->name), "%s", name);
    snprintf(s->url, sizeof(s->url), "%s", url);
    s->enabled = en;
    s->allowlist = false;
}

void app_config_defaults(app_config_t *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->hostname, sizeof(c->hostname), "esp32-dns");
#ifdef CONFIG_APP_WIFI_SSID
    snprintf(c->ssid, sizeof(c->ssid), "%s", CONFIG_APP_WIFI_SSID); /* (menuconfig preset) */
    snprintf(c->password, sizeof(c->password), "%s", CONFIG_APP_WIFI_PASSWORD);
#endif
    c->ipv6 = true;
    snprintf(c->ntp[0], sizeof(c->ntp[0]), "ntp.aliyun.com");
    snprintf(c->ntp[1], sizeof(c->ntp[1]), "cn.pool.ntp.org");
    snprintf(c->timezone, sizeof(c->timezone), "CST-8");
    dns_config_defaults(&c->dns);
    snprintf(c->bootstrap[0], sizeof(c->bootstrap[0]), "223.5.5.5");
    snprintf(c->bootstrap[1], sizeof(c->bootstrap[1]), "119.29.29.29");
    c->nbootstrap = 2;
    add_sub(c, "AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", true);
    add_sub(c, "AdAway Default Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
            false);
    add_sub(c, "anti-AD", "https://anti-ad.net/easylist.txt", false);
    c->update_hours = 24;
    c->web_port = 80;
    c->https_port = 443;
    c->doh_server = true;
    c->dot_server = true;
    c->dot_port = 853;
    snprintf(c->username, sizeof(c->username), "admin");
}

/* ---- names -------------------------------------------------------------------------- */

static const char *k_block[] = {"default", "null_ip", "nxdomain", "refused", "custom_ip"};
static const char *k_strat[] = {"load_balance", "parallel", "fastest"};

const char *app_block_mode_name(dns_block_mode_t m) { return (unsigned)m < 5 ? k_block[m] : "default"; }
const char *app_strategy_name(dns_strategy_t s) { return (unsigned)s < 3 ? k_strat[s] : "fastest"; }

/* ---- JSON helpers --------------------------------------------------------------------- */

static void jstr(cJSON *o, const char *k, const char *v) { cJSON_AddStringToObject(o, k, v ? v : ""); }
static void jnum(cJSON *o, const char *k, double v) { cJSON_AddNumberToObject(o, k, v); }
static void jbool(cJSON *o, const char *k, bool v) { cJSON_AddBoolToObject(o, k, v); }

static void jip(cJSON *o, const char *k, const dc_ip_t *ip) {
    char b[48] = "";
    if (ip->family) dc_ip_format(ip, b, sizeof(b));
    jstr(o, k, b);
}

static void jprefix(cJSON *arr, const dc_prefix_t *p) {
    char b[64];
    size_t n = dc_ip_format(&p->ip, b, sizeof(b));
    if (p->bits != (p->ip.family == 4 ? 32 : 128)) snprintf(b + n, sizeof(b) - n, "/%u", p->bits);
    cJSON_AddItemToArray(arr, cJSON_CreateString(b));
}

cJSON *app_config_to_json(const app_config_t *c, bool secrets) {
    cJSON *r = cJSON_CreateObject();
    cJSON *n = cJSON_AddObjectToObject(r, "network");
    jstr(n, "hostname", c->hostname);
    jstr(n, "ssid", c->ssid);
    jstr(n, "password", secrets ? c->password : (c->password[0] ? "********" : ""));
    jbool(n, "static_ip", c->static_ip);
    jstr(n, "ip", c->ip);
    jstr(n, "netmask", c->netmask);
    jstr(n, "gateway", c->gateway);
    jbool(n, "ipv6", c->ipv6);
    cJSON *ntp = cJSON_AddArrayToObject(n, "ntp");
    for (int i = 0; i < 2; i++)
        if (c->ntp[i][0]) cJSON_AddItemToArray(ntp, cJSON_CreateString(c->ntp[i]));
    jstr(n, "timezone", c->timezone);

    const dns_config_t *d = &c->dns;
    cJSON *dj = cJSON_AddObjectToObject(r, "dns");
    jnum(dj, "port", d->port);
    jbool(dj, "ipv6", d->listen_v6);
    jbool(dj, "tcp", d->tcp);
    jbool(dj, "local_only", d->local_only);
    cJSON *al = cJSON_AddArrayToObject(dj, "allow");
    for (unsigned i = 0; i < d->nallow; i++) jprefix(al, &d->allow[i]);
    jnum(dj, "ratelimit", d->ratelimit);
    jbool(dj, "refuse_any", d->refuse_any);
    cJSON *ups = cJSON_AddArrayToObject(dj, "upstreams");
    for (unsigned i = 0; i < d->nup; i++) cJSON_AddItemToArray(ups, cJSON_CreateString(d->up[i].text));
    cJSON *bs = cJSON_AddArrayToObject(dj, "bootstrap");
    for (unsigned i = 0; i < c->nbootstrap; i++) cJSON_AddItemToArray(bs, cJSON_CreateString(c->bootstrap[i]));
    jstr(dj, "strategy", app_strategy_name(d->strategy));
    jnum(dj, "upstream_timeout_ms", d->up_timeout_ms);
    jnum(dj, "query_timeout_ms", d->query_timeout_ms);
    jnum(dj, "cache_size_kb", d->cache_bytes / 1024);
    jnum(dj, "cache_min_ttl", d->cache_min_ttl);
    jnum(dj, "cache_max_ttl", d->cache_max_ttl);
    jbool(dj, "optimistic", d->optimistic);
    jnum(dj, "optimistic_max_age", d->optimistic_max_age);
    jnum(dj, "qlog_entries", d->qlog_entries);

    cJSON *f = cJSON_AddObjectToObject(r, "filtering");
    jbool(f, "enabled", d->protection);
    jstr(f, "block_mode", app_block_mode_name(d->block_mode));
    jip(f, "custom_ipv4", &d->custom_v4);
    jip(f, "custom_ipv6", &d->custom_v6);
    jnum(f, "blocked_ttl", d->blocked_ttl);
    jnum(f, "update_interval_hours", c->update_hours);
    cJSON *subs = cJSON_AddArrayToObject(f, "subscriptions");
    for (unsigned i = 0; i < c->nsubs; i++) {
        cJSON *s = cJSON_CreateObject();
        jstr(s, "name", c->subs[i].name);
        jstr(s, "url", c->subs[i].url);
        jbool(s, "enabled", c->subs[i].enabled);
        jbool(s, "allowlist", c->subs[i].allowlist);
        cJSON_AddItemToArray(subs, s);
    }

    cJSON *sy = cJSON_AddObjectToObject(r, "system");
    jnum(sy, "web_port", c->web_port);
    jnum(sy, "https_port", c->https_port);
    jbool(sy, "doh", c->doh_server);
    jbool(sy, "dot", c->dot_server);
    jnum(sy, "dot_port", c->dot_port);
    jstr(sy, "username", c->username);
    jbool(sy, "password_set", c->pass_hash[0] != 0);
    if (secrets) {
        jstr(sy, "pass_hash", c->pass_hash);
        jstr(sy, "pass_salt", c->pass_salt);
    }
    return r;
}

/* ---- JSON -> struct ----------------------------------------------------------------------- */

#define FAIL(...)                                  \
    do {                                           \
        snprintf(err, errlen, __VA_ARGS__);        \
        return false;                              \
    } while (0)

static bool get_str(const cJSON *o, const char *k, char *dst, size_t cap, char *err, size_t errlen) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v) return true;
    if (!cJSON_IsString(v)) FAIL("%s: expected a string", k);
    if (strlen(v->valuestring) >= cap) FAIL("%s: too long (max %u)", k, (unsigned)cap - 1);
    strcpy(dst, v->valuestring);
    return true;
}

static bool get_bool(const cJSON *o, const char *k, bool *dst, char *err, size_t errlen) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v) return true;
    if (!cJSON_IsBool(v)) FAIL("%s: expected true/false", k);
    *dst = cJSON_IsTrue(v);
    return true;
}

static bool get_u32(const cJSON *o, const char *k, uint32_t *dst, uint32_t lo, uint32_t hi, char *err,
                    size_t errlen) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v) return true;
    if (!cJSON_IsNumber(v) || v->valuedouble < lo || v->valuedouble > hi)
        FAIL("%s: expected a number %u..%u", k, (unsigned)lo, (unsigned)hi);
    *dst = (uint32_t)v->valuedouble;
    return true;
}

static bool parse_prefix(const char *s, dc_prefix_t *p) {
    if (strchr(s, '/')) return dc_prefix_parse(s, strlen(s), p);
    if (!dc_ip_parse_z(s, &p->ip)) return false;
    p->bits = p->ip.family == 4 ? 32 : 128;
    return true;
}

static bool valid_ip4_or_empty(const char *s) {
    dc_ip_t ip;
    return !s[0] || (dc_ip_parse_z(s, &ip) && ip.family == 4);
}

static bool apply_upstreams(dns_config_t *d, const cJSON *ups, char *err, size_t errlen) {
    dns_upstream_cfg_t *tmp = calloc(DNS_MAX_UPSTREAMS, sizeof(*tmp));
    if (!tmp) FAIL("out of memory");
    unsigned nu = 0;
    const cJSON *e;
    cJSON_ArrayForEach(e, ups) {
        if (!cJSON_IsString(e) || !e->valuestring[0]) continue;
        if (nu >= DNS_MAX_UPSTREAMS) {
            free(tmp);
            FAIL("upstreams: at most %d", DNS_MAX_UPSTREAMS);
        }
        const char *perr;
        if (!dns_upstream_parse(e->valuestring, &tmp[nu], &perr)) {
            free(tmp);
            FAIL("upstream '%s': %s", e->valuestring, perr);
        }
        nu++;
    }
    if (!nu) {
        free(tmp);
        FAIL("at least one upstream is required");
    }
    memcpy(d->up, tmp, sizeof(tmp[0]) * nu);
    d->nup = (uint8_t)nu;
    free(tmp);
    return true;
}

static bool apply_subs(app_config_t *c, const cJSON *subs, char *err, size_t errlen) {
    app_sub_t *tmp = calloc(APP_MAX_SUBS, sizeof(*tmp));
    if (!tmp) FAIL("out of memory");
    unsigned ns = 0;
    const cJSON *e;
    cJSON_ArrayForEach(e, subs) {
        if (ns >= APP_MAX_SUBS) {
            free(tmp);
            FAIL("at most %d subscriptions", APP_MAX_SUBS);
        }
        tmp[ns].enabled = true;
        if (!get_str(e, "name", tmp[ns].name, sizeof(tmp[ns].name), err, errlen) ||
            !get_str(e, "url", tmp[ns].url, sizeof(tmp[ns].url), err, errlen) ||
            !get_bool(e, "enabled", &tmp[ns].enabled, err, errlen) ||
            !get_bool(e, "allowlist", &tmp[ns].allowlist, err, errlen)) {
            free(tmp);
            return false;
        }
        if (strncmp(tmp[ns].url, "https://", 8) && strncmp(tmp[ns].url, "http://", 7)) {
            snprintf(err, errlen, "subscription '%s': URL must start with http:// or https://", tmp[ns].name);
            free(tmp);
            return false;
        }
        if (!tmp[ns].name[0]) snprintf(tmp[ns].name, sizeof(tmp[ns].name), "list %u", ns + 1);
        ns++;
    }
    memcpy(c->subs, tmp, sizeof(tmp[0]) * ns);
    c->nsubs = (uint8_t)ns;
    free(tmp);
    return true;
}

bool app_config_apply_json(app_config_t *c, const cJSON *j, char *err, size_t errlen) {
    if (!cJSON_IsObject(j)) FAIL("expected a JSON object");
    const cJSON *n = cJSON_GetObjectItemCaseSensitive(j, "network");
    if (n) {
        char pw[sizeof(c->password)] = "\x01";
        if (!get_str(n, "hostname", c->hostname, sizeof(c->hostname), err, errlen) ||
            !get_str(n, "ssid", c->ssid, sizeof(c->ssid), err, errlen) ||
            !get_str(n, "password", pw, sizeof(pw), err, errlen) ||
            !get_bool(n, "static_ip", &c->static_ip, err, errlen) ||
            !get_str(n, "ip", c->ip, sizeof(c->ip), err, errlen) ||
            !get_str(n, "netmask", c->netmask, sizeof(c->netmask), err, errlen) ||
            !get_str(n, "gateway", c->gateway, sizeof(c->gateway), err, errlen) ||
            !get_bool(n, "ipv6", &c->ipv6, err, errlen) ||
            !get_str(n, "timezone", c->timezone, sizeof(c->timezone), err, errlen))
            return false;
        if (strcmp(pw, "\x01") != 0 && strcmp(pw, "********") != 0) strcpy(c->password, pw);
        if (!valid_ip4_or_empty(c->ip) || !valid_ip4_or_empty(c->netmask) || !valid_ip4_or_empty(c->gateway))
            FAIL("network: invalid IPv4 address");
        if (c->static_ip && (!c->ip[0] || !c->netmask[0])) FAIL("network: static IP needs ip and netmask");
        const cJSON *ntp = cJSON_GetObjectItemCaseSensitive(n, "ntp");
        if (cJSON_IsArray(ntp)) {
            memset(c->ntp, 0, sizeof(c->ntp));
            int i = 0;
            const cJSON *e;
            cJSON_ArrayForEach(e, ntp) {
                if (i >= 2) break;
                if (cJSON_IsString(e) && strlen(e->valuestring) < sizeof(c->ntp[0])) strcpy(c->ntp[i++], e->valuestring);
            }
        }
    }
    dns_config_t *d = &c->dns;
    const cJSON *dj = cJSON_GetObjectItemCaseSensitive(j, "dns");
    if (dj) {
        uint32_t port = d->port, rl = d->ratelimit, uto = d->up_timeout_ms, qto = d->query_timeout_ms;
        uint32_t ckb = d->cache_bytes / 1024, cmin = d->cache_min_ttl, cmax = d->cache_max_ttl;
        uint32_t oage = d->optimistic_max_age, qle = d->qlog_entries;
        if (!get_u32(dj, "port", &port, 1, 65535, err, errlen) || !get_bool(dj, "ipv6", &d->listen_v6, err, errlen) ||
            !get_bool(dj, "tcp", &d->tcp, err, errlen) || !get_bool(dj, "local_only", &d->local_only, err, errlen) ||
            !get_u32(dj, "ratelimit", &rl, 0, 100000, err, errlen) ||
            !get_bool(dj, "refuse_any", &d->refuse_any, err, errlen) ||
            !get_u32(dj, "upstream_timeout_ms", &uto, 100, 10000, err, errlen) ||
            !get_u32(dj, "query_timeout_ms", &qto, 500, 30000, err, errlen) ||
            !get_u32(dj, "cache_size_kb", &ckb, 0, 4096, err, errlen) ||
            !get_u32(dj, "cache_min_ttl", &cmin, 0, 86400, err, errlen) ||
            !get_u32(dj, "cache_max_ttl", &cmax, 0, 604800, err, errlen) ||
            !get_bool(dj, "optimistic", &d->optimistic, err, errlen) ||
            !get_u32(dj, "optimistic_max_age", &oage, 0, 604800, err, errlen) ||
            !get_u32(dj, "qlog_entries", &qle, 0, 5000, err, errlen))
            return false;
        d->port = (uint16_t)port;
        d->ratelimit = rl;
        d->up_timeout_ms = uto;
        d->query_timeout_ms = qto;
        d->cache_bytes = ckb * 1024;
        d->cache_min_ttl = cmin;
        d->cache_max_ttl = cmax;
        d->optimistic_max_age = oage;
        d->qlog_entries = (uint16_t)qle;
        const cJSON *al = cJSON_GetObjectItemCaseSensitive(dj, "allow");
        if (cJSON_IsArray(al)) {
            d->nallow = 0;
            const cJSON *e;
            cJSON_ArrayForEach(e, al) {
                if (d->nallow >= DNS_MAX_ALLOW) FAIL("allow: at most %d networks", DNS_MAX_ALLOW);
                if (!cJSON_IsString(e) || !parse_prefix(e->valuestring, &d->allow[d->nallow]))
                    FAIL("allow: invalid network '%s'", cJSON_IsString(e) ? e->valuestring : "?");
                d->nallow++;
            }
        }
        const cJSON *ups = cJSON_GetObjectItemCaseSensitive(dj, "upstreams");
        if (cJSON_IsArray(ups) && !apply_upstreams(d, ups, err, errlen)) return false;
        const cJSON *bs = cJSON_GetObjectItemCaseSensitive(dj, "bootstrap");
        if (cJSON_IsArray(bs)) {
            c->nbootstrap = 0;
            const cJSON *e;
            cJSON_ArrayForEach(e, bs) {
                dc_ip_t ip;
                if (!cJSON_IsString(e) || !e->valuestring[0]) continue;
                if (c->nbootstrap >= APP_MAX_BOOTSTRAP) FAIL("bootstrap: at most %d", APP_MAX_BOOTSTRAP);
                if (!dc_ip_parse_z(e->valuestring, &ip)) FAIL("bootstrap: '%s' is not an IP address", e->valuestring);
                snprintf(c->bootstrap[c->nbootstrap++], sizeof(c->bootstrap[0]), "%s", e->valuestring);
            }
        }
        const cJSON *st = cJSON_GetObjectItemCaseSensitive(dj, "strategy");
        if (st) {
            int k = -1;
            for (int i = 0; i < 3 && cJSON_IsString(st); i++)
                if (!strcmp(st->valuestring, k_strat[i])) k = i;
            if (k < 0) FAIL("strategy: load_balance, parallel or fastest");
            d->strategy = (dns_strategy_t)k;
        }
    }
    const cJSON *f = cJSON_GetObjectItemCaseSensitive(j, "filtering");
    if (f) {
        uint32_t bttl = d->blocked_ttl, uh = c->update_hours;
        if (!get_bool(f, "enabled", &d->protection, err, errlen) ||
            !get_u32(f, "blocked_ttl", &bttl, 0, 86400, err, errlen) ||
            !get_u32(f, "update_interval_hours", &uh, 0, 720, err, errlen))
            return false;
        d->blocked_ttl = bttl;
        c->update_hours = (uint16_t)uh;
        const cJSON *bm = cJSON_GetObjectItemCaseSensitive(f, "block_mode");
        if (bm) {
            int k = -1;
            for (int i = 0; i < 5 && cJSON_IsString(bm); i++)
                if (!strcmp(bm->valuestring, k_block[i])) k = i;
            if (k < 0) FAIL("block_mode: default, null_ip, nxdomain, refused or custom_ip");
            d->block_mode = (dns_block_mode_t)k;
        }
        char ip4[48] = "\x01", ip6[48] = "\x01";
        if (!get_str(f, "custom_ipv4", ip4, sizeof(ip4), err, errlen) ||
            !get_str(f, "custom_ipv6", ip6, sizeof(ip6), err, errlen))
            return false;
        if (strcmp(ip4, "\x01")) {
            memset(&d->custom_v4, 0, sizeof(d->custom_v4));
            if (ip4[0] && (!dc_ip_parse_z(ip4, &d->custom_v4) || d->custom_v4.family != 4))
                FAIL("custom_ipv4: invalid IPv4 address");
        }
        if (strcmp(ip6, "\x01")) {
            memset(&d->custom_v6, 0, sizeof(d->custom_v6));
            if (ip6[0] && (!dc_ip_parse_z(ip6, &d->custom_v6) || d->custom_v6.family != 6))
                FAIL("custom_ipv6: invalid IPv6 address");
        }
        const cJSON *subs = cJSON_GetObjectItemCaseSensitive(f, "subscriptions");
        if (cJSON_IsArray(subs) && !apply_subs(c, subs, err, errlen)) return false;
    }
    const cJSON *sy = cJSON_GetObjectItemCaseSensitive(j, "system");
    if (sy) {
        uint32_t wp = c->web_port, hp = c->https_port ? c->https_port : 443, dp = c->dot_port ? c->dot_port : 853;
        if (!get_u32(sy, "web_port", &wp, 1, 65535, err, errlen) ||
            !get_u32(sy, "https_port", &hp, 1, 65535, err, errlen) ||
            !get_bool(sy, "doh", &c->doh_server, err, errlen) ||
            !get_bool(sy, "dot", &c->dot_server, err, errlen) ||
            !get_u32(sy, "dot_port", &dp, 1, 65535, err, errlen) ||
            !get_str(sy, "username", c->username, sizeof(c->username), err, errlen) ||
            !get_str(sy, "pass_hash", c->pass_hash, sizeof(c->pass_hash), err, errlen) ||
            !get_str(sy, "pass_salt", c->pass_salt, sizeof(c->pass_salt), err, errlen))
            return false;
        c->web_port = (uint16_t)wp;
        c->https_port = (uint16_t)hp;
        c->dot_port = (uint16_t)dp;
        if (!c->username[0]) strcpy(c->username, "admin");
    }
    return true;
}

/* ---- persistence --------------------------------------------------------------------------- */

static esp_err_t open_ns(nvs_handle_t *h, nvs_open_mode_t mode) {
    return nvs_open_from_partition(PART, NS, mode, h);
}

char *app_blob_load(const char *key, size_t *len) {
    nvs_handle_t h;
    if (open_ns(&h, NVS_READONLY) != ESP_OK) return NULL;
    size_t n = 0;
    char *buf = NULL;
    if (nvs_get_blob(h, key, NULL, &n) == ESP_OK) {
        buf = malloc(n + 1);
        if (buf && nvs_get_blob(h, key, buf, &n) == ESP_OK) {
            buf[n] = 0;
            if (len) *len = n;
        } else {
            free(buf);
            buf = NULL;
        }
    }
    nvs_close(h);
    return buf;
}

esp_err_t app_blob_save(const char *key, const char *data, size_t len) {
    nvs_handle_t h;
    esp_err_t e = open_ns(&h, NVS_READWRITE);
    if (e != ESP_OK) return e;
    e = len ? nvs_set_blob(h, key, data, len) : nvs_erase_key(h, key);
    if (e == ESP_ERR_NVS_NOT_FOUND) e = ESP_OK;
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

static esp_err_t save_locked(const app_config_t *c) {
    cJSON *j = app_config_to_json(c, true);
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return ESP_ERR_NO_MEM;
    esp_err_t e = app_blob_save("config", s, strlen(s));
    cJSON_free(s);
    return e;
}

esp_err_t app_config_init(void) {
    g_mu = xSemaphoreCreateMutex();
    g_edit = xSemaphoreCreateMutex();
    esp_err_t e = nvs_flash_init_partition(PART);
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "configuration partition reformatted");
        nvs_flash_erase_partition(PART);
        e = nvs_flash_init_partition(PART);
    }
    if (e != ESP_OK) return e;
    g_cfg = calloc(1, sizeof(app_config_t));
    if (!g_cfg) return ESP_ERR_NO_MEM;
    app_config_defaults(g_cfg);
    size_t n;
    char *s = app_blob_load("config", &n);
    if (s) {
        cJSON *j = cJSON_ParseWithLength(s, n);
        char err[128];
        if (!j || !app_config_apply_json(g_cfg, j, err, sizeof(err))) {
            ESP_LOGE(TAG, "stored configuration invalid (%s): using defaults", j ? err : "parse error");
            app_config_defaults(g_cfg);
        }
        cJSON_Delete(j);
        free(s);
    } else {
        ESP_LOGI(TAG, "no configuration stored: defaults");
    }
    return ESP_OK;
}

app_config_t *app_config_get(void) {
    app_config_t *c = malloc(sizeof(*c));
    if (!c) return NULL;
    xSemaphoreTake(g_mu, portMAX_DELAY);
    memcpy(c, g_cfg, sizeof(*c));
    xSemaphoreGive(g_mu);
    return c;
}

app_config_t *app_config_edit_begin(void) {
    xSemaphoreTake(g_edit, portMAX_DELAY);
    app_config_t *c = app_config_get();
    if (!c) xSemaphoreGive(g_edit);
    return c;
}

esp_err_t app_config_edit_commit(app_config_t *c) {
    esp_err_t e = save_locked(c);
    if (e == ESP_OK) {
        xSemaphoreTake(g_mu, portMAX_DELAY);
        memcpy(g_cfg, c, sizeof(*c));
        xSemaphoreGive(g_mu);
    } else {
        ESP_LOGE(TAG, "saving configuration failed: %s", esp_err_to_name(e));
    }
    free(c);
    xSemaphoreGive(g_edit);
    return e;
}

void app_config_edit_abort(app_config_t *c) {
    free(c);
    xSemaphoreGive(g_edit);
}

esp_err_t app_config_factory_reset(void) {
    nvs_handle_t h;
    esp_err_t e = open_ns(&h, NVS_READWRITE);
    if (e != ESP_OK) return e;
    nvs_erase_all(h);
    e = nvs_commit(h);
    nvs_close(h);
    return e;
}

/* ---- password ----------------------------------------------------------------------------------- */

/* The on-disk password hash format is SHA256(salt || pw), then 2000
 * iterations of SHA256(previous_digest || salt). Keep it identical across
 * ESP-IDF 5.5 (Mbed TLS 3) and ESP-IDF 6.1 (Mbed TLS 4 / PSA).
 * Never commit a new password if the crypto backend reports failure. */
#if MBEDTLS_VERSION_MAJOR >= 4
static bool hash_parts(const uint8_t *a, size_t na, const uint8_t *b, size_t nb, uint8_t out[32]) {
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t got = 0;
    psa_status_t rc = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (rc == PSA_SUCCESS) rc = psa_hash_update(&op, a, na);
    if (rc == PSA_SUCCESS) rc = psa_hash_update(&op, b, nb);
    if (rc == PSA_SUCCESS) rc = psa_hash_finish(&op, out, 32, &got);
    if (rc != PSA_SUCCESS || got != 32) {
        psa_hash_abort(&op);
        return false;
    }
    return true;
}
#else
static bool hash_parts(const uint8_t *a, size_t na, const uint8_t *b, size_t nb, uint8_t out[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int rc = mbedtls_sha256_starts(&ctx, 0);
    if (!rc) rc = mbedtls_sha256_update(&ctx, a, na);
    if (!rc) rc = mbedtls_sha256_update(&ctx, b, nb);
    if (!rc) rc = mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
    return rc == 0;
}
#endif

static bool hash_pw(const char *salt, const char *pw, char out[65]) {
    uint8_t d[32];
    size_t ns = strlen(salt);
    const uint8_t *sb = (const uint8_t *)salt;
    if (!hash_parts(sb, ns, (const uint8_t *)pw, strlen(pw), d)) return false;
    for (int i = 0; i < 2000; i++) {
        if (!hash_parts(d, sizeof(d), sb, ns, d)) return false;
    }
    for (int i = 0; i < 32; i++) sprintf(out + i * 2, "%02x", d[i]);
    out[64] = 0;
    return true;
}

void app_password_set(app_config_t *c, const char *password) {
    if (!password || !password[0]) {
        c->pass_hash[0] = 0;
        c->pass_salt[0] = 0;
        return;
    }
    uint8_t r[16];
    esp_fill_random(r, sizeof(r));
    char new_salt[33] = {0}, new_hash[65];
    for (int i = 0; i < 16; i++) sprintf(new_salt + i * 2, "%02x", r[i]);
    if (!hash_pw(new_salt, password, new_hash)) {
        ESP_LOGE(TAG, "password hashing failed; leaving old credentials unchanged");
        return;
    }
    memcpy(c->pass_salt, new_salt, sizeof(new_salt));
    memcpy(c->pass_hash, new_hash, sizeof(new_hash));
}

bool app_auth_required(void) {
    xSemaphoreTake(g_mu, portMAX_DELAY);
    bool r = g_cfg->pass_hash[0] != 0;
    xSemaphoreGive(g_mu);
    return r;
}

bool app_auth_check(const char *user, const char *password) {
    char u[sizeof(g_cfg->username)], h[sizeof(g_cfg->pass_hash)], s[sizeof(g_cfg->pass_salt)];
    xSemaphoreTake(g_mu, portMAX_DELAY);
    memcpy(u, g_cfg->username, sizeof(u));
    memcpy(h, g_cfg->pass_hash, sizeof(h));
    memcpy(s, g_cfg->pass_salt, sizeof(s));
    xSemaphoreGive(g_mu);
    if (!h[0]) return true;
    if (!user || !password || strcmp(user, u) != 0) return false;
    char x[65];
    if (!hash_pw(s, password, x)) return false;
    unsigned diff = 0; /* constant time compare */
    for (int i = 0; i < 64; i++) diff |= (unsigned)(x[i] ^ h[i]);
    return diff == 0;
}
