/*
 * app_main.c - ESP32-S3 (N16R8) DNS filter / resolver firmware.
 *
 * Boot order matters for memory: the filter image is loaded into PSRAM
 * before the response cache takes its share, so the lists always fit.
 */
#include <stdio.h>
#include <string.h>

#include "app.h"
#include "dc_net.h"
#include "dot_server.h"
#include "driver/gpio.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/task.h"
#include "net.h"
#include "nvs_flash.h"
#include "rules.h"
#include "upstream_tls.h"

static const char *TAG = "app";

#define HIST_N 1440 /* 24 h at one point per minute */
#define RESET_GPIO GPIO_NUM_0
#define RESET_HOLD_MS 10000

static dns_server_t *g_dns;
static uint32_t (*g_hist)[2]; /* [minute][queries, blocked], in PSRAM */
static volatile unsigned g_hpos, g_hn;

dns_server_t *app_dns(void) { return g_dns; }

/* setup hotspot active and no other connection: captive portal */
static void on_net_state(bool captive, const char *ap_ip) {
    dc_ip_t ip;
    dc_prefix_t net;
    char pfx[24];
    snprintf(pfx, sizeof(pfx), "%s/24", ap_ip);
    if (captive && dc_ip_parse_z(ap_ip, &ip) && dc_prefix_parse(pfx, strlen(pfx), &net)) {
        dns_server_set_captive(g_dns, &ip, &net);
        web_set_captive(true, ap_ip);
        ESP_LOGI(TAG, "setup mode: all names on the hotspot resolve to %s", ap_ip);
    } else {
        dns_server_set_captive(g_dns, NULL, NULL);
        web_set_captive(false, NULL);
    }
}

static void reboot_cb(void *arg) { esp_restart(); }

void app_reboot_later(uint32_t ms) {
    static esp_timer_handle_t t;
    if (!t) {
        esp_timer_create_args_t a = {.callback = reboot_cb, .name = "reboot"};
        esp_timer_create(&a, &t);
    }
    esp_timer_start_once(t, (uint64_t)ms * 1000);
}

static bool subs_changed(const app_config_t *a, const app_config_t *b) {
    if (a->nsubs != b->nsubs) return true;
    for (unsigned i = 0; i < a->nsubs; i++)
        if (strcmp(a->subs[i].url, b->subs[i].url) || strcmp(a->subs[i].name, b->subs[i].name) ||
            a->subs[i].enabled != b->subs[i].enabled || a->subs[i].allowlist != b->subs[i].allowlist)
            return true;
    return false;
}

static bool wifi_changed(const app_config_t *a, const app_config_t *b) {
    return strcmp(a->ssid, b->ssid) || strcmp(a->password, b->password) || a->static_ip != b->static_ip ||
           strcmp(a->ip, b->ip) || strcmp(a->netmask, b->netmask) || strcmp(a->gateway, b->gateway) ||
           strcmp(a->hostname, b->hostname) || a->ipv6 != b->ipv6;
}

static bool services_changed(const app_config_t *a, const app_config_t *b) {
    return a->nbootstrap != b->nbootstrap || memcmp(a->bootstrap, b->bootstrap, sizeof(a->bootstrap)) ||
           memcmp(a->ntp, b->ntp, sizeof(a->ntp)) || strcmp(a->timezone, b->timezone);
}

void app_apply_config(const app_config_t *old, const app_config_t *cur, bool *restart) {
    dns_server_reconfigure(g_dns, &cur->dns);
    tls_upstreams_config(&cur->dns);
    web_set_doh(cur->doh_server);
    dot_server_set_enabled(cur->dot_server);
    bool wifi = wifi_changed(old, cur);
    if (wifi || services_changed(old, cur)) net_apply(cur, wifi);
    if (subs_changed(old, cur)) rules_trigger_update(false);
    const dns_config_t *a = &old->dns, *b = &cur->dns;
    if (a->port != b->port || a->listen_v6 != b->listen_v6 || a->tcp != b->tcp || a->qlog_entries != b->qlog_entries ||
        old->web_port != cur->web_port || old->https_port != cur->https_port ||
        old->dot_port != cur->dot_port || old->dot_server != cur->dot_server)
        *restart = true;
}

cJSON *app_history_json(void) {
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "interval", 60);
    cJSON *q = cJSON_AddArrayToObject(r, "queries"), *b = cJSON_AddArrayToObject(r, "blocked");
    unsigned n = g_hn, start = (g_hpos + HIST_N - n) % HIST_N;
    for (unsigned i = 0; i < n && g_hist; i++) {
        unsigned k = (start + i) % HIST_N;
        cJSON_AddItemToArray(q, cJSON_CreateNumber(g_hist[k][0]));
        cJSON_AddItemToArray(b, cJSON_CreateNumber(g_hist[k][1]));
    }
    return r;
}

/* per-minute history, firmware health check, factory reset button */
static void housekeeping_task(void *arg) {
    gpio_config_t io = {.pin_bit_mask = 1ULL << RESET_GPIO, .mode = GPIO_MODE_INPUT, .pull_up_en = GPIO_PULLUP_ENABLE};
    gpio_config(&io);
    dns_stats_t *st = malloc(sizeof(dns_stats_t));
    g_hist = heap_caps_calloc(HIST_N, sizeof(*g_hist), MALLOC_CAP_SPIRAM);
    uint32_t lq = 0, lb = 0, held = 0, tick = 0;
    bool valid_marked = false;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(100));
        tick++;
        if (gpio_get_level(RESET_GPIO) == 0) {
            held += 100;
            if (held == RESET_HOLD_MS) {
                ESP_LOGW(TAG, "BOOT button held: factory reset");
                flash_lock();
                app_config_factory_reset();
                flash_unlock();
                esp_restart();
            }
        } else {
            held = 0;
        }
        /* a new firmware is confirmed after a minute of healthy operation;
         * a crash before that rolls back to the previous one */
        if (!valid_marked && tick >= 600) {
            esp_ota_img_states_t s;
            const esp_partition_t *run = esp_ota_get_running_partition();
            if (esp_ota_get_state_partition(run, &s) == ESP_OK && s == ESP_OTA_IMG_PENDING_VERIFY) {
                flash_lock();
                esp_ota_mark_app_valid_cancel_rollback();
                flash_unlock();
                ESP_LOGI(TAG, "new firmware confirmed");
            }
            valid_marked = true;
        }
        if (st && g_hist && tick % 600 == 0) {
            dns_server_get_stats(g_dns, st);
            uint32_t q = st->queries, b = st->blocked + st->resp_blocked;
            g_hist[g_hpos][0] = q >= lq ? q - lq : q; /* (statistics reset) */
            g_hist[g_hpos][1] = b >= lb ? b - lb : b;
            lq = q;
            lb = b;
            g_hpos = (g_hpos + 1) % HIST_N;
            if (g_hn < HIST_N) g_hn++;
        }
    }
}

void app_main(void) {
    const esp_app_desc_t *d = esp_app_get_description();
    ESP_LOGI(TAG, "ESP32-S3 DNS %s (IDF %s)", d->version, d->idf_ver);
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        e = nvs_flash_init();
    }
    ESP_ERROR_CHECK(e);
    ESP_ERROR_CHECK(app_config_init());
    app_config_t *cfg = app_config_get();
    if (!cfg) abort();

    /* filters first, then the cache gets what is left */
    uint32_t saved_cache_bytes = cfg->dns.cache_bytes;
    cfg->dns.cache_bytes = 0;
    g_dns = dns_server_new(&cfg->dns);
    cfg->dns.cache_bytes = saved_cache_bytes;
    if (!g_dns) {
        ESP_LOGE(TAG, "out of memory creating the DNS server");
        abort();
    }
    tls_upstreams_init(g_dns);
    rules_init(g_dns);
    dns_server_reconfigure(g_dns, &cfg->dns);
    tls_upstreams_config(&cfg->dns);

    net_set_state_cb(on_net_state);
    net_start(cfg);
    if (dns_server_start(g_dns) != 0) ESP_LOGE(TAG, "DNS server failed to start");
    dot_server_set_enabled(cfg->dot_server);
    web_set_doh(cfg->doh_server);
    web_start(g_dns, cfg->web_port, cfg->https_port);
    dot_server_start(g_dns, cfg->dot_port, cfg->dns.listen_v6);
    rules_start_updater();
    xTaskCreatePinnedToCoreWithCaps(housekeeping_task, "housekeeping", 4096, NULL, 3, NULL, tskNO_AFFINITY,
                                    MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    free(cfg);
}
