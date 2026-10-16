/* net.c - Wi-Fi station / setup access point, static IP, IPv6, SNTP.
 *
 * Every state change runs in the default event loop task: the timers and
 * net_apply() only post events, so no locking is needed. */
#include "net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"
#include "lwip/inet.h"

static const char *TAG = "net";

#define BIT_UP BIT0
#define AP_FALLBACK_MS 60000  /* station not connected for this long: open the setup hotspot */
#define AP_GRACE_MS 180000    /* hotspot kept after connecting, so the setup page can show the address */
#define AP_RETRY_MS 15000     /* station retry interval while the hotspot serves a phone */
#define APPLY_DELAY_MS 500    /* lets the web request that saved the settings finish first */
#ifdef CONFIG_APP_SETUP_AP_PASSWORD
#define AP_PASSWORD CONFIG_APP_SETUP_AP_PASSWORD
#else
#define AP_PASSWORD "esp32dns"
#endif

ESP_EVENT_DEFINE_BASE(NET_APP_EVENT);
enum { EV_RETRY, EV_AP_FALLBACK, EV_AP_CLOSE, EV_APPLY };

static esp_netif_t *g_sta, *g_ap;
static EventGroupHandle_t g_ev;
static TimerHandle_t g_retry, g_apfb, g_apclose, g_apply;
static volatile bool g_up, g_ap_on, g_ap_closing;
static bool g_sntp_started, g_has_ssid, g_ipv6;
static uint32_t g_reconnects, g_backoff_ms;
static volatile uint16_t g_last_reason;
static net_state_cb g_cb;
static char g_ap_ssid[33];
static char g_bootstrap[APP_MAX_BOOTSTRAP][48];
static char g_ntp[2][64];

/* pending net_apply() (taken by the event task) */
static portMUX_TYPE g_apply_mux = portMUX_INITIALIZER_UNLOCKED;
static app_config_t *g_apply_cfg;
static bool g_apply_reconnect;

/* The device itself resolves (subscriptions, NTP, DoT/DoH names) through the
 * bootstrap servers, never through its own filtering server.  DHCP does not
 * override them (LWIP_DHCP_MAX_DNS_SERVERS=0, see the top CMakeLists.txt). */
static void set_dns_servers(void) {
    static const esp_netif_dns_type_t types[] = {ESP_NETIF_DNS_MAIN, ESP_NETIF_DNS_BACKUP, ESP_NETIF_DNS_FALLBACK};
    int n = 0;
    for (int i = 0; i < APP_MAX_BOOTSTRAP && n < 3; i++) {
        esp_netif_dns_info_t d;
        memset(&d, 0, sizeof(d));
        if (!g_bootstrap[i][0] || ipaddr_aton(g_bootstrap[i], (ip_addr_t *)&d.ip) == 0) continue;
        esp_netif_set_dns_info(g_sta, types[n++], &d);
    }
    esp_netif_ip_info_t ii;
    if (!n && esp_netif_get_ip_info(g_sta, &ii) == ESP_OK && ii.gw.addr) { /* none configured: the router */
        esp_netif_dns_info_t d;
        memset(&d, 0, sizeof(d));
        d.ip.type = ESP_IPADDR_TYPE_V4;
        d.ip.u_addr.ip4.addr = ii.gw.addr;
        esp_netif_set_dns_info(g_sta, ESP_NETIF_DNS_MAIN, &d);
    }
}

void net_set_state_cb(net_state_cb cb) { g_cb = cb; }

/* captive portal while the hotspot is the only way to reach the device */
static void notify(void) {
    if (!g_cb) return;
    char ip[16] = "192.168.4.1";
    esp_netif_ip_info_t ii;
    if (g_ap && esp_netif_get_ip_info(g_ap, &ii) == ESP_OK && ii.ip.addr) snprintf(ip, sizeof(ip), IPSTR, IP2STR(&ii.ip));
    g_cb(g_ap_on && !g_up, ip);
}

static void start_ap(void) {
    if (g_ap_on) return;
    wifi_config_t ap;
    memset(&ap, 0, sizeof(ap));
    memcpy(ap.ap.ssid, g_ap_ssid, strnlen(g_ap_ssid, sizeof(ap.ap.ssid)));
    ap.ap.ssid_len = (uint8_t)strlen(g_ap_ssid);
    size_t pl = strlen(AP_PASSWORD);
    if (pl >= 8 && pl < sizeof(ap.ap.password)) {
        memcpy(ap.ap.password, AP_PASSWORD, pl);
        ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        ap.ap.authmode = WIFI_AUTH_OPEN; /* (WPA2 needs 8..63 characters) */
    }
    ap.ap.max_connection = 4;
    ap.ap.channel = 1;
    esp_wifi_set_mode(WIFI_MODE_APSTA); /* the station part is needed for scanning */
    esp_wifi_set_config(WIFI_IF_AP, &ap);
    g_ap_on = true;
    g_ap_closing = false;
    ESP_LOGW(TAG, "setup hotspot '%s' (password %s): open http://192.168.4.1/", g_ap_ssid,
             ap.ap.authmode == WIFI_AUTH_OPEN ? "none" : AP_PASSWORD);
    notify();
}

static void stop_ap(void) {
    if (!g_ap_on) return;
    xTimerStop(g_apclose, 0);
    esp_wifi_set_mode(WIFI_MODE_STA);
    g_ap_on = false;
    g_ap_closing = false;
    ESP_LOGI(TAG, "setup hotspot closed");
    notify();
}

static void post_cb(TimerHandle_t t) {
    if (esp_event_post(NET_APP_EVENT, (int32_t)(intptr_t)pvTimerGetTimerID(t), NULL, 0, pdMS_TO_TICKS(20)) != ESP_OK)
        xTimerChangePeriod(t, pdMS_TO_TICKS(100), 0); /* event queue full: again shortly */
}

static void start_sntp(void) {
    if (g_sntp_started || !g_ntp[0][0]) return;
    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(g_ntp[0]);
    if (g_ntp[1][0]) {
        cfg.num_of_servers = 2;
        cfg.servers[1] = g_ntp[1];
    }
    cfg.start = true;
    cfg.wait_for_sync = false;
    if (esp_netif_sntp_init(&cfg) == ESP_OK) g_sntp_started = true;
}

/* settings that apply without reconnecting */
static void set_services(const app_config_t *c) {
    bool ntp_changed = false;
    for (int i = 0; i < APP_MAX_BOOTSTRAP; i++)
        snprintf(g_bootstrap[i], sizeof(g_bootstrap[i]), "%s", i < c->nbootstrap ? c->bootstrap[i] : "");
    for (int i = 0; i < 2; i++) {
        ntp_changed |= strcmp(g_ntp[i], c->ntp[i]) != 0;
        snprintf(g_ntp[i], sizeof(g_ntp[i]), "%s", c->ntp[i]);
    }
    if (ntp_changed && g_sntp_started) { /* restarted with the new servers */
        esp_netif_sntp_deinit();
        g_sntp_started = false;
    }
    if (c->timezone[0]) {
        setenv("TZ", c->timezone, 1);
        tzset();
    }
}

static void configure_sta(const app_config_t *c) {
    wifi_config_t w;
    memset(&w, 0, sizeof(w));
    memcpy(w.sta.ssid, c->ssid, strnlen(c->ssid, sizeof(w.sta.ssid))); /* (not NUL terminated when full) */
    memcpy(w.sta.password, c->password, strnlen(c->password, sizeof(w.sta.password)));
    w.sta.threshold.authmode = c->password[0] ? WIFI_AUTH_WPA_PSK : WIFI_AUTH_OPEN;
    w.sta.pmf_cfg.capable = true;
    w.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    w.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    w.sta.failure_retry_cnt = 2;
    esp_wifi_set_config(WIFI_IF_STA, &w);
    g_has_ssid = c->ssid[0] != 0;
    g_ipv6 = c->ipv6;

    esp_netif_set_hostname(g_sta, c->hostname[0] ? c->hostname : "esp32-dns");
    if (c->static_ip && c->ip[0]) {
        esp_netif_dhcpc_stop(g_sta);
        esp_netif_ip_info_t ii;
        memset(&ii, 0, sizeof(ii));
        ii.ip.addr = ipaddr_addr(c->ip);
        ii.netmask.addr = ipaddr_addr(c->netmask);
        ii.gw.addr = c->gateway[0] ? ipaddr_addr(c->gateway) : 0;
        esp_netif_set_ip_info(g_sta, &ii);
    } else {
        esp_netif_dhcpc_start(g_sta);
    }
    set_services(c);
}

static void do_apply(void) {
    taskENTER_CRITICAL(&g_apply_mux);
    app_config_t *c = g_apply_cfg;
    bool reconnect = g_apply_reconnect;
    g_apply_cfg = NULL;
    g_apply_reconnect = false;
    taskEXIT_CRITICAL(&g_apply_mux);
    if (!c) return;
    if (!reconnect) {
        set_services(c);
        if (g_up) {
            set_dns_servers();
            start_sntp();
        }
        free(c);
        return;
    }
    ESP_LOGI(TAG, "network settings changed: reconnecting");
    if (g_up) esp_wifi_disconnect(); /* (the disconnect event schedules the retry) */
    configure_sta(c);
    free(c);
    g_backoff_ms = 0;
    g_last_reason = 0;
    if (g_has_ssid) {
        if (!g_up) esp_wifi_connect();
        if (!g_ap_on) xTimerStart(g_apfb, 0);
    } else {
        start_ap();
    }
}

static void on_wifi_disconnected(const wifi_event_sta_disconnected_t *d) {
    bool was_up = g_up;
    if (was_up || d->reason != g_last_reason) ESP_LOGW(TAG, "Wi-Fi disconnected (reason %d)", d->reason);
    g_last_reason = d->reason;
    g_up = false;
    xEventGroupClearBits(g_ev, BIT_UP);
    g_reconnects++;
    if (g_ap_closing) { /* lost again during the grace period: the hotspot stays */
        xTimerStop(g_apclose, 0);
        g_ap_closing = false;
    }
    if (was_up) notify();
    if (!g_has_ssid) return;
    g_backoff_ms = g_backoff_ms ? (g_backoff_ms * 2 > 10000 ? 10000 : g_backoff_ms * 2) : 200;
    /* each attempt scans all channels, which disturbs the hotspot: slower then */
    xTimerChangePeriod(g_retry, pdMS_TO_TICKS(g_ap_on ? AP_RETRY_MS : g_backoff_ms), 0);
    xTimerStart(g_retry, 0);
    if (!g_ap_on && !xTimerIsTimerActive(g_apfb)) xTimerStart(g_apfb, 0);
}

static void on_got_ip(const ip_event_got_ip_t *e) {
    ESP_LOGI(TAG, "IPv4 " IPSTR " gw " IPSTR, IP2STR(&e->ip_info.ip), IP2STR(&e->ip_info.gw));
    ESP_LOGI(TAG, "web UI: http://" IPSTR "/  (DNS server " IPSTR ")", IP2STR(&e->ip_info.ip), IP2STR(&e->ip_info.ip));
    g_up = true;
    g_last_reason = 0;
    xTimerStop(g_apfb, 0);
    set_dns_servers();
    if (g_ap_on && !g_ap_closing) {
        /* a phone on the hotspot is probably watching the setup page:
         * keep the hotspot a while so the page can show the new address */
        wifi_sta_list_t sl;
        if (esp_wifi_ap_get_sta_list(&sl) == ESP_OK && sl.num > 0) {
            g_ap_closing = true;
            xTimerStart(g_apclose, 0);
            ESP_LOGI(TAG, "setup hotspot closes in %d s", AP_GRACE_MS / 1000);
        } else {
            stop_ap();
        }
    }
    notify();
    start_sntp();
    xEventGroupSetBits(g_ev, BIT_UP);
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT) {
        if (id == WIFI_EVENT_STA_START && g_has_ssid) esp_wifi_connect();
        if (id == WIFI_EVENT_STA_CONNECTED) {
            if (g_ipv6) esp_netif_create_ip6_linklocal(g_sta);
            g_backoff_ms = 0;
        }
        if (id == WIFI_EVENT_STA_DISCONNECTED) on_wifi_disconnected((const wifi_event_sta_disconnected_t *)data);
    } else if (base == IP_EVENT) {
        if (id == IP_EVENT_STA_GOT_IP) on_got_ip((const ip_event_got_ip_t *)data);
        if (id == IP_EVENT_GOT_IP6) ESP_LOGI(TAG, "IPv6 " IPV6STR, IPV62STR(((ip_event_got_ip6_t *)data)->ip6_info.ip));
    } else if (base == NET_APP_EVENT) {
        switch (id) {
        case EV_RETRY:
            if (!g_up && g_has_ssid) esp_wifi_connect();
            break;
        case EV_AP_FALLBACK:
            if (!g_up) start_ap();
            break;
        case EV_AP_CLOSE:
            if (g_up) stop_ap();
            break;
        case EV_APPLY:
            do_apply();
            break;
        }
    }
}

static TimerHandle_t timer(const char *name, uint32_t ms, int ev) {
    TimerHandle_t t = xTimerCreate(name, pdMS_TO_TICKS(ms), pdFALSE, (void *)(intptr_t)ev, post_cb);
    if (!t) abort();
    return t;
}

void net_start(const app_config_t *c) {
    g_ev = xEventGroupCreate();
    g_retry = timer("wifi-retry", 1000, EV_RETRY);
    g_apfb = timer("wifi-apfb", AP_FALLBACK_MS, EV_AP_FALLBACK);
    g_apclose = timer("wifi-apclose", AP_GRACE_MS, EV_AP_CLOSE);
    g_apply = timer("net-apply", APPLY_DELAY_MS, EV_APPLY);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    g_sta = esp_netif_create_default_wifi_sta();
    g_ap = esp_netif_create_default_wifi_ap();
    /* setup clients use our DNS server */
    esp_netif_dhcps_stop(g_ap);
    uint8_t offer = 0x02; /* OFFER_DNS */
    esp_netif_dhcps_option(g_ap, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &offer, sizeof(offer));
    esp_netif_dhcps_start(g_ap);

    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wc));
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    esp_event_handler_register(NET_APP_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(g_ap_ssid, sizeof(g_ap_ssid), "ESP32-DNS-%02X%02X", mac[4], mac[5]);
    esp_wifi_set_country_code("CN", true);
    esp_wifi_set_mode(WIFI_MODE_STA);
    configure_sta(c);
    ESP_ERROR_CHECK(esp_wifi_start());
    /* latency first: never sleep the radio */
    esp_wifi_set_ps(WIFI_PS_NONE);
    if (!g_has_ssid)
        start_ap();
    else
        xTimerStart(g_apfb, 0);
}

void net_apply(const app_config_t *c, bool reconnect) {
    app_config_t *copy = malloc(sizeof(*copy));
    if (!copy) return;
    memcpy(copy, c, sizeof(*copy));
    taskENTER_CRITICAL(&g_apply_mux);
    app_config_t *old = g_apply_cfg;
    g_apply_cfg = copy;
    g_apply_reconnect |= reconnect;
    taskEXIT_CRITICAL(&g_apply_mux);
    free(old);
    xTimerReset(g_apply, portMAX_DELAY);
}

bool net_is_up(void) { return g_up; }

bool net_wait_up(uint32_t timeout_ms) {
    TickType_t t = timeout_ms == UINT32_MAX ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    return (xEventGroupWaitBits(g_ev, BIT_UP, pdFALSE, pdTRUE, t) & BIT_UP) != 0;
}

bool net_time_synced(void) { return time(NULL) > 1704067200; }

void net_get_info(net_info_t *i) {
    memset(i, 0, sizeof(*i));
    i->sta_connected = g_up;
    i->ap_active = g_ap_on;
    i->ap_closing = g_ap_closing;
    i->last_reason = g_last_reason;
    i->configured = g_has_ssid;
    i->reconnects = g_reconnects;
    snprintf(i->ap_ssid, sizeof(i->ap_ssid), "%s", g_ap_on ? g_ap_ssid : "");
    wifi_ap_record_t ap;
    if (g_up && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        snprintf(i->ssid, sizeof(i->ssid), "%s", (const char *)ap.ssid);
        i->rssi = ap.rssi;
        i->channel = ap.primary;
    }
    esp_netif_ip_info_t ii;
    if (esp_netif_get_ip_info(g_sta, &ii) == ESP_OK && ii.ip.addr) {
        snprintf(i->ip, sizeof(i->ip), IPSTR, IP2STR(&ii.ip));
        snprintf(i->netmask, sizeof(i->netmask), IPSTR, IP2STR(&ii.netmask));
        snprintf(i->gateway, sizeof(i->gateway), IPSTR, IP2STR(&ii.gw));
    }
    if (g_ap_on && esp_netif_get_ip_info(g_ap, &ii) == ESP_OK)
        snprintf(i->ap_ip, sizeof(i->ap_ip), IPSTR, IP2STR(&ii.ip));
    esp_ip6_addr_t a6[LWIP_IPV6_NUM_ADDRESSES];
    int n6 = esp_netif_get_all_ip6(g_sta, a6);
    for (int k = 0; k < n6 && k < 3; k++) snprintf(i->ip6[k], sizeof(i->ip6[k]), IPV6STR, IPV62STR(a6[k]));
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(i->mac, sizeof(i->mac), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

cJSON *net_scan_json(void) {
    cJSON *arr = cJSON_CreateArray();
    wifi_scan_config_t sc;
    memset(&sc, 0, sizeof(sc));
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) { /* busy (connection attempt): once more */
        vTaskDelay(pdMS_TO_TICKS(1500));
        if (esp_wifi_scan_start(&sc, true) != ESP_OK) return arr;
    }
    uint16_t n = 24;
    wifi_ap_record_t *recs = calloc(n, sizeof(wifi_ap_record_t));
    if (!recs) {
        esp_wifi_clear_ap_list();
        return arr;
    }
    if (esp_wifi_scan_get_ap_records(&n, recs) == ESP_OK) { /* (frees the driver's list) */
        for (int k = 0; k < n; k++) {
            if (!recs[k].ssid[0]) continue;
            cJSON *o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "ssid", (const char *)recs[k].ssid);
            cJSON_AddNumberToObject(o, "rssi", recs[k].rssi);
            cJSON_AddNumberToObject(o, "channel", recs[k].primary);
            cJSON_AddBoolToObject(o, "secure", recs[k].authmode != WIFI_AUTH_OPEN);
            cJSON_AddItemToArray(arr, o);
        }
    }
    free(recs);
    return arr;
}
