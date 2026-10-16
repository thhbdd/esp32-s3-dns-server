/* net.h - Wi-Fi (station + provisioning access point), IP, SNTP. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "app_config.h"
#include "cJSON.h"

typedef struct {
    bool sta_connected;
    bool ap_active;
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    char ip[16], netmask[16], gateway[16];
    char ip6[3][48];
    char ap_ssid[33];
    char ap_ip[16];
    char mac[18];
    uint32_t reconnects;
    bool configured;      /* a Wi-Fi network is configured */
    bool ap_closing;      /* connected; hotspot closes soon */
    uint16_t last_reason; /* last disconnect reason (WIFI_REASON_*), 0 = none */
} net_info_t;

/* Called when setup (captive portal) mode starts or ends: captive is true
 * while the hotspot is the only way to reach the device. */
typedef void (*net_state_cb)(bool captive, const char *ap_ip);
void net_set_state_cb(net_state_cb cb);

/* Starts Wi-Fi with the configuration.  Without an SSID (or when the
 * station cannot connect for 60 s) the setup hotspot "ESP32-DNS-XXXX" is
 * opened (password "esp32dns", http://192.168.4.1, captive portal).  After
 * the station connects, the hotspot stays 3 minutes if a phone uses it. */
void net_start(const app_config_t *c);
/* Applies changed network settings shortly after the call (so a web request
 * can still be answered): reconnect = Wi-Fi / IP settings changed, otherwise
 * only bootstrap DNS, NTP and time zone are updated. */
void net_apply(const app_config_t *c, bool reconnect);
void net_get_info(net_info_t *i);
bool net_is_up(void);
/* Blocks until an IPv4 address is available (or timeout). */
bool net_wait_up(uint32_t timeout_ms);
cJSON *net_scan_json(void);
bool net_time_synced(void);
