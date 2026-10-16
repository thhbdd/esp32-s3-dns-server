/* app.h - glue between the application modules. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "app_config.h"
#include "cJSON.h"
#include "dns_server.h"

#define APP_VERSION_FALLBACK "1.0.3"

dns_server_t *app_dns(void);
/* Applies a committed configuration change to the running services.
 * *restart is set when a change needs a reboot (listeners, web/https/dot ports). */
void app_apply_config(const app_config_t *old, const app_config_t *cur, bool *restart);
void app_reboot_later(uint32_t ms);
/* 24 h of per-minute counters for the dashboard chart. */
cJSON *app_history_json(void);

/* web.c */
void web_start(dns_server_t *srv, uint16_t http_port, uint16_t https_port);
void web_set_doh(bool on);
void web_reload_https(void);
void web_set_captive(bool on, const char *ap_ip);
