/*
 * rules.h - filter rule storage and updates.
 *
 * Subscriptions are downloaded (HTTPS, streaming) and compiled directly into
 * the inactive flash slot (rules_a / rules_b) with the external sort runs in
 * the "staging" partition.  Only a fully written and verified image is
 * activated; failures attempt to preserve or restore the previous image.  Activation maps the new
 * image from flash, switches the DNS server to it, then copies it into
 * PSRAM and switches again. The response cache is temporarily released
 * during full rebuilds to create room for the compiler and image switch.
 *
 * Custom rules (web UI) are compiled into a small separate image in RAM, so
 * editing them takes effect immediately without recompiling the lists.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "dns_server.h"
#include "esp_err.h"

void rules_init(dns_server_t *srv);
/* Starts the background updater (after the network is up). */
void rules_start_updater(void);
/* force: rebuild even if no list changed. */
void rules_trigger_update(bool force);
bool rules_update_running(void);

esp_err_t rules_set_custom(const char *text, size_t len, char *err, size_t errlen);
esp_err_t rules_set_local(const char *text, size_t len, char *err, size_t errlen);

cJSON *rules_status_json(void);
/* Which rules match a name (diagnostics). */
cJSON *rules_check_json(const char *host, uint16_t qtype);

/* Serializes flash writers (rule updates, OTA, configuration saves) with
 * the window in which the rule image is read directly from flash. */
void flash_lock(void);
void flash_unlock(void);
