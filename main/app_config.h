/*
 * app_config.h - persistent device configuration.
 *
 * Stored as JSON in the "cfg" NVS partition (namespace "app"):
 *   config   - this structure (see app_config_to_json for the schema)
 *   rules    - custom filtering rules (text, AdGuard syntax)
 *   local    - local DNS records ("domain TYPE value [ttl=N]" per line)
 *   substat  - subscription update status
 *   tls_cert - PEM server certificate chain for HTTPS DoH and DoT
 *   tls_key  - PEM private key for HTTPS DoH and DoT
 * The same JSON schema is used by the REST API (GET/PUT /api/config).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "cJSON.h"
#include "esp_err.h"
#include "dns_server.h"

#define APP_MAX_SUBS 16
#define APP_MAX_BOOTSTRAP 3
#define APP_RULES_MAX (96 * 1024) /* custom rules (NVS) */
#define APP_LOCAL_MAX (32 * 1024)
#define APP_TLS_MAX (16 * 1024)   /* PEM cert or private key (NVS) */

typedef struct {
    char name[64];
    char url[256];
    bool enabled;
    bool allowlist;
} app_sub_t;

typedef struct {
    /* network */
    char hostname[32];
    char ssid[33];
    char password[65];
    bool static_ip;
    char ip[16], netmask[16], gateway[16];
    bool ipv6;
    char ntp[2][64];
    char timezone[48]; /* POSIX TZ, e.g. "CST-8" */
    /* DNS (listeners, policy, cache, upstreams) */
    dns_config_t dns;
    char bootstrap[APP_MAX_BOOTSTRAP][48]; /* plain DNS used to resolve DoT/DoH host names */
    uint8_t nbootstrap;
    /* filter subscriptions */
    app_sub_t subs[APP_MAX_SUBS];
    uint8_t nsubs;
    uint16_t update_hours; /* 0 = manual only */
    /* system & encrypted DNS endpoints (DoH / DoT) */
    uint16_t web_port;
    uint16_t https_port; /* esp_https_server port (default 443) for https://<device>/dns-query */
    bool doh_server;     /* serve DNS-over-HTTPS (RFC 8484) at /dns-query */
    bool dot_server;     /* serve DNS-over-TLS (RFC 7858) on dot_port */
    uint16_t dot_port;   /* DoT TCP port (default 853) */
    char username[32];
    char pass_hash[65]; /* hex SHA-256(salt || password), "" = no password */
    char pass_salt[33];
} app_config_t;

esp_err_t app_config_init(void); /* opens NVS and loads (or defaults) */
void app_config_defaults(app_config_t *c);

/* The structure is heap allocated.
 * app_config_get: a snapshot (free with free()).
 * edit_begin/commit: read-modify-write under the writer lock; commit saves
 * to flash, replaces the live configuration and frees `c`. */
app_config_t *app_config_get(void);
app_config_t *app_config_edit_begin(void);
esp_err_t app_config_edit_commit(app_config_t *c);
void app_config_edit_abort(app_config_t *c);

/* JSON <-> struct.  to_json omits secrets unless `secrets` is true. */
cJSON *app_config_to_json(const app_config_t *c, bool secrets);
/* Applies the fields present in `j` onto `c`.  Returns false with *err. */
bool app_config_apply_json(app_config_t *c, const cJSON *j, char *err, size_t errlen);

/* large text blobs */
char *app_blob_load(const char *key, size_t *len); /* malloc'ed, NUL terminated; NULL if absent */
esp_err_t app_blob_save(const char *key, const char *data, size_t len);
esp_err_t app_config_factory_reset(void);

/* password helpers */
void app_password_set(app_config_t *c, const char *password);
bool app_auth_required(void);
bool app_auth_check(const char *user, const char *password); /* against the live configuration */

/* block mode / strategy names */
const char *app_block_mode_name(dns_block_mode_t m);
const char *app_strategy_name(dns_strategy_t s);
