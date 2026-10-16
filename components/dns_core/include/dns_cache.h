/*
 * dns_cache.h - two level TTL-aware DNS response cache.
 *
 * L2 (PSRAM): variable-size entries in a ring buffer (no fragmentation,
 *   FIFO eviction) + open-addressing hash index.
 * L1 (internal SRAM): small direct-mapped copy of hot, small responses.
 *
 * Stored messages are upstream responses with ID 0, TTLs already clamped,
 * and the OPT record normalized (see dns_engine.c).  On a hit the message
 * is copied out with every TTL decremented by the entry age.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t name[DNS_MAX_NAME]; /* lowercase wire */
    uint8_t name_len;
    uint16_t qtype, qclass;
    uint8_t flags; /* DNS_CK_* */
} dns_ckey_t;

enum { DNS_CK_DO = 1, DNS_CK_CD = 2 };

typedef struct dns_cache dns_cache_t;

typedef struct {
    size_t l2_bytes;      /* ring buffer size (PSRAM) */
    unsigned l1_entries;  /* power of two, 0 disables L1 */
    uint32_t stale_max_s; /* optimistic serving window after expiry, 0 = off */
} dns_cache_cfg_t;

enum { DNS_CACHE_MISS = 0, DNS_CACHE_HIT = 1, DNS_CACHE_STALE = 2 };

typedef struct {
    uint16_t len;
    bool l1;
    uint8_t rcode;
    /* response-filtering memo (see dns_engine.c) */
    uint32_t memo_gen, memo_fp;
    uint8_t memo;
} dns_cache_hit_t;

typedef struct {
    uint32_t entries;
    uint32_t bytes_used;
    uint32_t bytes_total;
    uint32_t l1_hits, l2_hits, stale_hits, misses;
    uint32_t inserts, evictions, too_large;
} dns_cache_stats_t;

dns_cache_t *dns_cache_new(const dns_cache_cfg_t *cfg);
void dns_cache_free(dns_cache_t *c);
uint32_t dns_ckey_hash(const dns_ckey_t *k);

/* Copies the cached message into out (TTLs adjusted).  now = seconds. */
int dns_cache_get(dns_cache_t *c, const dns_ckey_t *k, uint8_t *out, size_t cap, uint32_t now,
                  uint32_t stale_ttl, dns_cache_hit_t *hit);
/* Stores msg (TTLs must already be clamped) for ttl seconds. */
void dns_cache_put(dns_cache_t *c, const dns_ckey_t *k, const uint8_t *msg, size_t len, const dns_resp_t *r,
                   uint32_t ttl, uint32_t now);
void dns_cache_set_memo(dns_cache_t *c, const dns_ckey_t *k, uint32_t gen, uint32_t fp, uint8_t memo);
/* Removes the entry (e.g. the name's answer is no longer cacheable). */
void dns_cache_del(dns_cache_t *c, const dns_ckey_t *k);
void dns_cache_flush(dns_cache_t *c);
/* Applies new sizes / stale window.  Always drops the cached entries. */
void dns_cache_reconfigure(dns_cache_t *c, const dns_cache_cfg_t *cfg);
/* Temporarily release L1/L2 memory for large filter builds. DNS continues
 * working without response caching. Configuration changes made while paused
 * take effect on resume; no stale cache size is restored. Thread-safe. */
void dns_cache_set_build_mode(dns_cache_t *c, bool building);
void dns_cache_get_stats(dns_cache_t *c, dns_cache_stats_t *st);

#ifdef __cplusplus
}
#endif
