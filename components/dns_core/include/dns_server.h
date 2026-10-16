/*
 * dns_server.h - the DNS server: listeners, query pipeline, cache, upstreams.
 *
 * Portable: uses BSD sockets (lwIP on the ESP32-S3, POSIX on Linux) and the
 * dc_port.h abstraction.  Encrypted upstream transports (DoT/DoH) are
 * plugged in by the platform through dns_up_ops_t.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dc_net.h"
#include "dns_cache.h"
#include "dns_local.h"
#include "dns_wire.h"
#include "fl_filter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_MAX_UPSTREAMS 8
#define DNS_MAX_ALLOW 16

typedef enum {
    DNS_BLOCK_DEFAULT = 0, /* AdGuard "default": hosts-rule IPs, otherwise 0.0.0.0 / :: */
    DNS_BLOCK_NULL_IP,
    DNS_BLOCK_NXDOMAIN,
    DNS_BLOCK_REFUSED,
    DNS_BLOCK_CUSTOM_IP,
} dns_block_mode_t;

typedef enum { DNS_UP_UDP = 0, DNS_UP_TCP, DNS_UP_DOT, DNS_UP_DOH } dns_up_proto_t;

typedef enum {
    DNS_STRAT_LOAD_BALANCE = 0, /* weighted by measured latency (AdGuard default) */
    DNS_STRAT_PARALLEL,         /* query the two best at once, first answer wins */
    DNS_STRAT_FASTEST,          /* always the lowest latency (with exploration) */
} dns_strategy_t;

typedef struct {
    dns_up_proto_t proto;
    dc_ip_t ip;
    uint16_t port;
    char host[128]; /* TLS server name (DoT/DoH) */
    char path[96];  /* DoH path, default /dns-query */
    char text[200]; /* original address text, for display */
} dns_upstream_cfg_t;

typedef struct {
    /* listeners */
    uint16_t port;
    bool listen_v4, listen_v6, tcp;
    uint8_t udp_workers; /* receive threads per UDP socket (1 on lwIP) */
    uint8_t tcp_workers;
    char bind_v4[16];    /* "" = any */
    /* access */
    bool local_only;                   /* only private/link-local/loopback clients */
    dc_prefix_t allow[DNS_MAX_ALLOW];  /* additional allowed networks */
    uint8_t nallow;
    uint32_t ratelimit;                /* queries/s per client IP, 0 = unlimited */
    bool refuse_any;
    /* filtering policy */
    bool protection;                   /* global switch (rewrites still apply) */
    dns_block_mode_t block_mode;
    dc_ip_t custom_v4, custom_v6;
    uint32_t blocked_ttl;
    /* cache */
    uint32_t cache_bytes;
    uint16_t cache_l1;
    uint32_t cache_min_ttl, cache_max_ttl;
    bool optimistic;
    uint32_t optimistic_max_age;
    /* upstreams */
    dns_upstream_cfg_t up[DNS_MAX_UPSTREAMS];
    uint8_t nup;
    dns_strategy_t strategy;
    uint32_t up_timeout_ms;            /* per attempt (adaptive below this) */
    uint32_t query_timeout_ms;         /* overall */
    /* logging */
    uint16_t qlog_entries;
} dns_config_t;

void dns_config_defaults(dns_config_t *c);
/* "1.1.1.1", "[2606:4700::1111]:53", "tcp://9.9.9.9", "tls://dns.google",
 * "tls://1.1.1.1@cloudflare-dns.com", "https://dns.google/dns-query". */
bool dns_upstream_parse(const char *s, dns_upstream_cfg_t *u, const char **err);

typedef struct dns_server dns_server_t;

/* ---- pluggable encrypted transports ---------------------------------------- */
typedef struct {
    /* Queue a query; must not block for long.  The transport later calls
     * dns_server_deliver() or dns_server_fail() with the same ticket. */
    int (*submit)(void *ctx, int up_index, uint32_t ticket, const uint8_t *q, size_t len);
    void *ctx;
} dns_up_ops_t;
void dns_server_set_transport(dns_server_t *s, dns_up_proto_t proto, const dns_up_ops_t *ops);
void dns_server_deliver(dns_server_t *s, uint32_t ticket, const uint8_t *resp, size_t len);
/* The attempt failed (connection error, overload): the next one starts. */
void dns_server_fail(dns_server_t *s, uint32_t ticket);

/* ---- lifecycle -------------------------------------------------------------- */
dns_server_t *dns_server_new(const dns_config_t *cfg);
int dns_server_start(dns_server_t *s);
/* Stops all threads and frees the server (stop DoH/DoT front ends first). */
void dns_server_stop(dns_server_t *s);
/* Policy/upstream/cache-size changes at runtime (listeners stay). */
int dns_server_reconfigure(dns_server_t *s, const dns_config_t *cfg);
void dns_server_get_config(dns_server_t *s, dns_config_t *out);
/* Takes a reference; NULL disables filtering.  The cache keeps upstream
 * answers only (verdicts are computed per query), so it stays valid. */
void dns_server_set_filters(dns_server_t *s, fl_set_t *set);
fl_set_t *dns_server_get_filters(dns_server_t *s); /* new reference or NULL */
void dns_server_set_local(dns_server_t *s, dns_local_t *local); /* takes ownership */
void dns_server_cache_flush(dns_server_t *s);
/* Free cache buffers for rule compilation, restore latest desired budget after.
 * Never disables DNS resolution or the active filter image. */
void dns_server_cache_build_mode(dns_server_t *s, bool building);
/* Setup (captive portal) mode: every query from `net` is answered locally,
 * A with `ip` and other types with an empty answer, so phones joining the
 * setup hotspot open the setup page by themselves.  ip == NULL: off. */
void dns_server_set_captive(dns_server_t *s, const dc_ip_t *ip, const dc_prefix_t *net);

/* ---- synchronous queries (DoH/DoT servers, diagnostics) --------------------- */
typedef struct {
    dc_ip_t ip;
    uint16_t port;
    uint8_t transport; /* DNS_TR_* */
} dns_peer_t;
enum { DNS_TR_UDP = 0, DNS_TR_TCP, DNS_TR_DOT, DNS_TR_DOH, DNS_TR_INTERNAL };
/* Output buffer size for dns_server_query (minimum 4160 bytes; answers
 * larger than the buffer are reported as SERVFAIL). */
#define DNS_QUERY_BUF (16384 + 64)
/* Returns response length (0 = dropped). */
size_t dns_server_query(dns_server_t *s, const dns_peer_t *peer, const uint8_t *q, size_t qlen, uint8_t *out,
                        size_t cap);

/* ---- statistics --------------------------------------------------------------- */
#define DNS_HIST_BUCKETS 96
typedef struct {
    uint32_t count;
    uint64_t sum_us;
    uint32_t b[DNS_HIST_BUCKETS]; /* log-linear microsecond buckets, 4 per octave */
} dns_hist_t;
uint32_t dns_hist_percentile(const dns_hist_t *h, unsigned pct); /* microseconds */
uint32_t dns_hist_mean(const dns_hist_t *h);

typedef struct {
    uint32_t queries, udp, tcp, dot, doh;
    uint32_t blocked, rewritten, local, allowed, cached, forwarded, failed, refused, dropped;
    uint32_t ratelimited, malformed, truncated, resp_blocked, stale_served, coalesced;
    uint32_t qtype_a, qtype_aaaa, qtype_https, qtype_other;
    dns_hist_t local_us;   /* answered without upstream: parse -> send */
    dns_hist_t cached_us;  /* cache hits */
    dns_hist_t forward_us; /* forwarded: receive -> reply */
    dns_cache_stats_t cache;
    struct {
        char text[64];
        uint32_t sent, ok, timeouts, errors;
        uint32_t rtt_us; /* smoothed */
        bool healthy;
    } up[DNS_MAX_UPSTREAMS];
    uint8_t nup;
    uint32_t pending;
    uint32_t filter_generation;
} dns_stats_t;
void dns_server_get_stats(dns_server_t *s, dns_stats_t *st);
void dns_server_reset_stats(dns_server_t *s);

typedef struct {
    uint32_t time;     /* wall clock (s) */
    uint32_t elapsed_us;
    dc_ip_t client;
    uint16_t qtype;
    uint8_t result;    /* DNS_QL_* */
    uint8_t rcode;
    uint8_t upstream;  /* 0xFF none */
    char name[88];     /* truncated */
} dns_qlog_t;
enum { DNS_QL_FORWARDED = 0, DNS_QL_CACHED, DNS_QL_BLOCKED, DNS_QL_REWRITTEN, DNS_QL_LOCAL, DNS_QL_ALLOWED,
       DNS_QL_FAILED, DNS_QL_REFUSED, DNS_QL_RESP_BLOCKED };
/* Copies up to max newest entries (newest first). */
unsigned dns_server_qlog(dns_server_t *s, dns_qlog_t *out, unsigned max);

#ifdef __cplusplus
}
#endif
