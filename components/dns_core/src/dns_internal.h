/* dns_internal.h - shared internals of the DNS server. */
#pragma once

#include <stdatomic.h>

#include "dc_port.h"
#include "dc_util.h"
#include "dns_server.h"

#ifdef ESP_PLATFORM
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#define dns_closesocket(s) closesocket(s)
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#define dns_closesocket(s) close(s)
#endif

#ifdef ESP_PLATFORM
#define DNS_MAX_PENDING 256
#define DNS_MAX_WAITERS 512
#else
#define DNS_MAX_PENDING 1024
#define DNS_MAX_WAITERS 4096
#endif
#define DNS_MAX_WAIT_PER 32  /* clients coalesced onto one upstream query */
#define DNS_UP_SOCKS 4       /* upstream UDP sockets per address family */
#define DNS_MSG_MAX 4096     /* largest UDP message handled/cached */
#define DNS_TCP_MAX 16384    /* largest TCP message accepted (memory bound) */
#define DNS_RL_SLOTS 256
#define DNS_SYNC_SLOTS 32
#define DNS_STALE_TTL 30     /* TTL of optimistic (expired) answers */
#ifdef ESP_PLATFORM
#define DNS_TCPQ 8 /* queued TCP connections (lwIP sockets are limited) */
#else
#define DNS_TCPQ 16
#endif
#define DNS_MAX_TCPW 16      /* TCP client worker threads */
#ifdef ESP_PLATFORM
#define DNS_STREAMS 1        /* stream (TCP upstream) worker threads */
#else
#define DNS_STREAMS 2
#endif

/* Ticket of one upstream attempt (stream transports report back with it):
 * generation (16) | attempt (3) | upstream (3) | pending slot (10). */
#define T_SLOT(t) ((unsigned)(t) & 0x3FFu)
#define T_UP(t) (((unsigned)(t) >> 10) & 7u)
#define T_TRY(t) (((unsigned)(t) >> 13) & 7u)
#define T_GEN(t) ((uint16_t)((t) >> 16))
_Static_assert(DNS_MAX_PENDING <= 1024 && DNS_MAX_UPSTREAMS <= 8, "ticket layout");

/* ---- immutable snapshot read by the query path --------------------------- */
typedef struct {
    _Atomic int refs;
    dns_local_t *l;
} lref_t;

typedef struct view {
    _Atomic int refs;
    fl_set_t *filters; /* NULL: no filtering */
    uint32_t fgen;     /* filter generation (response-filter memo key) */
    lref_t *local;     /* NULL: no local records */
    /* setup (captive portal) mode */
    bool captive;
    dc_ip_t captive_ip;
    dc_prefix_t captive_net;
    dns_config_t cfg;
} view_t;

/* compact client query (kept by waiters) */
typedef struct {
    uint16_t id, flags, qtype, qclass;
    uint8_t qname[DNS_MAX_NAME]; /* case as sent */
    uint8_t qname_len;
    bool has_edns, do_bit;
    uint16_t edns_udp;
    uint8_t transport;
    dc_ip_t ip;
    /* policy */
    bool resp_filter; /* run response filtering on the upstream answer */
    bool cname_rw;    /* CNAME rewrite: the forwarded name is the rewrite target */
    uint32_t rw_ttl;  /* TTL of the CNAME added for a rewrite */
    uint8_t result;   /* DNS_QL_* for statistics (0xFF: not decided yet) */
    uint8_t path;     /* P_* latency class */
    uint64_t t0;
} cq_t;

typedef struct dns_sync {
    dc_sem_t *sem;
    uint8_t *buf;
    size_t cap;
    size_t len;
    uint32_t ticket;
    bool busy;
} dns_sync_t;

typedef struct waiter {
    struct waiter *next;
    uint8_t kind; /* W_* */
    int sock;     /* UDP reply socket */
    struct sockaddr_storage sa;
    socklen_t salen;
    dns_sync_t *sync;
    uint32_t sync_ticket;
    cq_t cq;
} waiter_t;

enum { W_UDP = 1, W_SYNC, W_REFRESH };
enum { P_LOCAL = 0, P_CACHE, P_FWD };

typedef struct {
    uint8_t active;
    uint8_t tries;
    uint8_t up_idx;    /* upstream of the current attempt */
    uint8_t sock_idx;
    uint8_t up_mask;   /* upstreams this query was sent to */
    uint8_t nwait;
    uint8_t stream;    /* the current attempt goes over a stream (TCP/DoT/DoH) */
    uint8_t accounted; /* the current attempt's failure has been counted */
    uint16_t gen;
    uint16_t up_id;
    int16_t knext;     /* key hash bucket chain */
    uint32_t deadline_ms, attempt_ms;
    uint32_t sent_us[DNS_MAX_UPSTREAMS];
    uint32_t key_hash;
    dns_ckey_t key;
    waiter_t *waiters;
    uint16_t qlen;
    uint8_t qbuf[DNS_MAX_NAME + 32]; /* the upstream query (name in random case) */
} pending_t;

typedef struct {
    dns_upstream_cfg_t cfg;
    struct sockaddr_storage sa;
    socklen_t salen;
    uint32_t srtt_us; /* smoothed RTT (EWMA 1/8), 0 = unknown */
    uint32_t sent, ok, timeouts, errors;
    uint32_t fail_streak;
    uint32_t down_until_ms;
    uint8_t case_miss; /* consecutive answers with the question's case changed */
    bool no_0x20;      /* this upstream does not keep the case: not checked */
} upstream_t;

typedef struct {
    dc_ip_t ip;
    uint32_t tokens; /* x1000 */
    uint32_t last_ms;
} rl_slot_t;

/* stream (TCP) upstream job queue */
typedef struct sjob {
    struct sjob *next;
    int up;
    uint32_t ticket;
    uint16_t len;
    uint8_t q[DNS_MAX_NAME + 32];
} sjob_t;

struct dns_server {
    dc_mutex_t *vmu; /* protects `view` (the pointer) */
    view_t *view;
    atomic_bool running;
    _Atomic int threads;

    int udp_sock[2]; /* v4, v6 */
    int tcp_sock[2];
    int up_sock[2][DNS_UP_SOCKS];

    dns_cache_t *cache;

    dc_mutex_t *pmu; /* pending table, waiters, upstream runtime, sync slots */
    pending_t *pend;
    unsigned npend_active;
    int16_t *khead;  /* DNS_MAX_PENDING buckets by key hash */
    uint16_t *idmap; /* 65536 entries: upstream query ID -> slot + 1 */
    uint16_t *pfree; /* free slot stack */
    unsigned npfree;
    waiter_t *wpool, *wfree;
    upstream_t up[DNS_MAX_UPSTREAMS];
    uint8_t nup;
    dns_strategy_t strategy;
    uint32_t up_timeout_ms, query_timeout_ms;
    dns_up_ops_t ops[4];
    dns_sync_t sync[DNS_SYNC_SLOTS];

    /* stream upstream workers */
    dc_mutex_t *smu;
    dc_sem_t *ssem;
    sjob_t *shead, *stail;
    unsigned sjobs;

    /* TCP client connections */
    dc_mutex_t *tmu; /* also guards the active connection lists */
    dc_sem_t *tsem;
    int tconn[DNS_TCPQ];
    unsigned tq_head, tq_len;
    int tact[DNS_MAX_TCPW];  /* connection served by each TCP worker (-1 none) */
    int sact[DNS_STREAMS];   /* upstream connection of each stream worker */

    dc_mutex_t *rlmu;
    rl_slot_t rl[DNS_RL_SLOTS];

    dns_stats_t st; /* counters updated with relaxed atomics */

    dc_mutex_t *qmu; /* query log */
    dns_qlog_t *qlog;
    uint16_t qlog_n;
    uint32_t qlog_pos;
};

/* dns_server.c: snapshot handling */
view_t *dns_view_get(dns_server_t *s);
void dns_view_put(view_t *v);

/* dns_engine.c */
enum { H_DONE = 0, H_PENDING, H_DROP };
typedef struct {
    const uint8_t *msg;
    size_t len;
    dns_peer_t peer;
    /* UDP async reply target */
    int sock;
    const struct sockaddr *sa;
    socklen_t salen;
    dns_sync_t *sync;
    uint32_t sync_ticket;
    uint64_t t0;
    uint8_t *out; /* at least DNS_MSG_MAX + 64 bytes */
    size_t cap;
    size_t out_len;
} qctx_t;

int dns_handle(dns_server_t *s, qctx_t *c);
/* Completes all waiters of a detached pending entry with an upstream answer
 * (resp == NULL: failure -> SERVFAIL).  Frees the waiters. */
void dns_complete(dns_server_t *s, waiter_t *ws, const dns_ckey_t *key, const uint8_t *resp, size_t len,
                  uint8_t up_idx);

/* dns_server.c (upstream side) */
/* Takes ownership of w (also on failure).  Returns 0 or -1 (w freed). */
int dns_forward(dns_server_t *s, const dns_ckey_t *key, uint32_t key_hash, waiter_t *w);
waiter_t *dns_waiter_alloc(dns_server_t *s);
void dns_waiter_free_list(dns_server_t *s, waiter_t *w);
/* Hands a finished response to a synchronous caller (under pmu). */
void dns_sync_deliver(dns_server_t *s, waiter_t *w, const uint8_t *msg, size_t len);

size_t dns_sockaddr_from_ip(const dc_ip_t *ip, uint16_t port, struct sockaddr_storage *sa);
void dns_ip_from_sockaddr(const struct sockaddr *sa, dc_ip_t *ip, uint16_t *port);

/* dns_stats.c */
void dns_hist_add(dns_hist_t *h, uint32_t us);
void dns_stat_query(dns_server_t *s, const cq_t *cq, uint8_t rcode, uint8_t up);

#define DNS_STAT_INC(s, field) __atomic_fetch_add(&(s)->st.field, 1u, __ATOMIC_RELAXED)
