/* dns_stats.c - counters, latency histograms and the query log. */
#include <string.h>

#include "dns_internal.h"

/* 4 buckets per power of two: values 0..3 map to themselves, then
 * idx = 4 * (octave - 1) + next two bits. */
static unsigned hist_idx(uint32_t us) {
    if (us < 4) return us;
    unsigned o = 31u - (unsigned)__builtin_clz(us);
    unsigned idx = 4u * (o - 1u) + ((us >> (o - 2u)) & 3u);
    return idx < DNS_HIST_BUCKETS ? idx : DNS_HIST_BUCKETS - 1;
}

static uint32_t hist_mid(unsigned idx) {
    if (idx < 4) return idx;
    unsigned o = idx / 4 + 1, sub = idx % 4;
    uint32_t lo = (4u + sub) << (o - 2), w = 1u << (o - 2);
    return lo + w / 2;
}

void dns_hist_add(dns_hist_t *h, uint32_t us) {
    __atomic_fetch_add(&h->b[hist_idx(us)], 1u, __ATOMIC_RELAXED);
    __atomic_fetch_add(&h->count, 1u, __ATOMIC_RELAXED);
    __atomic_fetch_add(&h->sum_us, (uint64_t)us, __ATOMIC_RELAXED);
}

uint32_t dns_hist_percentile(const dns_hist_t *h, unsigned pct) {
    uint64_t total = 0;
    for (unsigned i = 0; i < DNS_HIST_BUCKETS; i++) total += h->b[i];
    if (!total) return 0;
    uint64_t want = (total * pct + 99) / 100, acc = 0;
    if (!want) want = 1;
    for (unsigned i = 0; i < DNS_HIST_BUCKETS; i++) {
        acc += h->b[i];
        if (acc >= want) return hist_mid(i);
    }
    return hist_mid(DNS_HIST_BUCKETS - 1);
}

uint32_t dns_hist_mean(const dns_hist_t *h) { return h->count ? (uint32_t)(h->sum_us / h->count) : 0; }

void dns_stat_query(dns_server_t *s, const cq_t *cq, uint8_t rcode, uint8_t up) {
    uint64_t d = dc_time_us() - cq->t0;
    uint32_t us = d > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)d;
    switch (cq->path) {
    case P_CACHE: dns_hist_add(&s->st.cached_us, us); break;
    case P_FWD: dns_hist_add(&s->st.forward_us, us); break;
    default: dns_hist_add(&s->st.local_us, us); break;
    }
    switch (cq->result) {
    case DNS_QL_FORWARDED: DNS_STAT_INC(s, forwarded); break;
    case DNS_QL_CACHED: DNS_STAT_INC(s, cached); break;
    case DNS_QL_BLOCKED: DNS_STAT_INC(s, blocked); break;
    case DNS_QL_REWRITTEN: DNS_STAT_INC(s, rewritten); break;
    case DNS_QL_LOCAL: DNS_STAT_INC(s, local); break;
    case DNS_QL_ALLOWED: DNS_STAT_INC(s, allowed); break;
    case DNS_QL_FAILED: DNS_STAT_INC(s, failed); break;
    case DNS_QL_REFUSED: DNS_STAT_INC(s, refused); break;
    case DNS_QL_RESP_BLOCKED: DNS_STAT_INC(s, resp_blocked); break;
    default: break;
    }
    if (!s->qlog) return;
    char host[DNS_HOST_MAX];
    int hl = fl_name_from_wire(cq->qname, cq->qname_len, host, sizeof(host));
    if (hl < 0) hl = 0;
    dc_mutex_lock(s->qmu);
    dns_qlog_t *e = &s->qlog[s->qlog_pos % s->qlog_n];
    s->qlog_pos++;
    e->time = dc_wall_time();
    e->elapsed_us = us;
    e->client = cq->ip;
    e->qtype = cq->qtype;
    e->result = cq->result;
    e->rcode = rcode;
    e->upstream = up;
    size_t n = (size_t)hl < sizeof(e->name) - 1 ? (size_t)hl : sizeof(e->name) - 1;
    for (size_t i = 0; i < n; i++) e->name[i] = (char)dc_lower((uint8_t)host[i]);
    e->name[n] = 0;
    dc_mutex_unlock(s->qmu);
}

unsigned dns_server_qlog(dns_server_t *s, dns_qlog_t *out, unsigned max) {
    if (!s->qlog) return 0;
    dc_mutex_lock(s->qmu);
    unsigned have = s->qlog_pos < s->qlog_n ? s->qlog_pos : s->qlog_n;
    unsigned n = have < max ? have : max;
    for (unsigned i = 0; i < n; i++) out[i] = s->qlog[(s->qlog_pos - 1 - i) % s->qlog_n];
    dc_mutex_unlock(s->qmu);
    return n;
}
