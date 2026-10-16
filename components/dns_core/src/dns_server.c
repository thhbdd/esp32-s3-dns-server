/*
 * dns_server.c - sockets, threads, upstream manager, synchronous API.
 *
 * Threads:
 *   udp-rx (per listening socket x udp_workers): receive, dns_handle(), reply.
 *       Local / blocked / cached answers are produced right here.
 *   upstream: select() over the upstream UDP sockets; matches answers to the
 *       pending table (16-bit random ID -> slot map, source address and
 *       question checked), runs dns_complete(), drives retries/timeouts.
 *   stream: TCP exchanges with upstreams (tcp:// upstreams and the
 *       fallback after a truncated UDP answer).
 *   tcp-accept + tcp workers: DNS over TCP clients.
 *
 * Concurrent identical questions are coalesced onto one upstream query.
 */
#include <stdlib.h>
#include <string.h>

#include "dns_internal.h"

static const char *TAG = "dns";

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif

#ifdef ESP_PLATFORM
#define STACK_RX 12288
#define STACK_UP 12288
#define STACK_STREAM 10240
#define STACK_TCP 12288
#else
#define STACK_RX 262144
#define STACK_UP 262144
#define STACK_STREAM 131072
#define STACK_TCP 262144
#endif

#define TICK_MS 20
#define RETRY_MIN_MS 250 /* retry delay when only failed upstreams are left */

/* ---- addresses ------------------------------------------------------------------- */

size_t dns_sockaddr_from_ip(const dc_ip_t *ip, uint16_t port, struct sockaddr_storage *sa) {
    memset(sa, 0, sizeof(*sa));
    if (ip->family == 4) {
        struct sockaddr_in *a = (struct sockaddr_in *)sa;
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        memcpy(&a->sin_addr, ip->addr, 4);
        return sizeof(*a);
    }
    if (ip->family == 6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)sa;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        memcpy(&a->sin6_addr, ip->addr, 16);
        return sizeof(*a);
    }
    return 0;
}

void dns_ip_from_sockaddr(const struct sockaddr *sa, dc_ip_t *ip, uint16_t *port) {
    memset(ip, 0, sizeof(*ip));
    *port = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
        ip->family = 4;
        memcpy(ip->addr, &a->sin_addr, 4);
        *port = ntohs(a->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
        ip->family = 6;
        memcpy(ip->addr, &a->sin6_addr, 16);
        *port = ntohs(a->sin6_port);
        dc_ip_unmap4(ip);
    }
}

static bool sa_equal(const struct sockaddr_storage *a, const struct sockaddr *b) {
    if (a->ss_family != b->sa_family) return false;
    if (b->sa_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)a, *y = (const struct sockaddr_in *)b;
        return x->sin_port == y->sin_port && memcmp(&x->sin_addr, &y->sin_addr, 4) == 0;
    }
    if (b->sa_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a, *y = (const struct sockaddr_in6 *)b;
        return x->sin6_port == y->sin6_port && memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0;
    }
    return false;
}

/* ---- snapshot ------------------------------------------------------------------------ */

static void lref_put(lref_t *l) {
    if (l && atomic_fetch_sub(&l->refs, 1) == 1) {
        dns_local_free(l->l);
        dc_free(l);
    }
}

view_t *dns_view_get(dns_server_t *s) {
    dc_mutex_lock(s->vmu);
    view_t *v = s->view;
    atomic_fetch_add(&v->refs, 1);
    dc_mutex_unlock(s->vmu);
    return v;
}

void dns_view_put(view_t *v) {
    if (!v || atomic_fetch_sub(&v->refs, 1) != 1) return;
    fl_set_unref(v->filters);
    lref_put(v->local);
    dc_free(v);
}

/* new snapshot from the current one; caller holds vmu */
static view_t *view_clone(const view_t *o) {
    view_t *v = (view_t *)dc_malloc(sizeof(view_t));
    if (!v) return NULL;
    atomic_store(&v->refs, 1); /* (o->refs changes concurrently: not copied) */
    v->filters = o->filters;
    v->fgen = o->fgen;
    v->local = o->local;
    v->captive = o->captive;
    v->captive_ip = o->captive_ip;
    v->captive_net = o->captive_net;
    v->cfg = o->cfg;
    if (v->filters) fl_set_ref(v->filters);
    if (v->local) atomic_fetch_add(&v->local->refs, 1);
    return v;
}

static void view_swap(dns_server_t *s, view_t *nv) {
    view_t *old = s->view;
    s->view = nv;
    dns_view_put(old);
}

/* ---- waiters ------------------------------------------------------------------------- */

waiter_t *dns_waiter_alloc(dns_server_t *s) {
    dc_mutex_lock(s->pmu);
    waiter_t *w = s->wfree;
    if (w) s->wfree = w->next;
    dc_mutex_unlock(s->pmu);
    if (w) w->next = NULL;
    return w;
}

static void waiter_free_locked(dns_server_t *s, waiter_t *w) {
    while (w) {
        waiter_t *n = w->next;
        w->next = s->wfree;
        s->wfree = w;
        w = n;
    }
}

void dns_waiter_free_list(dns_server_t *s, waiter_t *w) {
    if (!w) return;
    dc_mutex_lock(s->pmu);
    waiter_free_locked(s, w);
    dc_mutex_unlock(s->pmu);
}

void dns_sync_deliver(dns_server_t *s, waiter_t *w, const uint8_t *msg, size_t len) {
    dns_sync_t *y = w->sync;
    if (!y) return;
    dc_mutex_lock(s->pmu);
    if (y->busy && y->ticket == w->sync_ticket) {
        size_t n = len <= y->cap ? len : 0;
        if (n) memcpy(y->buf, msg, n);
        y->len = n;
        y->ticket++;
        dc_sem_give(y->sem);
    }
    dc_mutex_unlock(s->pmu);
}

/* ---- upstream selection ---------------------------------------------------------------- */

static bool up_usable(const upstream_t *u, uint32_t now) {
    return !u->down_until_ms || (int32_t)(now - u->down_until_ms) >= 0;
}

static int pick_upstream(dns_server_t *s, uint8_t exclude) {
    unsigned n = s->nup;
    if (!n) return -1;
    uint32_t now = dc_time_ms();
    int cand[DNS_MAX_UPSTREAMS];
    unsigned nc = 0;
    for (int pass = 0; pass < 3 && !nc; pass++)
        for (unsigned i = 0; i < n; i++) {
            if (pass < 2 && (exclude & (1u << i))) continue;
            if (pass == 0 && !up_usable(&s->up[i], now)) continue;
            cand[nc++] = (int)i;
        }
    if (nc == 1) return cand[0];
    if (s->strategy == DNS_STRAT_LOAD_BALANCE) {
        uint64_t w[DNS_MAX_UPSTREAMS], tot = 0;
        for (unsigned k = 0; k < nc; k++) {
            uint32_t rtt = s->up[cand[k]].srtt_us;
            w[k] = 1000000000ull / ((rtt ? rtt : 20000) + 1000);
            tot += w[k];
        }
        uint64_t r = dc_random32() % (tot ? tot : 1);
        for (unsigned k = 0; k < nc; k++) {
            if (r < w[k]) return cand[k];
            r -= w[k];
        }
        return cand[0];
    }
    if ((dc_random32() & 15) == 0) return cand[dc_random32() % nc]; /* exploration */
    int best = cand[0];
    for (unsigned k = 1; k < nc; k++)
        if (s->up[cand[k]].srtt_us < s->up[best].srtt_us) best = cand[k];
    return best;
}

/* an upstream not tried yet for this query that is not marked down */
static bool has_alternative(const dns_server_t *s, const pending_t *p, uint32_t now) {
    for (unsigned i = 0; i < s->nup; i++)
        if (!(p->up_mask & (1u << i)) && up_usable(&s->up[i], now)) return true;
    return false;
}

static void up_success(upstream_t *u, uint32_t rtt_us) {
    u->ok++;
    u->fail_streak = 0;
    u->down_until_ms = 0;
    if (rtt_us) u->srtt_us = u->srtt_us ? u->srtt_us - u->srtt_us / 8 + rtt_us / 8 : rtt_us;
}

static void up_failure(dns_server_t *s, upstream_t *u, bool timeout) {
    if (timeout)
        u->timeouts++;
    else
        u->errors++;
    uint32_t pen = s->up_timeout_ms * 1000u;
    u->srtt_us = u->srtt_us ? u->srtt_us + (pen > u->srtt_us ? (pen - u->srtt_us) / 4 : 0) : pen / 2;
    if (++u->fail_streak >= 3) {
        uint32_t k = u->fail_streak - 3;
        uint32_t back = 1000u << (k > 5 ? 5 : k);
        u->down_until_ms = dc_time_ms() + (back > 30000 ? 30000 : back);
        if (!u->down_until_ms) u->down_until_ms = 1;
    }
}

/* ---- pending table ------------------------------------------------------------------- */

enum { OP_NONE = 0, OP_UDP, OP_STREAM };
typedef struct {
    uint8_t kind;
    uint8_t proto;
    int up;
    int sock;
    struct sockaddr_storage sa;
    socklen_t salen;
    uint32_t ticket;
    uint16_t len;
    uint8_t q[DNS_MAX_NAME + 32];
} sendop_t;

static inline uint32_t ticket_of(const pending_t *p, unsigned slot, unsigned up) {
    return ((uint32_t)p->gen << 16) | ((uint32_t)(p->tries & 7u) << 13) | ((up & 7u) << 10) | slot;
}

/* the ticket belongs to the attempt in progress */
static inline bool ticket_current(const pending_t *p, uint32_t t) {
    return T_UP(t) == p->up_idx && T_TRY(t) == (p->tries & 7u);
}

static bool key_eq(const dns_ckey_t *a, const dns_ckey_t *b) {
    return a->name_len == b->name_len && a->qtype == b->qtype && a->qclass == b->qclass && a->flags == b->flags &&
           memcmp(a->name, b->name, a->name_len) == 0;
}

static waiter_t *pend_detach(dns_server_t *s, unsigned slot, dns_ckey_t *key_out) {
    pending_t *p = &s->pend[slot];
    waiter_t *ws = p->waiters;
    if (key_out) *key_out = p->key;
    int16_t *pp = &s->khead[p->key_hash & (DNS_MAX_PENDING - 1)];
    while (*pp >= 0) {
        if ((unsigned)*pp == slot) {
            *pp = p->knext;
            break;
        }
        pp = &s->pend[*pp].knext;
    }
    if (s->idmap[p->up_id] == slot + 1) s->idmap[p->up_id] = 0;
    p->active = 0;
    p->waiters = NULL;
    p->nwait = 0;
    s->pfree[s->npfree++] = (uint16_t)slot;
    s->npend_active--;
    return ws;
}

/* under pmu: prepares the next attempt of a pending query */
static bool pend_attempt(dns_server_t *s, unsigned slot, uint32_t now, sendop_t *op) {
    pending_t *p = &s->pend[slot];
    int ui = pick_upstream(s, p->up_mask);
    op->kind = OP_NONE;
    if (ui < 0) return false;
    upstream_t *u = &s->up[ui];
    p->up_idx = (uint8_t)ui;
    p->up_mask |= (uint8_t)(1u << ui);
    p->tries++;
    p->accounted = 0;
    p->sent_us[ui] = (uint32_t)dc_time_us();
    u->sent++;
    uint32_t t;
    op->up = ui;
    op->proto = (uint8_t)u->cfg.proto;
    op->len = p->qlen;
    memcpy(op->q, p->qbuf, p->qlen);
    op->ticket = ticket_of(p, slot, (unsigned)ui);
    if (u->cfg.proto == DNS_UP_UDP) {
        uint32_t srtt_ms = u->srtt_us / 1000;
        t = u->srtt_us ? srtt_ms * 3 + 60 : s->up_timeout_ms;
        if (t < 150) t = 150;
        if (t > s->up_timeout_ms) t = s->up_timeout_ms;
        int fam = u->cfg.ip.family == 6 ? 1 : 0;
        op->kind = OP_UDP;
        op->sock = s->up_sock[fam][p->sock_idx];
        memcpy(&op->sa, &u->sa, u->salen);
        op->salen = u->salen;
        p->stream = 0;
    } else {
        t = s->up_timeout_ms * 2;
        op->kind = OP_STREAM;
        p->stream = 1;
    }
    p->attempt_ms = now + t;
    if ((int32_t)(p->attempt_ms - p->deadline_ms) > 0) p->attempt_ms = p->deadline_ms;
    return true;
}

static void stream_enqueue(dns_server_t *s, int up, uint32_t ticket, const uint8_t *q, size_t len);

static void op_run(dns_server_t *s, sendop_t *op) {
    if (op->kind == OP_UDP) {
        if (op->sock < 0 ||
            sendto(op->sock, (const char *)op->q, op->len, 0, (const struct sockaddr *)&op->sa, op->salen) < 0)
            dns_server_fail(s, op->ticket); /* (e.g. no route): the next upstream right away */
    } else if (op->kind == OP_STREAM) {
        if (op->proto == DNS_UP_TCP) {
            stream_enqueue(s, op->up, op->ticket, op->q, op->len);
        } else {
            dns_up_ops_t ops = s->ops[op->proto & 3];
            if (!ops.submit || ops.submit(ops.ctx, op->up, op->ticket, op->q, op->len) != 0)
                dns_server_fail(s, op->ticket);
        }
    }
}

/* DNS 0x20: letters of the upstream question in random case; UDP answers
 * must repeat it exactly, which makes spoofed answers much harder to fit. */
static void mix_case(uint8_t *name, size_t len) {
    uint32_t r = 0;
    unsigned bits = 0;
    for (size_t i = 0; i < len && name[i];) {
        size_t end = i + 1 + name[i];
        for (i++; i < end && i < len; i++) {
            uint8_t c = name[i];
            if (c < 'a' || c > 'z') continue;
            if (!bits) {
                r = dc_random32();
                bits = 32;
            }
            if (r & 1) name[i] = (uint8_t)(c ^ 0x20);
            r >>= 1;
            bits--;
        }
    }
}

int dns_forward(dns_server_t *s, const dns_ckey_t *key, uint32_t h, waiter_t *w) {
    sendop_t ops[2];
    int nops = 0;
    w->next = NULL;
    dc_mutex_lock(s->pmu);
    if (!s->running || !s->nup) goto fail;
    unsigned b = h & (DNS_MAX_PENDING - 1);
    for (int16_t i = s->khead[b]; i >= 0; i = s->pend[i].knext) {
        pending_t *p = &s->pend[i];
        if (p->key_hash != h || !key_eq(&p->key, key)) continue;
        if (w->kind == W_REFRESH) { /* already being refreshed / resolved */
            waiter_free_locked(s, w);
            dc_mutex_unlock(s->pmu);
            return 0;
        }
        if (p->nwait < DNS_MAX_WAIT_PER) {
            w->next = p->waiters;
            p->waiters = w;
            p->nwait++;
            dc_mutex_unlock(s->pmu);
            DNS_STAT_INC(s, coalesced);
            return 0;
        }
    }
    if (!s->npfree) goto fail;
    unsigned slot = s->pfree[--s->npfree];
    pending_t *p = &s->pend[slot];
    uint32_t now = dc_time_ms();
    p->active = 1;
    p->gen++;
    p->tries = 0;
    p->up_mask = 0;
    p->nwait = 1;
    p->stream = 0;
    p->key = *key;
    p->key_hash = h;
    p->waiters = w;
    p->deadline_ms = now + s->query_timeout_ms;
    s->npend_active++;
    p->knext = s->khead[b];
    s->khead[b] = (int16_t)slot;
    uint16_t id;
    do {
        id = (uint16_t)dc_random32();
    } while (s->idmap[id]);
    s->idmap[id] = (uint16_t)(slot + 1);
    p->up_id = id;
    p->sock_idx = (uint8_t)(dc_random32() % DNS_UP_SOCKS);
    p->qlen = (uint16_t)dns_make_query(p->qbuf, sizeof(p->qbuf), id, key->name, key->name_len, key->qtype,
                                       key->qclass, (key->flags & DNS_CK_CD) != 0, (key->flags & DNS_CK_DO) != 0,
                                       true);
    if (p->qlen) mix_case(p->qbuf + DNS_HDR_LEN, key->name_len);
    if (!p->qlen || !pend_attempt(s, slot, now, &ops[0])) {
        pend_detach(s, slot, NULL);
        goto fail;
    }
    nops = 1;
    /* (the second pick excludes the first upstream) */
    if (s->strategy == DNS_STRAT_PARALLEL && s->nup > 1 && pend_attempt(s, slot, now, &ops[1])) nops = 2;
    dc_mutex_unlock(s->pmu);
    for (int i = 0; i < nops; i++) op_run(s, &ops[i]);
    return 0;
fail:
    waiter_free_locked(s, w);
    dc_mutex_unlock(s->pmu);
    return -1;
}

/* checks that a response answers our question (name case-insensitively) */
static bool question_matches(const uint8_t *m, size_t n, const dns_ckey_t *k) {
    if (n < DNS_HDR_LEN + (size_t)k->name_len + 4) return false;
    if (!(dc_be16(m + 2) & DNS_F_QR) || dc_be16(m + 4) != 1) return false;
    for (unsigned i = 0; i < k->name_len; i++)
        if (dc_lower(m[DNS_HDR_LEN + i]) != k->name[i]) return false;
    const uint8_t *t = m + DNS_HDR_LEN + k->name_len;
    return dc_be16(t) == k->qtype && dc_be16(t + 2) == k->qclass;
}

/* Under pmu: SERVFAIL / REFUSED from an upstream is passed on only when no
 * other upstream is left to ask; otherwise it counts as a failure and the
 * next attempt starts right away.  Returns true when the answer is dropped. */
static bool try_elsewhere(dns_server_t *s, pending_t *p, bool current, unsigned ui, uint8_t rcode) {
    if (rcode != DNS_RC_SERVFAIL && rcode != DNS_RC_REFUSED) return false;
    uint32_t now = dc_time_ms();
    if (!current) return true; /* a newer attempt is still running */
    if (!has_alternative(s, p, now)) return false;
    up_failure(s, &s->up[ui], false);
    p->accounted = 1;
    p->stream = 0;
    p->attempt_ms = now;
    return true;
}

static void handle_up_udp(dns_server_t *s, const uint8_t *buf, size_t n, const struct sockaddr *from) {
    if (n < DNS_HDR_LEN) return;
    uint16_t id = dc_be16(buf);
    dns_ckey_t key;
    dc_mutex_lock(s->pmu);
    uint16_t sl = s->idmap[id];
    if (!sl) goto drop;
    unsigned slot = sl - 1u;
    pending_t *p = &s->pend[slot];
    if (!p->active || p->up_id != id) goto drop;
    int ui = -1;
    for (unsigned i = 0; i < s->nup; i++)
        if ((p->up_mask & (1u << i)) && s->up[i].cfg.proto == DNS_UP_UDP && sa_equal(&s->up[i].sa, from)) {
            ui = (int)i;
            break;
        }
    if (ui < 0 || !question_matches(buf, n, &p->key)) goto drop;
    upstream_t *u = &s->up[ui];
    if (memcmp(buf + DNS_HDR_LEN, p->qbuf + DNS_HDR_LEN, p->key.name_len) != 0) { /* 0x20 case changed */
        if (!u->no_0x20) {
            if (++u->case_miss < 8) goto drop;
            u->no_0x20 = true;
            DC_LOGW(TAG, "%s does not keep the question case: 0x20 check off", u->cfg.text);
        }
    } else {
        u->case_miss = 0;
    }
    if (dc_be16(buf + 2) & DNS_F_TC) { /* this upstream once more over TCP */
        if (p->stream) goto drop;
        p->stream = 1;
        p->up_idx = (uint8_t)ui;
        p->tries++;
        p->accounted = 0;
        p->attempt_ms = dc_time_ms() + s->up_timeout_ms * 2;
        if ((int32_t)(p->attempt_ms - p->deadline_ms) > 0) p->attempt_ms = p->deadline_ms;
        uint32_t ticket = ticket_of(p, slot, (unsigned)ui);
        uint8_t q[DNS_MAX_NAME + 32];
        uint16_t ql = p->qlen;
        memcpy(q, p->qbuf, ql);
        DNS_STAT_INC(s, truncated);
        dc_mutex_unlock(s->pmu);
        stream_enqueue(s, ui, ticket, q, ql);
        return;
    }
    if (try_elsewhere(s, p, ui == p->up_idx, (unsigned)ui, buf[3] & 0xF)) goto drop;
    up_success(u, (uint32_t)dc_time_us() - p->sent_us[ui]);
    waiter_t *ws = pend_detach(s, slot, &key);
    dc_mutex_unlock(s->pmu);
    dns_complete(s, ws, &key, buf, n, (uint8_t)ui);
    return;
drop:
    dc_mutex_unlock(s->pmu);
}

void dns_server_deliver(dns_server_t *s, uint32_t ticket, const uint8_t *resp, size_t len) {
    unsigned slot = T_SLOT(ticket), ui = T_UP(ticket);
    if (slot >= DNS_MAX_PENDING) return;
    dns_ckey_t key;
    dc_mutex_lock(s->pmu);
    pending_t *p = &s->pend[slot];
    if (!p->active || p->gen != T_GEN(ticket) || ui >= s->nup || !question_matches(resp, len, &p->key) ||
        try_elsewhere(s, p, ticket_current(p, ticket), ui, resp[3] & 0xF)) {
        dc_mutex_unlock(s->pmu);
        return;
    }
    upstream_t *u = &s->up[ui];
    /* (a TCP retry of a UDP upstream says nothing about its UDP latency) */
    up_success(u, u->cfg.proto == DNS_UP_UDP ? 0 : (uint32_t)dc_time_us() - p->sent_us[ui]);
    waiter_t *ws = pend_detach(s, slot, &key);
    dc_mutex_unlock(s->pmu);
    dns_complete(s, ws, &key, resp, len, (uint8_t)ui);
}

void dns_server_fail(dns_server_t *s, uint32_t ticket) {
    unsigned slot = T_SLOT(ticket);
    if (slot >= DNS_MAX_PENDING) return;
    dc_mutex_lock(s->pmu);
    pending_t *p = &s->pend[slot];
    /* only the attempt in progress counts: an older one was already
     * counted as a timeout when the next attempt started */
    if (p->active && p->gen == T_GEN(ticket) && ticket_current(p, ticket) && p->up_idx < s->nup) {
        uint32_t now = dc_time_ms();
        if (!p->accounted) up_failure(s, &s->up[p->up_idx], false);
        p->accounted = 1;
        p->stream = 0;
        /* the next attempt at once, unless only failed upstreams are left */
        unsigned k = p->tries > 4 ? 3 : p->tries - 1u;
        p->attempt_ms = has_alternative(s, p, now) ? now : now + (RETRY_MIN_MS << k);
        if ((int32_t)(p->attempt_ms - p->deadline_ms) > 0) p->attempt_ms = p->deadline_ms;
    }
    dc_mutex_unlock(s->pmu);
}

/* retries and timeouts (upstream thread) */
static void check_timeouts(dns_server_t *s) {
    for (bool more = true; more;) {
        sendop_t ops[2];
        struct {
            waiter_t *w;
            dns_ckey_t key;
        } failed[2];
        int nops = 0, nfail = 0;
        uint32_t now = dc_time_ms();
        more = false;
        dc_mutex_lock(s->pmu);
        for (unsigned i = 0; i < DNS_MAX_PENDING && s->npend_active; i++) {
            pending_t *p = &s->pend[i];
            if (!p->active) continue;
            bool expired = (int32_t)(now - p->deadline_ms) >= 0;
            if (!expired && (int32_t)(now - p->attempt_ms) < 0) continue;
            if (nops == 2 || nfail == 2) { /* the rest in the next round */
                more = true;
                break;
            }
            if (p->tries && !p->accounted) {
                up_failure(s, &s->up[p->up_idx], true);
                p->accounted = 1;
            }
            if (!expired && pend_attempt(s, i, now, &ops[nops])) {
                nops++;
                continue;
            }
            failed[nfail].w = pend_detach(s, i, &failed[nfail].key);
            nfail++;
        }
        dc_mutex_unlock(s->pmu);
        for (int i = 0; i < nops; i++) op_run(s, &ops[i]);
        for (int i = 0; i < nfail; i++) dns_complete(s, failed[i].w, &failed[i].key, NULL, 0, 0xFF);
    }
}

/* ---- sockets ---------------------------------------------------------------------- */

static void set_rcvtimeo(int fd, uint32_t ms) {
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}
static void set_sndtimeo(int fd, uint32_t ms) {
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int open_listener(int fam, int type, const char *bind4, uint16_t port) {
    int fd = socket(fam == 4 ? AF_INET : AF_INET6, type, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_storage sa;
    dc_ip_t any;
    memset(&any, 0, sizeof(any));
    any.family = (uint8_t)fam;
    if (fam == 4 && bind4 && bind4[0]) dc_ip_parse_z(bind4, &any);
    size_t sl = dns_sockaddr_from_ip(&any, port, &sa);
    if (fam == 6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
#ifndef ESP_PLATFORM
    if (type == SOCK_DGRAM) {
        int sz = 4 << 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    }
#endif
    if (bind(fd, (struct sockaddr *)&sa, (socklen_t)sl) < 0 || (type == SOCK_STREAM && listen(fd, 16) < 0)) {
        dns_closesocket(fd);
        return -1;
    }
    set_rcvtimeo(fd, 500);
    return fd;
}

static int open_up_socket(int fam) {
    int fd = socket(fam == 4 ? AF_INET : AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_storage sa;
    dc_ip_t any;
    memset(&any, 0, sizeof(any));
    any.family = (uint8_t)fam;
    size_t sl = dns_sockaddr_from_ip(&any, 0, &sa);
    if (fam == 6) {
        int one = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    }
#ifndef ESP_PLATFORM
    int sz = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
#endif
    if (bind(fd, (struct sockaddr *)&sa, (socklen_t)sl) < 0) {
        dns_closesocket(fd);
        return -1;
    }
    return fd;
}

/* Whole buffer within the deadline (each call is also bounded by the socket
 * timeouts), so a peer sending byte by byte cannot hold a thread. */
static bool io_full(int fd, uint8_t *b, size_t n, bool wr, uint32_t deadline_ms) {
    while (n) {
        if ((int32_t)(dc_time_ms() - deadline_ms) >= 0) return false;
        int k = wr ? (int)send(fd, (const char *)b, n, MSG_NOSIGNAL) : (int)recv(fd, (char *)b, n, 0);
        if (k <= 0) {
            if (k < 0 && errno == EINTR) continue;
            return false;
        }
        b += k;
        n -= (size_t)k;
    }
    return true;
}

static int connect_timeout(const struct sockaddr_storage *sa, socklen_t sl, uint32_t ms) {
    int fd = socket(sa->ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int r = connect(fd, (const struct sockaddr *)sa, sl);
    if (r < 0 && errno != EINPROGRESS) {
        dns_closesocket(fd);
        return -1;
    }
    if (r < 0) {
        fd_set ws;
        FD_ZERO(&ws);
        FD_SET(fd, &ws);
        struct timeval tv = {(long)(ms / 1000), (long)((ms % 1000) * 1000)};
        int err = 0;
        socklen_t el = sizeof(err);
        if (select(fd + 1, NULL, &ws, NULL, &tv) <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 ||
            err) {
            dns_closesocket(fd);
            return -1;
        }
    }
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    set_rcvtimeo(fd, ms);
    set_sndtimeo(fd, ms);
    return fd;
}

/* registers the connection a thread blocks on, so dns_server_stop can wake it */
static void set_active(dns_server_t *s, int *slot, int fd) {
    dc_mutex_lock(s->tmu);
    *slot = fd;
    dc_mutex_unlock(s->tmu);
}

/* one query over a fresh TCP connection (stream worker k) */
static size_t tcp_exchange(dns_server_t *s, unsigned k, int up, const uint8_t *q, size_t qlen, uint8_t *out,
                           size_t cap) {
    struct sockaddr_storage sa;
    socklen_t sl;
    uint32_t tmo;
    dc_mutex_lock(s->pmu);
    if (up < 0 || up >= s->nup) {
        dc_mutex_unlock(s->pmu);
        return 0;
    }
    sa = s->up[up].sa;
    sl = s->up[up].salen;
    if (s->up[up].cfg.proto != DNS_UP_TCP && s->up[up].cfg.proto != DNS_UP_UDP) sl = 0;
    tmo = s->up_timeout_ms * 2;
    dc_mutex_unlock(s->pmu);
    if (!sl || !s->running) return 0;
    uint32_t deadline = dc_time_ms() + 2 * tmo;
    int fd = connect_timeout(&sa, sl, tmo);
    if (fd < 0) return 0;
    set_active(s, &s->sact[k], fd);
    uint8_t hdr[2 + DNS_MAX_NAME + 32];
    dc_wbe16(hdr, (uint16_t)qlen);
    memcpy(hdr + 2, q, qlen);
    size_t n = 0;
    uint8_t lb[2];
    if (io_full(fd, hdr, qlen + 2, true, deadline) && io_full(fd, lb, 2, false, deadline)) {
        n = dc_be16(lb);
        if (n < DNS_HDR_LEN || n > cap || !io_full(fd, out, n, false, deadline)) n = 0;
        if (n && dc_be16(out) != dc_be16(q)) n = 0;
    }
    set_active(s, &s->sact[k], -1);
    dns_closesocket(fd);
    return n;
}

static void stream_enqueue(dns_server_t *s, int up, uint32_t ticket, const uint8_t *q, size_t len) {
    sjob_t *j = (sjob_t *)dc_malloc(sizeof(sjob_t));
    if (!j) {
        dns_server_fail(s, ticket);
        return;
    }
    j->next = NULL;
    j->up = up;
    j->ticket = ticket;
    j->len = (uint16_t)len;
    memcpy(j->q, q, len);
    dc_mutex_lock(s->smu);
    if (s->sjobs >= 64) { /* overloaded */
        dc_mutex_unlock(s->smu);
        dc_free(j);
        dns_server_fail(s, ticket);
        return;
    }
    if (s->stail)
        s->stail->next = j;
    else
        s->shead = j;
    s->stail = j;
    s->sjobs++;
    dc_mutex_unlock(s->smu);
    dc_sem_give(s->ssem);
}

/* ---- threads ------------------------------------------------------------------------- */

typedef struct {
    dns_server_t *s;
    int sock;
} targ_t;

static int spawn(dns_server_t *s, dc_thread_fn fn, int sock, const char *name, uint32_t stack, int prio) {
    targ_t *a = (targ_t *)dc_malloc(sizeof(targ_t));
    if (!a) return -1;
    a->s = s;
    a->sock = sock;
    atomic_fetch_add(&s->threads, 1);
    if (dc_thread_start(fn, a, name, stack, prio, DC_CORE_ANY) != 0) {
        atomic_fetch_sub(&s->threads, 1);
        dc_free(a);
        return -1;
    }
    return 0;
}

static void udp_thread(void *arg) {
    targ_t *a = (targ_t *)arg;
    dns_server_t *s = a->s;
    int sock = a->sock;
    dc_free(a);
    uint8_t *in = (uint8_t *)dc_malloc(DNS_MSG_MAX);
    uint8_t *out = (uint8_t *)dc_malloc(DNS_MSG_MAX + 64);
    while (s->running && in && out) {
        struct sockaddr_storage sa;
        socklen_t sl = sizeof(sa);
        int n = (int)recvfrom(sock, (char *)in, DNS_MSG_MAX, 0, (struct sockaddr *)&sa, &sl);
        if (n <= 0) continue;
        qctx_t c;
        c.msg = in;
        c.len = (size_t)n;
        dns_ip_from_sockaddr((struct sockaddr *)&sa, &c.peer.ip, &c.peer.port);
        c.peer.transport = DNS_TR_UDP;
        c.sock = sock;
        c.sa = (struct sockaddr *)&sa;
        c.salen = sl;
        c.sync = NULL;
        c.sync_ticket = 0;
        c.t0 = dc_time_us();
        c.out = out;
        c.cap = DNS_MSG_MAX + 64;
        if (dns_handle(s, &c) == H_DONE && c.out_len)
            sendto(sock, (const char *)out, c.out_len, 0, (struct sockaddr *)&sa, sl);
    }
    dc_free(in);
    dc_free(out);
    atomic_fetch_sub(&s->threads, 1);
}

static void up_thread(void *arg) {
    targ_t *a = (targ_t *)arg;
    dns_server_t *s = a->s;
    dc_free(a);
    uint8_t *buf = (uint8_t *)dc_malloc(DNS_MSG_MAX);
    uint32_t last_check = 0;
    while (s->running && buf) {
        fd_set rs;
        FD_ZERO(&rs);
        int maxfd = -1;
        for (int f = 0; f < 2; f++)
            for (int k = 0; k < DNS_UP_SOCKS; k++) {
                int fd = s->up_sock[f][k];
                if (fd < 0) continue;
                FD_SET(fd, &rs);
                if (fd > maxfd) maxfd = fd;
            }
        struct timeval tv = {0, TICK_MS * 1000};
        int n = maxfd >= 0 ? select(maxfd + 1, &rs, NULL, NULL, &tv) : (dc_sleep_ms(TICK_MS), 0);
        if (n > 0) {
            for (int f = 0; f < 2; f++)
                for (int k = 0; k < DNS_UP_SOCKS; k++) {
                    int fd = s->up_sock[f][k];
                    if (fd < 0 || !FD_ISSET(fd, &rs)) continue;
                    for (int burst = 0; burst < 64; burst++) {
                        struct sockaddr_storage sa;
                        socklen_t sl = sizeof(sa);
                        int r = (int)recvfrom(fd, (char *)buf, DNS_MSG_MAX, MSG_DONTWAIT, (struct sockaddr *)&sa, &sl);
                        if (r <= 0) break;
                        handle_up_udp(s, buf, (size_t)r, (struct sockaddr *)&sa);
                    }
                }
        }
        uint32_t now = dc_time_ms();
        if (now - last_check >= TICK_MS / 2) {
            last_check = now;
            check_timeouts(s);
        }
    }
    dc_free(buf);
    atomic_fetch_sub(&s->threads, 1);
}

static void stream_thread(void *arg) {
    targ_t *a = (targ_t *)arg;
    dns_server_t *s = a->s;
    unsigned k = (unsigned)a->sock; /* (worker index) */
    dc_free(a);
    uint8_t *buf = (uint8_t *)dc_malloc(DNS_TCP_MAX);
    while (s->running && buf) {
        dc_mutex_lock(s->smu);
        sjob_t *j = s->shead;
        if (j) {
            s->shead = j->next;
            if (!s->shead) s->stail = NULL;
            s->sjobs--;
        }
        bool more = s->shead != NULL;
        dc_mutex_unlock(s->smu);
        if (!j) {
            dc_sem_take(s->ssem, 200);
            continue;
        }
        if (more) dc_sem_give(s->ssem); /* wake another worker */
        size_t n = tcp_exchange(s, k, j->up, j->q, j->len, buf, DNS_TCP_MAX);
        if (n)
            dns_server_deliver(s, j->ticket, buf, n);
        else
            dns_server_fail(s, j->ticket);
        dc_free(j);
    }
    dc_free(buf);
    atomic_fetch_sub(&s->threads, 1);
}

static void tcp_accept_thread(void *arg) {
    targ_t *a = (targ_t *)arg;
    dns_server_t *s = a->s;
    dc_free(a);
    while (s->running) {
        fd_set rs;
        FD_ZERO(&rs);
        int maxfd = -1;
        for (int f = 0; f < 2; f++)
            if (s->tcp_sock[f] >= 0) {
                FD_SET(s->tcp_sock[f], &rs);
                if (s->tcp_sock[f] > maxfd) maxfd = s->tcp_sock[f];
            }
        if (maxfd < 0) break;
        struct timeval tv = {0, 500000};
        if (select(maxfd + 1, &rs, NULL, NULL, &tv) <= 0) continue;
        for (int f = 0; f < 2; f++) {
            if (s->tcp_sock[f] < 0 || !FD_ISSET(s->tcp_sock[f], &rs)) continue;
            int c = accept(s->tcp_sock[f], NULL, NULL);
            if (c < 0) continue;
            dc_mutex_lock(s->tmu);
            if (s->tq_len < DNS_TCPQ) {
                s->tconn[(s->tq_head + s->tq_len) % DNS_TCPQ] = c;
                s->tq_len++;
                c = -1;
            }
            dc_mutex_unlock(s->tmu);
            if (c >= 0)
                dns_closesocket(c); /* overloaded */
            else
                dc_sem_give(s->tsem);
        }
    }
    atomic_fetch_sub(&s->threads, 1);
}

#ifdef ESP_PLATFORM
#define TCP_IDLE_MS 5000
#else
#define TCP_IDLE_MS 10000
#endif
#define TCP_IO_MS 5000 /* one message in or out */

/* one client connection: queries are answered in order (RFC 7766 allows
 * pipelining; answers are sequential here).  The connection is closed when
 * idle, or after a fair share of queries while other connections wait. */
static void serve_tcp(dns_server_t *s, unsigned k, int fd, uint8_t *in, uint8_t *out) {
    struct sockaddr_storage sa;
    socklen_t sl = sizeof(sa);
    dns_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    if (getpeername(fd, (struct sockaddr *)&sa, &sl) == 0) dns_ip_from_sockaddr((struct sockaddr *)&sa, &peer.ip, &peer.port);
    peer.transport = DNS_TR_TCP;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    set_rcvtimeo(fd, TCP_IDLE_MS);
    set_sndtimeo(fd, TCP_IO_MS);
    set_active(s, &s->tact[k], fd);
    for (unsigned nq = 0; s->running; nq++) {
        if (nq >= 64 && (nq & 15) == 0) {
            dc_mutex_lock(s->tmu);
            bool waiting = s->tq_len > 0;
            dc_mutex_unlock(s->tmu);
            if (waiting) break;
        }
        uint8_t lb[2];
        if (!io_full(fd, lb, 2, false, dc_time_ms() + TCP_IDLE_MS)) break;
        size_t n = dc_be16(lb);
        if (n < DNS_HDR_LEN || n > DNS_MSG_MAX || !io_full(fd, in, n, false, dc_time_ms() + TCP_IO_MS)) break;
        size_t r = dns_server_query(s, &peer, in, n, out + 2, DNS_TCP_MAX + 64);
        if (!r) break;
        dc_wbe16(out, (uint16_t)r);
        if (!io_full(fd, out, r + 2, true, dc_time_ms() + TCP_IO_MS)) break;
    }
    set_active(s, &s->tact[k], -1);
    dns_closesocket(fd);
}

static void tcp_worker_thread(void *arg) {
    targ_t *a = (targ_t *)arg;
    dns_server_t *s = a->s;
    unsigned k = (unsigned)a->sock; /* (worker index) */
    dc_free(a);
    uint8_t *in = (uint8_t *)dc_malloc(DNS_MSG_MAX);
    uint8_t *out = (uint8_t *)dc_malloc(DNS_TCP_MAX + 66);
    while (s->running && in && out) {
        int fd = -1;
        dc_mutex_lock(s->tmu);
        if (s->tq_len) {
            fd = s->tconn[s->tq_head];
            s->tq_head = (s->tq_head + 1) % DNS_TCPQ;
            s->tq_len--;
        }
        bool more = s->tq_len > 0;
        dc_mutex_unlock(s->tmu);
        if (fd < 0) {
            dc_sem_take(s->tsem, 200);
            continue;
        }
        if (more) dc_sem_give(s->tsem); /* wake another worker */
        serve_tcp(s, k, fd, in, out);
    }
    dc_free(in);
    dc_free(out);
    atomic_fetch_sub(&s->threads, 1);
}

/* ---- synchronous API -------------------------------------------------------------------- */

size_t dns_server_query(dns_server_t *s, const dns_peer_t *peer, const uint8_t *q, size_t qlen, uint8_t *out,
                        size_t cap) {
    if (cap < DNS_MSG_MAX + 64) return 0;
    dns_sync_t *y = NULL;
    uint32_t ticket = 0;
    dc_mutex_lock(s->pmu);
    for (unsigned i = 0; i < DNS_SYNC_SLOTS; i++)
        if (!s->sync[i].busy && s->sync[i].sem) {
            y = &s->sync[i];
            y->busy = true;
            ticket = ++y->ticket;
            y->buf = out;
            y->cap = cap;
            y->len = 0;
            break;
        }
    dc_mutex_unlock(s->pmu);
    if (!y) return 0;
    qctx_t c;
    c.msg = q;
    c.len = qlen;
    c.peer = *peer;
    c.sock = -1;
    c.sa = NULL;
    c.salen = 0;
    c.sync = y;
    c.sync_ticket = ticket;
    c.t0 = dc_time_us();
    c.out = out;
    c.cap = cap;
    size_t res = 0;
    int r = dns_handle(s, &c);
    if (r == H_DONE) {
        res = c.out_len;
    } else if (r == H_PENDING) {
        bool got = dc_sem_take(y->sem, s->query_timeout_ms + 1000);
        dc_mutex_lock(s->pmu);
        if (y->ticket == ticket) { /* not delivered: cancel */
            y->ticket++;
            res = 0;
        } else {
            res = y->len;
            if (!got) dc_sem_take(y->sem, 0);
        }
        dc_mutex_unlock(s->pmu);
        if (!res) {
            dns_query_t pq;
            if (dns_parse_query(q, qlen, &pq) == DNS_PARSE_OK)
                res = dns_make_error(out, cap, q, qlen, &pq, DNS_RC_SERVFAIL);
        }
    }
    dc_mutex_lock(s->pmu);
    y->busy = false;
    dc_mutex_unlock(s->pmu);
    return res;
}

/* ---- lifecycle ------------------------------------------------------------------------------ */

static void up_apply(dns_server_t *s, const dns_config_t *cfg) {
    upstream_t *old = (upstream_t *)dc_malloc(sizeof(upstream_t) * DNS_MAX_UPSTREAMS);
    unsigned nold = s->nup;
    if (old) memcpy(old, s->up, sizeof(upstream_t) * DNS_MAX_UPSTREAMS);
    unsigned n = cfg->nup > DNS_MAX_UPSTREAMS ? DNS_MAX_UPSTREAMS : cfg->nup;
    for (unsigned i = 0; i < n; i++) {
        upstream_t *u = &s->up[i];
        memset(u, 0, sizeof(*u));
        for (unsigned k = 0; old && k < nold; k++)
            if (strcmp(old[k].cfg.text, cfg->up[i].text) == 0) {
                *u = old[k];
                break;
            }
        u->cfg = cfg->up[i];
        u->salen = (socklen_t)dns_sockaddr_from_ip(&u->cfg.ip, u->cfg.port, &u->sa);
    }
    s->nup = (uint8_t)n;
    s->strategy = cfg->strategy;
    s->up_timeout_ms = cfg->up_timeout_ms ? cfg->up_timeout_ms : 1500;
    s->query_timeout_ms = cfg->query_timeout_ms ? cfg->query_timeout_ms : 4000;
    if (s->up_timeout_ms > s->query_timeout_ms) s->up_timeout_ms = s->query_timeout_ms;
    dc_free(old);
}

static dns_cache_cfg_t cache_cfg(const dns_config_t *c) {
    dns_cache_cfg_t cc;
    cc.l2_bytes = c->cache_bytes;
    cc.l1_entries = c->cache_l1;
    cc.stale_max_s = c->optimistic ? (c->optimistic_max_age ? c->optimistic_max_age : 43200) : 0;
    return cc;
}

dns_server_t *dns_server_new(const dns_config_t *cfg) {
    dns_server_t *s = (dns_server_t *)dc_calloc(1, sizeof(dns_server_t));
    if (!s) return NULL;
    for (int f = 0; f < 2; f++) {
        s->udp_sock[f] = s->tcp_sock[f] = -1;
        for (int k = 0; k < DNS_UP_SOCKS; k++) s->up_sock[f][k] = -1;
    }
    for (int k = 0; k < DNS_MAX_TCPW; k++) s->tact[k] = -1;
    for (int k = 0; k < DNS_STREAMS; k++) s->sact[k] = -1;
    s->vmu = dc_mutex_new();
    s->pmu = dc_mutex_new();
    s->smu = dc_mutex_new();
    s->tmu = dc_mutex_new();
    s->rlmu = dc_mutex_new();
    s->qmu = dc_mutex_new();
    s->ssem = dc_sem_new();
    s->tsem = dc_sem_new();
    s->view = (view_t *)dc_calloc(1, sizeof(view_t));
    if (s->view) atomic_store(&s->view->refs, 1);
    s->pend = (pending_t *)dc_calloc_ext(DNS_MAX_PENDING, sizeof(pending_t));
    s->wpool = (waiter_t *)dc_calloc_ext(DNS_MAX_WAITERS, sizeof(waiter_t));
    s->khead = (int16_t *)dc_malloc_ext(DNS_MAX_PENDING * sizeof(int16_t));
    s->idmap = (uint16_t *)dc_calloc_ext(65536, sizeof(uint16_t));
    s->pfree = (uint16_t *)dc_malloc_ext(DNS_MAX_PENDING * sizeof(uint16_t));
    dns_cache_cfg_t cc = cache_cfg(cfg);
    s->cache = dns_cache_new(&cc); /* (always exists; size 0 = off) */
    bool ok = s->vmu && s->pmu && s->smu && s->tmu && s->rlmu && s->qmu && s->ssem && s->tsem && s->view &&
              s->pend && s->wpool && s->khead && s->idmap && s->pfree && s->cache;
    for (unsigned i = 0; ok && i < DNS_SYNC_SLOTS; i++) ok = (s->sync[i].sem = dc_sem_new()) != NULL;
    if (!ok) {
        dns_server_stop(s);
        return NULL;
    }
    for (unsigned i = 0; i < DNS_MAX_PENDING; i++) {
        s->khead[i] = -1;
        s->pfree[i] = (uint16_t)(DNS_MAX_PENDING - 1 - i);
    }
    s->npfree = DNS_MAX_PENDING;
    for (unsigned i = 0; i < DNS_MAX_WAITERS; i++) {
        s->wpool[i].next = s->wfree;
        s->wfree = &s->wpool[i];
    }
    s->view->cfg = *cfg;
    if (cfg->qlog_entries) {
        s->qlog = (dns_qlog_t *)dc_calloc_ext(cfg->qlog_entries, sizeof(dns_qlog_t));
        if (s->qlog) s->qlog_n = cfg->qlog_entries;
    }
    up_apply(s, cfg);
    return s;
}

int dns_server_start(dns_server_t *s) {
    const dns_config_t *cfg = &s->view->cfg;
    if (cfg->listen_v4) {
        s->udp_sock[0] = open_listener(4, SOCK_DGRAM, cfg->bind_v4, cfg->port);
        if (s->udp_sock[0] < 0) {
            DC_LOGE(TAG, "cannot bind UDP port %u (IPv4)", cfg->port);
            return -1;
        }
        if (cfg->tcp) s->tcp_sock[0] = open_listener(4, SOCK_STREAM, cfg->bind_v4, cfg->port);
    }
    if (cfg->listen_v6) {
        s->udp_sock[1] = open_listener(6, SOCK_DGRAM, NULL, cfg->port);
        if (s->udp_sock[1] < 0) DC_LOGW(TAG, "IPv6 UDP listener unavailable");
        if (cfg->tcp && s->udp_sock[1] >= 0) s->tcp_sock[1] = open_listener(6, SOCK_STREAM, NULL, cfg->port);
    }
    for (int k = 0; k < DNS_UP_SOCKS; k++) {
        s->up_sock[0][k] = open_up_socket(4);
        s->up_sock[1][k] = open_up_socket(6);
    }
    if (s->up_sock[0][0] < 0) {
        DC_LOGE(TAG, "cannot open upstream sockets");
        return -1;
    }
    s->running = true;
    int err = 0;
    unsigned nw = cfg->udp_workers ? cfg->udp_workers : 1;
    for (int f = 0; f < 2; f++)
        for (unsigned i = 0; i < nw && s->udp_sock[f] >= 0; i++)
            err |= spawn(s, udp_thread, s->udp_sock[f], f ? "dns-rx6" : "dns-rx4", STACK_RX, DC_PRIO_HIGH);
    err |= spawn(s, up_thread, -1, "dns-up", STACK_UP, DC_PRIO_HIGH);
    for (int i = 0; i < DNS_STREAMS; i++) err |= spawn(s, stream_thread, i, "dns-stream", STACK_STREAM, DC_PRIO_MID);
    if (s->tcp_sock[0] >= 0 || s->tcp_sock[1] >= 0) {
        err |= spawn(s, tcp_accept_thread, -1, "dns-tcpa", 4096 + STACK_STREAM / 4, DC_PRIO_MID);
        unsigned nt = cfg->tcp_workers ? cfg->tcp_workers : 1;
        if (nt > DNS_MAX_TCPW) nt = DNS_MAX_TCPW;
        for (unsigned i = 0; i < nt; i++) err |= spawn(s, tcp_worker_thread, (int)i, "dns-tcp", STACK_TCP, DC_PRIO_MID);
    }
    if (err) {
        DC_LOGE(TAG, "cannot start threads");
        return -1;
    }
    DC_LOGI(TAG, "listening on port %u (udp%s%s), %u upstream(s)", cfg->port, s->tcp_sock[0] >= 0 ? "+tcp" : "",
            s->udp_sock[1] >= 0 ? ", ipv6" : "", s->nup);
    return 0;
}

/* completes everything in flight with SERVFAIL (synchronous callers too) */
static void fail_pending(dns_server_t *s) {
    for (unsigned i = 0; i < DNS_MAX_PENDING; i++) {
        dns_ckey_t key;
        dc_mutex_lock(s->pmu);
        waiter_t *ws = s->pend[i].active ? pend_detach(s, i, &key) : NULL;
        dc_mutex_unlock(s->pmu);
        if (ws) dns_complete(s, ws, &key, NULL, 0, 0xFF);
    }
}

void dns_server_stop(dns_server_t *s) {
    if (!s) return;
    s->running = false;
    if (s->pend && s->pmu && s->khead && s->idmap && s->pfree) {
        /* wake every thread: pending queries fail, blocked connections are
         * shut down; the sockets stay open until all threads are gone */
        for (int i = 0; atomic_load(&s->threads) > 0; i++) {
            if (i == 600) { /* 30 s: something is stuck, freeing would be worse */
                DC_LOGE(TAG, "server threads do not stop: not freed");
                return;
            }
            fail_pending(s);
            dc_mutex_lock(s->tmu);
            for (int k = 0; k < DNS_MAX_TCPW; k++)
                if (s->tact[k] >= 0) shutdown(s->tact[k], SHUT_RDWR);
            for (int k = 0; k < DNS_STREAMS; k++)
                if (s->sact[k] >= 0) shutdown(s->sact[k], SHUT_RDWR);
            dc_mutex_unlock(s->tmu);
            dc_sem_give(s->ssem);
            dc_sem_give(s->tsem);
            dc_sleep_ms(50);
        }
        fail_pending(s);
    }
    for (int f = 0; f < 2; f++) {
        if (s->udp_sock[f] >= 0) dns_closesocket(s->udp_sock[f]);
        if (s->tcp_sock[f] >= 0) dns_closesocket(s->tcp_sock[f]);
        for (int k = 0; k < DNS_UP_SOCKS; k++)
            if (s->up_sock[f][k] >= 0) dns_closesocket(s->up_sock[f][k]);
    }
    while (s->shead) {
        sjob_t *j = s->shead;
        s->shead = j->next;
        dc_free(j);
    }
    while (s->tq_len) {
        dns_closesocket(s->tconn[s->tq_head]);
        s->tq_head = (s->tq_head + 1) % DNS_TCPQ;
        s->tq_len--;
    }
    for (unsigned i = 0; i < DNS_SYNC_SLOTS; i++) dc_sem_free(s->sync[i].sem);
    dns_view_put(s->view);
    dns_cache_free(s->cache);
    dc_free(s->pend);
    dc_free(s->wpool);
    dc_free(s->khead);
    dc_free(s->idmap);
    dc_free(s->pfree);
    dc_free(s->qlog);
    dc_mutex_free(s->vmu);
    dc_mutex_free(s->pmu);
    dc_mutex_free(s->smu);
    dc_mutex_free(s->tmu);
    dc_mutex_free(s->rlmu);
    dc_mutex_free(s->qmu);
    dc_sem_free(s->ssem);
    dc_sem_free(s->tsem);
    dc_free(s);
}

int dns_server_reconfigure(dns_server_t *s, const dns_config_t *cfg) {
    dc_mutex_lock(s->vmu);
    view_t *nv = view_clone(s->view);
    if (!nv) {
        dc_mutex_unlock(s->vmu);
        return -1;
    }
    dns_config_t *old = &s->view->cfg;
    bool cache_changed = old->cache_bytes != cfg->cache_bytes || old->cache_l1 != cfg->cache_l1 ||
                         old->optimistic != cfg->optimistic || old->optimistic_max_age != cfg->optimistic_max_age ||
                         old->cache_min_ttl != cfg->cache_min_ttl || old->cache_max_ttl != cfg->cache_max_ttl;
    /* listeners cannot change without a restart (write directly to nv->cfg to avoid stack copy) */
    nv->cfg = *cfg;
    nv->cfg.port = old->port;
    nv->cfg.listen_v4 = old->listen_v4;
    nv->cfg.listen_v6 = old->listen_v6;
    nv->cfg.tcp = old->tcp;
    nv->cfg.udp_workers = old->udp_workers;
    nv->cfg.tcp_workers = old->tcp_workers;
    memcpy(nv->cfg.bind_v4, old->bind_v4, sizeof(nv->cfg.bind_v4));
    nv->cfg.qlog_entries = old->qlog_entries;
    view_swap(s, nv);
    dc_mutex_unlock(s->vmu);
    dc_mutex_lock(s->pmu);
    up_apply(s, cfg);
    dc_mutex_unlock(s->pmu);
    if (cache_changed) {
        dns_cache_cfg_t cc = cache_cfg(cfg);
        dns_cache_reconfigure(s->cache, &cc);
    }
    return 0;
}

void dns_server_get_config(dns_server_t *s, dns_config_t *out) {
    dc_mutex_lock(s->vmu);
    *out = s->view->cfg;
    dc_mutex_unlock(s->vmu);
}

void dns_server_set_filters(dns_server_t *s, fl_set_t *set) {
    static uint32_t counter;
    dc_mutex_lock(s->vmu);
    view_t *nv = view_clone(s->view);
    if (nv) {
        fl_set_unref(nv->filters);
        if (set) fl_set_ref(set);
        nv->filters = set;
        nv->fgen = ++counter;
        view_swap(s, nv);
    }
    dc_mutex_unlock(s->vmu);
}

fl_set_t *dns_server_get_filters(dns_server_t *s) {
    dc_mutex_lock(s->vmu);
    fl_set_t *f = s->view->filters;
    if (f) fl_set_ref(f);
    dc_mutex_unlock(s->vmu);
    return f;
}

void dns_server_set_local(dns_server_t *s, dns_local_t *local) {
    lref_t *lr = NULL;
    if (local) {
        lr = dns_local_seal(local) == 0 ? (lref_t *)dc_malloc(sizeof(lref_t)) : NULL;
        if (!lr) { /* (out of memory: the current records stay) */
            dns_local_free(local);
            return;
        }
        atomic_store(&lr->refs, 1);
        lr->l = local;
    }
    dc_mutex_lock(s->vmu);
    view_t *nv = view_clone(s->view);
    if (nv) {
        lref_put(nv->local);
        nv->local = lr;
        view_swap(s, nv);
    } else {
        lref_put(lr);
    }
    dc_mutex_unlock(s->vmu);
}

void dns_server_set_captive(dns_server_t *s, const dc_ip_t *ip, const dc_prefix_t *net) {
    dc_mutex_lock(s->vmu);
    bool on = ip && net;
    if (on != s->view->captive || (on && (!dc_ip_equal(ip, &s->view->captive_ip) ||
                                          !dc_ip_equal(&net->ip, &s->view->captive_net.ip) ||
                                          net->bits != s->view->captive_net.bits))) {
        view_t *nv = view_clone(s->view);
        if (nv) {
            nv->captive = on;
            if (on) {
                nv->captive_ip = *ip;
                nv->captive_net = *net;
            }
            view_swap(s, nv);
        }
    }
    dc_mutex_unlock(s->vmu);
}

void dns_server_cache_flush(dns_server_t *s) { dns_cache_flush(s->cache); }

void dns_server_cache_build_mode(dns_server_t *s, bool building) {
    if (s) dns_cache_set_build_mode(s->cache, building);
}

void dns_server_set_transport(dns_server_t *s, dns_up_proto_t proto, const dns_up_ops_t *ops) {
    dc_mutex_lock(s->pmu);
    if ((unsigned)proto < 4) {
        if (ops)
            s->ops[proto] = *ops;
        else
            memset(&s->ops[proto], 0, sizeof(s->ops[proto]));
    }
    dc_mutex_unlock(s->pmu);
}

/* counters are updated with relaxed atomics: read and reset them the same way */
#define DNS_COUNTERS(X)                                                                                      \
    X(queries) X(udp) X(tcp) X(dot) X(doh) X(blocked) X(rewritten) X(local) X(allowed) X(cached) X(forwarded) \
    X(failed) X(refused) X(dropped) X(ratelimited) X(malformed) X(truncated) X(resp_blocked) X(stale_served)  \
    X(coalesced) X(qtype_a) X(qtype_aaaa) X(qtype_https) X(qtype_other)

static void hist_copy(dns_hist_t *d, dns_hist_t *h, bool reset) {
    d->count = reset ? __atomic_exchange_n(&h->count, 0, __ATOMIC_RELAXED) : __atomic_load_n(&h->count, __ATOMIC_RELAXED);
    d->sum_us = reset ? __atomic_exchange_n(&h->sum_us, 0, __ATOMIC_RELAXED) : __atomic_load_n(&h->sum_us, __ATOMIC_RELAXED);
    for (unsigned i = 0; i < DNS_HIST_BUCKETS; i++)
        d->b[i] = reset ? __atomic_exchange_n(&h->b[i], 0, __ATOMIC_RELAXED) : __atomic_load_n(&h->b[i], __ATOMIC_RELAXED);
}

void dns_server_get_stats(dns_server_t *s, dns_stats_t *st) {
    memset(st, 0, sizeof(*st));
#define LOAD(f) st->f = __atomic_load_n(&s->st.f, __ATOMIC_RELAXED);
    DNS_COUNTERS(LOAD)
#undef LOAD
    hist_copy(&st->local_us, &s->st.local_us, false);
    hist_copy(&st->cached_us, &s->st.cached_us, false);
    hist_copy(&st->forward_us, &s->st.forward_us, false);
    dns_cache_get_stats(s->cache, &st->cache);
    uint32_t now = dc_time_ms();
    dc_mutex_lock(s->pmu);
    st->nup = s->nup;
    for (unsigned i = 0; i < s->nup; i++) {
        const upstream_t *u = &s->up[i];
        dc_strlcpy(st->up[i].text, u->cfg.text, sizeof(st->up[i].text));
        st->up[i].sent = u->sent;
        st->up[i].ok = u->ok;
        st->up[i].timeouts = u->timeouts;
        st->up[i].errors = u->errors;
        st->up[i].rtt_us = u->srtt_us;
        st->up[i].healthy = up_usable(u, now);
    }
    st->pending = s->npend_active;
    dc_mutex_unlock(s->pmu);
    dc_mutex_lock(s->vmu);
    st->filter_generation = s->view->filters ? fl_set_generation(s->view->filters) : 0;
    dc_mutex_unlock(s->vmu);
}

void dns_server_reset_stats(dns_server_t *s) {
#define CLEAR(f) __atomic_store_n(&s->st.f, 0, __ATOMIC_RELAXED);
    DNS_COUNTERS(CLEAR)
#undef CLEAR
    dns_hist_t tmp;
    hist_copy(&tmp, &s->st.local_us, true);
    hist_copy(&tmp, &s->st.cached_us, true);
    hist_copy(&tmp, &s->st.forward_us, true);
    dc_mutex_lock(s->pmu);
    for (unsigned i = 0; i < s->nup; i++) {
        upstream_t *u = &s->up[i];
        u->sent = u->ok = u->timeouts = u->errors = 0;
    }
    dc_mutex_unlock(s->pmu);
}
