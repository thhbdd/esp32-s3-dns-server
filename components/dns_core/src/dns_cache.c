/* dns_cache.c - two level response cache (see dns_cache.h). */
#include "dns_cache.h"

#include <string.h>

#include "dc_util.h"

#define MAX_MSG 4096
#define L1_MSG_MAX 512
#define L1_KEY_MAX 80
#define L1_TTLS 16
#define NO_WRAP 0xFFFFFFFFu
#define DEAD 0xFFFFFFFFu

typedef struct {
    uint32_t hash;
    uint32_t stored, expire;
    uint32_t slot; /* index slot, DEAD once removed from the index */
    uint16_t total;
    uint16_t msg_len;
    uint16_t key_len;
    uint8_t nttl; /* 0xFF: walk the message */
    uint8_t rcode;
    uint16_t an_off, an, ns, ar;
    uint8_t memo;
    uint8_t pad[3];
    uint32_t memo_gen, memo_fp;
} ent_t;

typedef struct {
    uint32_t hash;
    uint32_t pos1; /* entry offset + 1, 0 = empty */
} slot_t;

typedef struct {
    bool valid;
    uint8_t klen;
    uint8_t nttl;
    uint8_t rcode;
    uint8_t memo;
    uint16_t msg_len;
    uint32_t hash, stored, expire;
    uint32_t memo_gen, memo_fp;
    uint16_t ttl_off[L1_TTLS];
    uint8_t key[L1_KEY_MAX];
    uint8_t msg[L1_MSG_MAX];
} l1_t;

struct dns_cache {
    dc_mutex_t *mu;
    uint8_t *ring;
    uint32_t size, head, tail, wrap_end, count, used;
    slot_t *idx;
    uint32_t mask;
    l1_t *l1;
    unsigned nl1;
    uint32_t stale_max;
    dns_cache_cfg_t wanted; /* most recent live configuration */
    bool build_mode;
    dns_cache_stats_t st;
};

static size_t key_ser(const dns_ckey_t *k, uint8_t *out) {
    memcpy(out, k->name, k->name_len);
    size_t o = k->name_len;
    dc_wbe16(out + o, k->qtype);
    dc_wbe16(out + o + 2, k->qclass);
    out[o + 4] = k->flags;
    return o + 5;
}

uint32_t dns_ckey_hash(const dns_ckey_t *k) {
    uint8_t b[DNS_MAX_NAME + 8];
    size_t n = key_ser(k, b);
    uint32_t h = dc_fmix32(dc_fnv32(b, n));
    return h ? h : 1;
}

/* (Re)allocates ring, index and L1 for the configuration, emptying the
 * cache.  Size 0 (or no memory even for the minimum) leaves it off. */
static void cache_alloc(dns_cache_t *c, const dns_cache_cfg_t *cfg) {
    uint32_t size = cfg->l2_bytes ? (uint32_t)(cfg->l2_bytes & ~7u) : 0;
    if (size && size < 16384) size = 16384;
    unsigned nl1 = size ? cfg->l1_entries : 0; /* (L1 is filled from L2) */
    if (nl1 & (nl1 - 1)) nl1 = 16;
    if (size != c->size || !c->ring) {
        /* release first: the old and the new ring may not fit in PSRAM together */
        dc_free(c->ring);
        dc_free(c->idx);
        c->ring = NULL;
        c->idx = NULL;
        while (size) {
            uint32_t nslots = 1024;
            while (nslots < size / 64) nslots <<= 1;
            c->ring = (uint8_t *)dc_malloc_ext(size);
            c->idx = (slot_t *)dc_calloc_ext(nslots, sizeof(slot_t));
            c->mask = nslots - 1;
            if (c->ring && c->idx) break;
            dc_free(c->ring);
            dc_free(c->idx);
            c->ring = NULL;
            c->idx = NULL;
            size = size > 16384 ? 16384 : 0; /* then the minimum, then off */
        }
        c->size = size;
    } else {
        memset(c->idx, 0, (c->mask + 1) * sizeof(slot_t));
    }
    if (!c->ring) nl1 = 0;
    if (nl1 != c->nl1) {
        dc_free(c->l1);
        c->l1 = NULL;
        c->nl1 = nl1;
        if (nl1) {
            c->l1 = (l1_t *)dc_malloc_int(nl1 * sizeof(l1_t));
            if (!c->l1) c->l1 = (l1_t *)dc_malloc(nl1 * sizeof(l1_t));
            if (!c->l1) c->nl1 = 0;
        }
    }
    if (c->l1) memset(c->l1, 0, c->nl1 * sizeof(l1_t));
    c->stale_max = cfg->stale_max_s;
    c->head = c->tail = c->count = c->used = 0;
    c->wrap_end = NO_WRAP;
    c->st.entries = 0;
    c->st.bytes_total = c->size;
}

dns_cache_t *dns_cache_new(const dns_cache_cfg_t *cfg) {
    dns_cache_t *c = (dns_cache_t *)dc_calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->mu = dc_mutex_new();
    if (!c->mu) {
        dc_free(c);
        return NULL;
    }
    c->wanted = *cfg;
    cache_alloc(c, cfg);
    return c;
}

void dns_cache_free(dns_cache_t *c) {
    if (!c) return;
    dc_free(c->ring);
    dc_free(c->idx);
    dc_free(c->l1);
    dc_mutex_free(c->mu);
    dc_free(c);
}

static inline ent_t *ent_at(dns_cache_t *c, uint32_t pos) { return (ent_t *)(c->ring + pos); }

static void idx_delete(dns_cache_t *c, uint32_t i) {
    uint32_t j = i;
    for (;;) {
        j = (j + 1) & c->mask;
        if (!c->idx[j].pos1) break;
        uint32_t k = c->idx[j].hash & c->mask;
        bool stays = (i <= j) ? (i < k && k <= j) : (i < k || k <= j);
        if (stays) continue;
        c->idx[i] = c->idx[j];
        ent_at(c, c->idx[i].pos1 - 1)->slot = i;
        i = j;
    }
    c->idx[i].pos1 = 0;
    c->idx[i].hash = 0;
}

static void ent_kill(dns_cache_t *c, ent_t *e) {
    if (e->slot != DEAD) {
        idx_delete(c, e->slot);
        e->slot = DEAD;
        c->st.entries--;
    }
}

static void evict_tail(dns_cache_t *c) {
    ent_t *e = ent_at(c, c->tail);
    ent_kill(c, e);
    c->used -= e->total;
    c->tail += e->total;
    c->count--;
    c->st.evictions++;
    if (c->wrap_end != NO_WRAP && c->tail == c->wrap_end) {
        c->tail = 0;
        c->wrap_end = NO_WRAP;
    }
    if (!c->count) {
        c->head = c->tail = 0;
        c->wrap_end = NO_WRAP;
    }
}

static int32_t ring_alloc(dns_cache_t *c, uint32_t s) {
    if (s > c->size) return -1;
    for (;;) {
        if (!c->count) {
            c->head = c->tail = 0;
            c->wrap_end = NO_WRAP;
        }
        if (c->wrap_end == NO_WRAP) {
            if (c->size - c->head >= s) {
                uint32_t p = c->head;
                c->head += s;
                return (int32_t)p;
            }
            c->wrap_end = c->head;
            c->head = 0;
            continue;
        }
        if (c->tail - c->head >= s) {
            uint32_t p = c->head;
            c->head += s;
            return (int32_t)p;
        }
        evict_tail(c);
    }
}

static int32_t idx_find(dns_cache_t *c, uint32_t h, const uint8_t *key, size_t klen) {
    uint32_t i = h & c->mask;
    for (;;) {
        const slot_t *s = &c->idx[i];
        if (!s->pos1) return -1;
        if (s->hash == h) {
            ent_t *e = ent_at(c, s->pos1 - 1);
            if (e->key_len == klen && memcmp((uint8_t *)(e + 1), key, klen) == 0) return (int32_t)i;
        }
        i = (i + 1) & c->mask;
    }
}

static void fill_resp(dns_resp_t *r, uint16_t an_off, uint16_t an, uint16_t ns, uint16_t ar, uint8_t nttl,
                      const uint16_t *offs) {
    r->an_off = an_off;
    r->ancount = an;
    r->nscount = ns;
    r->arcount = ar;
    if (nttl == 0xFF) {
        r->ttl_overflow = true;
        r->nttl = 0;
    } else {
        r->ttl_overflow = false;
        r->nttl = nttl;
        memcpy(r->ttl_off, offs, nttl * sizeof(uint16_t));
    }
}

int dns_cache_get(dns_cache_t *c, const dns_ckey_t *k, uint8_t *out, size_t cap, uint32_t now,
                  uint32_t stale_ttl, dns_cache_hit_t *hit) {
    uint8_t key[DNS_MAX_NAME + 8];
    size_t klen = key_ser(k, key);
    uint32_t h = dc_fmix32(dc_fnv32(key, klen));
    if (!h) h = 1;
    dns_resp_t r;
    memset(hit, 0, sizeof(*hit));
    dc_mutex_lock(c->mu);
    /* L1 (only used together with L2) */
    if (c->nl1 && klen <= L1_KEY_MAX) {
        l1_t *e = &c->l1[h & (c->nl1 - 1)];
        if (e->valid && e->hash == h && e->klen == klen && now < e->expire && e->msg_len <= cap &&
            memcmp(e->key, key, klen) == 0) {
            memcpy(out, e->msg, e->msg_len);
            r.ttl_overflow = false;
            r.nttl = e->nttl;
            memcpy(r.ttl_off, e->ttl_off, e->nttl * sizeof(uint16_t));
            dns_adjust_ttls(out, e->msg_len, &r, now - e->stored, 0, 0);
            hit->len = e->msg_len;
            hit->l1 = true;
            hit->rcode = e->rcode;
            hit->memo_gen = e->memo_gen;
            hit->memo_fp = e->memo_fp;
            hit->memo = e->memo;
            c->st.l1_hits++;
            dc_mutex_unlock(c->mu);
            return DNS_CACHE_HIT;
        }
    }
    int32_t s = c->ring ? idx_find(c, h, key, klen) : -1;
    if (s < 0) {
        c->st.misses++;
        dc_mutex_unlock(c->mu);
        return DNS_CACHE_MISS;
    }
    ent_t *e = ent_at(c, c->idx[s].pos1 - 1);
    int res = DNS_CACHE_HIT;
    if (now >= e->expire) {
        if (!c->stale_max || now - e->expire >= c->stale_max) {
            ent_kill(c, e);
            c->st.misses++;
            dc_mutex_unlock(c->mu);
            return DNS_CACHE_MISS;
        }
        res = DNS_CACHE_STALE;
    }
    if (e->msg_len > cap) {
        c->st.misses++;
        dc_mutex_unlock(c->mu);
        return DNS_CACHE_MISS;
    }
    const uint16_t *offs = (const uint16_t *)((const uint8_t *)(e + 1) + e->key_len);
    const uint8_t *msg = (const uint8_t *)(offs + (e->nttl == 0xFF ? 0 : e->nttl));
    memcpy(out, msg, e->msg_len);
    fill_resp(&r, e->an_off, e->an, e->ns, e->ar, e->nttl, offs);
    if (res == DNS_CACHE_STALE) {
        dns_adjust_ttls(out, e->msg_len, &r, 0xFFFFFFFFu, stale_ttl ? stale_ttl : 10, 0);
        c->st.stale_hits++;
    } else {
        dns_adjust_ttls(out, e->msg_len, &r, now - e->stored, 0, 0);
        c->st.l2_hits++;
    }
    hit->len = e->msg_len;
    hit->rcode = e->rcode;
    hit->memo_gen = e->memo_gen;
    hit->memo_fp = e->memo_fp;
    hit->memo = e->memo;
    /* promote small, fresh entries to L1 */
    if (res == DNS_CACHE_HIT && c->nl1 && klen <= L1_KEY_MAX && e->msg_len <= L1_MSG_MAX &&
        e->nttl != 0xFF && e->nttl <= L1_TTLS) {
        l1_t *l = &c->l1[h & (c->nl1 - 1)];
        l->valid = true;
        l->hash = h;
        l->klen = (uint8_t)klen;
        memcpy(l->key, key, klen);
        l->stored = e->stored;
        l->expire = e->expire;
        l->msg_len = e->msg_len;
        l->nttl = e->nttl;
        memcpy(l->ttl_off, offs, e->nttl * sizeof(uint16_t));
        memcpy(l->msg, msg, e->msg_len);
        l->rcode = e->rcode;
        l->memo_gen = e->memo_gen;
        l->memo_fp = e->memo_fp;
        l->memo = e->memo;
    }
    dc_mutex_unlock(c->mu);
    return res;
}

void dns_cache_put(dns_cache_t *c, const dns_ckey_t *k, const uint8_t *msg, size_t len, const dns_resp_t *r,
                   uint32_t ttl, uint32_t now) {
    uint8_t key[DNS_MAX_NAME + 8];
    size_t klen = key_ser(k, key);
    if (len > MAX_MSG || len < DNS_HDR_LEN || !ttl) {
        if (len > MAX_MSG) c->st.too_large++;
        return;
    }
    uint32_t h = dc_fmix32(dc_fnv32(key, klen));
    if (!h) h = 1;
    uint8_t nttl = r->ttl_overflow ? 0xFF : (uint8_t)r->nttl;
    size_t noffs = nttl == 0xFF ? 0 : nttl;
    uint32_t total = (uint32_t)((sizeof(ent_t) + klen + noffs * 2 + len + 7) & ~(size_t)7);
    dc_mutex_lock(c->mu);
    if (!c->ring) {
        dc_mutex_unlock(c->mu);
        return;
    }
    int32_t s = idx_find(c, h, key, klen);
    if (s >= 0) ent_kill(c, ent_at(c, c->idx[s].pos1 - 1));
    /* keep the index at most 3/4 full */
    while (c->count && c->st.entries + 1 > (c->mask + 1) * 3 / 4) evict_tail(c);
    int32_t pos = ring_alloc(c, total);
    if (pos < 0) {
        dc_mutex_unlock(c->mu);
        return;
    }
    ent_t *e = ent_at(c, (uint32_t)pos);
    memset(e, 0, sizeof(*e));
    e->hash = h;
    e->stored = now;
    e->expire = now + ttl;
    e->total = (uint16_t)total;
    e->msg_len = (uint16_t)len;
    e->key_len = (uint16_t)klen;
    e->nttl = nttl;
    e->an_off = r->an_off;
    e->an = r->ancount;
    e->ns = r->nscount;
    e->ar = r->arcount;
    e->rcode = r->rcode;
    uint8_t *p = (uint8_t *)(e + 1);
    memcpy(p, key, klen);
    p += klen;
    memcpy(p, r->ttl_off, noffs * 2);
    p += noffs * 2;
    memcpy(p, msg, len);
    c->count++;
    c->used += total;
    /* index */
    uint32_t i = h & c->mask;
    while (c->idx[i].pos1) i = (i + 1) & c->mask;
    c->idx[i].hash = h;
    c->idx[i].pos1 = (uint32_t)pos + 1;
    e->slot = i;
    c->st.entries++;
    c->st.inserts++;
    if (c->nl1) {
        l1_t *l = &c->l1[h & (c->nl1 - 1)];
        if (l->valid && l->hash == h) l->valid = false;
    }
    dc_mutex_unlock(c->mu);
}

void dns_cache_set_memo(dns_cache_t *c, const dns_ckey_t *k, uint32_t gen, uint32_t fp, uint8_t memo) {
    uint8_t key[DNS_MAX_NAME + 8];
    size_t klen = key_ser(k, key);
    uint32_t h = dc_fmix32(dc_fnv32(key, klen));
    if (!h) h = 1;
    dc_mutex_lock(c->mu);
    int32_t s = c->ring ? idx_find(c, h, key, klen) : -1;
    if (s >= 0) {
        ent_t *e = ent_at(c, c->idx[s].pos1 - 1);
        e->memo_gen = gen;
        e->memo_fp = fp;
        e->memo = memo;
    }
    if (c->nl1 && klen <= L1_KEY_MAX) {
        l1_t *l = &c->l1[h & (c->nl1 - 1)];
        if (l->valid && l->hash == h && l->klen == klen && memcmp(l->key, key, klen) == 0) {
            l->memo_gen = gen;
            l->memo_fp = fp;
            l->memo = memo;
        }
    }
    dc_mutex_unlock(c->mu);
}

void dns_cache_del(dns_cache_t *c, const dns_ckey_t *k) {
    uint8_t key[DNS_MAX_NAME + 8];
    size_t klen = key_ser(k, key);
    uint32_t h = dc_fmix32(dc_fnv32(key, klen));
    if (!h) h = 1;
    dc_mutex_lock(c->mu);
    int32_t s = c->ring ? idx_find(c, h, key, klen) : -1;
    if (s >= 0) ent_kill(c, ent_at(c, c->idx[s].pos1 - 1));
    if (c->nl1) {
        l1_t *l = &c->l1[h & (c->nl1 - 1)];
        if (l->valid && l->hash == h) l->valid = false;
    }
    dc_mutex_unlock(c->mu);
}

void dns_cache_flush(dns_cache_t *c) {
    dc_mutex_lock(c->mu);
    if (c->idx) memset(c->idx, 0, (c->mask + 1) * sizeof(slot_t));
    c->head = c->tail = c->count = c->used = 0;
    c->wrap_end = NO_WRAP;
    c->st.entries = 0;
    if (c->l1) memset(c->l1, 0, c->nl1 * sizeof(l1_t));
    dc_mutex_unlock(c->mu);
}

void dns_cache_reconfigure(dns_cache_t *c, const dns_cache_cfg_t *cfg) {
    if (!c || !cfg) return;
    dc_mutex_lock(c->mu);
    c->wanted = *cfg;
    if (!c->build_mode) cache_alloc(c, cfg);
    dc_mutex_unlock(c->mu);
}

void dns_cache_set_build_mode(dns_cache_t *c, bool building) {
    if (!c) return;
    dc_mutex_lock(c->mu);
    if (c->build_mode != building) {
        c->build_mode = building;
        if (building) {
            /* cache_alloc actually releases the ring, index, and L1; flushing
             * entries alone would not reclaim a single byte of heap. */
            dns_cache_cfg_t off = {0};
            cache_alloc(c, &off);
        } else {
            cache_alloc(c, &c->wanted);
        }
    }
    dc_mutex_unlock(c->mu);
}

void dns_cache_get_stats(dns_cache_t *c, dns_cache_stats_t *st) {
    dc_mutex_lock(c->mu);
    *st = c->st;
    st->bytes_used = c->used;
    dc_mutex_unlock(c->mu);
}
