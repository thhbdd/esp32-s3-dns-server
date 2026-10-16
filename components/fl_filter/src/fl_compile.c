/*
 * fl_compile.c - rule list compiler.
 *
 * Pipeline (bounded memory, flash friendly):
 *   1. lines are parsed one by one (fl_rule.c); every domain-level rule
 *      becomes a small record  (reversed key, type, value, source)
 *      appended to an in-RAM arena;  rules with modifiers/patterns are
 *      compiled immediately into fl_crule_t + pool data.
 *   2. when the arena is full it is sorted, records with equal keys are
 *      combined, and the result is written as a front-coded "run" to the
 *      run store (external sort - on the device this is a flash partition).
 *   3. finish: $badfilter is resolved, all runs are k-way merged twice
 *      (count, then build) producing the Bloom filter, the front-coded key
 *      index and the payload tables, which are streamed to the sink.
 *   4. the sink is read back and verified against the computed CRC.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fl_internal.h"

#define TAG "flc"

enum { REC_MASK = 0, REC_BF = 1, REC_HOST = 2, REC_CR = 3 };

#define MAX_IPS_PER_KEY FL_MAX_HOST_IPS
#define IDENT_MAX 8192
#define IDENT_ITEM 300
#define MAX_CR_PER_KEY FL_MAX_CR_PER_KEY
#define RREFILL 2048

const char *const fl_kind_prefix[FLK_COUNT] = {"||", "||", "|", "|", "||*.", ".", "*.", "://"};
const char *const fl_kind_suffix[FLK_COUNT] = {"^", "^|", "^", "^|", "^", "^", "^", "^"};

typedef struct {
    uint16_t *secs; /* sector chain */
    uint32_t nsecs, capsecs;
    uint32_t len;   /* bytes */
    uint32_t nkeys;
} run_t;

typedef struct {
    uint32_t re_off; /* tmp: regex text */
    uint16_t re_len;
    uint16_t lit_len; /* prefilter literal (tmp) */
    uint32_t lit_off;
    uint8_t generic;
    uint8_t disabled;
    uint8_t hot;
} crinfo_t;

typedef struct {
    uint64_t mask;
    uint32_t bf;
    uint32_t src;
    uint16_t nips;
    uint16_t ncr;
    uint32_t ips[MAX_IPS_PER_KEY];
    uint32_t cr[MAX_CR_PER_KEY];
} comb_t;

struct fl_compiler {
    fl_compile_opts_t o;
    fl_stats_t st;
    fl_stats_t sst[FL_MAX_SOURCES];
    char *src_name[FL_MAX_SOURCES];
    uint32_t src_flags[FL_MAX_SOURCES];
    int nsrc, cur;
    bool src_seen_rule;
    int src_reject; /* FL_ERR_HTML / FL_ERR_BINARY: the current source is rejected */
    int fatal;
    char err[160];
    uint64_t t0;

    char *line;
    size_t line_len;
    bool line_overflow;

    fl_rule_t *rule;
    char *regex_buf;

    dc_buf_t arena;
    dc_buf_t offs;

    run_t *runs;
    int nruns, runcap;
    uint16_t *freelist; /* free sectors of the run store */
    uint32_t nfree, nsec;

    dc_buf_t ips; /* dc_ip_t array */
    uint32_t nips;

    dc_buf_t crules; /* fl_crule_t */
    dc_buf_t crinfo; /* crinfo_t */
    dc_buf_t pool;
    dc_buf_t tmp;    /* compile-time only strings */
    dc_buf_t bf;     /* fl_bfent_t */
    dc_buf_t bf_neg; /* u32 ident hashes of unconditional complex badfilters (tmp offsets follow) */
    uint32_t order;
    uint32_t dfa_bytes;
    char *identbuf;
    char *ident;
    fl_symtab_t symtab;
    bool symtab_ready;
};

/* ------------------------------------------------------------------------- */
/* memory store                                                              */

static int mem_write(fl_store_t *s, uint32_t off, const void *buf, size_t len) {
    fl_memstore_t *m = (fl_memstore_t *)s;
    if ((uint64_t)off + len > s->capacity) return FL_ERR_FULL;
    if (m->buf.len < off + len) {
        size_t old = m->buf.len;
        if (!dc_buf_reserve(&m->buf, off + len - old)) return FL_ERR_NOMEM;
        memset(m->buf.data + old, 0xFF, off + len - old);
        m->buf.len = off + len;
    }
    memcpy(m->buf.data + off, buf, len);
    return 0;
}

static int mem_read(fl_store_t *s, uint32_t off, void *buf, size_t len) {
    fl_memstore_t *m = (fl_memstore_t *)s;
    if ((uint64_t)off + len > m->buf.len) return FL_ERR_IO;
    memcpy(buf, m->buf.data + off, len);
    return 0;
}

void fl_memstore_init(fl_memstore_t *m, uint32_t capacity) {
    memset(m, 0, sizeof(*m));
    m->st.write = mem_write;
    m->st.read = mem_read;
    m->st.capacity = capacity;
    m->st.ctx = m;
    dc_buf_init(&m->buf);
}

void fl_memstore_free(fl_memstore_t *m) { dc_buf_free(&m->buf); }

/* ------------------------------------------------------------------------- */
/* helpers                                                                   */

static int set_err(fl_compiler_t *c, int code, const char *msg) {
    if (!c->fatal) {
        c->fatal = code;
        dc_strlcpy(c->err, msg, sizeof(c->err));
    }
    return code;
}

static uint32_t pool_put_str16(dc_buf_t *pool, const char *s, size_t n) {
    if (n > 0xFFFF) n = 0xFFFF;
    uint32_t off = (uint32_t)pool->len;
    dc_buf_put16(pool, (uint16_t)n);
    dc_buf_append(pool, s, n);
    return off;
}

static fl_stats_t *cur_stats(fl_compiler_t *c) { return &c->sst[c->cur >= 0 ? c->cur : 0]; }

#define BUMP(field)                                                                             \
    do {                                                                                        \
        c->st.field++;                                                                          \
        cur_stats(c)->field++;                                                                  \
    } while (0)

/* ------------------------------------------------------------------------- */

fl_compiler_t *fl_compile_new(const fl_compile_opts_t *opts) {
    fl_compiler_t *c = (fl_compiler_t *)dc_calloc_ext(1, sizeof(*c));
    if (!c) return NULL;
    c->o = *opts;
    if (!c->o.chunk_bytes) c->o.chunk_bytes = 512 * 1024;
    if (c->o.chunk_bytes < 16 * 1024) c->o.chunk_bytes = 16 * 1024;
    if (!c->o.max_complex) c->o.max_complex = 65536;
    if (!c->o.max_dfa_states) c->o.max_dfa_states = 64;
    if (!c->o.dfa_budget_bytes) c->o.dfa_budget_bytes = 128 * 1024;
    if (!c->o.block_entries) c->o.block_entries = 16;
    if (!c->o.bloom_bits_per_key) c->o.bloom_bits_per_key = 12;
    c->cur = -1;
    c->t0 = dc_time_us();
    c->line = (char *)dc_malloc_ext(FL_MAX_LINE + 2);
    c->rule = (fl_rule_t *)dc_malloc_ext(sizeof(fl_rule_t));
    c->regex_buf = (char *)dc_malloc_ext(FL_MAX_LINE * 24 + 128);
    c->identbuf = (char *)dc_malloc_ext((size_t)FL_MAX_LIST * IDENT_ITEM);
    if (c->o.runs) {
        c->nsec = c->o.runs->capacity / 4096u;
        if (c->nsec > 65535) c->nsec = 65535;
        c->freelist = (uint16_t *)dc_malloc((c->nsec ? c->nsec : 1) * sizeof(uint16_t));
        if (c->freelist)
            for (uint32_t i = 0; i < c->nsec; i++) c->freelist[i] = (uint16_t)(c->nsec - 1 - i);
        c->nfree = c->nsec;
    }
    c->ident = (char *)dc_malloc_ext(IDENT_MAX);
    dc_buf_init(&c->arena);
    dc_buf_init(&c->offs);
    dc_buf_init(&c->ips);
    dc_buf_init(&c->crules);
    dc_buf_init(&c->crinfo);
    dc_buf_init(&c->pool);
    dc_buf_init(&c->tmp);
    dc_buf_init(&c->bf);
    dc_buf_init(&c->bf_neg);
    if (!c->line || !c->rule || !c->regex_buf || !c->identbuf || !c->ident || !c->freelist || !c->o.runs) {
        fl_compile_free(c);
        return NULL;
    }
    /* pool offset 0 means "none": reserve 8 bytes */
    dc_buf_zero(&c->pool, 8);
    dc_buf_zero(&c->tmp, 8);
    return c;
}

void fl_compile_free(fl_compiler_t *c) {
    if (!c) return;
    for (int i = 0; i < c->nsrc; i++) dc_free(c->src_name[i]);
    dc_free(c->line);
    dc_free(c->rule);
    dc_free(c->regex_buf);
    dc_free(c->identbuf);
    dc_free(c->ident);
    dc_free(c->freelist);
    for (int i = 0; i < c->nruns; i++) dc_free(c->runs[i].secs);
    dc_free(c->runs);
    dc_buf_free(&c->arena);
    dc_buf_free(&c->offs);
    dc_buf_free(&c->ips);
    dc_buf_free(&c->crules);
    dc_buf_free(&c->crinfo);
    dc_buf_free(&c->pool);
    dc_buf_free(&c->tmp);
    dc_buf_free(&c->bf);
    dc_buf_free(&c->bf_neg);
    dc_free(c);
}

const fl_stats_t *fl_compile_source_stats(const fl_compiler_t *c, int src) {
    return (src >= 0 && src < c->nsrc) ? &c->sst[src] : NULL;
}
const char *fl_compile_error(const fl_compiler_t *c) { return c->err; }

int fl_compile_begin_source(fl_compiler_t *c, const char *name, uint32_t flags) {
    if (c->fatal) return c->fatal;
    if (c->nsrc >= FL_MAX_SOURCES) return set_err(c, FL_ERR_LIMIT, "too many sources");
    size_t nl = strlen(name);
    c->src_name[c->nsrc] = (char *)dc_malloc(nl + 1);
    if (!c->src_name[c->nsrc]) return set_err(c, FL_ERR_NOMEM, "out of memory");
    memcpy(c->src_name[c->nsrc], name, nl + 1);
    c->src_flags[c->nsrc] = flags;
    c->cur = c->nsrc++;
    c->src_seen_rule = false;
    c->src_reject = 0;
    c->line_len = 0;
    c->line_overflow = false;
    return c->cur;
}

/* ------------------------------------------------------------------------- */
/* sorting & runs                                                            */

static int key_cmp(const uint8_t *base, uint32_t a, uint32_t b) {
    const uint8_t *ka = base + a, *kb = base + b;
    unsigned la = ka[0], lb = kb[0];
    int r = memcmp(ka + 1, kb + 1, la < lb ? la : lb);
    if (r) return r;
    return (int)la - (int)lb;
}

static void msort(uint32_t *a, uint32_t *t, size_t n, const uint8_t *base) {
    /* bottom-up merge sort (stable, no recursion, no global state) */
    uint32_t *src = a, *dst = t;
    for (size_t w = 1; w < n; w *= 2) {
        for (size_t i = 0; i < n; i += 2 * w) {
            size_t m = i + w < n ? i + w : n, e = i + 2 * w < n ? i + 2 * w : n;
            size_t x = i, y = m, k = i;
            while (x < m && y < e) dst[k++] = key_cmp(base, src[x], src[y]) <= 0 ? src[x++] : src[y++];
            while (x < m) dst[k++] = src[x++];
            while (y < e) dst[k++] = src[y++];
        }
        uint32_t *sw = src;
        src = dst;
        dst = sw;
    }
    if (src != a) memcpy(a, src, n * sizeof(uint32_t));
}

static void comb_reset(comb_t *cb) {
    cb->mask = 0;
    cb->bf = 0;
    cb->src = 0;
    cb->nips = 0;
    cb->ncr = 0;
}

static bool comb_add_ip(comb_t *cb, uint32_t ip) {
    for (unsigned i = 0; i < cb->nips; i++)
        if (cb->ips[i] == ip) return true;
    if (cb->nips >= MAX_IPS_PER_KEY) return false;
    cb->ips[cb->nips++] = ip;
    return true;
}

/* Adds a modifier rule to a domain key.  Beyond MAX_CR_PER_KEY the earliest
 * rules (lowest ids) are kept, wherever the records come from; returns false
 * when one rule was left out. */
static bool comb_add_cr(comb_t *cb, uint32_t cr) {
    for (unsigned i = 0; i < cb->ncr; i++)
        if (cb->cr[i] == cr) return true;
    if (cb->ncr < MAX_CR_PER_KEY) {
        cb->cr[cb->ncr++] = cr;
        return true;
    }
    unsigned hi = 0;
    for (unsigned i = 1; i < cb->ncr; i++)
        if (cb->cr[i] > cb->cr[hi]) hi = i;
    if (cr < cb->cr[hi]) cb->cr[hi] = cr;
    return false;
}

/* returns the number of rules left out */
static unsigned comb_merge(comb_t *d, const comb_t *s) {
    unsigned dropped = 0;
    d->mask |= s->mask;
    d->bf |= s->bf;
    d->src |= s->src;
    for (unsigned i = 0; i < s->nips; i++) dropped += !comb_add_ip(d, s->ips[i]);
    for (unsigned i = 0; i < s->ncr; i++) dropped += !comb_add_cr(d, s->cr[i]);
    return dropped;
}

/* compact run payload: u8 F, [varint mask], [varint bf], [ips], [crs], source */
enum { CF_MASK = 1, CF_BF = 2, CF_IPS = 4, CF_CRS = 8, CF_SRC1 = 16 };

static size_t comb_encode(const comb_t *cb, uint8_t *out) {
    size_t o = 1;
    uint8_t f = 0;
    if (cb->mask) {
        f |= CF_MASK;
        o += dc_varint_put(out + o, cb->mask);
    }
    if (cb->bf) {
        f |= CF_BF;
        o += dc_varint_put(out + o, cb->bf);
    }
    if (cb->nips) {
        f |= CF_IPS;
        o += dc_varint_put(out + o, cb->nips);
        for (unsigned i = 0; i < cb->nips; i++) o += dc_varint_put(out + o, cb->ips[i]);
    }
    if (cb->ncr) {
        f |= CF_CRS;
        o += dc_varint_put(out + o, cb->ncr);
        for (unsigned i = 0; i < cb->ncr; i++) o += dc_varint_put(out + o, cb->cr[i]);
    }
    if (cb->src && !(cb->src & (cb->src - 1))) {
        f |= CF_SRC1;
        out[o++] = (uint8_t)__builtin_ctz(cb->src);
    } else {
        o += dc_varint_put(out + o, cb->src);
    }
    out[0] = f;
    return o;
}

static const uint8_t *comb_decode(const uint8_t *p, const uint8_t *end, comb_t *cb) {
    uint64_t v;
    comb_reset(cb);
    if (p >= end) return NULL;
    uint8_t f = *p++;
    if (f & CF_MASK) {
        if (!(p = dc_varint_get_safe(p, end, &v))) return NULL;
        cb->mask = v;
    }
    if (f & CF_BF) {
        if (!(p = dc_varint_get_safe(p, end, &v))) return NULL;
        cb->bf = (uint32_t)v;
    }
    if (f & CF_IPS) {
        if (!(p = dc_varint_get_safe(p, end, &v)) || v > MAX_IPS_PER_KEY) return NULL;
        cb->nips = (uint16_t)v;
        for (unsigned i = 0; i < cb->nips; i++) {
            if (!(p = dc_varint_get_safe(p, end, &v))) return NULL;
            cb->ips[i] = (uint32_t)v;
        }
    }
    if (f & CF_CRS) {
        if (!(p = dc_varint_get_safe(p, end, &v)) || v > MAX_CR_PER_KEY) return NULL;
        cb->ncr = (uint16_t)v;
        for (unsigned i = 0; i < cb->ncr; i++) {
            if (!(p = dc_varint_get_safe(p, end, &v))) return NULL;
            cb->cr[i] = (uint32_t)v;
        }
    }
    if (f & CF_SRC1) {
        if (p >= end || *p >= 32) return NULL;
        cb->src = 1u << *p++;
    } else {
        if (!(p = dc_varint_get_safe(p, end, &v))) return NULL;
        cb->src = (uint32_t)v;
    }
    return p;
}

/* ---- sector-chained run store ----------------------------------------------
 * The run store is split into 4 KiB sectors.  A run is a chain of sectors
 * taken from a free list; every sector is written exactly once with a single
 * write starting at the sector boundary (a flash backend erases the sector
 * first).  While runs are merged ("compaction", removing duplicates across
 * sources) every input sector is returned to the free list as soon as it has
 * been read into RAM, so the merge works in place: it needs only a few free
 * sectors, and staging space tracks the number of distinct keys instead of
 * the total number of rule lines. */

#define SEC 4096u

static int sec_alloc(fl_compiler_t *c, uint16_t *out) {
    if (!c->nfree) return FL_ERR_FULL;
    *out = c->freelist[--c->nfree];
    uint32_t used = c->nsec - c->nfree;
    if (used * SEC > c->st.staging_peak) c->st.staging_peak = used * SEC;
    return 0;
}

static void sec_release(fl_compiler_t *c, uint16_t s) {
    c->freelist[c->nfree++] = s;
    if (c->o.runs->discard) c->o.runs->discard(c->o.runs, (uint32_t)s * SEC, SEC);
}

static void run_free(run_t *r) {
    dc_free(r->secs);
    memset(r, 0, sizeof(*r));
}

typedef struct {
    fl_compiler_t *c;
    run_t run;
    uint8_t buf[SEC];
    size_t n;
    char prev[256];
    unsigned prevlen;
    uint8_t hdr[1 + 2 + 2 * 256];
    uint8_t pay[16 + MAX_IPS_PER_KEY * 5 + MAX_CR_PER_KEY * 5 + 16];
} runw_t;

static void runw_begin(fl_compiler_t *c, runw_t *w) {
    memset(&w->run, 0, sizeof(w->run));
    w->c = c;
    w->n = 0;
    w->prevlen = 0;
}

static int runw_flush(runw_t *w) {
    if (!w->n) return 0;
    fl_compiler_t *c = w->c;
    uint16_t s;
    int rc = sec_alloc(c, &s);
    if (rc) return rc;
    if (w->run.nsecs >= w->run.capsecs) {
        uint32_t nc = w->run.capsecs ? w->run.capsecs * 2 : 64;
        uint16_t *ns = (uint16_t *)dc_realloc(w->run.secs, nc * sizeof(uint16_t));
        if (!ns) {
            sec_release(c, s);
            return FL_ERR_NOMEM;
        }
        w->run.secs = ns;
        w->run.capsecs = nc;
    }
    rc = c->o.runs->write(c->o.runs, (uint32_t)s * SEC, w->buf, w->n);
    if (rc) {
        sec_release(c, s);
        return rc;
    }
    w->run.secs[w->run.nsecs++] = s;
    w->run.len += (uint32_t)w->n;
    w->n = 0;
    return 0;
}

static int runw_put(runw_t *w, const void *d, size_t n) {
    const uint8_t *p = (const uint8_t *)d;
    while (n) {
        size_t k = SEC - w->n < n ? SEC - w->n : n;
        memcpy(w->buf + w->n, p, k);
        w->n += k;
        p += k;
        n -= k;
        if (w->n == SEC) {
            int rc = runw_flush(w);
            if (rc) return rc;
        }
    }
    return 0;
}

/* front coded record with compressed suffix + compact payload */
static int runw_rec(runw_t *w, const char *key, unsigned kl, const comb_t *cb) {
    unsigned sh = 0;
    while (sh < w->prevlen && sh < kl && w->prev[sh] == key[sh]) sh++;
    w->hdr[0] = (uint8_t)sh;
    size_t hl = 1 + fl_suffix_put(&w->c->symtab, (const uint8_t *)key + sh, kl - sh, w->hdr + 1);
    size_t pl = comb_encode(cb, w->pay);
    int rc = runw_put(w, w->hdr, hl);
    if (!rc) rc = runw_put(w, w->pay, pl);
    memcpy(w->prev, key, kl);
    w->prevlen = kl;
    w->run.nkeys++;
    return rc;
}

static int runs_push(fl_compiler_t *c, run_t *r) {
    if (c->nruns >= c->runcap) {
        int ncap = c->runcap ? c->runcap * 2 : 16;
        run_t *nr = (run_t *)dc_realloc(c->runs, (size_t)ncap * sizeof(run_t));
        if (!nr) return FL_ERR_NOMEM;
        c->runs = nr;
        c->runcap = ncap;
    }
    c->runs[c->nruns++] = *r;
    memset(r, 0, sizeof(*r));
    return 0;
}

static int runw_end(runw_t *w) {
    int rc = runw_flush(w);
    if (rc) return rc;
    w->c->st.runs++;
    return runs_push(w->c, &w->run);
}

/* releases the sectors of a partially written run (error paths) */
static void runw_abort(runw_t *w) {
    for (uint32_t i = 0; i < w->run.nsecs; i++) sec_release(w->c, w->run.secs[i]);
    run_free(&w->run);
}

typedef int (*merge_cb)(fl_compiler_t *c, void *arg, const char *key, unsigned kl, comb_t *cb);
static int run_merge(fl_compiler_t *c, merge_cb cb, void *arg, bool release);

static int compact_cb(fl_compiler_t *c, void *arg, const char *key, unsigned kl, comb_t *cb) {
    (void)c;
    return runw_rec((runw_t *)arg, key, kl, cb);
}

/* Merges all runs into one, in place. */
static int compact_runs(fl_compiler_t *c) {
    runw_t *w = (runw_t *)dc_malloc_ext(sizeof(runw_t));
    if (!w) return FL_ERR_NOMEM;
    runw_begin(c, w);
    int rc = run_merge(c, compact_cb, w, true);
    if (!rc) rc = runw_flush(w);
    if (rc) {
        /* the inputs were (partially) recycled: the compilation cannot go on */
        runw_abort(w);
        dc_free(w);
        return rc;
    }
    for (int i = 0; i < c->nruns; i++) run_free(&c->runs[i]); /* sectors already released */
    c->nruns = 0;
    rc = runs_push(c, &w->run);
    dc_free(w);
    c->st.compactions++;
    return rc;
}

/* Before writing a run of up to `est` bytes. */
static int maybe_compact(fl_compiler_t *c, uint32_t est) {
    uint32_t need = (est + SEC - 1) / SEC + 2;
    bool low = c->nfree < need;
    if (c->nruns < 2 || (!low && c->nruns < 48)) return 0;
    uint32_t used = c->nsec - c->nfree;
    if (c->nfree < 4 + used / 32 + (uint32_t)c->nruns) return 0; /* unsafe: would fail mid-way */
    if (c->o.progress && !c->o.progress(c->o.progress_arg, "compact", used, c->nsec)) return FL_ERR_ABORT;
    return compact_runs(c);
}

static int flush_chunk(fl_compiler_t *c) {
    size_t n = c->offs.len / 4;
    if (!n) return 0;
    uint32_t *a = (uint32_t *)c->offs.data;
    uint32_t *t = (uint32_t *)dc_malloc_ext(n * sizeof(uint32_t));
    if (!t) return set_err(c, FL_ERR_NOMEM, "out of memory (sort)");
    msort(a, t, n, c->arena.data);
    dc_free(t);
    if (!c->symtab_ready) {
        /* sample front-coded suffixes of this chunk (~32 KiB) */
        dc_buf_t smp, so;
        dc_buf_init(&smp);
        dc_buf_init(&so);
        size_t step = n / 2500 + 1;
        const uint8_t *prevk = NULL;
        for (size_t i = 0; i < n && smp.len < 32768; i++) {
            const uint8_t *k = c->arena.data + a[i];
            if (prevk && key_cmp(c->arena.data, a[i - 1], a[i]) == 0) continue;
            unsigned sh = 0;
            if (prevk)
                while (sh < prevk[0] && sh < k[0] && prevk[1 + sh] == k[1 + sh]) sh++;
            prevk = k;
            if (i % step) continue;
            dc_buf_put32(&so, (uint32_t)smp.len);
            dc_buf_append(&smp, k + 1 + sh, k[0] - sh);
        }
        dc_buf_put32(&so, (uint32_t)smp.len);
        int brc = (smp.oom || so.oom) ? FL_ERR_NOMEM
                                      : fl_fsst_build(&c->symtab, smp.data, (const uint32_t *)so.data,
                                                      so.len / 4 - 1);
        dc_buf_free(&smp);
        dc_buf_free(&so);
        if (brc == FL_ERR_NOMEM) {
            /* FSST is only a storage optimization. A zero-symbol table
             * stores key suffixes as raw strings via fl_suffix_put(), so
             * low-memory compilation must not discard valid filter rules.
             * Keep the standard symbol-table section/image format. The
             * larger raw image is still subject to normal Flash limits. */
            (void)fl_fsst_build(&c->symtab, NULL, NULL, 0);
        } else if (brc) {
            return set_err(c, brc, "symbol table construction failed");
        }
        c->symtab_ready = true;
    }

    int rc = maybe_compact(c, (uint32_t)(c->arena.len + c->arena.len / 4));
    if (rc) return set_err(c, rc, rc == FL_ERR_ABORT ? "aborted" : "run compaction failed");
    runw_t *w = (runw_t *)dc_malloc_ext(sizeof(runw_t));
    comb_t *cb = (comb_t *)dc_malloc_ext(sizeof(comb_t));
    if (!w || !cb) {
        dc_free(w);
        dc_free(cb);
        return set_err(c, FL_ERR_NOMEM, "out of memory (run)");
    }
    runw_begin(c, w);
    size_t i = 0;
    while (i < n && !rc) {
        const uint8_t *k = c->arena.data + a[i];
        unsigned kl = k[0];
        comb_reset(cb);
        size_t j = i;
        while (j < n && key_cmp(c->arena.data, a[i], a[j]) == 0) {
            const uint8_t *r = c->arena.data + a[j] + 1 + kl;
            uint8_t type = r[0];
            uint64_t val;
            const uint8_t *p = dc_varint_get(r + 1, &val);
            uint8_t src = *p;
            cb->src |= 1u << src;
            switch (type) {
            case REC_MASK:
                cb->mask |= val;
                break;
            case REC_BF:
                cb->bf |= (uint32_t)val;
                break;
            case REC_HOST:
                if (!comb_add_ip(cb, (uint32_t)val)) BUMP(unsupported);
                break;
            case REC_CR:
                if (!comb_add_cr(cb, (uint32_t)val)) BUMP(unsupported); /* (more than 255 for one domain) */
                break;
            }
            j++;
        }
        if (!rc) rc = runw_rec(w, (const char *)k + 1, kl, cb);
        i = j;
    }
    if (!rc) rc = runw_end(w);
    if (rc) runw_abort(w); /* (sectors of an unfinished run) */
    dc_free(w);
    dc_free(cb);
    c->arena.len = 0;
    c->offs.len = 0;
    if (rc == FL_ERR_FULL) return set_err(c, rc, "rule staging area full (too many rules)");
    if (rc) return set_err(c, rc, "run write failed");
    if (c->o.progress && !c->o.progress(c->o.progress_arg, "sort", (uint32_t)c->nruns, 0))
        return set_err(c, FL_ERR_ABORT, "aborted");
    return 0;
}

static int emit_rec(fl_compiler_t *c, const char *rkey, size_t kl, uint8_t type, uint64_t val) {
    if (kl == 0 || kl > 255) return 0;

    uint8_t t[16];
    uint32_t off = (uint32_t)c->arena.len;
    dc_buf_put8(&c->arena, (uint8_t)kl);
    dc_buf_append(&c->arena, rkey, kl);
    t[0] = type;
    size_t n = 1 + dc_varint_put(t + 1, val);
    t[n++] = (uint8_t)c->cur;
    dc_buf_append(&c->arena, t, n);
    dc_buf_put32(&c->offs, off);
    if (c->arena.oom || c->offs.oom) return set_err(c, FL_ERR_NOMEM, "out of memory (arena)");
    if (c->arena.len >= c->o.chunk_bytes) return flush_chunk(c);
    return 0;
}

/* lowercases and reverses a hostname; returns length or 0 */
static size_t make_key(const char *h, size_t n, char *out) {
    if (n == 0 || n > FL_MAX_HOST) return 0;
    char low[256];
    for (size_t i = 0; i < n; i++) low[i] = (char)dc_lower((uint8_t)h[i]);
    return fl_reverse_name(low, n, out);
}

static uint32_t ip_index(fl_compiler_t *c, const dc_ip_t *ip) {
    const dc_ip_t *a = (const dc_ip_t *)c->ips.data;
    for (uint32_t i = 0; i < c->nips; i++)
        if (dc_ip_equal(&a[i], ip)) return i;
    if (c->nips >= 4096 || !dc_buf_append(&c->ips, ip, sizeof(*ip))) return 0xFFFFFFFFu;
    return c->nips++;
}

/* ------------------------------------------------------------------------- */
/* identities ($badfilter)                                                   */

static int cmp_str_item(const void *a, const void *b) {
    const char *const *x = (const char *const *)a, *const *y = (const char *const *)b;
    return strcmp(*x, *y);
}

/* canonical identity of a rule for $badfilter negation (negatesBadfilter):
 * whitelist, pattern, important, request types, client tags and clients;
 * $dnstype, $denyallow and $dnsrewrite are not part of it. */
static size_t build_ident(fl_compiler_t *c, const fl_rule_t *r, const char *pat, size_t pl, char *out,
                          size_t cap) {
    size_t o = 0;
    char *tmpc = c->identbuf; /* FL_MAX_LIST * IDENT_ITEM */
#define APP(s, n)                                                                               \
    do {                                                                                        \
        size_t _n = (n);                                                                        \
        if (o + _n < cap) {                                                                     \
            memcpy(out + o, (s), _n);                                                           \
            o += _n;                                                                            \
        }                                                                                       \
    } while (0)
    APP(r->whitelist ? "W|" : "B|", 2);
    APP(pat, pl);
    if (r->important) APP("|i", 2);
    if (r->perm_types || r->restr_types) {
        char t[32];
        int k = snprintf(t, sizeof(t), "|t%x/%x", (unsigned)r->perm_types, (unsigned)r->restr_types);
        APP(t, (size_t)k);
    }
    /* ctags: sorted unique strings */
    for (int pass = 0; pass < 2; pass++) {
        unsigned n = pass ? r->n_ctag_restr : r->n_ctag_perm;
        if (!n) continue;
        const char *pt[FL_MAX_LIST];
        for (unsigned i = 0; i < n; i++) {
            size_t l = pass ? r->ctag_restr_l[i] : r->ctag_perm_l[i];
            if (l > IDENT_ITEM - 1) l = IDENT_ITEM - 1;
            char *d = tmpc + (size_t)i * IDENT_ITEM;
            memcpy(d, pass ? r->ctag_restr_s[i] : r->ctag_perm_s[i], l);
            d[l] = 0;
            pt[i] = d;
        }
        qsort(pt, n, sizeof(pt[0]), cmp_str_item);
        APP(pass ? "|ctr" : "|ctp", 4);
        for (unsigned i = 0; i < n; i++) {
            if (i && strcmp(pt[i], pt[i - 1]) == 0) continue;
            APP(",", 1);
            APP(pt[i], strlen(pt[i]));
        }
    }
    /* clients: names and prefixes, sorted unique */
    for (int pass = 0; pass < 2; pass++) {
        unsigned n = pass ? r->n_cli_restr : r->n_cli_perm;
        const fl_cli_item_t *items = pass ? r->cli_restr : r->cli_perm;
        if (!n) continue;
        const char *pt[FL_MAX_LIST];
        for (unsigned i = 0; i < n; i++) {
            const fl_cli_item_t *it = &items[i];
            char *d = tmpc + (size_t)i * IDENT_ITEM;
            if (it->kind == 'n') {
                size_t l = it->name_len > IDENT_ITEM - 2 ? IDENT_ITEM - 2 : it->name_len;
                d[0] = 'n';
                memcpy(d + 1, it->name, l);
                d[1 + l] = 0;
            } else {
                size_t k = (size_t)snprintf(d, 8, "%c%03u", it->kind == 4 ? '4' : '6', it->bits);
                for (int b = 0; b < 16; b++) k += (size_t)snprintf(d + k, 4, "%02x", it->addr[b]);
            }
            pt[i] = d;
        }
        qsort(pt, n, sizeof(pt[0]), cmp_str_item);
        APP(pass ? "|cr" : "|cp", 3);
        for (unsigned i = 0; i < n; i++) {
            if (i && strcmp(pt[i], pt[i - 1]) == 0) continue;
            APP(",", 1);
            APP(pt[i], strlen(pt[i]));
        }
    }
#undef APP
    out[o] = 0;
    return o;
}

/* ------------------------------------------------------------------------- */
/* complex rules                                                             */

#define COND_NOMEM 0xFFFFFFFFu

static uint32_t encode_conditions(fl_compiler_t *c, const fl_rule_t *r) {
    uint8_t nitems = 0;
    dc_buf_t b;
    dc_buf_init(&b);
    dc_buf_put8(&b, 0);
    if (r->n_dt_perm || r->n_dt_restr) {
        for (int pass = 0; pass < 2; pass++) {
            unsigned n = pass ? r->n_dt_restr : r->n_dt_perm;
            if (!n) continue;
            dc_buf_put8(&b, pass ? FLC_DNSTYPE_RESTR : FLC_DNSTYPE_PERM);
            dc_buf_put8(&b, (uint8_t)n);
            for (unsigned i = 0; i < n; i++) dc_buf_put16(&b, pass ? r->dt_restr[i] : r->dt_perm[i]);
            nitems++;
        }
    }
    if (r->has_ctag) {
        if (r->n_ctag_perm) {
            dc_buf_put8(&b, FLC_CTAG_PERM);
            dc_buf_put32(&b, r->ctag_perm);
            nitems++;
        }
        if (r->n_ctag_restr) {
            dc_buf_put8(&b, FLC_CTAG_RESTR);
            dc_buf_put32(&b, r->ctag_restr);
            nitems++;
        }
    }
    for (int pass = 0; pass < 2; pass++) {
        unsigned n = pass ? r->n_cli_restr : r->n_cli_perm;
        const fl_cli_item_t *items = pass ? r->cli_restr : r->cli_perm;
        if (!n) continue;
        dc_buf_put8(&b, pass ? FLC_CLIENT_RESTR : FLC_CLIENT_PERM);
        dc_buf_put8(&b, (uint8_t)n);
        for (unsigned i = 0; i < n; i++) {
            const fl_cli_item_t *it = &items[i];
            dc_buf_put8(&b, it->kind);
            if (it->kind == 'n') {
                uint8_t l = (uint8_t)(it->name_len > 255 ? 255 : it->name_len);
                dc_buf_put8(&b, l);
                dc_buf_append(&b, it->name, l);
            } else {
                dc_buf_put8(&b, it->bits);
                dc_buf_append(&b, it->addr, it->kind == 4 ? 4 : 16);
            }
        }
        nitems++;
    }
    if (r->n_deny) {
        dc_buf_put8(&b, FLC_DENYALLOW);
        dc_buf_put8(&b, r->n_deny);
        for (unsigned i = 0; i < r->n_deny; i++) {
            dc_buf_put8(&b, r->deny_len[i]);
            for (unsigned k = 0; k < r->deny_len[i]; k++) dc_buf_put8(&b, dc_lower((uint8_t)r->deny[i][k]));
        }
        nitems++;
    }
    uint32_t off = 0;
    if (b.oom) {
        off = COND_NOMEM;
    } else if (nitems) {
        b.data[0] = nitems;
        off = (uint32_t)c->pool.len;
        dc_buf_append(&c->pool, b.data, b.len);
    }
    dc_buf_free(&b);
    return off;
}

static uint32_t encode_rewrite(fl_compiler_t *c, const fl_rw_t *rw) {
    uint32_t off = (uint32_t)c->pool.len;
    uint8_t h[6] = {rw->kind, rw->rcode, 0, 0, 0, 0};
    dc_st16(h + 2, rw->rrtype);
    dc_st16(h + 4, rw->rdlen);
    dc_buf_append(&c->pool, h, 6);
    dc_buf_append(&c->pool, rw->rdata, rw->rdlen);
    return off;
}

static bool has_conditions(const fl_rule_t *r) {
    return r->n_cli_perm || r->n_cli_restr || r->has_ctag || r->n_dt_perm || r->n_dt_restr ||
           r->n_deny;
}

/* Recognizes pattern shapes equivalent to label-aligned lookups. */
static int plain_kind(const char *p, size_t n, const char **dom, size_t *dl) {
    static const struct {
        const char *pre, *suf;
        int kind;
    } shapes[] = {{"||*.", "^", FLK_STRICT}, {"||", "^|", FLK_SUFFIX_P}, {"||", "^", FLK_SUFFIX},
                  {"|", "^|", FLK_EXACT_P},  {"|", "^", FLK_EXACT},      {"://", "^", FLK_URLEXACT},
                  {"*.", "^", FLK_STRICT_S}, {".", "^", FLK_STRICT_D}};
    for (size_t i = 0; i < DC_ARRAY_SIZE(shapes); i++) {
        size_t a = strlen(shapes[i].pre), b = strlen(shapes[i].suf);
        if (n <= a + b) continue;
        if (memcmp(p, shapes[i].pre, a) != 0 || memcmp(p + n - b, shapes[i].suf, b) != 0) continue;
        const char *d = p + a;
        size_t l = n - a - b;
        if (l > FL_MAX_HOST || d[0] == '.' || d[l - 1] == '.') return -1;
        for (size_t k = 0; k < l; k++) {
            char ch = d[k];
            bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
                      ch == '.';
            if (!ok) return -1;
            if (ch == '.' && d[k + 1] == '.') return -1;
        }
        *dom = d;
        *dl = l;
        return shapes[i].kind;
    }
    return -1;
}

static int scope_of_kind(int kind) {
    switch (kind) {
    case FLK_SUFFIX:
    case FLK_SUFFIX_P:
        return FL_SCOPE_SUFFIX;
    case FLK_EXACT:
    case FLK_EXACT_P:
    case FLK_URLEXACT:
        return FL_SCOPE_EXACT;
    default:
        return FL_SCOPE_SUB;
    }
}

/* Creates a complex rule.  Returns index or -1 (rejected: counted in the
 * statistics, nothing of it stays in the pool; or c->fatal is set). */
static int add_crule(fl_compiler_t *c, const fl_rule_t *r, const char *text, size_t tl, uint8_t action,
                     int kind) {
    if (c->crules.len / sizeof(fl_crule_t) >= c->o.max_complex) {
        BUMP(unsupported);
        return -1;
    }
    size_t pool_mark = c->pool.len, tmp_mark = c->tmp.len;
#define REJECT(stat)                                                                            \
    do {                                                                                        \
        c->pool.len = pool_mark;                                                                \
        c->tmp.len = tmp_mark;                                                                  \
        BUMP(stat);                                                                             \
        return -1;                                                                              \
    } while (0)
    fl_crule_t cr;
    crinfo_t ci;
    memset(&cr, 0, sizeof(cr));
    memset(&ci, 0, sizeof(ci));
    cr.action = action;
    cr.src = (uint8_t)c->cur;
    cr.order = c->order++;
    if (r->important) cr.flags |= FL_CRF_IMPORTANT;
    cr.text_off = pool_put_str16(&c->pool, text, tl);
    char *ident = c->ident;
    size_t il = build_ident(c, r, r->pattern, r->pattern_len, ident, IDENT_MAX);
    cr.ident_hash = dc_fnv32(ident, il);
    cr.ident_off = pool_put_str16(&c->pool, ident, il);
    cr.cond_off = has_conditions(r) ? encode_conditions(c, r) : 0;
    if (cr.cond_off == COND_NOMEM) {
        set_err(c, FL_ERR_NOMEM, "out of memory (conditions)");
        return -1;
    }
    if (r->has_rewrite) cr.rw_off = encode_rewrite(c, &r->rw);

    if (kind >= 0) {
        cr.scope = (uint8_t)scope_of_kind(kind);
    } else {
        /* generic: compile the pattern program */
        bool url = false, all = false;
        char *re = c->regex_buf;
        int rl = fl_pattern_to_regex(r->pattern, r->pattern_len, re, FL_MAX_LINE * 24 + 64, &url, &all);
        if (rl < 0) REJECT(unsupported);
        cr.flags |= FL_CRF_GENERIC;
        if (url) cr.flags |= FL_CRF_URLSUBJ;
        ci.generic = 1;
        bool is_regex = r->pattern_len > 1 && r->pattern[0] == '/' && r->pattern[r->pattern_len - 1] == '/';
        bool lit_is_shortcut = false; /* (then one memmem check suffices) */
        if (all) {
            cr.flags |= FL_CRF_MATCHALL;
        } else {
            dc_buf_t prog;
            dc_buf_init(&prog);
            fl_re_info_t info;
            const char *err = NULL;
            int rc = fl_re_compile(re, (size_t)rl, FL_RE_ICASE | FL_RE_PREFER_NFA, 0, &prog, &info, &err);
            if (rc) {
                dc_buf_free(&prog);
                /* syntax error: Go fails to compile it as well, the rule matches nothing */
                if (rc == FL_RE_ESYNTAX) REJECT(never_match);
                REJECT(unsupported);
            }
            dc_buf_align(&c->pool, 4);
            cr.prog_off = (uint32_t)c->pool.len;
            dc_buf_append(&c->pool, prog.data, prog.len);
            dc_buf_free(&prog);
            BUMP(nfa);
            /* keep regex text for a possible DFA upgrade at finish */
            ci.re_off = (uint32_t)c->tmp.len;
            ci.re_len = (uint16_t)(rl > 0xFFFF ? 0xFFFF : rl);
            dc_buf_append(&c->tmp, re, (size_t)rl);
            /* prefilter literal: urlfilter shortcut (always required), else AST literal */
            const char *lit = r->shortcut_len >= 2 ? r->shortcut : info.req;
            size_t ll = r->shortcut_len >= 2 ? r->shortcut_len : info.req_len;
            if (r->shortcut_len >= 2 && info.req_len > ll && !url) {
                /* the AST literal of a hostname-subject program is also sound */
                lit = info.req;
                ll = info.req_len;
            }
            if (ll >= 2) {
                ci.lit_off = (uint32_t)c->tmp.len;
                ci.lit_len = (uint16_t)ll;
                dc_buf_append(&c->tmp, lit, ll);
                lit_is_shortcut = lit == r->shortcut && ll <= 255;
                if (ll > 255) ll = 255;
                cr.lit_off = (uint32_t)c->pool.len;
                dc_buf_put8(&c->pool, (uint8_t)ll);
                dc_buf_append(&c->pool, lit, ll);
            }
        }
        if (r->shortcut_len >= 2 && is_regex && !lit_is_shortcut) {
            cr.shortcut_off = (uint32_t)c->pool.len;
            dc_buf_put8(&c->pool, (uint8_t)r->shortcut_len);
            dc_buf_append(&c->pool, r->shortcut, r->shortcut_len);
        }
        if (is_regex) BUMP(regex);
        BUMP(generic);
    }
#undef REJECT
    if (c->pool.oom || c->tmp.oom) {
        set_err(c, FL_ERR_NOMEM, "out of memory (pool)");
        return -1;
    }
    int idx = (int)(c->crules.len / sizeof(fl_crule_t));
    dc_buf_append(&c->crules, &cr, sizeof(cr));
    dc_buf_append(&c->crinfo, &ci, sizeof(ci));
    if (c->crules.oom || c->crinfo.oom) {
        set_err(c, FL_ERR_NOMEM, "out of memory (rules)");
        return -1;
    }
    return idx;
}

static void add_bf_entry(fl_compiler_t *c, const char *ident, size_t il, uint32_t cond_off, uint32_t crule) {
    fl_bfent_t e;
    e.hash = dc_fnv32(ident, il);
    e.ident_off = pool_put_str16(&c->pool, ident, il);
    e.cond_off = cond_off;
    e.crule = crule;
    dc_buf_append(&c->bf, &e, sizeof(e));
}

static int add_badfilter(fl_compiler_t *c, const fl_rule_t *r, const char *text, size_t tl, int kind,
                         const char *key, size_t kl) {
    bool conditional = r->n_dt_perm || r->n_dt_restr || r->n_deny;
    bool plain = kind >= 0 && !has_conditions(r) && !r->perm_types && !r->restr_types;
    char *ident = c->ident;
    size_t il = build_ident(c, r, r->pattern, r->pattern_len, ident, IDENT_MAX);
    if (plain) {
        /* compile-time negation of the plain target + runtime entry */
        int rc = emit_rec(c, key, kl, REC_BF, 1ull << FLK_BIT(kind, r->whitelist, r->important));
        if (rc) return rc;
        add_bf_entry(c, ident, il, 0, 0xFFFFFFFFu);
        return 0;
    }
    if (!conditional) {
        uint32_t h = dc_fnv32(ident, il);
        dc_buf_put32(&c->bf_neg, h);
        dc_buf_put32(&c->bf_neg, pool_put_str16(&c->pool, ident, il));
        add_bf_entry(c, ident, il, 0, 0xFFFFFFFFu);
        return 0;
    }
    /* conditional: evaluated at query time */
    int idx = add_crule(c, r, text, tl, FL_ACT_BADFILTER, kind);
    if (idx < 0) return c->fatal;
    const fl_crule_t *cr = (const fl_crule_t *)c->crules.data + idx;
    fl_bfent_t e = {cr->ident_hash, cr->ident_off, cr->cond_off, (uint32_t)idx};
    dc_buf_append(&c->bf, &e, sizeof(e));
    if (kind >= 0) return emit_rec(c, key, kl, REC_CR, (uint64_t)idx);
    return 0;
}

static int process_net(fl_compiler_t *c, const fl_rule_t *r, const char *text, size_t tl) {
    bool allowlist = (c->src_flags[c->cur] & FL_SRC_ALLOWLIST) != 0;
    const char *dom = NULL;
    size_t dl = 0;
    int kind = -1;
    bool lower = true;
    for (size_t i = 0; i < r->pattern_len; i++)
        if (r->pattern[i] >= 'A' && r->pattern[i] <= 'Z') lower = false;
    if (lower) kind = plain_kind(r->pattern, r->pattern_len, &dom, &dl);
    char key[256];
    size_t kl = kind >= 0 ? fl_reverse_name(dom, dl, key) : 0;

    if (r->badfilter) {
        BUMP(badfilter);
        if (allowlist) {
            BUMP(unsupported);
            return 0;
        }
        int rc = add_badfilter(c, r, text, tl, kind, key, kl);
        /* urlfilter's DNSRewrites() ignores $badfilter: such a rule still
         * acts as a $dnsrewrite rule (see FILTER_COMPAT.md) */
        if (rc || !r->has_rewrite) return rc;
    }

    if (r->has_rewrite) {
        if (allowlist) {
            BUMP(not_dns);
            return 0;
        }
        uint8_t act = r->whitelist ? FL_ACT_REWRITE_EXC : FL_ACT_REWRITE;
        int idx = add_crule(c, r, text, tl, act, kind);
        if (idx < 0) return c->fatal;
        BUMP(dnsrewrite);
        BUMP(net_rules);
        if (kind >= 0) {
            BUMP(complex_domain);
            return emit_rec(c, key, kl, REC_CR, (uint64_t)idx);
        }
        return 0;
    }

    if (kind >= 0 && !has_conditions(r) && !r->perm_types && !r->restr_types) {
        BUMP(net_rules);
        BUMP(plain);
        uint64_t bit = allowlist ? (1ull << FLK_AL_BIT(kind))
                                 : (1ull << FLK_BIT(kind, r->whitelist, r->important));
        return emit_rec(c, key, kl, REC_MASK, bit);
    }
    uint8_t act = allowlist ? FL_ACT_ALLOWLIST : r->whitelist ? FL_ACT_ALLOW : FL_ACT_BLOCK;
    int idx = add_crule(c, r, text, tl, act, kind);
    if (idx < 0) return c->fatal;
    BUMP(net_rules);
    if (kind >= 0) {
        BUMP(complex_domain);
        return emit_rec(c, key, kl, REC_CR, (uint64_t)idx);
    }
    return 0;
}

int fl_compile_line(fl_compiler_t *c, const char *line, size_t len) {
    if (c->fatal) return c->fatal;
    if (c->cur < 0) return set_err(c, FL_ERR_STATE, "no source");
    if (c->src_reject) return c->src_reject;
    BUMP(lines);
    /* AdGuard rulelist parser: HTML pages and binary data reject the list */
    const char *t = line;
    size_t tl = len;
    while (tl && (t[0] == ' ' || t[0] == '\t' || t[0] == '\r')) {
        t++;
        tl--;
    }
    while (tl && (t[tl - 1] == ' ' || t[tl - 1] == '\t' || t[tl - 1] == '\r')) tl--;
    if (!c->src_seen_rule && tl >= 5 &&
        (dc_strnieq(t, "<html", 5) || (tl >= 9 && dc_strnieq(t, "<!doctype", 9))))
        return c->src_reject = FL_ERR_HTML;
    if (tl && t[0] != '#' && t[0] != '!') {
        for (size_t i = 0; i < tl; i++) {
            uint8_t b = (uint8_t)t[i];
            if ((b < ' ' || b == 0x7f) && b != '\t' && b != '\r' && b != '\n') {
                /* rules of this list are already in the build: it cannot be used */
                if (c->src_seen_rule) return set_err(c, FL_ERR_BINARY, "binary data inside a filter list");
                return c->src_reject = FL_ERR_BINARY;
            }
        }
        c->src_seen_rule = true;
    }

    fl_rule_t *r = c->rule;
    int k = fl_rule_parse(line, len, r);
    switch (k) {
    case FL_LINE_EMPTY:
    case FL_LINE_COMMENT:
        BUMP(empty_comment);
        return 0;
    case FL_LINE_COSMETIC:
        BUMP(cosmetic);
        return 0;
    case FL_LINE_INVALID:
        BUMP(invalid);
        return 0;
    case FL_LINE_NOTDNS:
        BUMP(not_dns);
        return 0;
    case FL_LINE_NEVER:
        BUMP(never_match);
        return 0;
    case FL_LINE_TOOWIDE:
        BUMP(too_wide);
        return 0;
    case FL_LINE_CLIENT_SKIP:
        BUMP(client_skipped);
        BUMP(unsupported);
        return 0;
    case FL_LINE_UNSUPPORTED:
        BUMP(unsupported);
        return 0;
    case FL_LINE_HOST: {
        BUMP(host_rules);
        bool allowlist = (c->src_flags[c->cur] & FL_SRC_ALLOWLIST) != 0;
        uint32_t ipi = allowlist ? 0 : ip_index(c, &r->host_ip);
        if (ipi == 0xFFFFFFFFu) {
            BUMP(unsupported);
            return 0;
        }
        for (unsigned i = 0; i < r->n_hosts; i++) {
            char key[256];
            size_t kl = make_key(r->hosts[i], r->host_len[i], key);
            if (!kl) continue;
            int rc = allowlist ? emit_rec(c, key, kl, REC_MASK, 1ull << FLK_AL_HOST_BIT)
                               : emit_rec(c, key, kl, REC_HOST, ipi);
            if (rc) return rc;
        }
        return 0;
    }
    case FL_LINE_NET: {
        /* original (trimmed) text for diagnostics */
        const char *s = line;
        size_t n = len;
        while (n && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r')) {
            s++;
            n--;
        }
        while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) n--;
        return process_net(c, r, s, n);
    }
    }
    return 0;
}

int fl_compile_feed(fl_compiler_t *c, const char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char ch = data[i];
        if (ch == '\n') {
            int rc = 0;
            if (c->line_overflow) {
                BUMP(lines);
                BUMP(too_long);
            } else {
                rc = fl_compile_line(c, c->line, c->line_len);
            }
            c->line_len = 0;
            c->line_overflow = false;
            if (rc) return rc;
            continue;
        }
        if (c->line_len >= FL_MAX_LINE) {
            c->line_overflow = true;
            continue;
        }
        c->line[c->line_len++] = ch;
    }
    return c->fatal;
}

int fl_compile_end_source(fl_compiler_t *c) {
    int rc = 0;
    if (c->src_reject) return c->src_reject;
    if (c->line_len || c->line_overflow) {
        if (c->line_overflow) {
            BUMP(lines);
            BUMP(too_long);
        } else {
            rc = fl_compile_line(c, c->line, c->line_len);
        }
        c->line_len = 0;
        c->line_overflow = false;
    }
    if (rc) return rc;
    return c->fatal;
}

/* ------------------------------------------------------------------------- */
/* merge                                                                     */

typedef struct {
    fl_compiler_t *c;
    const fl_symtab_t *symtab;
    run_t *run;
    uint32_t next_sec;  /* next sector of the chain to load */
    uint32_t loaded;    /* bytes of the run loaded so far */
    bool release;       /* recycle sectors once loaded (in-place merge) */
    uint8_t buf[2 * SEC];
    uint32_t bpos, blen;
    char key[256 + 8];
    uint8_t klen;
    bool valid;
    comb_t rec;
} rreader_t;

static int rr_fill(rreader_t *r) {
    if (r->blen - r->bpos >= RREFILL || r->loaded >= r->run->len) return 0;
    uint32_t keep = r->blen - r->bpos;
    memmove(r->buf, r->buf + r->bpos, keep);
    r->bpos = 0;
    r->blen = keep;
    while (r->loaded < r->run->len && r->blen + SEC <= sizeof(r->buf)) {
        uint32_t want = r->run->len - r->loaded;
        if (want > SEC) want = SEC;
        uint16_t s = r->run->secs[r->next_sec];
        int rc = r->c->o.runs->read(r->c->o.runs, (uint32_t)s * SEC, r->buf + r->blen, want);
        if (rc) return FL_ERR_IO;
        r->blen += want;
        r->loaded += want;
        r->next_sec++;
        if (r->release) sec_release(r->c, s); /* the bytes now live in RAM */
        if (r->blen - r->bpos >= RREFILL) break;
    }
    return 0;
}

static int rr_next(rreader_t *r) {
    r->valid = false;
    int rc = rr_fill(r);
    if (rc) return rc;
    if (r->bpos >= r->blen) return 0;
    const uint8_t *p = r->buf + r->bpos, *end = r->buf + r->blen;
    if (end - p < 2) return FL_ERR_CORRUPT;
    unsigned sh = p[0], sl = 0;
    if (sh > r->klen) return FL_ERR_CORRUPT;
    p = fl_suffix_get(r->symtab, p + 1, end, (uint8_t *)r->key + sh, 255 - sh, &sl);
    if (!p) return FL_ERR_CORRUPT;
    r->klen = (uint8_t)(sh + sl);
    p = comb_decode(p, end, &r->rec);
    if (!p) return FL_ERR_CORRUPT;
    r->bpos = (uint32_t)(p - r->buf);
    r->valid = true;
    return 0;
}

static int rr_cmp(const rreader_t *a, const rreader_t *b) {
    int r = memcmp(a->key, b->key, a->klen < b->klen ? a->klen : b->klen);
    if (r) return r;
    return (int)a->klen - (int)b->klen;
}

typedef struct {
    rreader_t **h;
    int n;
} heap_t;

static void heap_down(heap_t *hp, int i) {
    for (;;) {
        int l = 2 * i + 1, r = l + 1, m = i;
        if (l < hp->n && rr_cmp(hp->h[l], hp->h[m]) < 0) m = l;
        if (r < hp->n && rr_cmp(hp->h[r], hp->h[m]) < 0) m = r;
        if (m == i) return;
        rreader_t *t = hp->h[i];
        hp->h[i] = hp->h[m];
        hp->h[m] = t;
        i = m;
    }
}

static int run_merge(fl_compiler_t *c, merge_cb cb, void *arg, bool release) {
    int n = c->nruns;
    if (n == 0) return 0;
    rreader_t *rd = (rreader_t *)dc_calloc_ext((size_t)n, sizeof(rreader_t));
    rreader_t **hv = (rreader_t **)dc_malloc((size_t)n * sizeof(rreader_t *));
    comb_t *acc = (comb_t *)dc_malloc_ext(sizeof(comb_t));
    int rc = 0;
    if (!rd || !hv || !acc) {
        rc = FL_ERR_NOMEM;
        goto out;
    }
    heap_t hp = {hv, 0};
    for (int i = 0; i < n; i++) {
        rd[i].c = c;
        rd[i].symtab = &c->symtab;
        rd[i].run = &c->runs[i];
        rd[i].release = release;
        rc = rr_next(&rd[i]);
        if (rc) goto out;
        if (rd[i].valid) hp.h[hp.n++] = &rd[i];
    }
    for (int i = hp.n / 2 - 1; i >= 0; i--) heap_down(&hp, i);
    char key[256];
    uint32_t done = 0;
    while (hp.n) {
        rreader_t *top = hp.h[0];
        unsigned kl = top->klen;
        memcpy(key, top->key, kl);
        comb_reset(acc);
        while (hp.n && hp.h[0]->klen == kl && memcmp(hp.h[0]->key, key, kl) == 0) {
            rreader_t *t = hp.h[0];
            c->st.unsupported += comb_merge(acc, &t->rec);
            rc = rr_next(t);
            if (rc) goto out;
            if (!t->valid) hp.h[0] = hp.h[--hp.n];
            if (hp.n) heap_down(&hp, 0);
        }
        rc = cb(c, arg, key, kl, acc);
        if (rc) goto out;
        if ((++done & 0x3FFF) == 0 && c->o.progress &&
            !c->o.progress(c->o.progress_arg, "merge", done, 0)) {
            rc = FL_ERR_ABORT;
            goto out;
        }
    }
out:
    dc_free(rd);
    dc_free(hv);
    dc_free(acc);
    return rc;
}

/* applies compile-time negation; returns false if nothing remains */
static bool finalize_comb(fl_compiler_t *c, comb_t *cb) {
    uint64_t neg = cb->bf;
    cb->mask &= ~neg;
    const crinfo_t *ci = (const crinfo_t *)c->crinfo.data;
    unsigned w = 0;
    for (unsigned i = 0; i < cb->ncr; i++)
        if (!ci[cb->cr[i]].disabled) cb->cr[w++] = cb->cr[i];
    cb->ncr = (uint16_t)w;
    /* sort complex ids (global order) */
    for (unsigned i = 1; i < cb->ncr; i++) {
        uint32_t v = cb->cr[i];
        unsigned j = i;
        while (j && cb->cr[j - 1] > v) {
            cb->cr[j] = cb->cr[j - 1];
            j--;
        }
        cb->cr[j] = v;
    }
    return cb->mask || cb->nips || cb->ncr;
}

typedef struct {
    uint32_t nkeys;
    uint32_t onelabel;
} count_t;

static int count_cb(fl_compiler_t *c, void *arg, const char *key, unsigned kl, comb_t *cb) {
    count_t *ct = (count_t *)arg;
    if (!finalize_comb(c, cb)) return 0;
    ct->nkeys++;
    if (!memchr(key, '.', kl)) ct->onelabel++;
    return 0;
}

typedef struct {
    fl_store_t *sink;
    uint32_t keys_base;
    uint32_t keys_len;
    uint32_t crc_keys;
    uint8_t *bloom;
    uint32_t bloom_blocks;
    uint32_t *blkoff;
    uint32_t nblocks;
    uint64_t *samples;
    uint32_t nsamples;
    uint32_t sample_step;
    uint32_t *onelabel;
    uint32_t nonelabel;
    dc_buf_t block;
    unsigned in_block;
    char prev[256];
    unsigned prevlen;
    uint32_t nkeys;
    bool multisrc;
    /* hostsets */
    dc_buf_t hs_off; /* u32 pool offsets */
    dc_buf_t hs_keys; /* tmp: concatenated sorted ip index lists, u32 off/len pairs in hs_idx */
    dc_buf_t hs_idx;
    uint32_t nhostsets;
    int err;
} build_t;

static int flush_block(fl_compiler_t *c, build_t *b) {
    (void)c;
    if (!b->in_block) return 0;
    int rc = b->sink->write(b->sink, b->keys_base + b->keys_len, b->block.data, b->block.len);
    if (rc) return rc == FL_ERR_FULL ? FL_ERR_FULL : FL_ERR_IO;
    b->crc_keys = dc_crc32(b->crc_keys, b->block.data, b->block.len);
    b->keys_len += (uint32_t)b->block.len;
    b->block.len = 0;
    b->in_block = 0;
    return 0;
}

static uint32_t hostset_id(fl_compiler_t *c, build_t *b, comb_t *cb) {
    /* sort ip indices for a canonical set */
    for (unsigned i = 1; i < cb->nips; i++) {
        uint32_t v = cb->ips[i];
        unsigned j = i;
        while (j && cb->ips[j - 1] > v) {
            cb->ips[j] = cb->ips[j - 1];
            j--;
        }
        cb->ips[j] = v;
    }
    const uint32_t *idx = (const uint32_t *)b->hs_idx.data;
    for (uint32_t s = 0; s < b->nhostsets; s++) {
        if (idx[2 * s + 1] != cb->nips) continue;
        if (memcmp(b->hs_keys.data + idx[2 * s], cb->ips, cb->nips * 4) == 0) return s;
    }
    dc_buf_put32(&b->hs_idx, (uint32_t)b->hs_keys.len);
    dc_buf_put32(&b->hs_idx, cb->nips);
    dc_buf_append(&b->hs_keys, cb->ips, cb->nips * 4);
    /* pool encoding: u8 n4, u8 n6, addrs */
    const dc_ip_t *ips = (const dc_ip_t *)c->ips.data;
    uint8_t n4 = 0, n6 = 0;
    for (unsigned i = 0; i < cb->nips; i++) {
        if (ips[cb->ips[i]].family == 4)
            n4++;
        else
            n6++;
    }
    dc_buf_put32(&b->hs_off, (uint32_t)c->pool.len);
    dc_buf_put8(&c->pool, n4);
    dc_buf_put8(&c->pool, n6);
    for (int fam = 4; fam <= 6; fam += 2)
        for (unsigned i = 0; i < cb->nips; i++)
            if (ips[cb->ips[i]].family == fam) dc_buf_append(&c->pool, ips[cb->ips[i]].addr, fam == 4 ? 4 : 16);
    return b->nhostsets++;
}

static int build_cb(fl_compiler_t *c, void *arg, const char *key, unsigned kl, comb_t *cb) {
    build_t *b = (build_t *)arg;
    if (!finalize_comb(c, cb)) return 0;
    uint32_t h = dc_fnv32(key, kl);
    /* bloom */
    uint32_t blk = fl_bloom_block(h, b->bloom_blocks);
    uint8_t pos[6];
    fl_bloom_bits(h, pos);
    uint8_t *bb = b->bloom + (size_t)blk * FLI_BLOOM_BLOCK;
    for (int i = 0; i < 6; i++) bb[pos[i] >> 3] |= (uint8_t)(1u << (pos[i] & 7));
    if (!memchr(key, '.', kl)) b->onelabel[b->nonelabel++] = h;

    /* block boundaries */
    if (b->in_block == 0) {
        b->blkoff[b->nblocks] = b->keys_len;
        if (b->nblocks % b->sample_step == 0) {
            uint64_t pfx = 0;
            for (unsigned i = 0; i < 8; i++) pfx = (pfx << 8) | (i < kl ? (uint8_t)key[i] : 0);
            b->samples[b->nsamples++] = pfx;
        }
        b->nblocks++;
        b->prevlen = 0;
    }
    unsigned sh = 0;
    while (sh < b->prevlen && sh < kl && b->prev[sh] == key[sh]) sh++;
    uint8_t hdr[1 + 2 + 2 * 256];
    hdr[0] = (uint8_t)sh;
    size_t hl = 1 + fl_suffix_put(&c->symtab, (const uint8_t *)key + sh, kl - sh, hdr + 1);
    dc_buf_append(&b->block, hdr, hl);
    memcpy(b->prev, key, kl);
    b->prevlen = kl;

    /* payload */
    uint64_t m = cb->mask;
    const uint64_t simple = (1ull << FLK_BIT(FLK_SUFFIX, 0, 0)) | (1ull << FLK_BIT(FLK_SUFFIX, 1, 0));
    uint8_t m0 = 0;
    if (m & ~simple) {
        m0 |= FLP_EXT;
    } else {
        if (m & (1ull << FLK_BIT(FLK_SUFFIX, 0, 0))) m0 |= FLP_SUFFIX_BLOCK;
        if (m & (1ull << FLK_BIT(FLK_SUFFIX, 1, 0))) m0 |= FLP_SUFFIX_ALLOW;
    }
    if (cb->nips) m0 |= FLP_HOSTS;
    if (cb->ncr) m0 |= FLP_COMPLEX;
    if (b->multisrc) m0 |= FLP_SRC;
    uint8_t pay[48];
    size_t pl = 0;
    pay[pl++] = m0;
    if (m0 & FLP_EXT) pl += dc_varint_put(pay + pl, m);
    if (m0 & FLP_HOSTS) pl += dc_varint_put(pay + pl, hostset_id(c, b, cb));
    if (m0 & FLP_COMPLEX) {
        uint32_t goff = (uint32_t)c->pool.len;
        dc_buf_putv(&c->pool, cb->ncr);
        uint32_t prev = 0;
        for (unsigned i = 0; i < cb->ncr; i++) {
            dc_buf_putv(&c->pool, cb->cr[i] - prev);
            prev = cb->cr[i];
        }
        pl += dc_varint_put(pay + pl, goff);
    }
    if (m0 & FLP_SRC) pl += dc_varint_put(pay + pl, cb->src);
    dc_buf_append(&b->block, pay, pl);
    if (b->block.oom || c->pool.oom) return FL_ERR_NOMEM;
    b->nkeys++;
    if (++b->in_block >= c->o.block_entries) return flush_block(c, b);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* generic index                                                             */

static bool is_common_ngram(const char *g, unsigned n) {
    static const char *const common[] = {".com", "com.", "http", "ttp:", "tp:/", "p://", "://",
                                         ".net", ".org", "www.", ".cn",  "com",  "www",  ".co",
                                         "net",  "org",  "cdn",  "api",  "-",    ".",    "co",
                                         "om",   "ww",   "tp",   "ht",   ":/",   "//"};
    for (size_t i = 0; i < DC_ARRAY_SIZE(common); i++)
        if (strlen(common[i]) == n && memcmp(common[i], g, n) == 0) return true;
    return false;
}

typedef struct {
    uint32_t key;
    uint32_t rule;
} ngent_t;

static uint32_t freq_slot(const uint32_t *fk, uint32_t cap, uint32_t k) {
    uint32_t h = fl_ngram_hash(k) & (cap - 1);
    while (fk[h] && fk[h] != k) h = (h + 1) & (cap - 1);
    return h;
}

static int cmp_ngent(const void *a, const void *b) {
    const ngent_t *x = (const ngent_t *)a, *y = (const ngent_t *)b;
    if (x->key != y->key) return x->key < y->key ? -1 : 1;
    return x->rule < y->rule ? -1 : x->rule > y->rule;
}

#define ALWAYS_NFA_BUDGET 4096 /* NFA instructions run for every query (rules without a literal) */

/* Replaces the NFA program of rule i by a DFA when it can be built within
 * the DFA byte budget.  Returns true if the rule now has a DFA. */
static bool try_dfa(fl_compiler_t *c, uint32_t i) {
    fl_crule_t *cr = (fl_crule_t *)c->crules.data + i;
    crinfo_t *ci = (crinfo_t *)c->crinfo.data + i;
    if (c->pool.data[cr->prog_off] == 'D') return true;
    if (c->dfa_bytes + 256 > c->o.dfa_budget_bytes) return false;
    dc_buf_t prog;
    dc_buf_init(&prog);
    fl_re_info_t info;
    const char *err;
    int rc = fl_re_compile((const char *)c->tmp.data + ci->re_off, ci->re_len, FL_RE_ICASE, c->o.max_dfa_states,
                           &prog, &info, &err);
    bool ok = rc == 0 && info.dfa_states && c->dfa_bytes + prog.len <= c->o.dfa_budget_bytes;
    if (ok) {
        dc_buf_align(&c->pool, 4);
        cr->prog_off = (uint32_t)c->pool.len;
        dc_buf_append(&c->pool, prog.data, prog.len);
        c->dfa_bytes += (uint32_t)prog.len;
        c->st.dfa++;
        c->st.nfa--;
        ci->hot = 0; /* (done) */
    }
    dc_buf_free(&prog);
    return ok;
}

static int build_generic(fl_compiler_t *c, dc_buf_t *out) {
    uint32_t ncr = (uint32_t)(c->crules.len / sizeof(fl_crule_t));
    fl_crule_t *cr = (fl_crule_t *)c->crules.data;
    crinfo_t *ci = (crinfo_t *)c->crinfo.data;
    dc_buf_t always, ents[3];
    dc_buf_init(&always);
    for (int i = 0; i < 3; i++) dc_buf_init(&ents[i]);

    /* n-gram frequency over all candidate literals (to pick rare ones) */
    uint32_t freq_cap = 4096;
    uint32_t *fk = (uint32_t *)dc_calloc_ext(freq_cap, sizeof(uint32_t));
    uint32_t *fv = (uint32_t *)dc_calloc_ext(freq_cap, sizeof(uint32_t));
    if (!fk || !fv) {
        dc_free(fk);
        dc_free(fv);
        return FL_ERR_NOMEM;
    }
#define FREQ_SLOT(k) freq_slot(fk, freq_cap, (k))
    uint32_t nfreq = 0;
    for (uint32_t i = 0; i < ncr; i++) {
        if (!ci[i].generic || ci[i].disabled || ci[i].lit_len < 2) continue;
        const uint8_t *lit = c->tmp.data + ci[i].lit_off;
        unsigned n = ci[i].lit_len >= 4 ? 4 : ci[i].lit_len;
        for (unsigned p = 0; p + n <= ci[i].lit_len; p++) {
            uint32_t k = fl_ngram_key(lit + p, n);
            if (nfreq * 2 >= freq_cap) break;
            uint32_t s = FREQ_SLOT(k);
            if (!fk[s]) {
                fk[s] = k;
                nfreq++;
            }
            fv[s]++;
        }
    }
    uint32_t always_cost = 0;
    for (uint32_t i = 0; i < ncr; i++) {
        if (!ci[i].generic || ci[i].disabled) continue;
        if (ci[i].lit_len < 2 || (cr[i].flags & FL_CRF_MATCHALL)) {
            /* checked for every query: as a DFA, or within a total NFA budget */
            if (!(cr[i].flags & FL_CRF_MATCHALL) && !try_dfa(c, i)) {
                uint32_t ninst = dc_ld16(c->pool.data + cr[i].prog_off + 2);
                if (always_cost + ninst > ALWAYS_NFA_BUDGET) {
                    ci[i].disabled = 1;
                    c->st.unsupported++;
                    c->st.nfa--;
                    continue;
                }
                always_cost += ninst;
            }
            dc_buf_put32(&always, i);
            continue;
        }
        const uint8_t *lit = c->tmp.data + ci[i].lit_off;
        unsigned n = ci[i].lit_len >= 4 ? 4 : ci[i].lit_len;
        uint32_t best_k = 0, best_score = 0xFFFFFFFFu;
        for (unsigned p = 0; p + n <= ci[i].lit_len; p++) {
            uint32_t k = fl_ngram_key(lit + p, n);
            uint32_t s = FREQ_SLOT(k);
            uint32_t score = (fk[s] == k ? fv[s] : 1) * 4;
            if (is_common_ngram((const char *)lit + p, n)) score += 1000;
            if (score < best_score) {
                best_score = score;
                best_k = k;
            }
        }
        ngent_t e = {best_k, i};
        dc_buf_append(&ents[n - 2], &e, sizeof(e));
        if (n == 2 || best_score >= 1000) ci[i].hot = 1;
    }
#undef FREQ_SLOT
    dc_free(fk);
    dc_free(fv);

    /* serialize */
    uint32_t na = (uint32_t)(always.len / 4);
    dc_buf_put32(out, na);
    dc_buf_append(out, always.data, always.len);
    for (int g = 0; g < 3; g++) {
        size_t ne = ents[g].len / sizeof(ngent_t);
        ngent_t *e = (ngent_t *)ents[g].data;
        if (ne) qsort(e, ne, sizeof(ngent_t), cmp_ngent);
        size_t distinct = 0;
        for (size_t i = 0; i < ne; i++)
            if (i == 0 || e[i].key != e[i - 1].key) distinct++;
        uint32_t nb = 1;
        while (nb < distinct * 2) nb <<= 1;
        if (!distinct) nb = 0;
        uint32_t bl2 = 9;
        while ((1u << bl2) < distinct * 16 && bl2 < 14) bl2++;
        if (!distinct) bl2 = 3;
        dc_buf_put32(out, nb);
        dc_buf_put32(out, bl2);
        size_t bm_off = out->len;
        dc_buf_zero(out, (1u << bl2) / 8);
        size_t bk_off = out->len;
        dc_buf_zero(out, (size_t)nb * 8);
        if (out->oom) break;
        for (size_t i = 0; i < ne;) {
            size_t j = i;
            while (j < ne && e[j].key == e[i].key) j++;
            uint32_t loff = (uint32_t)c->pool.len;
            dc_buf_putv(&c->pool, j - i);
            uint32_t prev = 0;
            for (size_t k = i; k < j; k++) {
                dc_buf_putv(&c->pool, e[k].rule - prev);
                prev = e[k].rule;
            }
            uint32_t hh = fl_ngram_hash(e[i].key);
            uint32_t bit = hh >> (32 - bl2);
            out->data[bm_off + bit / 8] |= (uint8_t)(1u << (bit & 7));
            uint32_t slot = hh & (nb - 1);
            while (dc_ld32(out->data + bk_off + slot * 8)) slot = (slot + 1) & (nb - 1);
            dc_st32(out->data + bk_off + slot * 8, e[i].key);
            dc_st32(out->data + bk_off + slot * 8 + 4, loff);
            i = j;
        }
    }
    dc_buf_free(&always);
    for (int i = 0; i < 3; i++) dc_buf_free(&ents[i]);
    return out->oom || c->pool.oom ? FL_ERR_NOMEM : 0;
}

/* Upgrades hot generic programs to DFAs within the byte budget. */
/* DFAs for the rules checked often (short or common n-grams), while the
 * budget lasts; stops after a long series of failures (hostile lists) */
static int upgrade_dfas(fl_compiler_t *c) {
    uint32_t ncr = (uint32_t)(c->crules.len / sizeof(fl_crule_t));
    const fl_crule_t *cr = (const fl_crule_t *)c->crules.data;
    const crinfo_t *ci = (const crinfo_t *)c->crinfo.data;
    unsigned fails = 0, tried = 0;
    for (uint32_t i = 0; i < ncr && fails < 256 && c->dfa_bytes + 256 <= c->o.dfa_budget_bytes; i++) {
        if (!ci[i].generic || ci[i].disabled || !ci[i].hot || !cr[i].prog_off) continue;
        if ((++tried & 63) == 0 && c->o.progress && !c->o.progress(c->o.progress_arg, "dfa", i, ncr))
            return FL_ERR_ABORT;
        fails = try_dfa(c, i) ? 0 : fails + 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* CRC32 combination (zlib crc32_combine)                                    */

static uint32_t gf2_times(const uint32_t *mat, uint32_t vec) {
    uint32_t sum = 0;
    while (vec) {
        if (vec & 1) sum ^= *mat;
        vec >>= 1;
        mat++;
    }
    return sum;
}

static void gf2_square(uint32_t *sq, const uint32_t *mat) {
    for (int n = 0; n < 32; n++) sq[n] = gf2_times(mat, mat[n]);
}

static uint32_t crc32_combine(uint32_t crc1, uint32_t crc2, uint64_t len2) {
    uint32_t even[32], odd[32];
    if (len2 == 0) return crc1;
    odd[0] = 0xedb88320u;
    uint32_t row = 1;
    for (int n = 1; n < 32; n++) {
        odd[n] = row;
        row <<= 1;
    }
    gf2_square(even, odd);
    gf2_square(odd, even);
    do {
        gf2_square(even, odd);
        if (len2 & 1) crc1 = gf2_times(even, crc1);
        len2 >>= 1;
        if (len2 == 0) break;
        gf2_square(odd, even);
        if (len2 & 1) crc1 = gf2_times(odd, crc1);
        len2 >>= 1;
    } while (len2);
    return crc1 ^ crc2;
}

/* ------------------------------------------------------------------------- */

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

static int cmp_bf(const void *a, const void *b) {
    const fl_bfent_t *x = (const fl_bfent_t *)a, *y = (const fl_bfent_t *)b;
    return x->hash < y->hash ? -1 : x->hash > y->hash;
}

static uint32_t align8(uint32_t v) { return (v + 7u) & ~7u; }

int fl_compile_finish(fl_compiler_t *c, fl_store_t *sink, fl_stats_t *stats_out) {
    if (c->fatal) return c->fatal;
    int rc = flush_chunk(c);
    if (rc) return rc;
    if (c->o.progress && !c->o.progress(c->o.progress_arg, "merge", 0, 0))
        return set_err(c, FL_ERR_ABORT, "aborted");

    /* ---- resolve unconditional complex $badfilter ---- */
    uint32_t ncr = (uint32_t)(c->crules.len / sizeof(fl_crule_t));
    {
        fl_crule_t *cr = (fl_crule_t *)c->crules.data;
        crinfo_t *ci = (crinfo_t *)c->crinfo.data;
        size_t nneg = c->bf_neg.len / 8;
        const uint8_t *ng = c->bf_neg.data;
        for (uint32_t i = 0; i < ncr && nneg; i++) {
            if (cr[i].action == FL_ACT_BADFILTER || cr[i].action == FL_ACT_ALLOWLIST ||
                cr[i].action == FL_ACT_REWRITE || cr[i].action == FL_ACT_REWRITE_EXC)
                continue;
            for (size_t k = 0; k < nneg; k++) {
                if (dc_ld32(ng + k * 8) != cr[i].ident_hash) continue;
                uint16_t l1, l2;
                const char *a = fl_pool_str(c->pool.data, cr[i].ident_off, &l1);
                const char *b = fl_pool_str(c->pool.data, dc_ld32(ng + k * 8 + 4), &l2);
                if (l1 == l2 && memcmp(a, b, l1) == 0) {
                    ci[i].disabled = 1;
                    c->st.negated++;
                    break;
                }
            }
        }
    }

    /* ---- pass 1: count ---- */
    count_t ct = {0, 0};
    rc = run_merge(c, count_cb, &ct, false);
    if (rc) return set_err(c, rc, "merge (count) failed");

    build_t *b = (build_t *)dc_calloc_ext(1, sizeof(build_t));
    if (!b) return set_err(c, FL_ERR_NOMEM, "out of memory");
    dc_buf_init(&b->block);
    dc_buf_init(&b->hs_off);
    dc_buf_init(&b->hs_keys);
    dc_buf_init(&b->hs_idx);
    b->sink = sink;
    b->crc_keys = 0;
    b->multisrc = c->nsrc > 1;
    uint32_t nblocks_max = (ct.nkeys + c->o.block_entries - 1) / c->o.block_entries;
    b->sample_step = 8;
    while (nblocks_max / b->sample_step > 2048) b->sample_step *= 2;
    uint32_t nsamples_max = (nblocks_max + b->sample_step - 1) / b->sample_step;
    b->bloom_blocks = (uint32_t)(((uint64_t)ct.nkeys * c->o.bloom_bits_per_key + 255) / 256);
    if (b->bloom_blocks == 0) b->bloom_blocks = 1;
    b->bloom = (uint8_t *)dc_calloc_ext(b->bloom_blocks, FLI_BLOOM_BLOCK);
    b->blkoff = (uint32_t *)dc_calloc_ext(nblocks_max + 1, sizeof(uint32_t));
    b->samples = (uint64_t *)dc_calloc_ext(nsamples_max + 1, sizeof(uint64_t));
    b->onelabel = (uint32_t *)dc_calloc_ext(ct.onelabel + 1, sizeof(uint32_t));
    if (!b->bloom || !b->blkoff || !b->samples || !b->onelabel) {
        rc = set_err(c, FL_ERR_NOMEM, "out of memory (index)");
        goto out;
    }

    uint32_t off = FLI_HDR_SIZE;
    fli_header_t h;
    memset(&h, 0, sizeof(h));
    h.sec[FLS_BLOOM].off = off;
    h.sec[FLS_BLOOM].len = b->bloom_blocks * FLI_BLOOM_BLOCK;
    off = align8(off + h.sec[FLS_BLOOM].len);
    h.sec[FLS_SAMPLES].off = off;
    h.sec[FLS_SAMPLES].len = nsamples_max * 8;
    off = align8(off + h.sec[FLS_SAMPLES].len);
    h.sec[FLS_BLKOFF].off = off;
    h.sec[FLS_BLKOFF].len = (nblocks_max + 1) * 4;
    off = align8(off + h.sec[FLS_BLKOFF].len);
    h.sec[FLS_ONELABEL].off = off;
    h.sec[FLS_ONELABEL].len = ct.onelabel * 4;
    off = align8(off + h.sec[FLS_ONELABEL].len);
    h.sec[FLS_KEYS].off = off;
    b->keys_base = off;

    /* ---- pass 2: build ---- */
    rc = run_merge(c, build_cb, b, false);
    if (!rc) rc = flush_block(c, b);
    if (rc) {
        rc = set_err(c, rc, rc == FL_ERR_FULL ? "rule image exceeds partition size" : "merge (build) failed");
        goto out;
    }
    b->blkoff[b->nblocks] = b->keys_len;
    h.sec[FLS_KEYS].len = b->keys_len;
    if (b->nblocks != nblocks_max || b->nkeys != ct.nkeys) {
        rc = set_err(c, FL_ERR_CORRUPT, "merge pass mismatch");
        goto out;
    }
    qsort(b->onelabel, b->nonelabel, sizeof(uint32_t), cmp_u32);

    /* ---- generic index, DFA upgrade, tails ---- */
    {
        dc_buf_t gen;
        dc_buf_init(&gen);
        rc = build_generic(c, &gen);
        if (!rc) rc = upgrade_dfas(c);
        dc_buf_t tail; /* hostsets | crules | generic | badfilter | sources */
        dc_buf_init(&tail);
        uint32_t toff = align8(h.sec[FLS_KEYS].off + h.sec[FLS_KEYS].len);
        uint32_t base = toff;
        h.sec[FLS_HOSTSETS].off = toff;
        h.sec[FLS_HOSTSETS].len = (uint32_t)b->hs_off.len;
        dc_buf_append(&tail, b->hs_off.data, b->hs_off.len);
        dc_buf_align(&tail, 8);
        h.sec[FLS_CRULES].off = base + (uint32_t)tail.len;
        h.sec[FLS_CRULES].len = (uint32_t)c->crules.len;
        dc_buf_append(&tail, c->crules.data, c->crules.len);
        dc_buf_align(&tail, 8);
        h.sec[FLS_GENERIC].off = base + (uint32_t)tail.len;
        h.sec[FLS_GENERIC].len = (uint32_t)gen.len;
        dc_buf_append(&tail, gen.data, gen.len);
        dc_buf_align(&tail, 8);
        size_t nbf = c->bf.len / sizeof(fl_bfent_t);
        if (nbf) qsort(c->bf.data, nbf, sizeof(fl_bfent_t), cmp_bf);
        h.sec[FLS_BADFILTER].off = base + (uint32_t)tail.len;
        h.sec[FLS_BADFILTER].len = (uint32_t)c->bf.len;
        dc_buf_append(&tail, c->bf.data, c->bf.len);
        dc_buf_align(&tail, 8);
        h.sec[FLS_SOURCES].off = base + (uint32_t)tail.len;
        for (int i = 0; i < c->nsrc; i++) {
            fl_srcent_t se;
            memset(&se, 0, sizeof(se));
            se.name_off = pool_put_str16(&c->pool, c->src_name[i], strlen(c->src_name[i]));
            se.flags = c->src_flags[i];
            se.rules = c->sst[i].plain + c->sst[i].complex_domain + c->sst[i].generic + c->sst[i].host_rules;
            dc_buf_append(&tail, &se, sizeof(se));
        }
        h.sec[FLS_SOURCES].len = (uint32_t)(c->nsrc * sizeof(fl_srcent_t));
        dc_buf_align(&tail, 8);
        {
            h.sec[FLS_SYMTAB].off = base + (uint32_t)tail.len;
            h.sec[FLS_SYMTAB].len = FL_SYMTAB_BYTES;
            size_t st_off = tail.len;
            if (dc_buf_zero(&tail, FL_SYMTAB_BYTES))
                fl_fsst_serialize(&c->symtab, tail.data + st_off);
            dc_buf_align(&tail, 8);
        }
        h.sec[FLS_POOL].off = base + (uint32_t)tail.len;
        h.sec[FLS_POOL].len = (uint32_t)c->pool.len;
        dc_buf_free(&gen);
        if (rc || tail.oom || c->pool.oom || c->bf.oom || c->bf_neg.oom || c->ips.oom || b->hs_off.oom) {
            dc_buf_free(&tail);
            rc = set_err(c, rc ? rc : FL_ERR_NOMEM, rc == FL_ERR_ABORT ? "aborted" : "out of memory (tables)");
            goto out;
        }
        uint32_t total = h.sec[FLS_POOL].off + h.sec[FLS_POOL].len;
        if (total > sink->capacity) {
            dc_buf_free(&tail);
            rc = set_err(c, FL_ERR_FULL, "rule image exceeds partition size");
            goto out;
        }
        /* write tail and pool */
        rc = sink->write(sink, base, tail.data, tail.len);
        if (!rc) rc = sink->write(sink, h.sec[FLS_POOL].off, c->pool.data, c->pool.len);
        /* write head sections (bloom, samples, blkoff, onelabel) */
        uint8_t pad[8] = {0};
        dc_buf_t head;
        dc_buf_init(&head);
        dc_buf_append(&head, b->bloom, h.sec[FLS_BLOOM].len);
        dc_buf_align(&head, 8);
        for (uint32_t i = 0; i < b->nsamples; i++) {
            uint8_t t[8];
            dc_st64(t, b->samples[i]);
            dc_buf_append(&head, t, 8);
        }
        dc_buf_align(&head, 8);
        for (uint32_t i = 0; i <= b->nblocks; i++) dc_buf_put32(&head, b->blkoff[i]);
        dc_buf_align(&head, 8);
        for (uint32_t i = 0; i < b->nonelabel; i++) dc_buf_put32(&head, b->onelabel[i]);
        dc_buf_align(&head, 8);
        (void)pad;
        if (head.oom) rc = FL_ERR_NOMEM;
        if (!rc && FLI_HDR_SIZE + head.len != h.sec[FLS_KEYS].off) rc = FL_ERR_CORRUPT;
        if (!rc) rc = sink->write(sink, FLI_HDR_SIZE, head.data, head.len);

        /* CRC over [hdr, total) in file order */
        uint32_t crc = dc_crc32(0, head.data, head.len);
        crc = crc32_combine(crc, b->crc_keys, b->keys_len);
        uint32_t gap = base - (h.sec[FLS_KEYS].off + h.sec[FLS_KEYS].len);
        if (gap) {
            /* alignment gap after KEYS: write zeros so the CRC is defined */
            if (!rc) rc = sink->write(sink, h.sec[FLS_KEYS].off + h.sec[FLS_KEYS].len, pad, gap);
            crc = dc_crc32(crc, pad, gap);
        }
        crc = dc_crc32(crc, tail.data, tail.len);
        crc = dc_crc32(crc, c->pool.data, c->pool.len);
        dc_buf_free(&head);
        dc_buf_free(&tail);
        if (rc) {
            rc = set_err(c, rc == FL_ERR_FULL ? rc : FL_ERR_IO, "image write failed");
            goto out;
        }

        /* header */
        c->st.keys = b->nkeys;
        c->st.image_bytes = total;
        c->st.compile_ms = (uint32_t)((dc_time_us() - c->t0) / 1000);
        h.magic = FLI_MAGIC;
        h.version = FLI_VERSION;
        h.hdr_size = FLI_HDR_SIZE;
        h.total_len = total;
        h.crc32 = crc;
        h.generation = c->o.generation;
        h.build_time = dc_wall_time();
        h.flags = 0;
        h.n_keys = b->nkeys;
        h.n_blocks = b->nblocks;
        h.block_entries = c->o.block_entries;
        h.sample_step = (uint16_t)b->sample_step;
        h.n_samples = b->nsamples;
        h.bloom_blocks = b->bloom_blocks;
        h.n_onelabel = b->nonelabel;
        h.n_hostsets = b->nhostsets;
        h.n_crules = ncr;
        h.n_badfilter = (uint32_t)nbf;
        h.n_sources = (uint32_t)c->nsrc;
        h.stats = c->st;
        h.hdr_crc32 = 0;
        uint8_t hb[FLI_HDR_SIZE];
        memset(hb, 0, sizeof(hb));
        memcpy(hb, &h, sizeof(h));
        uint32_t hc = dc_crc32(0, hb, sizeof(hb));
        ((fli_header_t *)hb)->hdr_crc32 = hc;
        if (c->o.progress && !c->o.progress(c->o.progress_arg, "verify", 0, total)) {
            rc = set_err(c, FL_ERR_ABORT, "aborted");
            goto out;
        }
        /* verify body by reading it back before committing the header */
        uint8_t *vb = (uint8_t *)dc_malloc_ext(8192);
        if (!vb) {
            rc = set_err(c, FL_ERR_NOMEM, "out of memory");
            goto out;
        }
        uint32_t vcrc = 0;
        for (uint32_t p = FLI_HDR_SIZE; p < total && !rc;) {
            uint32_t chunk = total - p > 8192 ? 8192 : total - p;
            rc = sink->read(sink, p, vb, chunk);
            vcrc = dc_crc32(vcrc, vb, chunk);
            p += chunk;
        }
        dc_free(vb);
        if (rc || vcrc != crc) {
            rc = set_err(c, FL_ERR_CORRUPT, "image verification failed");
            goto out;
        }
        rc = sink->write(sink, 0, hb, sizeof(hb));
        if (rc) {
            rc = set_err(c, FL_ERR_IO, "header write failed");
            goto out;
        }
        if (stats_out) *stats_out = c->st;
        rc = (int)total;
    }

out:
    dc_buf_free(&b->block);
    dc_buf_free(&b->hs_off);
    dc_buf_free(&b->hs_keys);
    dc_buf_free(&b->hs_idx);
    dc_free(b->bloom);
    dc_free(b->blkoff);
    dc_free(b->samples);
    dc_free(b->onelabel);
    dc_free(b);
    return rc;
}
