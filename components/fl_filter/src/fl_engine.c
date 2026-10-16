/*
 * fl_engine.c - image loading/validation and the query-time matcher.
 *
 * Query flow for "a.b.example.com" (reversed: "com.example.b.a"):
 *   for every label level ("com", "com.example", ...):
 *       1-label level -> sorted hash table in internal RAM
 *       otherwise     -> blocked Bloom filter (one 32-byte cache line)
 *       on hit        -> sample index (internal RAM) -> block binary search
 *                        -> front-coded block scan -> exact key compare
 *   generic rules: n-gram bitmap probes over "http://"+host, then the
 *   bounded DFA/NFA program of each candidate.
 *   Priorities follow AdGuard Home (filtering.go / urlfilter rules/match.go).
 */
#include <stdio.h>
#include <string.h>

#include "fl_internal.h"

#define TAG "fl"

/* ------------------------------------------------------------------------- */
/* loading                                                                   */

static bool sec_ok(const fli_header_t *h, int s, uint32_t total) {
    const fli_sec_t *x = &h->sec[s];
    if (x->len == 0) return x->off <= total;
    if (x->off < FLI_HDR_SIZE || (x->off & 3)) return false;
    return (uint64_t)x->off + x->len <= total;
}

static bool pool_ok(const fl_image_t *im, uint32_t off, uint32_t need) {
    return off && (uint64_t)off + need <= im->pool_len;
}

static bool str16_ok(const fl_image_t *im, uint32_t off) {
    if (!pool_ok(im, off, 2)) return false;
    return pool_ok(im, off, 2u + dc_ld16(im->pool + off));
}

static bool cond_ok(const fl_image_t *im, uint32_t off) {
    if (!off) return true;
    if (!pool_ok(im, off, 1)) return false;
    const uint8_t *p = im->pool + off, *end = im->pool + im->pool_len;
    unsigned n = *p++;
    for (unsigned i = 0; i < n; i++) {
        if (p >= end) return false;
        uint8_t t = *p++;
        switch (t) {
        case FLC_DNSTYPE_PERM:
        case FLC_DNSTYPE_RESTR: {
            if (p >= end) return false;
            unsigned k = *p++;
            if ((size_t)(end - p) < k * 2u) return false;
            p += k * 2;
            break;
        }
        case FLC_CTAG_PERM:
        case FLC_CTAG_RESTR:
            if (end - p < 4) return false;
            p += 4;
            break;
        case FLC_CLIENT_PERM:
        case FLC_CLIENT_RESTR: {
            if (p >= end) return false;
            unsigned k = *p++;
            for (unsigned j = 0; j < k; j++) {
                if (end - p < 2) return false;
                uint8_t kind = *p++;
                if (kind == 'n') {
                    unsigned l = *p++;
                    if ((size_t)(end - p) < l) return false;
                    p += l;
                } else if (kind == 4 || kind == 6) {
                    unsigned bits = *p++;
                    unsigned l = kind == 4 ? 4 : 16;
                    if (bits > l * 8 || (size_t)(end - p) < l) return false;
                    p += l;
                } else {
                    return false;
                }
            }
            break;
        }
        case FLC_DENYALLOW: {
            if (p >= end) return false;
            unsigned k = *p++;
            for (unsigned j = 0; j < k; j++) {
                if (p >= end) return false;
                unsigned l = *p++;
                if ((size_t)(end - p) < l) return false;
                p += l;
            }
            break;
        }
        default:
            return false;
        }
    }
    return true;
}

/* delta-coded rule id list: at most `max` entries, ids below n_crules */
static bool ids_ok(const fl_image_t *im, uint32_t off, uint64_t max) {
    if (!pool_ok(im, off, 1)) return false;
    const uint8_t *p = im->pool + off, *end = im->pool + im->pool_len;
    uint64_t n, v, acc = 0;
    if (!(p = dc_varint_get_safe(p, end, &n)) || n > max) return false;
    for (uint64_t i = 0; i < n; i++) {
        if (!(p = dc_varint_get_safe(p, end, &v))) return false;
        acc += v;
        if (acc >= im->h->n_crules) return false;
    }
    return true;
}

/* modifier rules of one domain key (FL_MAX_CR_PER_KEY) / of one n-gram */
static bool group_ok(const fl_image_t *im, uint32_t off) { return ids_ok(im, off, FL_MAX_CR_PER_KEY); }
static bool list_ok(const fl_image_t *im, uint32_t off) { return ids_ok(im, off, im->h->n_crules); }

static void image_free(fl_image_t *im) {
    if (!im) return;
    dc_free(im->symtab);
    dc_free(im->samples_fast);
    dc_free((void *)im->onelabel);
    if (im->release)
        im->release(im->data, im->release_arg);
    else
        dc_free(im->data);
    dc_free(im);
}

/* Walks every key entry once to validate payload references. */
static bool validate_keys(const fl_image_t *im) {
    const fli_header_t *h = im->h;
    for (uint32_t b = 0; b < h->n_blocks; b++) {
        uint32_t s = dc_ld32(im->blkoff + b * 4), e = dc_ld32(im->blkoff + (b + 1) * 4);
        if (s > e || e > im->keys_len) return false;
        const uint8_t *p = im->keys + s, *end = im->keys + e;
        unsigned prevlen = 0, cnt = 0;
        uint8_t kb[256 + 8];
        while (p < end) {
            unsigned sh = p[0], sl = 0;
            if ((cnt == 0 && sh != 0) || sh > prevlen) return false;
            p = fl_suffix_get(im->symtab, p + 1, end, kb, 255 - sh, &sl);
            if (!p || sh + sl == 0 || p >= end) return false;
            prevlen = sh + sl;
            uint8_t m0 = *p++;
            uint64_t v;
            if (m0 & ~0x3Fu) return false;
            if (m0 & FLP_EXT) {
                if (!(p = dc_varint_get_safe(p, end, &v))) return false;
            }
            if (m0 & FLP_HOSTS) {
                if (!(p = dc_varint_get_safe(p, end, &v)) || v >= h->n_hostsets) return false;
            }
            if (m0 & FLP_COMPLEX) {
                if (!(p = dc_varint_get_safe(p, end, &v)) || !group_ok(im, (uint32_t)v)) return false;
            }
            if (m0 & FLP_SRC) {
                if (!(p = dc_varint_get_safe(p, end, &v))) return false;
            }
            cnt++;
        }
        if (cnt == 0 || cnt > h->block_entries) return false;
    }
    return true;
}

int fl_image_load(uint8_t *data, size_t len, bool verify_crc, fl_image_t **out) {
    return fl_image_load_ex(data, len, verify_crc, NULL, NULL, out);
}

int fl_image_load_ex(const uint8_t *cdata, size_t len, bool verify_crc, void (*release)(const uint8_t *, void *),
                     void *release_arg, fl_image_t **out) {
    uint8_t *data = (uint8_t *)cdata; /* never written */
    *out = NULL;
    if (len < FLI_HDR_SIZE) return FL_ERR_CORRUPT;
    fli_header_t h;
    memcpy(&h, data, sizeof(h));
    if (h.magic != FLI_MAGIC || h.version != FLI_VERSION || h.hdr_size != FLI_HDR_SIZE)
        return FL_ERR_CORRUPT;
    {
        uint8_t hb[FLI_HDR_SIZE];
        memcpy(hb, data, FLI_HDR_SIZE);
        ((fli_header_t *)hb)->hdr_crc32 = 0;
        if (dc_crc32(0, hb, FLI_HDR_SIZE) != h.hdr_crc32) return FL_ERR_CORRUPT;
    }
    if (h.total_len > len || h.total_len < FLI_HDR_SIZE) return FL_ERR_CORRUPT;
    for (int s = 0; s < FLS_COUNT; s++)
        if (!sec_ok(&h, s, h.total_len)) return FL_ERR_CORRUPT;
    if (verify_crc && dc_crc32(0, data + FLI_HDR_SIZE, h.total_len - FLI_HDR_SIZE) != h.crc32)
        return FL_ERR_CORRUPT;
    if (h.block_entries == 0 || h.sample_step == 0) return FL_ERR_CORRUPT;
    if (h.sec[FLS_BLOOM].len != (uint64_t)h.bloom_blocks * FLI_BLOOM_BLOCK || h.bloom_blocks == 0) return FL_ERR_CORRUPT;
    if (h.sec[FLS_SAMPLES].len < h.n_samples * 8ull) return FL_ERR_CORRUPT;
    if (h.sec[FLS_BLKOFF].len < (h.n_blocks + 1ull) * 4) return FL_ERR_CORRUPT;
    if (h.sec[FLS_ONELABEL].len < h.n_onelabel * 4ull) return FL_ERR_CORRUPT;
    if (h.sec[FLS_HOSTSETS].len < h.n_hostsets * 4ull) return FL_ERR_CORRUPT;
    if (h.sec[FLS_CRULES].len != h.n_crules * (uint64_t)sizeof(fl_crule_t)) return FL_ERR_CORRUPT;
    if (h.sec[FLS_BADFILTER].len != h.n_badfilter * (uint64_t)sizeof(fl_bfent_t)) return FL_ERR_CORRUPT;
    if (h.sec[FLS_SOURCES].len != h.n_sources * (uint64_t)sizeof(fl_srcent_t)) return FL_ERR_CORRUPT;
    if (h.n_samples != (h.n_blocks + h.sample_step - 1) / h.sample_step) return FL_ERR_CORRUPT;
    if (h.sec[FLS_SYMTAB].len != FL_SYMTAB_BYTES) return FL_ERR_CORRUPT;

    fl_image_t *im = (fl_image_t *)dc_calloc(1, sizeof(fl_image_t));
    if (!im) return FL_ERR_NOMEM;
    atomic_store(&im->refs, 1);
    im->data = data;
    im->release = release;
    im->release_arg = release_arg;
    im->len = h.total_len;
    im->h = (const fli_header_t *)data;
    im->bloom = data + h.sec[FLS_BLOOM].off;
    im->bloom_blocks = h.bloom_blocks;
    im->samples = data + h.sec[FLS_SAMPLES].off;
    im->blkoff = data + h.sec[FLS_BLKOFF].off;
    im->keys = data + h.sec[FLS_KEYS].off;
    im->keys_len = h.sec[FLS_KEYS].len;
    im->hostsets = data + h.sec[FLS_HOSTSETS].off;
    im->crules = (const fl_crule_t *)(data + h.sec[FLS_CRULES].off);
    im->generic = data + h.sec[FLS_GENERIC].off;
    im->generic_len = h.sec[FLS_GENERIC].len;
    im->bf = (const fl_bfent_t *)(data + h.sec[FLS_BADFILTER].off);
    im->sources = (const fl_srcent_t *)(data + h.sec[FLS_SOURCES].off);
    im->pool = data + h.sec[FLS_POOL].off;
    im->pool_len = h.sec[FLS_POOL].len;
    int rc = FL_ERR_NOMEM;
    im->symtab = (fl_symtab_t *)dc_malloc_int(sizeof(fl_symtab_t));
    if (!im->symtab) im->symtab = (fl_symtab_t *)dc_malloc(sizeof(fl_symtab_t));
    if (!im->symtab) goto bad;
    rc = FL_ERR_CORRUPT;
    if (!fl_fsst_load(im->symtab, data + h.sec[FLS_SYMTAB].off)) goto bad;

    /* generic section */
    if (im->generic_len) {
        const uint8_t *p = im->generic, *end = im->generic + im->generic_len;
        if (end - p < 4) goto bad;
        im->n_always = dc_ld32(p);
        p += 4;
        if ((uint64_t)im->n_always * 4 > (uint64_t)(end - p)) goto bad;
        im->always = p;
        p += im->n_always * 4;
        for (unsigned i = 0; i < im->n_always; i++)
            if (dc_ld32(im->always + i * 4) >= h.n_crules) goto bad;
        for (int g = 0; g < 3; g++) {
            if (end - p < 8) goto bad;
            uint32_t nb = dc_ld32(p), bl2 = dc_ld32(p + 4);
            p += 8;
            if (bl2 < 3 || bl2 > 20 || nb == 1 || (nb & (nb - 1))) goto bad;
            uint64_t need = ((uint64_t)1 << bl2) / 8 + (uint64_t)nb * 8;
            if (need > (uint64_t)(end - p)) goto bad;
            im->ng[g].nbuckets = nb;
            im->ng[g].bits_log2 = bl2;
            im->ng[g].bitmap = p;
            im->ng[g].buckets = p + ((size_t)1 << bl2) / 8;
            im->ng[g].nsmall = 0;
            uint32_t empty = 0; /* (the probe loop needs at least one empty bucket) */
            for (uint32_t k = 0; k < nb; k++) {
                const uint8_t *bk = im->ng[g].buckets + k * 8;
                if (!dc_ld32(bk)) {
                    empty++;
                    continue;
                }
                if (!list_ok(im, dc_ld32(bk + 4))) goto bad;
                if (im->ng[g].nsmall < 16) {
                    im->ng[g].small_key[im->ng[g].nsmall] = dc_ld32(bk);
                    im->ng[g].small_list[im->ng[g].nsmall] = dc_ld32(bk + 4);
                    im->ng[g].nsmall++;
                } else {
                    im->ng[g].nsmall = 0xFF;
                }
            }
            if (nb && !empty) goto bad;
            p += need;
        }
    }
    /* complex rules */
    for (uint32_t i = 0; i < h.n_crules; i++) {
        const fl_crule_t *cr = &im->crules[i];
        if (!str16_ok(im, cr->text_off) || !str16_ok(im, cr->ident_off) || !cond_ok(im, cr->cond_off))
            goto bad;
        if (cr->rw_off) {
            if (!pool_ok(im, cr->rw_off, 6) || !pool_ok(im, cr->rw_off, 6u + dc_ld16(im->pool + cr->rw_off + 4)))
                goto bad;
        }
        if (cr->shortcut_off && (!pool_ok(im, cr->shortcut_off, 1) ||
                                 !pool_ok(im, cr->shortcut_off, 1u + im->pool[cr->shortcut_off])))
            goto bad;
        if (cr->lit_off &&
            (!pool_ok(im, cr->lit_off, 1) || !pool_ok(im, cr->lit_off, 1u + im->pool[cr->lit_off])))
            goto bad;
        if (cr->prog_off) {
            if ((cr->prog_off & 3) || !pool_ok(im, cr->prog_off, 8)) goto bad;
            size_t pl;
            if (!fl_re_validate(im->pool + cr->prog_off, im->pool_len - cr->prog_off, &pl)) goto bad;
        } else if ((cr->flags & FL_CRF_GENERIC) && !(cr->flags & FL_CRF_MATCHALL)) {
            goto bad;
        }
        if (cr->src >= (h.n_sources ? h.n_sources : 1) || cr->src >= FL_MAX_SOURCES) goto bad;
    }
    for (uint32_t i = 0; i < h.n_badfilter; i++) {
        if (!str16_ok(im, im->bf[i].ident_off) || !cond_ok(im, im->bf[i].cond_off)) goto bad;
        if (im->bf[i].crule != 0xFFFFFFFFu && im->bf[i].crule >= h.n_crules) goto bad;
    }
    for (uint32_t i = 0; i < h.n_sources; i++)
        if (!str16_ok(im, im->sources[i].name_off)) goto bad;
    for (uint32_t i = 0; i < h.n_hostsets; i++) {
        uint32_t o = dc_ld32(im->hostsets + i * 4);
        if (!pool_ok(im, o, 2)) goto bad;
        unsigned n4 = im->pool[o], n6 = im->pool[o + 1];
        if (n4 + n6 > FL_MAX_HOST_IPS || !pool_ok(im, o, 2u + n4 * 4u + n6 * 16u)) goto bad;
    }
    if (dc_ld32(im->blkoff + h.n_blocks * 4) != im->keys_len) goto bad;
    if (!validate_keys(im)) goto bad;

    /* hot copies in internal RAM */
    rc = FL_ERR_NOMEM;
    im->samples_fast = (uint64_t *)dc_malloc_int((h.n_samples + 1) * sizeof(uint64_t));
    if (!im->samples_fast) im->samples_fast = (uint64_t *)dc_malloc((h.n_samples + 1) * sizeof(uint64_t));
    if (!im->samples_fast) goto bad;
    for (uint32_t i = 0; i < h.n_samples; i++) im->samples_fast[i] = dc_ld64(im->samples + i * 8);
    im->n_onelabel = h.n_onelabel;
    uint32_t *ol = (uint32_t *)dc_malloc_int((h.n_onelabel + 1) * 4);
    if (!ol) ol = (uint32_t *)dc_malloc((h.n_onelabel + 1) * 4);
    if (!ol) goto bad;
    for (uint32_t i = 0; i < h.n_onelabel; i++) ol[i] = dc_ld32(data + h.sec[FLS_ONELABEL].off + i * 4);
    im->onelabel = ol;
    *out = im;
    return 0;
bad:
    im->data = NULL; /* caller keeps ownership on failure */
    im->release = NULL;
    image_free(im);
    return rc;
}

void fl_image_ref(fl_image_t *img) { atomic_fetch_add(&img->refs, 1); }
void fl_image_unref(fl_image_t *img) {
    if (img && atomic_fetch_sub(&img->refs, 1) == 1) image_free(img);
}
const fl_stats_t *fl_image_stats(const fl_image_t *img) { return &img->h->stats; }
uint32_t fl_image_generation(const fl_image_t *img) { return img->h->generation; }
uint32_t fl_image_size(const fl_image_t *img) { return img->len; }
uint32_t fl_image_source_count(const fl_image_t *img) { return img->h->n_sources; }
const char *fl_image_source_name(const fl_image_t *img, uint32_t i, uint16_t *len) {
    *len = 0;
    if (i >= img->h->n_sources) return "";
    return fl_pool_str(img->pool, img->sources[i].name_off, len);
}

int fl_image_probe(fl_store_t *st, uint32_t *total_len, uint32_t *generation) {
    uint8_t hb[FLI_HDR_SIZE];
    if (st->read(st, 0, hb, sizeof(hb))) return FL_ERR_IO;
    fli_header_t h;
    memcpy(&h, hb, sizeof(h));
    if (h.magic != FLI_MAGIC || h.version != FLI_VERSION) return FL_ERR_CORRUPT;
    ((fli_header_t *)hb)->hdr_crc32 = 0;
    if (dc_crc32(0, hb, sizeof(hb)) != h.hdr_crc32) return FL_ERR_CORRUPT;
    if (h.total_len > st->capacity) return FL_ERR_CORRUPT;
    *total_len = h.total_len;
    if (generation) *generation = h.generation;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* sets                                                                      */

/* true if a condition block depends on the client ($client / $ctag) */
static bool cond_has_client(const uint8_t *pool, uint32_t off) {
    if (!off) return false;
    const uint8_t *p = pool + off;
    unsigned n = *p++;
    for (unsigned i = 0; i < n; i++) {
        uint8_t t = *p++;
        switch (t) {
        case FLC_DNSTYPE_PERM:
        case FLC_DNSTYPE_RESTR:
            p += 1 + (size_t)p[0] * 2;
            break;
        case FLC_DENYALLOW: {
            unsigned k = *p++;
            for (unsigned j = 0; j < k; j++) p += 1 + (size_t)p[0];
            break;
        }
        default: /* client / ctag (or unknown: be conservative) */
            return true;
        }
    }
    return false;
}

static bool image_client_dep(const fl_image_t *im) {
    for (uint32_t i = 0; i < im->h->n_crules; i++)
        if (cond_has_client(im->pool, im->crules[i].cond_off)) return true;
    for (uint32_t i = 0; i < im->h->n_badfilter; i++)
        if (cond_has_client(im->pool, im->bf[i].cond_off)) return true;
    return false;
}

fl_set_t *fl_set_new(fl_image_t *const *imgs, unsigned n, uint32_t generation) {
    if (n > FL_MAX_IMAGES) return NULL;
    fl_set_t *s = (fl_set_t *)dc_calloc(1, sizeof(fl_set_t));
    if (!s) return NULL;
    atomic_store(&s->refs, 1);
    s->generation = generation;
    for (unsigned i = 0; i < n; i++) {
        if (!imgs[i]) continue;
        fl_image_ref(imgs[i]);
        s->img[s->n++] = imgs[i];
        if (imgs[i]->h->n_badfilter) s->any_bf = true;
        if (image_client_dep(imgs[i])) s->client_dep = true;
    }
    return s;
}

bool fl_set_client_dependent(const fl_set_t *s) { return s && s->client_dep; }

void fl_set_ref(fl_set_t *s) { atomic_fetch_add(&s->refs, 1); }
void fl_set_unref(fl_set_t *s) {
    if (!s || atomic_fetch_sub(&s->refs, 1) != 1) return;
    for (unsigned i = 0; i < s->n; i++) fl_image_unref(s->img[i]);
    dc_free(s);
}
uint32_t fl_set_generation(const fl_set_t *s) { return s->generation; }
unsigned fl_set_count(const fl_set_t *s) { return s->n; }
fl_image_t *fl_set_image(const fl_set_t *s, unsigned i) { return i < s->n ? s->img[i] : NULL; }

/* ------------------------------------------------------------------------- */
/* index lookup                                                              */

static inline uint64_t prefix8(const char *k, unsigned kl) {
    uint64_t p = 0;
    for (unsigned i = 0; i < 8; i++) p = (p << 8) | (i < kl ? (uint8_t)k[i] : 0);
    return p;
}

static inline int kcmp(const uint8_t *a, unsigned al, const char *b, unsigned bl) {
    int r = memcmp(a, b, al < bl ? al : bl);
    if (r) return r;
    return (int)al - (int)bl;
}

static bool bloom_maybe(const fl_image_t *im, uint32_t h) {
    const uint8_t *b = im->bloom + (size_t)fl_bloom_block(h, im->bloom_blocks) * FLI_BLOOM_BLOCK;
    uint8_t pos[6];
    fl_bloom_bits(h, pos);
    for (int i = 0; i < 6; i++)
        if (!(b[pos[i] >> 3] & (1u << (pos[i] & 7)))) return false;
    return true;
}

static bool onelabel_has(const fl_image_t *im, uint32_t h) {
    uint32_t lo = 0, hi = im->n_onelabel;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        uint32_t v = im->onelabel[mid];
        if (v == h) return true;
        if (v < h)
            lo = mid + 1;
        else
            hi = mid;
    }
    return false;
}

/* Returns pointer to the payload of `key`, or NULL. */
static const uint8_t *idx_lookup(const fl_image_t *im, const char *key, unsigned kl) {
    const fli_header_t *h = im->h;
    if (!h->n_blocks) return NULL;
    uint64_t q8 = prefix8(key, kl);
    /* sample range */
    uint32_t ns = h->n_samples;
    uint32_t lo = 0, hi = ns;
    while (lo < hi) { /* first sample >= q8 */
        uint32_t mid = (lo + hi) / 2;
        if (im->samples_fast[mid] < q8)
            lo = mid + 1;
        else
            hi = mid;
    }
    uint32_t s_lo = lo ? lo - 1 : 0;
    lo = s_lo;
    hi = ns;
    while (lo < hi) { /* first sample > q8 */
        uint32_t mid = (lo + hi) / 2;
        if (im->samples_fast[mid] <= q8)
            lo = mid + 1;
        else
            hi = mid;
    }
    uint32_t b_lo = s_lo * h->sample_step;
    uint32_t b_hi = lo * h->sample_step;
    if (b_hi > h->n_blocks || lo >= ns) b_hi = h->n_blocks;
    /* last block in [b_lo, b_hi) whose first key <= key */
    const fl_symtab_t *st = im->symtab;
    uint8_t cur[256 + 8];
    unsigned cl = 0;
    lo = b_lo;
    hi = b_hi;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        const uint8_t *e = im->keys + dc_ld32(im->blkoff + mid * 4);
        fl_suffix_get(st, e + 1, im->keys + im->keys_len, cur, 255, &cl);
        if (kcmp(cur, cl, key, kl) <= 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == b_lo) return NULL; /* key precedes the first candidate block */
    uint32_t blk = lo - 1;
    const uint8_t *p = im->keys + dc_ld32(im->blkoff + blk * 4);
    const uint8_t *end = im->keys + dc_ld32(im->blkoff + (blk + 1) * 4);
    while (p < end) {
        unsigned sh = p[0], sl = 0;
        p = fl_suffix_get(st, p + 1, end, cur + sh, 255 - sh, &sl);
        if (!p) return NULL;
        cl = sh + sl;
        int c = kcmp(cur, cl, key, kl);
        if (c == 0) return p;
        if (c > 0) return NULL;
        /* skip payload */
        uint8_t m0 = *p++;
        uint64_t v;
        if (m0 & FLP_EXT) p = dc_varint_get(p, &v);
        if (m0 & FLP_HOSTS) p = dc_varint_get(p, &v);
        if (m0 & FLP_COMPLEX) p = dc_varint_get(p, &v);
        if (m0 & FLP_SRC) p = dc_varint_get(p, &v);
    }
    return NULL;
}

typedef struct {
    uint64_t mask;
    uint32_t hostset;  /* 0xFFFFFFFF none */
    uint32_t group;    /* pool offset, 0 none */
    uint32_t srcmask;
    bool has_hosts;
} payload_t;

static void decode_payload(const uint8_t *p, payload_t *pl) {
    uint8_t m0 = *p++;
    uint64_t v;
    pl->mask = 0;
    pl->hostset = 0xFFFFFFFFu;
    pl->has_hosts = false;
    pl->group = 0;
    pl->srcmask = 1;
    if (m0 & FLP_EXT) {
        p = dc_varint_get(p, &v);
        pl->mask = v;
    } else {
        if (m0 & FLP_SUFFIX_BLOCK) pl->mask |= 1ull << FLK_BIT(FLK_SUFFIX, 0, 0);
        if (m0 & FLP_SUFFIX_ALLOW) pl->mask |= 1ull << FLK_BIT(FLK_SUFFIX, 1, 0);
    }
    if (m0 & FLP_HOSTS) {
        p = dc_varint_get(p, &v);
        pl->hostset = (uint32_t)v;
        pl->has_hosts = true;
    }
    if (m0 & FLP_COMPLEX) {
        p = dc_varint_get(p, &v);
        pl->group = (uint32_t)v;
    }
    if (m0 & FLP_SRC) {
        p = dc_varint_get(p, &v);
        pl->srcmask = (uint32_t)v;
    }
}

/* ------------------------------------------------------------------------- */
/* matching context                                                          */

#define MAX_LEVELS 128
#define MAX_HITS 64

typedef struct {
    uint8_t img, level;
    uint8_t plain; /* 1: plain kind bit, 0: complex rule */
    uint8_t bit;
    uint32_t crule;
    uint32_t srcmask;
    uint8_t action; /* FL_ACT_* (derived for plain) */
    uint8_t important;
    uint8_t negated;
} hit_t;

typedef struct {
    const fl_set_t *set;
    const fl_req_t *req;
    char rev[FL_MAX_HOST + 3];
    unsigned rlen;
    unsigned nlev;
    uint16_t lev_end[MAX_LEVELS];
    uint32_t lev_hash[MAX_LEVELS];
    char url[FL_MAX_HOST + 16];
    unsigned ulen;
    bool host_is_ip;
    hit_t hits[MAX_HITS];
    unsigned nhits;
    /* hosts rules at the full name */
    uint8_t hs_img[FL_MAX_IMAGES];
    uint32_t hs_id[FL_MAX_IMAGES];
    uint32_t hs_src[FL_MAX_IMAGES];
    unsigned nhs;
} mctx_t;

static void add_hit(mctx_t *m, const hit_t *h) {
    if (m->nhits < MAX_HITS) {
        m->hits[m->nhits++] = *h;
        return;
    }
    /* full (many matching rules): a plain blocking hit, the weakest kind,
     * gives way to anything that can change the verdict */
    if (h->action == FL_ACT_BLOCK && !h->important) return;
    for (unsigned k = m->nhits; k-- > 0;)
        if (m->hits[k].action == FL_ACT_BLOCK && !m->hits[k].important) {
            m->hits[k] = *h;
            return;
        }
}

/* Is host equal to d or a subdomain of d? (lowercase) */
static bool is_domain_or_sub(const char *host, size_t hl, const char *d, size_t dl) {
    if (hl == dl) return memcmp(host, d, dl) == 0;
    if (hl > dl) return host[hl - dl - 1] == '.' && memcmp(host + hl - dl, d, dl) == 0;
    return false;
}

static bool client_match(const uint8_t **pp, const fl_client_t *cl) {
    const uint8_t *p = *pp;
    unsigned n = *p++;
    bool hit = false;
    for (unsigned i = 0; i < n; i++) {
        uint8_t kind = *p++;
        if (kind == 'n') {
            unsigned l = *p++;
            if (!hit && cl && cl->name && strlen(cl->name) == l && memcmp(cl->name, p, l) == 0) hit = true;
            p += l;
        } else {
            uint8_t bits = *p++;
            unsigned al = kind == 4 ? 4 : 16;
            if (!hit && cl && cl->ip.family == kind) {
                dc_prefix_t pf;
                memset(&pf, 0, sizeof(pf));
                pf.ip.family = kind;
                memcpy(pf.ip.addr, p, al);
                pf.bits = bits;
                if (dc_prefix_contains(&pf, &cl->ip)) hit = true;
            }
            p += al;
        }
    }
    *pp = p;
    return hit;
}

static bool cond_match(const uint8_t *pool, uint32_t off, const mctx_t *m) {
    if (!off) return true;
    const fl_req_t *rq = m->req;
    const fl_client_t *cl = rq->client;
    const uint8_t *p = pool + off;
    unsigned n = *p++;
    for (unsigned i = 0; i < n; i++) {
        uint8_t t = *p++;
        switch (t) {
        case FLC_DNSTYPE_PERM:
        case FLC_DNSTYPE_RESTR: {
            unsigned k = *p++;
            bool found = false;
            for (unsigned j = 0; j < k; j++)
                if (dc_ld16(p + j * 2) == rq->qtype) found = true;
            p += k * 2;
            if (t == FLC_DNSTYPE_RESTR && found) return false;
            if (t == FLC_DNSTYPE_PERM && !found) return false;
            break;
        }
        case FLC_CTAG_PERM:
        case FLC_CTAG_RESTR: {
            uint32_t mask = dc_ld32(p);
            p += 4;
            uint32_t tags = cl ? cl->tags : 0;
            bool inter = (mask & tags & 0x7FFFFFFFu) != 0;
            if (t == FLC_CTAG_RESTR && inter) return false;
            if (t == FLC_CTAG_PERM && !inter) return false;
            break;
        }
        case FLC_CLIENT_PERM:
        case FLC_CLIENT_RESTR: {
            bool hit = client_match(&p, cl);
            if (t == FLC_CLIENT_RESTR && hit) return false;
            if (t == FLC_CLIENT_PERM && !hit) return false;
            break;
        }
        case FLC_DENYALLOW: {
            unsigned k = *p++;
            bool in = false;
            for (unsigned j = 0; j < k; j++) {
                unsigned l = *p++;
                if (!in && is_domain_or_sub(rq->host, rq->host_len, (const char *)p, l)) in = true;
                p += l;
            }
            if (m->host_is_ip || in) return false;
            break;
        }
        default:
            return false;
        }
    }
    return true;
}

/* evaluates a complex rule for this request (conditions + program) */
static bool crule_match(const fl_image_t *im, const fl_crule_t *cr, const mctx_t *m) {
    if (!cond_match(im->pool, cr->cond_off, m)) return false;
    if (!(cr->flags & FL_CRF_GENERIC) || (cr->flags & FL_CRF_MATCHALL)) return true;
    if (cr->lit_off) { /* cheap necessary condition before running the automaton */
        unsigned ll = im->pool[cr->lit_off];
        if (!dc_memmem(m->url, m->ulen, im->pool + cr->lit_off + 1, ll)) return false;
    }
    if (cr->shortcut_off) {
        unsigned sl = im->pool[cr->shortcut_off];
        if (!dc_memmem(m->url, m->ulen, im->pool + cr->shortcut_off + 1, sl)) return false;
    }
    const uint8_t *prog = im->pool + cr->prog_off;
    if (cr->flags & FL_CRF_URLSUBJ) return fl_re_match(prog, (const uint8_t *)m->url, m->ulen);
    return fl_re_match(prog, (const uint8_t *)m->req->host, m->req->host_len);
}

static void push_crule(mctx_t *m, unsigned img, uint32_t id, unsigned level) {
    const fl_image_t *im = m->set->img[img];
    const fl_crule_t *cr = &im->crules[id];
    hit_t h;
    memset(&h, 0, sizeof(h));
    h.img = (uint8_t)img;
    h.level = (uint8_t)level;
    h.crule = id;
    h.action = cr->action;
    h.important = (cr->flags & FL_CRF_IMPORTANT) != 0;
    h.srcmask = 1u << cr->src;
    add_hit(m, &h);
}

static void scan_group(mctx_t *m, unsigned img, uint32_t goff, unsigned level, bool full) {
    const fl_image_t *im = m->set->img[img];
    const uint8_t *p = im->pool + goff;
    uint64_t n, v;
    uint32_t id = 0;
    p = dc_varint_get(p, &n);
    for (uint64_t i = 0; i < n; i++) {
        p = dc_varint_get(p, &v);
        id += (uint32_t)v;
        const fl_crule_t *cr = &im->crules[id];
        if (!(cr->scope & (full ? FL_SCOPE_EXACT : FL_SCOPE_SUB))) continue;
        if (crule_match(im, cr, m)) push_crule(m, img, id, level);
    }
}

static void scan_list(mctx_t *m, unsigned img, const uint8_t *p, uint32_t *seen, unsigned *nseen) {
    const fl_image_t *im = m->set->img[img];
    uint64_t cnt, v;
    uint32_t id = 0;
    p = dc_varint_get(p, &cnt);
    for (uint64_t i = 0; i < cnt; i++) {
        p = dc_varint_get(p, &v);
        id += (uint32_t)v;
        bool dup = false;
        for (unsigned s = 0; s < *nseen; s++)
            if (seen[s] == id) dup = true;
        if (dup) continue;
        if (*nseen < 32) seen[(*nseen)++] = id;
        if (crule_match(im, &im->crules[id], m)) push_crule(m, img, id, 0);
    }
}

static void scan_generic(mctx_t *m, unsigned img) {
    const fl_image_t *im = m->set->img[img];
    if (!im->generic_len) return;
    uint32_t seen[32];
    unsigned nseen = 0;
    for (uint32_t i = 0; i < im->n_always; i++) {
        uint32_t id = dc_ld32(im->always + i * 4);
        if (crule_match(im, &im->crules[id], m)) push_crule(m, img, id, 0);
    }
    const uint8_t *u = (const uint8_t *)m->url;
    for (int g = 0; g < 3; g++) {
        unsigned n = (unsigned)g + 2;
        uint32_t nb = im->ng[g].nbuckets;
        if (!nb || m->ulen < n) continue;
        if (im->ng[g].nsmall != 0xFF) {
            /* few keys: look for each of them directly */
            for (unsigned k = 0; k < im->ng[g].nsmall; k++) {
                uint8_t kb[4];
                dc_st32(kb, im->ng[g].small_key[k]);
                if (dc_memmem(u, m->ulen, kb, n))
                    scan_list(m, img, im->pool + im->ng[g].small_list[k], seen, &nseen);
            }
            continue;
        }
        uint32_t shift = 32 - im->ng[g].bits_log2;
        const uint8_t *bm = im->ng[g].bitmap;
        for (unsigned pos = 0; pos + n <= m->ulen; pos++) {
            uint32_t k = fl_ngram_key(u + pos, n);
            uint32_t hh = fl_ngram_hash(k);
            uint32_t bit = hh >> shift;
            if (!(bm[bit >> 3] & (1u << (bit & 7)))) continue;
            uint32_t slot = hh & (nb - 1);
            for (;;) {
                const uint8_t *bk = im->ng[g].buckets + slot * 8;
                uint32_t bkey = dc_ld32(bk);
                if (!bkey) break;
                if (bkey == k) {
                    scan_list(m, img, im->pool + dc_ld32(bk + 4), seen, &nseen);
                    break;
                }
                slot = (slot + 1) & (nb - 1);
            }
        }
    }
}

static bool prepare(mctx_t *m, const fl_set_t *set, const fl_req_t *req) {
    memset(m, 0, offsetof(mctx_t, hits));
    m->nhits = 0;
    m->nhs = 0;
    m->set = set;
    m->req = req;
    if (!set || !req->host_len || req->host_len > FL_MAX_HOST) return false;
    m->rlen = (unsigned)fl_reverse_name(req->host, req->host_len, m->rev);
    /* one pass: FNV hash of every label-level prefix of the reversed name */
    uint32_t h = DC_FNV32_INIT;
    unsigned i = 0;
    while (i < m->rlen) {
        char c = m->rev[i];
        if (c == '.' && m->nlev < MAX_LEVELS) {
            m->lev_end[m->nlev] = (uint16_t)i;
            m->lev_hash[m->nlev++] = h;
        }
        unsigned adv = 1;
        if (c == '\\') adv = (i + 1 < m->rlen && m->rev[i + 1] >= '0' && m->rev[i + 1] <= '9') ? 4 : 2;
        for (unsigned k = 0; k < adv && i < m->rlen; k++, i++) h = dc_fnv32_step(h, (uint8_t)m->rev[i]);
    }
    if (m->nlev < MAX_LEVELS) {
        m->lev_end[m->nlev] = (uint16_t)m->rlen;
        m->lev_hash[m->nlev++] = h;
    }
    memcpy(m->url, "http://", 7);
    memcpy(m->url + 7, req->host, req->host_len);
    m->ulen = 7u + req->host_len;
    m->url[m->ulen] = 0;
    dc_ip_t ip;
    m->host_is_ip = dc_ip_parse(req->host, req->host_len, &ip);
    return true;
}

static void collect(mctx_t *m) {
    const fl_set_t *set = m->set;
    for (unsigned i = 0; i < set->n; i++) {
        const fl_image_t *im = set->img[i];
        for (unsigned L = 0; L < m->nlev; L++) {
            uint32_t h = m->lev_hash[L];
            bool full = L + 1 == m->nlev;
            if (L == 0) {
                if (!onelabel_has(im, h)) continue;
            } else if (!bloom_maybe(im, h)) {
                continue;
            }
            const uint8_t *p = idx_lookup(im, m->rev, m->lev_end[L]);
            if (!p) continue;
            payload_t pl;
            decode_payload(p, &pl);
            uint64_t bits = pl.mask & (full ? FLK_EXACT_SCOPE : FLK_SUB_SCOPE);
            while (bits) {
                unsigned b = (unsigned)__builtin_ctzll(bits);
                bits &= bits - 1;
                hit_t ht;
                memset(&ht, 0, sizeof(ht));
                ht.img = (uint8_t)i;
                ht.level = (uint8_t)L;
                ht.plain = 1;
                ht.bit = (uint8_t)b;
                ht.srcmask = pl.srcmask;
                if (b >= 32) {
                    ht.action = FL_ACT_ALLOWLIST;
                } else {
                    ht.action = (b & 2) ? FL_ACT_ALLOW : FL_ACT_BLOCK;
                    ht.important = b & 1;
                }
                add_hit(m, &ht);
            }
            if (pl.has_hosts && full && m->nhs < FL_MAX_IMAGES) {
                m->hs_img[m->nhs] = (uint8_t)i;
                m->hs_src[m->nhs] = pl.srcmask;
                m->hs_id[m->nhs++] = pl.hostset;
            }
            if (pl.group) scan_group(m, i, pl.group, L, full);
        }
        scan_generic(m, i);
    }
}

/* identity of a hit for $badfilter (see build_ident in fl_compile.c):
 * complex rules keep theirs in the pool, plain ones are built into buf */
static const char *hit_ident(const mctx_t *m, const hit_t *h, char *buf, size_t cap, size_t *len,
                             uint32_t *hash) {
    const fl_image_t *im = m->set->img[h->img];
    if (!h->plain) {
        const fl_crule_t *cr = &im->crules[h->crule];
        uint16_t l;
        const char *s = fl_pool_str(im->pool, cr->ident_off, &l);
        *len = l;
        *hash = cr->ident_hash;
        return s;
    }
    unsigned kind = h->bit / 4;
    char dom[FL_MAX_HOST + 3];
    size_t dl = fl_reverse_name(m->rev, m->lev_end[h->level], dom);
    int k = snprintf(buf, cap, "%s%s%.*s%s%s", (h->bit & 2) ? "W|" : "B|", fl_kind_prefix[kind],
                     (int)dl, dom, fl_kind_suffix[kind], (h->bit & 1) ? "|i" : "");
    *len = k > 0 ? (size_t)k : 0;
    *hash = dc_fnv32(buf, *len);
    return buf;
}

static bool bf_lookup(const fl_image_t *im, uint32_t hash, const char *ident, size_t il,
                      const mctx_t *m) {
    uint32_t lo = 0, hi = im->h->n_badfilter;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (im->bf[mid].hash < hash)
            lo = mid + 1;
        else
            hi = mid;
    }
    for (uint32_t i = lo; i < im->h->n_badfilter && im->bf[i].hash == hash; i++) {
        uint16_t l;
        const char *s = fl_pool_str(im->pool, im->bf[i].ident_off, &l);
        if (l != il || memcmp(s, ident, il) != 0) continue;
        if (im->bf[i].crule == 0xFFFFFFFFu) return true; /* unconditional */
        /* conditional: the badfilter rule itself must match the request */
        for (unsigned k = 0; k < m->nhits; k++) {
            const hit_t *h = &m->hits[k];
            if (!h->plain && h->action == FL_ACT_BADFILTER && m->set->img[h->img] == im &&
                h->crule == im->bf[i].crule)
                return true;
        }
    }
    return false;
}

static void apply_badfilter(mctx_t *m) {
    if (!m->set->any_bf) return;
    char buf[FL_MAX_HOST + 64];
    for (unsigned k = 0; k < m->nhits; k++) {
        hit_t *h = &m->hits[k];
        if (h->action != FL_ACT_BLOCK && h->action != FL_ACT_ALLOW) continue;
        size_t il;
        uint32_t hash;
        const char *ident = hit_ident(m, h, buf, sizeof(buf), &il, &hash);
        for (unsigned i = 0; i < m->set->n && !h->negated; i++) {
            if (!m->set->img[i]->h->n_badfilter) continue;
            if (bf_lookup(m->set->img[i], hash, ident, il, m)) h->negated = 1;
        }
    }
}

static const uint8_t *rw_rec(const mctx_t *m, const hit_t *h) {
    const fl_image_t *im = m->set->img[h->img];
    return im->pool + im->crules[h->crule].rw_off;
}

static uint32_t hit_order(const mctx_t *m, const hit_t *h) {
    return m->set->img[h->img]->crules[h->crule].order + ((uint32_t)h->img << 26);
}

/* urlfilter DNSResult.DNSRewrites + AdGuard processDNSRewrites */
static bool resolve_rewrites(mctx_t *m, fl_result_t *res) {
    hit_t *rw[MAX_HITS];
    unsigned nrw = 0;
    for (unsigned k = 0; k < m->nhits; k++)
        if (m->hits[k].action == FL_ACT_REWRITE) rw[nrw++] = &m->hits[k];
    if (!nrw) return false;
    /* exceptions */
    for (unsigned k = 0; k < m->nhits; k++) {
        const hit_t *ex = &m->hits[k];
        if (ex->action != FL_ACT_REWRITE_EXC) continue;
        const uint8_t *er = rw_rec(m, ex);
        unsigned w = 0;
        for (unsigned i = 0; i < nrw; i++) {
            const hit_t *r = rw[i];
            bool remove;
            if (er[0] == FLRW_EMPTY) {
                remove = ex->important ? true : !r->important;
            } else if (!ex->important && r->important) {
                remove = false;
            } else {
                const uint8_t *rr = rw_rec(m, r);
                if (er[0] == FLRW_CNAME) {
                    remove = rr[0] == FLRW_CNAME && dc_ld16(rr + 4) == dc_ld16(er + 4) &&
                             memcmp(rr + 6, er + 6, dc_ld16(er + 4)) == 0;
                } else if (rr[0] == FLRW_CNAME) {
                    remove = false;
                } else if (er[1] != rr[1]) {
                    remove = false;
                } else if (er[1] != 0) {
                    remove = true;
                } else {
                    remove = dc_ld16(rr + 2) == dc_ld16(er + 2) && dc_ld16(rr + 4) == dc_ld16(er + 4) &&
                             memcmp(rr + 6, er + 6, dc_ld16(er + 4)) == 0;
                }
            }
            if (!remove) rw[w++] = rw[i];
        }
        nrw = w;
    }
    if (!nrw) return false;
    /* rule order */
    for (unsigned i = 1; i < nrw; i++) {
        hit_t *v = rw[i];
        unsigned j = i;
        while (j && hit_order(m, rw[j - 1]) > hit_order(m, v)) {
            rw[j] = rw[j - 1];
            j--;
        }
        rw[j] = v;
    }
    res->n_rr = 0;
    const hit_t *first = rw[0];
    for (unsigned i = 0; i < nrw; i++) {
        const uint8_t *rr = rw_rec(m, rw[i]);
        if (rr[0] == FLRW_CNAME) {
            /* a rewrite of the host to itself is ignored */
            char nm[FL_MAX_HOST + 3];
            int nl = fl_name_from_wire(rr + 6, dc_ld16(rr + 4), nm, sizeof(nm));
            if (nl == (int)m->req->host_len && memcmp(nm, m->req->host, (size_t)nl) == 0) return false;
            res->verdict = FL_V_REWRITE;
            res->rw_kind = FL_RW_CNAME;
            res->cname = rr + 6;
            res->rcode = 0;
            res->n_rr = 0;
            first = rw[i];
            goto done;
        }
        if (rr[1] != 0) {
            res->verdict = FL_V_REWRITE;
            res->rw_kind = FL_RW_RCODE;
            res->rcode = rr[1];
            res->n_rr = 0;
            first = rw[i];
            goto done;
        }
        if (rr[0] == FLRW_RR && dc_ld16(rr + 2) == m->req->qtype && res->n_rr < FL_MAX_RRS) {
            res->rr[res->n_rr].type = dc_ld16(rr + 2);
            res->rr[res->n_rr].rdlen = dc_ld16(rr + 4);
            res->rr[res->n_rr].rdata = rr + 6;
            res->n_rr++;
        }
    }
    res->verdict = FL_V_REWRITE;
    res->rw_kind = FL_RW_RRS;
    res->rcode = 0;
done:
    res->has_rule = true;
    res->rule.img = first->img;
    res->rule.is_plain = 0;
    res->rule.crule = first->crule;
    res->rule.level = first->level;
    return true;
}

static void set_rule(fl_result_t *res, const hit_t *h) {
    res->has_rule = true;
    res->rule.srcmask = h->srcmask;
    res->rule.img = h->img;
    res->rule.is_plain = h->plain;
    res->rule.kind = h->bit;
    res->rule.level = h->level;
    res->rule.crule = h->crule;
}

static void decide(mctx_t *m, fl_result_t *res) {
    if (m->req->flags & FL_REQ_REWRITES_ONLY) {
        resolve_rewrites(m, res);
        return;
    }
    /* 1. allowlists */
    for (unsigned k = 0; k < m->nhits; k++) {
        if (m->hits[k].action == FL_ACT_ALLOWLIST) {
            res->verdict = FL_V_ALLOWLIST;
            set_rule(res, &m->hits[k]);
            return;
        }
    }
    /* 2. $dnsrewrite */
    if (resolve_rewrites(m, res)) return;
    /* 3. basic rules */
    apply_badfilter(m);
    const hit_t *best[4] = {NULL, NULL, NULL, NULL}; /* imp_allow, imp_block, allow, block */
    for (unsigned k = 0; k < m->nhits; k++) {
        const hit_t *h = &m->hits[k];
        if (h->negated) continue;
        int cat;
        if (h->action == FL_ACT_ALLOW)
            cat = h->important ? 0 : 2;
        else if (h->action == FL_ACT_BLOCK)
            cat = h->important ? 1 : 3;
        else
            continue;
        if (!best[cat]) best[cat] = h;
    }
    for (int cat = 0; cat < 4; cat++) {
        if (!best[cat]) continue;
        res->verdict = (cat == 0 || cat == 2) ? FL_V_ALLOW : FL_V_BLOCK;
        set_rule(res, best[cat]);
        return;
    }
    /* 4. /etc/hosts rules */
    if (m->nhs) {
        res->verdict = FL_V_BLOCK;
        res->hosts_rule = 1;
        uint16_t qt = m->req->qtype;
        int fam = qt == 1 ? 4 : qt == 28 ? 6 : 0;
        for (unsigned i = 0; i < m->nhs && fam; i++) {
            const fl_image_t *im = m->set->img[m->hs_img[i]];
            const uint8_t *p = im->pool + dc_ld32(im->hostsets + m->hs_id[i] * 4);
            unsigned n4 = p[0], n6 = p[1];
            const uint8_t *a = p + 2;
            unsigned cnt = fam == 4 ? n4 : n6;
            if (fam == 6) a += n4 * 4;
            for (unsigned j = 0; j < cnt && res->n_ips < FL_MAX_IPS; j++) {
                dc_ip_t ip;
                memset(&ip, 0, sizeof(ip));
                ip.family = (uint8_t)fam;
                memcpy(ip.addr, a + j * (fam == 4 ? 4 : 16), fam == 4 ? 4 : 16);
                bool dup = false;
                for (unsigned q = 0; q < res->n_ips; q++)
                    if (dc_ip_equal(&res->ips[q], &ip)) dup = true;
                if (!dup) res->ips[res->n_ips++] = ip;
            }
        }
        res->has_rule = true;
        res->rule.img = m->hs_img[0];
        res->rule.is_plain = 1;
        res->rule.kind = 0xFF; /* hosts */
        res->rule.srcmask = m->hs_src[0];
        res->rule.level = (uint8_t)(m->nlev - 1);
        return;
    }
}

void fl_match(const fl_set_t *set, const fl_req_t *req, fl_result_t *res) {
    mctx_t m;
    res->verdict = FL_V_NONE;
    res->n_ips = 0;
    res->hosts_rule = 0;
    res->n_rr = 0;
    res->rw_kind = 0;
    res->rcode = 0;
    res->cname = NULL;
    res->has_rule = false;
    if (!prepare(&m, set, req)) return;
    collect(&m);
    if (!m.nhits && !m.nhs) return;
    decide(&m, res);
}

/* ------------------------------------------------------------------------- */
/* diagnostics                                                               */

static const char *src_name(const fl_image_t *im, uint32_t srcmask, char *buf, size_t cap) {
    size_t o = 0;
    buf[0] = 0;
    for (uint32_t i = 0; i < im->h->n_sources && i < 32; i++) {
        if (!(srcmask & (1u << i))) continue;
        uint16_t l;
        const char *s = fl_pool_str(im->pool, im->sources[i].name_off, &l);
        int k = snprintf(buf + o, cap - o, "%s%.*s", o ? ", " : "", (int)l, s);
        if (k < 0 || (size_t)k >= cap - o) break;
        o += (size_t)k;
    }
    return buf;
}

static size_t plain_text(const mctx_t *m, unsigned bit, unsigned level, char *buf, size_t cap) {
    char dom[FL_MAX_HOST + 3];
    size_t dl = fl_reverse_name(m->rev, m->lev_end[level], dom);
    int k;
    if (bit >= 32) {
        unsigned kind = bit - 32;
        if (bit == FLK_AL_HOST_BIT)
            k = snprintf(buf, cap, "%.*s", (int)dl, dom);
        else
            k = snprintf(buf, cap, "%s%.*s%s", fl_kind_prefix[kind], (int)dl, dom, fl_kind_suffix[kind]);
    } else {
        unsigned kind = bit / 4;
        k = snprintf(buf, cap, "%s%s%.*s%s%s", (bit & 2) ? "@@" : "", fl_kind_prefix[kind], (int)dl, dom,
                     fl_kind_suffix[kind], (bit & 1) ? "$important" : "");
    }
    return k > 0 ? (size_t)k : 0;
}

void fl_explain(const fl_set_t *set, const fl_req_t *req, fl_explain_cb cb, void *arg) {
    mctx_t *m = (mctx_t *)dc_malloc(sizeof(mctx_t));
    if (!m) return;
    if (!prepare(m, set, req)) {
        dc_free(m);
        return;
    }
    collect(m);
    apply_badfilter(m);
    char text[1100], src[256];
    for (unsigned k = 0; k < m->nhits; k++) {
        const hit_t *h = &m->hits[k];
        const fl_image_t *im = set->img[h->img];
        const char *eff;
        switch (h->action) {
        case FL_ACT_BLOCK:
            eff = h->important ? "block (important)" : "block";
            break;
        case FL_ACT_ALLOW:
            eff = h->important ? "allow (important)" : "allow";
            break;
        case FL_ACT_REWRITE:
            eff = "dnsrewrite";
            break;
        case FL_ACT_REWRITE_EXC:
            eff = "dnsrewrite exception";
            break;
        case FL_ACT_BADFILTER:
            eff = "badfilter";
            break;
        case FL_ACT_ALLOWLIST:
            eff = "allowlist";
            break;
        default:
            eff = "?";
        }
        if (h->negated) eff = "disabled by $badfilter";
        if (h->plain) {
            plain_text(m, h->bit, h->level, text, sizeof(text));
            cb(arg, text, src_name(im, h->srcmask, src, sizeof(src)), eff);
        } else {
            uint16_t l;
            const char *s = fl_pool_str(im->pool, im->crules[h->crule].text_off, &l);
            snprintf(text, sizeof(text), "%.*s", (int)l, s);
            cb(arg, text, src_name(im, 1u << im->crules[h->crule].src, src, sizeof(src)), eff);
        }
    }
    for (unsigned i = 0; i < m->nhs; i++) {
        const fl_image_t *im = set->img[m->hs_img[i]];
        const uint8_t *p = im->pool + dc_ld32(im->hostsets + m->hs_id[i] * 4);
        unsigned n4 = p[0], n6 = p[1];
        size_t o = 0;
        const uint8_t *a = p + 2;
        for (unsigned j = 0; j < n4 + n6 && o + 48 < sizeof(text); j++) {
            dc_ip_t ip;
            memset(&ip, 0, sizeof(ip));
            ip.family = j < n4 ? 4 : 6;
            memcpy(ip.addr, a, j < n4 ? 4 : 16);
            a += j < n4 ? 4 : 16;
            o += dc_ip_format(&ip, text + o, sizeof(text) - o - 1);
            text[o++] = ' ';
        }
        snprintf(text + o, sizeof(text) - o, "%.*s", (int)req->host_len, req->host);
        cb(arg, text, src_name(im, m->hs_src[i], src, sizeof(src)), "hosts");
    }
    dc_free(m);
}

size_t fl_rule_text(const fl_set_t *set, const fl_ruleref_t *ref, const char *host, char *buf, size_t cap,
                    char *srcbuf, size_t srccap) {
    if (!set || ref->img >= set->n || !cap) return 0;
    const fl_image_t *im = set->img[ref->img];
    buf[0] = 0;
    if (srcbuf && srccap) srcbuf[0] = 0;
    if (ref->is_plain) {
        if (!host) return 0;
        mctx_t *m = (mctx_t *)dc_malloc(sizeof(mctx_t));
        if (!m) return 0;
        fl_req_t rq = {host, (uint16_t)strlen(host), 1, 0, NULL};
        size_t k = 0;
        if (prepare(m, set, &rq) && ref->level < m->nlev) {
            if (ref->kind == 0xFF) {
                k = (size_t)snprintf(buf, cap, "<hosts> %s", host);
            } else {
                k = plain_text(m, ref->kind, ref->level, buf, cap);
            }
        }
        dc_free(m);
        if (srcbuf && srccap && im->h->n_sources) src_name(im, ref->srcmask ? ref->srcmask : 1u, srcbuf, srccap);
        return k;
    }
    if (ref->crule >= im->h->n_crules) return 0;
    uint16_t l;
    const char *s = fl_pool_str(im->pool, im->crules[ref->crule].text_off, &l);
    int k = snprintf(buf, cap, "%.*s", (int)l, s);
    if (srcbuf && srccap) src_name(im, 1u << im->crules[ref->crule].src, srcbuf, srccap);
    return k > 0 ? (size_t)k : 0;
}
