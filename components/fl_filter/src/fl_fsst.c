/*
 * fl_fsst.c - static symbol table string compression (FSST-like).
 *
 * Domain keys are compressed with a table of up to 255 symbols of 1..8
 * bytes ("com.", "ads", "track", ...).  Code 255 escapes one literal byte.
 * Decoding is a byte-indexed table lookup plus an 8-byte copy per code, so
 * scanning a front-coded block stays cheap while the index shrinks by ~40%.
 *
 * Table construction follows the FSST paper (Boncz, Neumann, Leis 2020):
 * a few rounds of greedy encoding of a sample, counting single symbols and
 * adjacent symbol pairs, and keeping the 255 candidates with the highest
 * gain (count * length).
 */
#include <stdlib.h>
#include <string.h>

#include "fl_internal.h"

#define CODE_ESC 255
#define NCODE 512 /* 0..254 symbols, 256+b literal byte b */

static void idx_build(fl_symtab_t *t) {
    /* per first byte: symbols sorted by length (desc) */
    memset(t->first, 0xFF, sizeof(t->first));
    uint8_t order[255];
    unsigned n = t->nsym;
    for (unsigned i = 0; i < n; i++) order[i] = (uint8_t)i;
    for (unsigned i = 1; i < n; i++) { /* insertion sort by (first byte, len desc) */
        uint8_t v = order[i];
        unsigned j = i;
        while (j) {
            uint8_t u = order[j - 1];
            uint8_t fu = (uint8_t)t->sym[u], fv = (uint8_t)t->sym[v];
            if (fu < fv || (fu == fv && t->len[u] >= t->len[v])) break;
            order[j] = u;
            j--;
        }
        order[j] = v;
    }
    memcpy(t->order, order, n);
    for (unsigned i = n; i-- > 0;) t->first[(uint8_t)t->sym[order[i]]] = (uint8_t)i;
}

/* longest symbol matching at s[0..n); returns code or -1 */
static int find_sym(const fl_symtab_t *t, const uint8_t *s, size_t n) {
    uint8_t f = t->first[s[0]];
    if (f == 0xFF) return -1;
    for (unsigned i = f; i < t->nsym; i++) {
        uint8_t c = t->order[i];
        if ((uint8_t)t->sym[c] != s[0]) break;
        unsigned l = t->len[c];
        if (l > n) continue;
        uint64_t v = 0;
        memcpy(&v, s, l);
        uint64_t mask = l == 8 ? ~0ull : ((1ull << (8 * l)) - 1);
        if ((t->sym[c] & mask) == v) return c;
    }
    return -1;
}

size_t fl_fsst_encode(const fl_symtab_t *t, const uint8_t *in, size_t n, uint8_t *out) {
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        int c = t->nsym ? find_sym(t, in + i, n - i) : -1;
        if (c < 0) {
            out[o++] = CODE_ESC;
            out[o++] = in[i++];
        } else {
            out[o++] = (uint8_t)c;
            i += t->len[c];
        }
    }
    return o;
}

typedef struct {
    uint32_t key; /* (a << 16) | b, codes < NCODE */
    uint32_t cnt;
} pair_t;

typedef struct {
    uint64_t sym;
    uint8_t len;
    uint32_t gain;
} cand_t;

static int cmp_cand(const void *a, const void *b) {
    const cand_t *x = (const cand_t *)a, *y = (const cand_t *)b;
    if (x->gain != y->gain) return x->gain > y->gain ? -1 : 1;
    if (x->len != y->len) return x->len > y->len ? -1 : 1;
    return x->sym < y->sym ? -1 : x->sym > y->sym;
}

static uint64_t code_sym(const fl_symtab_t *t, unsigned code, uint8_t *len) {
    if (code >= 256) {
        *len = 1;
        return code - 256;
    }
    *len = t->len[code];
    return t->sym[code];
}

int fl_fsst_build(fl_symtab_t *t, const uint8_t *sample, const uint32_t *offs, size_t nstr) {
    memset(t, 0, sizeof(*t));
    idx_build(t);
    if (!nstr) return 0;
    /* The first chunk supplies at most ~32 KiB of domain suffixes. A 64K
     * pair table plus 66K candidates needed >1.5 MiB of contiguous PSRAM
     * on the device, even after the DNS cache had been released. A bounded
     * 8K table needs ~202 KiB total, with the same on-flash image format.
     * Missed hash collisions can change compression ratio, never semantics. */
    const unsigned PAIRCAP = 1u << 13;
    uint32_t *cnt1 = (uint32_t *)dc_calloc_ext(NCODE, sizeof(uint32_t));
    pair_t *pairs = (pair_t *)dc_calloc_ext(PAIRCAP, sizeof(pair_t));
    cand_t *cand = (cand_t *)dc_malloc_ext(sizeof(cand_t) * (NCODE + PAIRCAP));
    if (!cnt1 || !pairs || !cand) {
        dc_free(cnt1);
        dc_free(pairs);
        dc_free(cand);
        return FL_ERR_NOMEM;
    }
    for (int round = 0; round < 5; round++) {
        memset(cnt1, 0, NCODE * sizeof(uint32_t));
        memset(pairs, 0, PAIRCAP * sizeof(pair_t));
        for (size_t s = 0; s < nstr; s++) {
            const uint8_t *str = sample + offs[s];
            size_t n = offs[s + 1] - offs[s];
            int prev = -1;
            for (size_t i = 0; i < n;) {
                int c = t->nsym ? find_sym(t, str + i, n - i) : -1;
                unsigned code;
                if (c < 0) {
                    code = 256u + str[i];
                    i++;
                } else {
                    code = (unsigned)c;
                    i += t->len[c];
                }
                cnt1[code]++;
                if (prev >= 0) {
                    uint32_t key = ((uint32_t)prev << 16) | code;
                    uint32_t h = dc_fmix32(key) & (PAIRCAP - 1);
                    for (unsigned probe = 0; probe < 64; probe++) {
                        pair_t *p = &pairs[(h + probe) & (PAIRCAP - 1)];
                        if (p->cnt == 0) {
                            p->key = key;
                            p->cnt = 1;
                            break;
                        }
                        if (p->key == key) {
                            p->cnt++;
                            break;
                        }
                    }
                }
                prev = (int)code;
            }
        }
        /* candidates */
        size_t nc = 0;
        for (unsigned code = 0; code < NCODE; code++) {
            if (!cnt1[code]) continue;
            if (code < 256 && code >= t->nsym) continue;
            uint8_t l;
            uint64_t s = code_sym(t, code, &l);
            cand[nc].sym = s;
            cand[nc].len = l;
            /* literals cost two bytes when escaped: gain counts saved bytes */
            cand[nc].gain = cnt1[code] * l;
            nc++;
        }
        for (unsigned i = 0; i < PAIRCAP; i++) {
            if (!pairs[i].cnt) continue;
            uint8_t la, lb;
            uint64_t a = code_sym(t, pairs[i].key >> 16, &la);
            uint64_t b = code_sym(t, pairs[i].key & 0xFFFF, &lb);
            if (la + lb > 8) continue;
            cand[nc].sym = a | (b << (8 * la));
            cand[nc].len = (uint8_t)(la + lb);
            cand[nc].gain = pairs[i].cnt * (la + lb);
            nc++;
        }
        qsort(cand, nc, sizeof(cand_t), cmp_cand);
        /* dedupe and take the best 255 (write directly into *t to save 2.3 KB stack) */
        memset(t, 0, sizeof(*t));
        for (size_t i = 0; i < nc && t->nsym < 255; i++) {
            bool dup = false;
            for (unsigned k = 0; k < t->nsym; k++)
                if (t->len[k] == cand[i].len && t->sym[k] == cand[i].sym) dup = true;
            if (dup || cand[i].gain < 2) continue;
            t->sym[t->nsym] = cand[i].sym;
            t->len[t->nsym] = cand[i].len;
            t->nsym++;
        }
        idx_build(t);
    }
    dc_free(cnt1);
    dc_free(pairs);
    dc_free(cand);
    return 0;
}

void fl_fsst_serialize(const fl_symtab_t *t, uint8_t out[FL_SYMTAB_BYTES]) {
    memset(out, 0, FL_SYMTAB_BYTES);
    out[0] = (uint8_t)t->nsym;
    for (unsigned i = 0; i < t->nsym; i++) {
        out[1 + i] = t->len[i];
        dc_st64(out + 256 + i * 8, t->sym[i]);
    }
}

bool fl_fsst_load(fl_symtab_t *t, const uint8_t *in) {
    memset(t, 0, sizeof(*t));
    t->nsym = in[0];
    if (t->nsym > 255) return false;
    for (unsigned i = 0; i < t->nsym; i++) {
        t->len[i] = in[1 + i];
        if (t->len[i] < 1 || t->len[i] > 8) return false;
        t->sym[i] = dc_ld64(in + 256 + i * 8);
    }
    idx_build(t);
    return true;
}
