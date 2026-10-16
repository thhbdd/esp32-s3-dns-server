/*
 * fl_internal.h - shared internal definitions: binary image format, parsed
 * rule representation and helpers.
 */
#pragma once

#include <stdatomic.h>

#include "fl_filter.h"
#include "fl_regex.h"

/* ========================================================================= */
/* Binary image format                                                       */
/*
 * All integers little endian, all references are byte offsets from the
 * image start.  The image is loaded into one contiguous (PSRAM) buffer.
 *
 *   header (FLI_HDR_SIZE bytes)
 *   [BLOOM]     blocked Bloom filter, 32-byte blocks, over domain keys
 *   [SAMPLES]   u64 big-endian 8-byte key prefixes, one per sample_step blocks
 *   [BLKOFF]    u32 offsets (relative to KEYS) of each block, + end sentinel
 *   [ONELABEL]  sorted u32 FNV-1a hashes of single-label keys
 *   [KEYS]      front-coded blocks of reversed-label keys + payloads
 *   [HOSTSETS]  u32 offsets (into POOL) of /etc/hosts address sets
 *   [CRULES]    fl_crule_t[n_crules] (rules with modifiers / patterns)
 *   [GENERIC]   generic rule index: always-list + n-gram hash tables
 *   [BADFILTER] fl_bfent_t[n] sorted by hash (runtime cross-image $badfilter)
 *   [SOURCES]   fl_srcent_t[n_sources]
 *   [POOL]      variable data (conditions, programs, rewrite RDATA, text)
 *   [SYMTAB]    key suffix compression table (fl_fsst.c)
 *
 * Keys are hostnames with labels reversed ("ads.example.com" ->
 * "com.example.ads").  Every label level of a query is a prefix of the
 * reversed query name, so the FNV hash of every level is computed in one
 * pass.  Front-coded entry:
 *     u8 shared, encoded suffix (see fl_suffix_put), payload
 * payload:
 *     varint m0  (FLP_* bits)
 *     [varint kindmask]   if FLP_EXT       (full 64-bit kind mask)
 *     [varint hostset]    if FLP_HOSTS
 *     [varint group_off]  if FLP_COMPLEX   (POOL offset: varint n, varint ids...)
 *     [varint srcmask]    if FLP_SRC
 */
#define FLI_MAGIC 0x31494C46u /* "FLI1" */
#define FLI_VERSION 1
#define FLI_HDR_SIZE 512
#define FLI_BLOOM_BLOCK 32

enum {
    FLS_BLOOM,
    FLS_SAMPLES,
    FLS_BLKOFF,
    FLS_ONELABEL,
    FLS_KEYS,
    FLS_HOSTSETS,
    FLS_CRULES,
    FLS_GENERIC,
    FLS_BADFILTER,
    FLS_SOURCES,
    FLS_POOL,
    FLS_SYMTAB,
    FLS_COUNT
};

typedef struct {
    uint32_t off, len;
} fli_sec_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t hdr_size;
    uint32_t total_len;
    uint32_t crc32;     /* over [hdr_size, total_len) */
    uint32_t hdr_crc32; /* over the header with this field zero */
    uint32_t generation;
    uint32_t build_time;
    uint32_t flags;
    uint32_t n_keys;
    uint32_t n_blocks;
    uint16_t block_entries;
    uint16_t sample_step;
    uint32_t n_samples;
    uint32_t bloom_blocks;
    uint32_t n_onelabel;
    uint32_t n_hostsets;
    uint32_t n_crules;
    uint32_t n_badfilter;
    uint32_t n_sources;
    uint32_t reserved[6];
    fli_sec_t sec[FLS_COUNT];
    fl_stats_t stats;
} fli_header_t;

_Static_assert(sizeof(fli_header_t) <= FLI_HDR_SIZE, "header too large");

/* payload m0 bits (kept in the first varint byte for the common cases) */
enum {
    FLP_SUFFIX_BLOCK = 1u << 0, /* ||d^           (kind 0, block) */
    FLP_SUFFIX_ALLOW = 1u << 1, /* @@||d^         (kind 0, allow) */
    FLP_HOSTS = 1u << 2,
    FLP_SRC = 1u << 3,
    FLP_COMPLEX = 1u << 4,
    FLP_EXT = 1u << 5,
};

/* Plain rule kinds: pattern shapes that are exactly equivalent to a
 * label-aligned lookup.  Bit layout of the 64-bit kind mask:
 *   bit = kind*4 + allow*2 + important       (normal sources, bits 0..31)
 *   bit = 32 + kind                          (allowlist sources)
 *   bit = 40                                 (allowlist /etc/hosts rule) */
enum {
    FLK_SUFFIX = 0,   /* ||d^    */
    FLK_SUFFIX_P = 1, /* ||d^|   */
    FLK_EXACT = 2,    /* |d^     */
    FLK_EXACT_P = 3,  /* |d^|    */
    FLK_STRICT = 4,   /* ||*.d^  */
    FLK_STRICT_D = 5, /* .d^     */
    FLK_STRICT_S = 6, /* *.d^    */
    FLK_URLEXACT = 7, /* ://d^   */
    FLK_COUNT = 8
};
#define FLK_BIT(kind, allow, imp) (((kind) * 4) + ((allow) ? 2 : 0) + ((imp) ? 1 : 0))
#define FLK_AL_BIT(kind) (32 + (kind))
#define FLK_AL_HOST_BIT 40

/* masks of kind bits that apply at the full name / at an ancestor level */
#define FLK_KIND_ALL4(k) (0xFull << ((k) * 4))
#define FLK_EXACT_SCOPE                                                                         \
    (FLK_KIND_ALL4(FLK_SUFFIX) | FLK_KIND_ALL4(FLK_SUFFIX_P) | FLK_KIND_ALL4(FLK_EXACT) |       \
     FLK_KIND_ALL4(FLK_EXACT_P) | FLK_KIND_ALL4(FLK_URLEXACT) | (1ull << FLK_AL_BIT(FLK_SUFFIX)) | \
     (1ull << FLK_AL_BIT(FLK_SUFFIX_P)) | (1ull << FLK_AL_BIT(FLK_EXACT)) |                     \
     (1ull << FLK_AL_BIT(FLK_EXACT_P)) | (1ull << FLK_AL_BIT(FLK_URLEXACT)) |                   \
     (1ull << FLK_AL_HOST_BIT))
#define FLK_SUB_SCOPE                                                                           \
    (FLK_KIND_ALL4(FLK_SUFFIX) | FLK_KIND_ALL4(FLK_SUFFIX_P) | FLK_KIND_ALL4(FLK_STRICT) |      \
     FLK_KIND_ALL4(FLK_STRICT_D) | FLK_KIND_ALL4(FLK_STRICT_S) |                                \
     (1ull << FLK_AL_BIT(FLK_SUFFIX)) | (1ull << FLK_AL_BIT(FLK_SUFFIX_P)) |                    \
     (1ull << FLK_AL_BIT(FLK_STRICT)) | (1ull << FLK_AL_BIT(FLK_STRICT_D)) |                    \
     (1ull << FLK_AL_BIT(FLK_STRICT_S)))
#define FLK_ALLOWLIST_MASK (0x1FFull << 32)

extern const char *const fl_kind_prefix[FLK_COUNT];
extern const char *const fl_kind_suffix[FLK_COUNT];

/* scope of domain-attached complex rules */
enum { FL_SCOPE_EXACT = 1, FL_SCOPE_SUB = 2, FL_SCOPE_SUFFIX = 3 };

/* complex rule actions */
enum {
    FL_ACT_BLOCK = 1,
    FL_ACT_ALLOW,
    FL_ACT_REWRITE,     /* $dnsrewrite */
    FL_ACT_REWRITE_EXC, /* @@...$dnsrewrite[=value] */
    FL_ACT_BADFILTER,   /* runtime $badfilter (conditional or cross image) */
    FL_ACT_ALLOWLIST,
    FL_ACT_HOSTS_AL,    /* unused placeholder */
};

enum {
    FL_CRF_IMPORTANT = 1u << 0,
    FL_CRF_GENERIC = 1u << 1,  /* matched by pattern program, not attached to a key */
    FL_CRF_URLSUBJ = 1u << 2,  /* program runs on "http://"+host */
    FL_CRF_MATCHALL = 1u << 3, /* pattern matches everything */
};

typedef struct {
    uint8_t action;
    uint8_t flags;
    uint8_t scope;
    uint8_t src;
    uint32_t cond_off;     /* POOL offset of condition block, 0 = none */
    uint32_t prog_off;     /* POOL offset of matcher program, 0 = none */
    uint32_t rw_off;       /* POOL offset of rewrite record, 0 = none */
    uint32_t text_off;     /* POOL offset: u16 len + original rule text */
    uint32_t ident_off;    /* POOL offset: u16 len + badfilter identity */
    uint32_t ident_hash;
    uint32_t shortcut_off; /* POOL offset: u8 len + urlfilter shortcut (regex rules), 0 = none */
    uint32_t order;        /* global order (dnsrewrite resolution) */
    uint32_t lit_off;      /* POOL offset: u8 len + literal required in "http://"+host, 0 = none */
} fl_crule_t;

_Static_assert(sizeof(fl_crule_t) == 40, "crule layout");

/* condition block item types */
enum {
    FLC_DNSTYPE_PERM = 1, /* u8 n, u16 types[n] */
    FLC_DNSTYPE_RESTR,
    FLC_CTAG_PERM, /* u32 mask (bit 31: unknown tag present) */
    FLC_CTAG_RESTR,
    FLC_CLIENT_PERM, /* u8 n, items: u8 kind (4/6: u8 bits + addr, 'n': u8 len + name) */
    FLC_CLIENT_RESTR,
    FLC_DENYALLOW, /* u8 n, items: u8 len + lowercase domain */
};

/* rewrite record (POOL) */
enum { FLRW_EMPTY = 0, FLRW_RCODE = 1, FLRW_RR = 2, FLRW_CNAME = 3, FLRW_NORR = 4 };
/*  u8 kind, u8 rcode, u16 rrtype, u16 rdlen, rdata[rdlen]
 *  FLRW_CNAME: rdata = wire name of the new canonical name
 *  FLRW_NORR:  NOERROR + rrtype without a supported value (answers nothing) */

typedef struct {
    uint32_t hash;
    uint32_t ident_off; /* POOL: u16 len + identity */
    uint32_t cond_off;  /* POOL: condition block for conditional badfilters, 0 = unconditional */
    uint32_t crule;     /* complex rule index for conditional ones (0xFFFFFFFF none) */
} fl_bfent_t;

typedef struct {
    uint32_t name_off; /* POOL: u16 len + name */
    uint32_t flags;
    uint32_t rules;
    uint32_t reserved;
} fl_srcent_t;

/* GENERIC section:
 *   u32 n_always, u32 always[n_always]
 *   for n in 2,3,4: u32 nbuckets (power of 2), u32 bitmap_log2,
 *                   u8 bitmap[1 << bitmap_log2 >> 3], {u32 key, u32 list_off}[nbuckets]
 * list_off is a POOL offset: varint count, varint crule ids (delta coded). */

/* ========================================================================= */
/* key suffix compression (fl_fsst.c)                                        */

#define FL_SYMTAB_BYTES (256 + 255 * 8)
typedef struct {
    unsigned nsym;
    uint8_t len[256];
    uint64_t sym[256];
    uint8_t first[256]; /* encoder index */
    uint8_t order[255];
} fl_symtab_t;

/* builds a table from nstr sample strings sample[offs[i]..offs[i+1]) */
int fl_fsst_build(fl_symtab_t *t, const uint8_t *sample, const uint32_t *offs, size_t nstr);
/* out must hold 2*n bytes */
size_t fl_fsst_encode(const fl_symtab_t *t, const uint8_t *in, size_t n, uint8_t *out);
void fl_fsst_serialize(const fl_symtab_t *t, uint8_t out[FL_SYMTAB_BYTES]);
bool fl_fsst_load(fl_symtab_t *t, const uint8_t *in);

/* Decodes n code bytes; out must have room for cap + 8 bytes.
 * Returns decoded length or a value > cap on overflow. */
static inline unsigned fl_fsst_decode(const fl_symtab_t *t, const uint8_t *in, unsigned n, uint8_t *out,
                                      unsigned cap) {
    unsigned o = 0;
    for (unsigned i = 0; i < n && o <= cap; i++) {
        uint8_t c = in[i];
        if (c == 255) {
            if (++i >= n) return cap + 1;
            out[o++] = in[i];
        } else {
            memcpy(out + o, &t->sym[c], 8);
            o += t->len[c];
        }
    }
    return o;
}

/* Encoded key suffix: u8 L; L < 255: L code bytes; L == 255: u8 raw_len + raw bytes. */
static inline size_t fl_suffix_put(const fl_symtab_t *t, const uint8_t *s, size_t n, uint8_t *out) {
    uint8_t tmp[2 * 256];
    size_t c = fl_fsst_encode(t, s, n, tmp);
    if (c < 255 && c < n + 1) {
        out[0] = (uint8_t)c;
        memcpy(out + 1, tmp, c);
        return 1 + c;
    }
    out[0] = 255;
    out[1] = (uint8_t)n;
    memcpy(out + 2, s, n);
    return 2 + n;
}

/* Decodes an encoded suffix at p into out (room for 256 + 8).  Returns the
 * pointer after it, sets *len; NULL on malformed data. */
static inline const uint8_t *fl_suffix_get(const fl_symtab_t *t, const uint8_t *p, const uint8_t *end,
                                           uint8_t *out, unsigned cap, unsigned *len) {
    if (p >= end) return NULL;
    unsigned l = *p++;
    if (l == 255) {
        if (p >= end) return NULL;
        unsigned rl = *p++;
        if ((size_t)(end - p) < rl || rl > cap) return NULL;
        memcpy(out, p, rl);
        *len = rl;
        return p + rl;
    }
    if ((size_t)(end - p) < l) return NULL;
    unsigned d = fl_fsst_decode(t, p, l, out, cap);
    if (d > cap) return NULL;
    *len = d;
    return p + l;
}

/* ========================================================================= */
/* parsed rule (output of fl_rule_parse)                                     */

enum {
    FL_LINE_EMPTY = 0,
    FL_LINE_COMMENT,
    FL_LINE_COSMETIC,
    FL_LINE_HOST,
    FL_LINE_NET,
    FL_LINE_INVALID,
    FL_LINE_NOTDNS,
    FL_LINE_NEVER,
    FL_LINE_TOOWIDE,
    FL_LINE_UNSUPPORTED,
    FL_LINE_CLIENT_SKIP,
};

#define FL_MAX_HOSTNAMES 64
#define FL_MAX_HOST_IPS 16    /* addresses kept for one hosts-file name */
#define FL_MAX_CR_PER_KEY 255 /* modifier rules kept for one domain */
#define FL_MAX_LIST 64

typedef struct {
    uint8_t kind; /* 4, 6 or 'n' */
    uint8_t bits;
    uint8_t addr[16];
    const char *name;
    uint16_t name_len;
} fl_cli_item_t;

typedef struct {
    uint8_t kind; /* FLRW_* */
    uint8_t rcode;
    uint16_t rrtype;
    uint16_t rdlen;
    uint8_t rdata[512];
} fl_rw_t;

typedef struct {
    int line_kind;
    const char *reason;

    /* host rule */
    dc_ip_t host_ip;
    uint16_t n_hosts;
    const char *hosts[FL_MAX_HOSTNAMES];
    uint16_t host_len[FL_MAX_HOSTNAMES];

    /* network rule */
    bool whitelist, important, badfilter;
    const char *pattern;
    uint16_t pattern_len;
    uint32_t perm_types, restr_types;
    uint8_t n_cli_perm, n_cli_restr;
    fl_cli_item_t cli_perm[FL_MAX_LIST], cli_restr[FL_MAX_LIST];
    bool has_ctag;
    uint32_t ctag_perm, ctag_restr;
    uint8_t n_ctag_perm, n_ctag_restr;
    const char *ctag_perm_s[FL_MAX_LIST], *ctag_restr_s[FL_MAX_LIST];
    uint8_t ctag_perm_l[FL_MAX_LIST], ctag_restr_l[FL_MAX_LIST];
    uint8_t n_dt_perm, n_dt_restr;
    uint16_t dt_perm[FL_MAX_LIST], dt_restr[FL_MAX_LIST];
    uint8_t n_deny;
    const char *deny[FL_MAX_LIST];
    uint8_t deny_len[FL_MAX_LIST];
    bool has_rewrite;
    fl_rw_t rw;
    /* urlfilter shortcut (lowercase) */
    char shortcut[FL_MAX_LINE > 256 ? 256 : FL_MAX_LINE];
    uint16_t shortcut_len;

    /* scratch for unescaped strings */
    char scratch[FL_MAX_LINE * 2];
    size_t scratch_used;
} fl_rule_t;

int fl_rule_parse(const char *line, size_t len, fl_rule_t *r);

/* request type bits (urlfilter) */
enum {
    FL_RT_DOCUMENT = 1u << 0,
    FL_RT_SUBDOCUMENT = 1u << 1,
    FL_RT_SCRIPT = 1u << 2,
    FL_RT_STYLESHEET = 1u << 3,
    FL_RT_OBJECT = 1u << 4,
    FL_RT_IMAGE = 1u << 5,
    FL_RT_XHR = 1u << 6,
    FL_RT_MEDIA = 1u << 7,
    FL_RT_FONT = 1u << 8,
    FL_RT_WEBSOCKET = 1u << 9,
    FL_RT_PING = 1u << 10,
    FL_RT_OTHER = 1u << 11,
};

/* urlfilter pattern -> Go regex text (patternToRegexp emulation).
 * Returns length written, sets *host_subject when the expression can be
 * applied to the bare hostname instead of "http://"+host. */
int fl_pattern_to_regex(const char *pat, size_t len, char *out, size_t cap, bool *url_subject,
                        bool *match_all);

/* ========================================================================= */
/* names / RR helpers (fl_name.c, fl_rr.c)                                   */

/* golibs netutil.ValidateHostname */
bool fl_valid_hostname(const char *s, size_t n);
/* urlfilter ufnet.IsDomainName */
bool fl_is_domain_name(const char *s, size_t n);
uint16_t fl_rrtype_from_name(const char *s, size_t n); /* 0 = unknown */
int fl_rcode_from_name(const char *s, size_t n); /* -1 unknown */
/* Parses the $dnsrewrite value. Returns 0 or -1 (sets *err). */
int fl_rewrite_parse(const char *s, size_t n, fl_rw_t *rw, const char **err);

/* reverse labels of a lowercase presentation hostname (escaped dots kept
 * inside labels).  Returns length. */
size_t fl_reverse_name(const char *host, size_t n, char *out);

/* ========================================================================= */
/* loaded image                                                              */

struct fl_image {
    _Atomic int refs;
    uint8_t *data;
    void (*release)(const uint8_t *data, void *arg); /* NULL: dc_free */
    void *release_arg;
    uint32_t len;
    const fli_header_t *h;
    const uint8_t *bloom;
    uint32_t bloom_blocks;
    const uint8_t *samples;
    uint64_t *samples_fast; /* internal-RAM copy of SAMPLES (host order) */
    const uint8_t *blkoff;
    const uint8_t *keys;
    uint32_t keys_len;
    const uint32_t *onelabel; /* internal-RAM copy */
    uint32_t n_onelabel;
    const uint8_t *hostsets;
    const fl_crule_t *crules;
    const uint8_t *generic;
    uint32_t generic_len;
    const fl_bfent_t *bf;
    fl_symtab_t *symtab; /* internal-RAM copy */
    const fl_srcent_t *sources;
    const uint8_t *pool;
    uint32_t pool_len;
    /* parsed GENERIC section */
    uint32_t n_always;
    const uint8_t *always;
    struct {
        uint32_t nbuckets;
        uint32_t bits_log2;
        const uint8_t *bitmap;
        const uint8_t *buckets;
        /* small tables are scanned directly (no per-position hashing) */
        uint8_t nsmall; /* 0xFF: use hashing */
        uint32_t small_key[16];
        uint32_t small_list[16];
    } ng[3]; /* n = 2, 3, 4 */
};

struct fl_set {
    _Atomic int refs;
    uint32_t generation;
    unsigned n;
    fl_image_t *img[FL_MAX_IMAGES];
    bool any_bf;
    bool client_dep; /* some rule depends on $client / $ctag */
};

/* bloom helpers shared by compiler and matcher */
static inline uint32_t fl_bloom_block(uint32_t h, uint32_t nblocks) {
    return (uint32_t)(((uint64_t)dc_fmix32(h) * nblocks) >> 32);
}
static inline void fl_bloom_bits(uint32_t h, uint8_t pos[6]) {
    uint32_t g = dc_fmix32(h ^ 0x9e3779b9u);
    uint32_t g2 = dc_fmix32(g + h);
    pos[0] = (uint8_t)g;
    pos[1] = (uint8_t)(g >> 8);
    pos[2] = (uint8_t)(g >> 16);
    pos[3] = (uint8_t)(g >> 24);
    pos[4] = (uint8_t)g2;
    pos[5] = (uint8_t)(g2 >> 8);
}

/* n-gram key: up to 4 bytes packed little endian, n in 2..4 */
static inline uint32_t fl_ngram_key(const uint8_t *p, unsigned n) {
    uint32_t k = 0;
    for (unsigned i = 0; i < n; i++) k |= (uint32_t)p[i] << (8 * i);
    return k; /* never 0: subject bytes are never NUL; tables are per n */
}
static inline uint32_t fl_ngram_hash(uint32_t key) {
    uint32_t h = key * 0x9E3779B1u;
    return h ^ (h >> 15);
}

/* reads a u16-length-prefixed string from the pool */
static inline const char *fl_pool_str(const uint8_t *pool, uint32_t off, uint16_t *len) {
    *len = dc_ld16(pool + off);
    return (const char *)pool + off + 2;
}
