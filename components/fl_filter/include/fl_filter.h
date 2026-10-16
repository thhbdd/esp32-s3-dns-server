/*
 * fl_filter.h - AdGuard Home compatible DNS filtering: compiler + matcher.
 *
 * Cold path (fl_compile_*): rule lists are streamed line by line, parsed with
 * the same semantics as AdGuard's urlfilter DNS engine, de-duplicated with
 * exact badfilter/exception semantics and compiled into one immutable binary
 * image (see fl_image.h for the on-flash layout).
 *
 * Hot path (fl_match): the image is queried with a hostname, the query type
 * and the client identity.  No rule text is parsed at query time:
 *   - plain domain rules: blocked Bloom filter + front-coded sorted index,
 *     exact verification (no false positives)
 *   - rules with modifiers: small condition records attached to the key
 *   - wildcard / regex rules: n-gram prefilter + bounded DFA/NFA program
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dc_net.h"
#include "dc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FL_MAX_SOURCES 32
#define FL_MAX_IMAGES 4
#define FL_MAX_LINE 4096
#define FL_MAX_HOST 253

/* ------------------------------------------------------------------------- */
/* statistics reported by the compiler                                       */

typedef struct {
    uint32_t lines;
    uint32_t empty_comment;  /* empty lines and comments */
    uint32_t cosmetic;       /* element hiding etc. (not DNS) */
    uint32_t host_rules;     /* /etc/hosts style lines and bare domains */
    uint32_t net_rules;      /* adblock-style network rules used for DNS */
    uint32_t invalid;        /* syntax errors (AdGuard rejects them too) */
    uint32_t not_dns;        /* valid but not host-level ($third-party, $domain, ...) */
    uint32_t never_match;    /* e.g. $script: can never match a DNS request */
    uint32_t too_wide;       /* rejected as too wide */
    uint32_t unsupported;    /* valid for AdGuard but unsupported here (see FILTER_COMPAT.md) */
    uint32_t client_skipped; /* $client / $ctag rules skipped at compile time */
    uint32_t too_long;       /* lines longer than FL_MAX_LINE */
    uint32_t plain;          /* compiled into the plain domain index */
    uint32_t complex_domain; /* domain rules with modifiers */
    uint32_t generic;        /* wildcard / substring / regex programs */
    uint32_t regex;          /* /regex/ rules among generic */
    uint32_t dfa;            /* programs compiled to DFA */
    uint32_t nfa;            /* programs kept as NFA */
    uint32_t badfilter;      /* $badfilter rules */
    uint32_t negated;        /* rules disabled by $badfilter at compile time */
    uint32_t dnsrewrite;     /* $dnsrewrite rules */
    uint32_t keys;           /* distinct keys in the domain index */
    uint32_t image_bytes;
    uint32_t runs;           /* external sort runs written */
    uint32_t compactions;    /* run merges performed to save staging space */
    uint32_t staging_peak;   /* peak bytes of run storage used */
    uint32_t compile_ms;
} fl_stats_t;

/* ------------------------------------------------------------------------- */
/* storage backends used by the compiler                                     */

/* Random-access byte store.  For the run store, data is appended at
 * increasing offsets and read back later.  For the image sink, every byte is
 * written exactly once (flash friendly) and read back for verification. */
typedef struct fl_store {
    int (*write)(struct fl_store *s, uint32_t off, const void *buf, size_t len);
    int (*read)(struct fl_store *s, uint32_t off, void *buf, size_t len);
    /* optional: the range (whole 4 KiB sectors) holds no live data anymore
     * and may be erased before it is written again */
    void (*discard)(struct fl_store *s, uint32_t off, size_t len);
    uint32_t capacity; /* the run store must be a multiple of 4096 */
    void *ctx;
} fl_store_t;

/* RAM-backed store (host tools, custom rules on the device). */
typedef struct {
    fl_store_t st;
    dc_buf_t buf;
} fl_memstore_t;
void fl_memstore_init(fl_memstore_t *m, uint32_t capacity);
void fl_memstore_free(fl_memstore_t *m);

/* ------------------------------------------------------------------------- */
/* compiler                                                                  */

typedef struct fl_compiler fl_compiler_t;

typedef struct {
    uint32_t chunk_bytes;      /* in-RAM record arena before spilling a run (default 512 KiB) */
    uint32_t max_complex;      /* cap on rules with modifiers (default 65536) */
    uint32_t max_dfa_states;   /* per program (default 64) */
    uint32_t dfa_budget_bytes; /* total DFA bytes (default 128 KiB) */
    uint32_t generation;
    uint8_t block_entries;     /* keys per front-coded block (default 16) */
    uint8_t bloom_bits_per_key;/* default 12 */
    fl_store_t *runs;          /* run storage (required) */
    /* Optional progress callback; returning false aborts compilation. */
    bool (*progress)(void *arg, const char *phase, uint32_t done, uint32_t total);
    void *progress_arg;
} fl_compile_opts_t;

enum {
    FL_SRC_ALLOWLIST = 1u << 0, /* every rule of this source unblocks (AGH "allowlist") */
};

fl_compiler_t *fl_compile_new(const fl_compile_opts_t *opts);
void fl_compile_free(fl_compiler_t *c);
/* Starts a new source (subscription or custom rules); returns its index. */
int fl_compile_begin_source(fl_compiler_t *c, const char *name, uint32_t flags);
/* Feeds one line (without line terminator).  Returns 0 or a fatal error. */
int fl_compile_line(fl_compiler_t *c, const char *line, size_t len);
/* Feeds a raw chunk of text; lines may span chunks. */
int fl_compile_feed(fl_compiler_t *c, const char *data, size_t len);
/* Ends the current source.  Returns FL_ERR_HTML / FL_ERR_BINARY when the
 * content was rejected (none of its rules are used; feed/line return the
 * same code once the rejection is noticed).  Binary data after rules of
 * the same list is a fatal error: the build must be discarded. */
int fl_compile_end_source(fl_compiler_t *c);
/* Writes the image to `sink` and verifies it.  Returns image size or <0. */
int fl_compile_finish(fl_compiler_t *c, fl_store_t *sink, fl_stats_t *stats);
const fl_stats_t *fl_compile_source_stats(const fl_compiler_t *c, int src);
const char *fl_compile_error(const fl_compiler_t *c);

/* Error codes */
enum {
    FL_OK = 0,
    FL_ERR_NOMEM = -1,
    FL_ERR_IO = -2,
    FL_ERR_FULL = -3,      /* run storage or image capacity exceeded */
    FL_ERR_HTML = -4,      /* source looks like an HTML page */
    FL_ERR_BINARY = -5,    /* source contains binary data */
    FL_ERR_LIMIT = -6,     /* too many complex rules / sources */
    FL_ERR_ABORT = -7,
    FL_ERR_CORRUPT = -8,   /* verification failed */
    FL_ERR_STATE = -9,
};

/* ------------------------------------------------------------------------- */
/* loaded images                                                             */

typedef struct fl_image fl_image_t;

/* Takes ownership of `data` (allocated with dc_malloc_ext) on success. */
int fl_image_load(uint8_t *data, size_t len, bool verify_crc, fl_image_t **out);
/* Same for memory owned elsewhere (e.g. memory-mapped flash): `release` is
 * called with the data pointer when the image is freed (may be NULL). */
int fl_image_load_ex(const uint8_t *data, size_t len, bool verify_crc, void (*release)(const uint8_t *, void *),
                     void *release_arg, fl_image_t **out);
void fl_image_ref(fl_image_t *img);
void fl_image_unref(fl_image_t *img);
const fl_stats_t *fl_image_stats(const fl_image_t *img);
uint32_t fl_image_generation(const fl_image_t *img);
uint32_t fl_image_size(const fl_image_t *img);
uint32_t fl_image_source_count(const fl_image_t *img);
/* returns the (not NUL terminated) source name and its length */
const char *fl_image_source_name(const fl_image_t *img, uint32_t i, uint16_t *len);
/* Reads only the header from a store to validate/size it before loading. */
int fl_image_probe(fl_store_t *st, uint32_t *total_len, uint32_t *generation);

/* ------------------------------------------------------------------------- */
/* matching                                                                  */

typedef struct {
    dc_ip_t ip;       /* family 0 = unknown */
    const char *name; /* persistent client name (for $client), may be NULL */
    uint32_t tags;    /* FL_CTAG_* bits (for $ctag) */
} fl_client_t;

/* AdGuard Home client tags ($ctag) */
enum {
    FL_CTAG_DEVICE_AUDIO, FL_CTAG_DEVICE_CAMERA, FL_CTAG_DEVICE_GAMECONSOLE, FL_CTAG_DEVICE_LAPTOP,
    FL_CTAG_DEVICE_NAS, FL_CTAG_DEVICE_OTHER, FL_CTAG_DEVICE_PC, FL_CTAG_DEVICE_PHONE,
    FL_CTAG_DEVICE_PRINTER, FL_CTAG_DEVICE_SECURITYALARM, FL_CTAG_DEVICE_TABLET, FL_CTAG_DEVICE_TV,
    FL_CTAG_OS_ANDROID, FL_CTAG_OS_IOS, FL_CTAG_OS_LINUX, FL_CTAG_OS_MACOS, FL_CTAG_OS_OTHER,
    FL_CTAG_OS_WINDOWS, FL_CTAG_USER_ADMIN, FL_CTAG_USER_CHILD, FL_CTAG_USER_REGULAR,
    FL_CTAG_COUNT
};
int fl_ctag_from_name(const char *s, size_t n); /* -1 if unknown */
const char *fl_ctag_name(int tag);

enum {
    /* global protection disabled: only $dnsrewrite rules apply (AdGuard Home) */
    FL_REQ_REWRITES_ONLY = 1u << 0,
};

typedef struct {
    const char *host; /* lowercase presentation format, no trailing dot */
    uint16_t host_len;
    uint16_t qtype;
    uint32_t flags; /* FL_REQ_* */
    const fl_client_t *client;
} fl_req_t;

enum {
    FL_V_NONE = 0,  /* no rule matched: resolve normally */
    FL_V_ALLOW,     /* exception rule: resolve, skip response filtering */
    FL_V_ALLOWLIST, /* matched an allowlist source */
    FL_V_BLOCK,     /* blocking rule */
    FL_V_REWRITE,   /* $dnsrewrite */
};

enum { FL_RW_RCODE = 1, FL_RW_RRS, FL_RW_CNAME };

typedef struct {
    uint8_t img;      /* image index in the set */
    uint8_t is_plain;
    uint8_t kind;     /* plain: kind bit index (0xFF: /etc/hosts rule) */
    uint8_t level;    /* label level the rule matched at */
    uint32_t crule;   /* complex rule index */
    uint32_t srcmask; /* sources that contain the rule (plain rules) */
} fl_ruleref_t;

#define FL_MAX_IPS 8
#define FL_MAX_RRS 16

typedef struct {
    uint8_t verdict;
    /* BLOCK via hosts rules: addresses to answer with (AGH "default" mode) */
    uint8_t n_ips;
    uint8_t hosts_rule; /* the block came from /etc/hosts style rules */
    dc_ip_t ips[FL_MAX_IPS];
    /* REWRITE */
    uint8_t rw_kind;
    uint8_t rcode;
    uint8_t n_rr;
    struct {
        uint16_t type;
        uint16_t rdlen;
        const uint8_t *rdata; /* points into the image: valid while the set is held */
    } rr[FL_MAX_RRS];
    const uint8_t *cname; /* wire-format target name for FL_RW_CNAME */
    /* reporting */
    fl_ruleref_t rule;
    bool has_rule;
} fl_result_t;

/* An immutable set of images matched together (e.g. custom rules +
 * compiled subscriptions).  Reference counted, swapped atomically by the
 * DNS core when a new generation is activated. */
typedef struct fl_set fl_set_t;

fl_set_t *fl_set_new(fl_image_t *const *imgs, unsigned n, uint32_t generation);
void fl_set_ref(fl_set_t *s);
void fl_set_unref(fl_set_t *s);
uint32_t fl_set_generation(const fl_set_t *s);
unsigned fl_set_count(const fl_set_t *s);
fl_image_t *fl_set_image(const fl_set_t *s, unsigned i);
/* True if some rule depends on the client ($client, $ctag): verdicts can
 * then differ between clients for the same name. */
bool fl_set_client_dependent(const fl_set_t *s);

/* Matches a request. Thread-safe; uses only the caller's stack. */
void fl_match(const fl_set_t *set, const fl_req_t *req, fl_result_t *res);

/* Diagnostics: calls cb for every rule that matches (before priority
 * resolution), with its reconstructed/original text and source name. */
typedef void (*fl_explain_cb)(void *arg, const char *rule_text, const char *source,
                              const char *effect);
void fl_explain(const fl_set_t *set, const fl_req_t *req, fl_explain_cb cb, void *arg);
/* Text of the rule referenced by a result (reconstructed for plain rules)
 * and the name(s) of the source list(s) it came from. */
size_t fl_rule_text(const fl_set_t *set, const fl_ruleref_t *ref, const char *host, char *buf,
                    size_t cap, char *source, size_t source_cap);

/* ------------------------------------------------------------------------- */
/* helpers                                                                   */

/* Converts a DNS wire name to the lowercase presentation form used for
 * matching (escapes like Go's miekg/dns).  Returns length or -1. */
int fl_name_from_wire(const uint8_t *wire, size_t wire_len, char *out, size_t cap);
/* Presentation -> wire (accepts \DDD and \X escapes).  Returns length or -1. */
int fl_name_to_wire(const char *name, size_t len, uint8_t *out, size_t cap);

/* Encodes RDATA for a record given in presentation form, e.g.
 * ("MX", "10 mail.example.com"), ("HTTPS", "1 . alpn=h2"), ("CAA", "0 issue \"ca.org\"").
 * Supported: A AAAA CNAME NS PTR MX TXT SRV HTTPS SVCB CAA.
 * Returns the RR type (>0) or -1 with *err set. */
int fl_encode_rdata(const char *type, const char *value, uint8_t *out, size_t cap, uint16_t *rdlen,
                    const char **err);
uint16_t fl_rr_type_code(const char *name); /* 0 if unknown */

#ifdef __cplusplus
}
#endif
