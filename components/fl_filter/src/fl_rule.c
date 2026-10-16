/*
 * fl_rule.c - single line parser, a faithful port of AdGuard urlfilter
 * (rules/rule.go, host.go, network.go, regexp.go) restricted to what the
 * DNS engine uses.  Deliberate deviations are listed in docs/FILTER_COMPAT.md.
 */
#include <string.h>

#include "fl_internal.h"

/* option bits (urlfilter NetworkRuleOption) */
enum {
    O_THIRD = 1u << 0,
    O_MATCHCASE = 1u << 1,
    O_IMPORTANT = 1u << 2,
    O_BADFILTER = 1u << 3,
    O_ELEMHIDE = 1u << 4,
    O_GENERICHIDE = 1u << 5,
    O_GENERICBLOCK = 1u << 6,
    O_JSINJECT = 1u << 7,
    O_URLBLOCK = 1u << 8,
    O_CONTENT = 1u << 9,
    O_EXTENSION = 1u << 10,
    O_STEALTH = 1u << 11,
    O_EMPTY = 1u << 12,
    O_MP4 = 1u << 13,
    O_POPUP = 1u << 14,
};
#define O_BLACKLIST_ONLY (O_EMPTY | O_MP4 | O_POPUP)
#define O_WHITELIST_ONLY                                                                         \
    (O_CONTENT | O_ELEMHIDE | O_EXTENSION | O_GENERICBLOCK | O_GENERICHIDE | O_JSINJECT |       \
     O_STEALTH | O_URLBLOCK)
#define O_HOSTLEVEL (O_IMPORTANT | O_BADFILTER)

static const char *const k_regex_sep = "([^ a-zA-Z0-9.%_-]|$)";

static bool is_space(int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'; }

/* UTF-8 length of the Unicode white space (unicode.IsSpace, non-ASCII) that
 * is exactly the n bytes at p, else 0 */
static size_t uspace(const uint8_t *p, size_t n) {
    if (n == 2) return p[0] == 0xC2 && (p[1] == 0x85 || p[1] == 0xA0) ? 2 : 0; /* U+0085, U+00A0 */
    if (n != 3) return 0;
    if (p[0] == 0xE1) return p[1] == 0x9A && p[2] == 0x80 ? 3 : 0;            /* U+1680 */
    if (p[0] == 0xE3) return p[1] == 0x80 && p[2] == 0x80 ? 3 : 0;            /* U+3000 */
    if (p[0] != 0xE2) return 0;
    if (p[1] == 0x80) /* U+2000..U+200A, U+2028, U+2029, U+202F */
        return (p[2] >= 0x80 && p[2] <= 0x8A) || p[2] == 0xA8 || p[2] == 0xA9 || p[2] == 0xAF ? 3 : 0;
    return p[1] == 0x81 && p[2] == 0x9F ? 3 : 0;                              /* U+205F */
}

/* Go strings.TrimSpace */
static void trim(const char **s, size_t *n) {
    const uint8_t *p = (const uint8_t *)*s;
    size_t l = *n, k;
    for (;;) {
        if (l && is_space(p[0]))
            k = 1;
        else if (!(l >= 2 && (k = uspace(p, 2))) && !(l >= 3 && (k = uspace(p, 3))))
            break;
        p += k;
        l -= k;
    }
    for (;;) {
        if (l && is_space(p[l - 1]))
            k = 1;
        else if (!(l >= 2 && (k = uspace(p + l - 2, 2))) && !(l >= 3 && (k = uspace(p + l - 3, 3))))
            break;
        l -= k;
    }
    *s = (const char *)p;
    *n = l;
}

static bool has_prefix(const char *s, size_t n, const char *p) {
    size_t pl = strlen(p);
    return n >= pl && memcmp(s, p, pl) == 0;
}

/* sorted by length desc (urlfilter cosmeticRulesMarkers) */
static const char *const k_cos_markers[] = {"#@$?#", "#@?#", "#@$#", "#$?#", "#@%#", "#?#", "#$#",
                                            "#@#",   "#%#",  "$@$",  "##",   "$$"};

static bool is_cosmetic(const char *s, size_t n) {
    static const char firsts[] = {'#', '$'};
    for (size_t f = 0; f < 2; f++) {
        const char *p = (const char *)memchr(s, firsts[f], n);
        if (!p) continue;
        size_t idx = (size_t)(p - s);
        if (idx > 0 && s[idx - 1] == ' ') continue;
        for (size_t m = 0; m < DC_ARRAY_SIZE(k_cos_markers); m++)
            if (has_prefix(s + idx, n - idx, k_cos_markers[m])) return true;
    }
    return false;
}

static char *scratch(fl_rule_t *r, size_t n) {
    if (r->scratch_used + n > sizeof(r->scratch)) return NULL;
    char *p = r->scratch + r->scratch_used;
    r->scratch_used += n;
    return p;
}

/* ------------------------------------------------------------------------- */
/* host rules                                                                */

static void split_ws(const char **s, size_t *n, const char **tok, size_t *tl) {
    const char *p = *s;
    size_t l = *n;
    while (l && (*p == ' ' || *p == '\t')) {
        p++;
        l--;
    }
    size_t i = 0;
    while (i < l && p[i] != ' ' && p[i] != '\t') i++;
    *tok = p;
    *tl = i;
    p += i;
    l -= i;
    while (l && (*p == ' ' || *p == '\t')) {
        p++;
        l--;
    }
    *s = p;
    *n = l;
}

static bool parse_host_rule(const char *s, size_t n, fl_rule_t *r) {
    /* Strip comments.  urlfilter cuts at index-1 (dropping the character
     * before '#', normally a space); we cut at '#' and trim, see
     * FILTER_COMPAT.md (deviation D1). */
    const char *hash = (const char *)memchr(s, '#', n);
    if (hash && hash > s) n = (size_t)(hash - s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) n--;
    const char *first;
    size_t fl;
    split_ws(&s, &n, &first, &fl);
    if (n == 0) {
        if (!fl_is_domain_name(first, fl)) return false;
        memset(&r->host_ip, 0, sizeof(r->host_ip));
        r->host_ip.family = 4;
        r->hosts[0] = first;
        r->host_len[0] = (uint16_t)fl;
        r->n_hosts = 1;
        return true;
    }
    if (!dc_ip_parse(first, fl, &r->host_ip)) return false;
    r->n_hosts = 0;
    while (n) {
        const char *h;
        size_t hl;
        split_ws(&s, &n, &h, &hl);
        if (!hl) break;
        if (r->n_hosts < FL_MAX_HOSTNAMES) {
            r->hosts[r->n_hosts] = h;
            r->host_len[r->n_hosts++] = (uint16_t)hl;
        }
    }
    return true;
}

/* ------------------------------------------------------------------------- */
/* options                                                                   */

/* splitWithEscapeCharacter(s, sep, '\\'): "\<sep>" -> sep; empty parts dropped.
 * Writes parts into scratch; returns count. */
static int split_esc(fl_rule_t *r, const char *s, size_t n, char sep, const char **parts,
                     size_t *plen, int maxp) {
    int np = 0;
    char *buf = scratch(r, n + 1);
    if (!buf) return -1;
    size_t o = 0, st = 0;
    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        if (ch == '\\' && i + 1 < n && s[i + 1] == sep) {
            buf[o++] = sep;
            i++;
        } else if (ch == sep) {
            if (o > st) {
                if (np >= maxp) return -1;
                parts[np] = buf + st;
                plen[np++] = o - st;
            }
            st = o;
        } else {
            buf[o++] = ch;
        }
    }
    if (o > st) {
        if (np >= maxp) return -1;
        parts[np] = buf + st;
        plen[np++] = o - st;
    }
    return np;
}

/* strings.Split(s, sep) (empty parts kept) */
static int split_plain(const char *s, size_t n, char sep, const char **parts, size_t *plen, int maxp) {
    int np = 0;
    size_t st = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == sep) {
            if (np >= maxp) return -1;
            parts[np] = s + st;
            plen[np++] = i - st;
            st = i + 1;
        }
    }
    return np;
}

typedef struct {
    uint32_t enabled, disabled;
    bool has_domain, has_geo, unsupported;
    const char *unsupported_reason;
} optstate_t;

static int set_opt(fl_rule_t *r, optstate_t *os, uint32_t opt, bool enable) {
    if (r->whitelist && (opt & O_BLACKLIST_ONLY) == opt) return -1;
    if (!r->whitelist && (opt & O_WHITELIST_ONLY) == opt) return -1;
    if (enable)
        os->enabled |= opt;
    else
        os->disabled |= opt;
    return 0;
}

/* urlfilter parseDomains(value, "|") validation */
static int parse_domains(const char *v, size_t n, const char **perm, uint8_t *perml, int *np,
                         int *nrestr, bool *wildcard) {
    const char *parts[FL_MAX_LIST];
    size_t pl[FL_MAX_LIST];
    if (n == 0) return -1;
    int k = split_plain(v, n, '|', parts, pl, FL_MAX_LIST);
    if (k < 0) return -2;
    *np = 0;
    *nrestr = 0;
    for (int i = 0; i < k; i++) {
        const char *d = parts[i];
        size_t dl = pl[i];
        bool restr = false;
        if (dl && d[0] == '~') {
            restr = true;
            d++;
            dl--;
        }
        bool wc = dl >= 2 && d[dl - 2] == '.' && d[dl - 1] == '*';
        if (!fl_is_domain_name(d, dl) && !wc) return -1;
        if (wc) *wildcard = true;
        if (restr) {
            (*nrestr)++;
        } else if (perm) {
            if (dl > 255) return -1;
            perm[*np] = d;
            perml[*np] = (uint8_t)dl;
            (*np)++;
        }
    }
    return 0;
}

static int add_client(fl_rule_t *r, const char *c, size_t cl) {
    bool restr = false;
    if (cl && c[0] == '~') {
        restr = true;
        c++;
        cl--;
    }
    char q = 0;
    if (cl >= 2 && (c[0] == '\'' || c[0] == '"') && c[0] == c[cl - 1]) {
        q = c[0];
        c++;
        cl -= 2;
    }
    /* unescape "\," and the quote character */
    char *u = scratch(r, cl + 1);
    if (!u) return -2;
    size_t o = 0;
    for (size_t i = 0; i < cl; i++) {
        if (c[i] == '\\' && i + 1 < cl && (c[i + 1] == ',' || (q && c[i + 1] == q))) {
            u[o++] = c[++i];
        } else {
            u[o++] = c[i];
        }
    }
    if (o == 0) return -1;
    fl_cli_item_t it;
    memset(&it, 0, sizeof(it));
    dc_ip_t ip;
    dc_prefix_t pf;
    if (!memchr(u, '%', o) && dc_ip_parse(u, o, &ip)) {
        it.kind = ip.family;
        it.bits = ip.family == 4 ? 32 : 128;
        memcpy(it.addr, ip.addr, 16);
    } else if (dc_prefix_parse(u, o, &pf)) {
        it.kind = pf.ip.family;
        it.bits = pf.bits;
        memcpy(it.addr, pf.ip.addr, 16);
    } else {
        it.kind = 'n';
        it.name = u;
        it.name_len = (uint16_t)o;
    }
    if (restr) {
        if (r->n_cli_restr >= FL_MAX_LIST) return -2;
        r->cli_restr[r->n_cli_restr++] = it;
    } else {
        if (r->n_cli_perm >= FL_MAX_LIST) return -2;
        r->cli_perm[r->n_cli_perm++] = it;
    }
    return 0;
}

static bool valid_ctag(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if ((c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_') return false;
    }
    return true;
}

static uint32_t req_type(const char *name, size_t n, bool *found) {
    static const struct {
        const char *n;
        uint32_t t;
    } t[] = {{"script", FL_RT_SCRIPT},       {"stylesheet", FL_RT_STYLESHEET},
             {"subdocument", FL_RT_SUBDOCUMENT}, {"object", FL_RT_OBJECT},
             {"image", FL_RT_IMAGE},         {"xmlhttprequest", FL_RT_XHR},
             {"media", FL_RT_MEDIA},         {"font", FL_RT_FONT},
             {"websocket", FL_RT_WEBSOCKET}, {"ping", FL_RT_PING},
             {"other", FL_RT_OTHER}};
    for (size_t i = 0; i < DC_ARRAY_SIZE(t); i++) {
        if (strlen(t[i].n) == n && memcmp(t[i].n, name, n) == 0) {
            *found = true;
            return t[i].t;
        }
    }
    *found = false;
    return 0;
}

#define NAME_IS(lit) (nl == sizeof(lit) - 1 && memcmp(name, lit, nl) == 0)

/* Returns 0, -1 (invalid rule) or -2 (internal limit / unsupported). */
static int set_option(fl_rule_t *r, optstate_t *os, const char *name, size_t nl, const char *val,
                      size_t vl) {
    if (NAME_IS("third-party") || NAME_IS("~first-party")) return set_opt(r, os, O_THIRD, true);
    if (NAME_IS("~third-party") || NAME_IS("first-party")) return set_opt(r, os, O_THIRD, false);
    if (NAME_IS("match-case")) return set_opt(r, os, O_MATCHCASE, true);
    if (NAME_IS("~match-case")) return set_opt(r, os, O_MATCHCASE, false);
    if (NAME_IS("important")) return set_opt(r, os, O_IMPORTANT, true);
    if (NAME_IS("badfilter")) return set_opt(r, os, O_BADFILTER, true);
    if (NAME_IS("elemhide")) return set_opt(r, os, O_ELEMHIDE, true);
    if (NAME_IS("generichide")) return set_opt(r, os, O_GENERICHIDE, true);
    if (NAME_IS("genericblock")) return set_opt(r, os, O_GENERICBLOCK, true);
    if (NAME_IS("jsinject")) return set_opt(r, os, O_JSINJECT, true);
    if (NAME_IS("urlblock")) return set_opt(r, os, O_URLBLOCK, true);
    if (NAME_IS("content")) return set_opt(r, os, O_CONTENT, true);
    if (NAME_IS("stealth")) return set_opt(r, os, O_STEALTH, true);
    if (NAME_IS("popup")) return set_opt(r, os, O_POPUP, true);
    if (NAME_IS("empty")) return set_opt(r, os, O_EMPTY, true);
    if (NAME_IS("mp4")) return set_opt(r, os, O_MP4, true);
    if (NAME_IS("extension")) return set_opt(r, os, O_EXTENSION, true);
    if (NAME_IS("~extension")) {
        os->enabled ^= O_EXTENSION;
        return 0;
    }
    if (NAME_IS("document")) {
        int e = set_opt(r, os, O_ELEMHIDE, true);
        set_opt(r, os, O_JSINJECT, true);
        set_opt(r, os, O_URLBLOCK, true);
        set_opt(r, os, O_CONTENT, true);
        set_opt(r, os, O_EXTENSION, true);
        return e;
    }
    {
        bool neg = nl && name[0] == '~';
        bool found;
        uint32_t t = req_type(name + (neg ? 1 : 0), nl - (neg ? 1 : 0), &found);
        if (found) {
            if (neg)
                r->restr_types |= t;
            else
                r->perm_types |= t;
            return 0;
        }
    }
    if (NAME_IS("dnstype")) {
        const char *parts[FL_MAX_LIST];
        size_t pl[FL_MAX_LIST];
        if (vl == 0) return -1;
        int k = split_plain(val, vl, '|', parts, pl, FL_MAX_LIST);
        if (k < 0) return -2;
        r->n_dt_perm = r->n_dt_restr = 0;
        for (int i = 0; i < k; i++) {
            const char *t = parts[i];
            size_t tl = pl[i];
            if (tl == 0) return -1;
            bool restr = t[0] == '~';
            if (restr) {
                t++;
                tl--;
            }
            if ((tl == 4 && dc_strnieq(t, "none", 4)) || (tl == 8 && dc_strnieq(t, "reserved", 8)))
                return -1;
            uint16_t rr = fl_rrtype_from_name(t, tl);
            if (!rr) return -1;
            if (restr)
                r->dt_restr[r->n_dt_restr++] = rr;
            else
                r->dt_perm[r->n_dt_perm++] = rr;
        }
        return 0;
    }
    if (NAME_IS("dnsrewrite")) {
        const char *err;
        int rc = fl_rewrite_parse(val, vl, &r->rw, &err);
        if (rc == -2) {
            os->unsupported = true;
            os->unsupported_reason = err;
            return 0;
        }
        if (rc) return -1;
        r->has_rewrite = true;
        return 0;
    }
    if (NAME_IS("domain")) {
        int np, nr;
        bool wc = false;
        int rc = parse_domains(val, vl, NULL, NULL, &np, &nr, &wc);
        if (rc) return rc;
        os->has_domain = true;
        return 0;
    }
    if (NAME_IS("denyallow")) {
        int np, nr;
        bool wc = false;
        int rc = parse_domains(val, vl, r->deny, r->deny_len, &np, &nr, &wc);
        if (rc) return rc;
        if (nr > 0 || np == 0) return -1;
        if (wc) {
            os->unsupported = true;
            os->unsupported_reason = "$denyallow with wildcard TLD (needs public suffix list)";
        }
        r->n_deny = (uint8_t)np;
        return 0;
    }
    if (NAME_IS("ctag")) {
        const char *parts[FL_MAX_LIST];
        size_t pl[FL_MAX_LIST];
        if (vl == 0) return -1;
        int k = split_plain(val, vl, '|', parts, pl, FL_MAX_LIST);
        if (k < 0) return -2;
        r->ctag_perm = r->ctag_restr = 0;
        r->n_ctag_perm = r->n_ctag_restr = 0;
        for (int i = 0; i < k; i++) {
            const char *t = parts[i];
            size_t tl = pl[i];
            bool restr = tl && t[0] == '~';
            if (restr) {
                t++;
                tl--;
            }
            if (!valid_ctag(t, tl)) return -1;
            int bit = fl_ctag_from_name(t, tl);
            uint32_t m = bit >= 0 ? (1u << bit) : (1u << 31);
            if (restr) {
                r->ctag_restr |= m;
                r->ctag_restr_s[r->n_ctag_restr] = t;
                r->ctag_restr_l[r->n_ctag_restr++] = (uint8_t)tl;
            } else {
                r->ctag_perm |= m;
                r->ctag_perm_s[r->n_ctag_perm] = t;
                r->ctag_perm_l[r->n_ctag_perm++] = (uint8_t)tl;
            }
        }
        r->has_ctag = true;
        return 0;
    }
    if (NAME_IS("client")) {
        const char *parts[FL_MAX_LIST];
        size_t pl[FL_MAX_LIST];
        if (vl == 0) return -1;
        int k = split_esc(r, val, vl, '|', parts, pl, FL_MAX_LIST);
        if (k < 0) return -2;
        r->n_cli_perm = r->n_cli_restr = 0;
        for (int i = 0; i < k; i++) {
            int rc = add_client(r, parts[i], pl[i]);
            if (rc) return rc;
        }
        return 0;
    }
    if (NAME_IS("respgeo")) {
        if (vl == 0) return -1;
        os->has_geo = true;
        return 0;
    }
    return -1; /* unknown filter modifier */
}

/* ------------------------------------------------------------------------- */
/* shortcuts                                                                 */

/* findShortcut: longest substring without '*', '^', '|' (first longest) */
static void find_shortcut(const char *p, size_t n, const char **sc, size_t *sl) {
    *sc = p;
    *sl = 0;
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && p[j] != '*' && p[j] != '^' && p[j] != '|') j++;
        if (j - i > *sl) {
            *sc = p + i;
            *sl = j - i;
        }
        i = j + 1;
    }
}

/* One greedy replacement of `([^\\])\<open>.*[^\\]\<close>` by "$1...". */
static size_t strip_brackets(char *s, size_t n, char open, char close) {
    /* last valid closing position */
    long last = -1;
    for (size_t j = 1; j < n; j++)
        if (s[j] == close && s[j - 1] != '\\') last = (long)j;
    if (last < 0) return n;
    for (size_t p = 0; p + 1 < n; p++) {
        if (s[p] == '\\' || s[p + 1] != open) continue;
        if ((long)p + 3 > last) break;
        /* '.' does not match '\n' (cannot occur in rule lines) */
        size_t tail = n - (size_t)last - 1;
        memmove(s + p + 1 + 3, s + last + 1, tail);
        memcpy(s + p + 1, "...", 3);
        return p + 1 + 3 + tail;
    }
    return n;
}

/* findRegexpShortcut */
static void find_regex_shortcut(fl_rule_t *r, const char *pat, size_t n, char *out, uint16_t *ol) {
    *ol = 0;
    if (n < 2) return;
    const char *in = pat + 1;
    size_t il = n - 2;
    if (memchr(in, '?', il)) return;
    char *s = scratch(r, il + 4);
    if (!s) return;
    memcpy(s, "...", 3);
    memcpy(s + 3, in, il);
    size_t sl = il + 3;
    sl = strip_brackets(s, sl, '{', '}');
    sl = strip_brackets(s, sl, '(', ')');
    sl = strip_brackets(s, sl, '[', ']');
    /* split by special characters, keep the first longest part */
    static const char spec[] = "\\^$*+?.()|[]{}";
    size_t best = 0, bl = 0, st = 0;
    for (size_t i = 0; i <= sl; i++) {
        if (i == sl || strchr(spec, s[i])) {
            if (i - st > bl) {
                best = st;
                bl = i - st;
            }
            st = i + 1;
        }
    }
    if (bl > 255) bl = 255;
    for (size_t i = 0; i < bl; i++) out[i] = (char)dc_lower((uint8_t)s[best + i]);
    *ol = (uint16_t)bl;
}

/* ------------------------------------------------------------------------- */
/* pattern -> regex (patternToRegexp)                                        */

int fl_pattern_to_regex(const char *pat, size_t n, char *out, size_t cap, bool *url_subject,
                        bool *match_all) {
    *match_all = false;
    /* subject selection (shouldMatchHostname) */
    bool url_prefix = has_prefix(pat, n, "||") || has_prefix(pat, n, "http://") ||
                      has_prefix(pat, n, "https://") || has_prefix(pat, n, "://");
    *url_subject = url_prefix || (n >= 4 && pat[0] == '/' && pat[n - 1] == '.');

    if ((n == 2 && memcmp(pat, "||", 2) == 0) || (n == 1 && (pat[0] == '|' || pat[0] == '*')) || n == 0) {
        *match_all = true;
        if (cap < 3) return -1;
        memcpy(out, ".*", 3);
        return 2;
    }
    if (n > 1 && pat[0] == '/' && pat[n - 1] == '/') {
        if (n - 2 + 1 > cap) return -1;
        memcpy(out, pat + 1, n - 2);
        out[n - 2] = 0;
        return (int)(n - 2);
    }
    /* specialCharReplacer -> a, escapePipes -> b, maskReplacer -> c2 (heap: cold path) */
    size_t acap = n * 2 + 8, bcap = acap * 2 + 8, ccap = bcap * 22 + 64;
    char *mem = (char *)dc_malloc(acap + bcap + ccap);
    if (!mem) return -1;
    char *a = mem, *b = mem + acap, *c2 = mem + acap + bcap;
    int ret = -1;
    size_t al = 0;
    for (size_t i = 0; i < n; i++) {
        char c = pat[i];
        if (c && strchr(".+?${}()[]/\\", c)) a[al++] = '\\';
        a[al++] = c;
    }
    size_t bl = 0;
    if (al <= 1) {
        memcpy(b, a, al);
        bl = al;
    } else {
        size_t pl = (a[0] == '|' && a[1] == '|') ? 2 : 1;
        memcpy(b, a, pl);
        bl = pl;
        for (size_t i = pl; i + 1 < al; i++) {
            if (a[i] == '|') b[bl++] = '\\';
            b[bl++] = a[i];
        }
        b[bl++] = a[al - 1];
    }
    size_t o = 0;
    for (size_t i = 0; i < bl; i++) {
        const char *rep = NULL;
        if (b[i] == '*') rep = ".*";
        else if (b[i] == '^') rep = k_regex_sep;
        if (rep) {
            size_t rl = strlen(rep);
            memcpy(c2 + o, rep, rl);
            o += rl;
        } else {
            c2[o++] = b[i];
        }
    }
    /* replacePrefix (with the "||" -> hostname transformation, see header) */
    size_t w = 0;
    const char *body = c2;
    size_t bodyl = o;
    if (o >= 2 && c2[0] == '|' && c2[1] == '|') {
        const char *hp = "^([a-z0-9-_.]+\\.)?";
        size_t hl = strlen(hp);
        if (hl + 1 > cap) goto out;
        memcpy(out, hp, hl);
        w = hl;
        body = c2 + 2;
        bodyl = o - 2;
        *url_subject = false; /* "http://"+host with RegexStartURL == host with this prefix */
    } else if (o >= 1 && c2[0] == '|') {
        out[w++] = '^';
        body = c2 + 1;
        bodyl = o - 1;
    }
    if (w + bodyl + 1 > cap) goto out;
    memcpy(out + w, body, bodyl);
    w += bodyl;
    /* replaceSuffix: a trailing '|' (never escaped by escapePipes) -> '$' */
    if (w && out[w - 1] == '|') out[w - 1] = '$';
    out[w] = 0;
    ret = (int)w;
out:
    dc_free(mem);
    return ret;
}

/* ------------------------------------------------------------------------- */

int fl_rule_parse(const char *line, size_t len, fl_rule_t *r) {
    r->line_kind = FL_LINE_INVALID;
    r->reason = NULL;
    r->n_hosts = 0;
    r->whitelist = r->important = r->badfilter = false;
    r->pattern = NULL;
    r->pattern_len = 0;
    r->perm_types = r->restr_types = 0;
    r->n_cli_perm = r->n_cli_restr = 0;
    r->has_ctag = false;
    r->ctag_perm = r->ctag_restr = 0;
    r->n_ctag_perm = r->n_ctag_restr = 0;
    r->n_dt_perm = r->n_dt_restr = 0;
    r->n_deny = 0;
    r->has_rewrite = false;
    r->shortcut_len = 0;
    r->scratch_used = 0;

    const char *s = line;
    size_t n = len;
    trim(&s, &n);
    if (n == 0) return r->line_kind = FL_LINE_EMPTY;
    /* AdGuard Home's list parser drops every line starting with '!' or '#'
     * before urlfilter sees it (rulelist/parser.go). */
    if (s[0] == '!' || s[0] == '#') return r->line_kind = FL_LINE_COMMENT;
    if (n > FL_MAX_LINE) {
        r->reason = "line too long";
        return r->line_kind = FL_LINE_UNSUPPORTED;
    }
    if (is_cosmetic(s, n)) return r->line_kind = FL_LINE_COSMETIC;

    if (parse_host_rule(s, n, r)) return r->line_kind = FL_LINE_HOST;

    /* ---- network rule ---- */
    if (n == 2 && s[0] == '@' && s[1] == '@') {
        r->reason = "rule is too short";
        return r->line_kind = FL_LINE_INVALID;
    }
    if (has_prefix(s, n, "@@")) {
        r->whitelist = true;
        s += 2;
        n -= 2;
    }
    const char *pat = s;
    size_t pl = n;
    const char *opts = NULL;
    size_t ol = 0;
    bool regex_noopt = n >= 1 && s[0] == '/' && s[n - 1] == '/' && !dc_memmem(s, n, "replace=", 8);
    if (!regex_noopt) {
        /* findOptionsDelimiter: last '$' not preceded by '\' */
        long idx = -1;
        bool escaped = false;
        for (long i = (long)n - 1; i >= 0; i--) {
            if (s[i] != '$') continue;
            if (i > 0 && s[i - 1] == '\\') {
                escaped = true;
                continue;
            }
            idx = i;
            break;
        }
        if (idx >= 0) {
            pl = (size_t)idx;
            opts = s + idx + 1;
            ol = n - (size_t)idx - 1;
            if (escaped) {
                char *u = scratch(r, ol + 1);
                if (!u) return r->line_kind = FL_LINE_UNSUPPORTED;
                size_t o = 0;
                for (size_t i = 0; i < ol; i++) {
                    if (opts[i] == '\\' && i + 1 < ol && opts[i + 1] == '$') continue;
                    u[o++] = opts[i];
                }
                opts = u;
                ol = o;
            }
        }
    }

    optstate_t os;
    memset(&os, 0, sizeof(os));
    if (ol) {
        const char *parts[128];
        size_t plen[128];
        int k = split_esc(r, opts, ol, ',', parts, plen, 128);
        if (k < 0) {
            r->reason = "too many modifiers";
            return r->line_kind = FL_LINE_UNSUPPORTED;
        }
        for (int i = 0; i < k; i++) {
            const char *eq = (const char *)memchr(parts[i], '=', plen[i]);
            int rc;
            if (eq && eq > parts[i])
                rc = set_option(r, &os, parts[i], (size_t)(eq - parts[i]), eq + 1,
                                plen[i] - (size_t)(eq - parts[i]) - 1);
            else
                rc = set_option(r, &os, parts[i], plen[i], "", 0);
            if (rc == -1) {
                r->reason = "invalid or unknown modifier";
                return r->line_kind = FL_LINE_INVALID;
            }
            if (rc == -2) {
                r->reason = "modifier value exceeds device limits";
                return r->line_kind = FL_LINE_UNSUPPORTED;
            }
        }
        if (os.enabled & (O_JSINJECT | O_ELEMHIDE | O_CONTENT | O_URLBLOCK | O_GENERICBLOCK |
                          O_GENERICHIDE | O_EXTENSION | O_POPUP))
            r->perm_types = FL_RT_DOCUMENT;
    }
    r->important = (os.enabled & O_IMPORTANT) != 0;
    r->badfilter = (os.enabled & O_BADFILTER) != 0;

    /* isTooWide uses the pattern before the "/\*" -> "^" normalization */
    bool no_restrictions = !os.has_domain && !r->n_cli_perm && !r->n_cli_restr && !r->has_ctag &&
                           !r->n_dt_perm && !r->n_dt_restr && !r->n_deny && !os.has_geo;
    bool wide = pl < 3; /* "", "|", "*", "||" or shorter than 3 */
    bool matches_nothing = pl == 1 && pat[0] == '^';

    /* normalize "example.org/\*" -> "example.org^" (urlfilter NewNetworkRule) */
    if (pl >= 2 && pat[pl - 2] == '/' && pat[pl - 1] == '*') {
        char *np = scratch(r, pl);
        if (!np) return r->line_kind = FL_LINE_UNSUPPORTED;
        memcpy(np, pat, pl - 2);
        np[pl - 2] = '^';
        pat = np;
        pl = pl - 1;
    }
    if (wide && no_restrictions) {
        r->reason = "rule is too wide";
        return r->line_kind = FL_LINE_TOOWIDE;
    }
    r->pattern = pat;
    r->pattern_len = (uint16_t)pl;

    /* host level? (IsHostLevelNetworkRule) */
    if (os.has_domain || (r->perm_types && r->restr_types) || os.disabled ||
        (os.enabled & ~(uint32_t)O_HOSTLEVEL)) {
        r->reason = "modifier not applicable to DNS filtering";
        return r->line_kind = FL_LINE_NOTDNS;
    }
    /* matchRequestType(TypeDocument) */
    if ((r->perm_types && !(r->perm_types & FL_RT_DOCUMENT)) ||
        (r->restr_types && (r->restr_types & FL_RT_DOCUMENT))) {
        r->reason = "request type modifiers never match DNS requests";
        return r->line_kind = FL_LINE_NEVER;
    }
    if (matches_nothing) {
        r->reason = "pattern matches nothing";
        return r->line_kind = FL_LINE_NEVER;
    }
    if (r->n_cli_perm || r->n_cli_restr || r->has_ctag) {
        r->reason = "$client/$ctag rule skipped (client identity disabled)";
        return r->line_kind = FL_LINE_CLIENT_SKIP;
    }
    if (os.has_geo) {
        r->reason = "$respgeo needs GeoIP data";
        return r->line_kind = FL_LINE_UNSUPPORTED;
    }
    if (os.unsupported) {
        r->reason = os.unsupported_reason;
        return r->line_kind = FL_LINE_UNSUPPORTED;
    }

    /* shortcut (setShortcut) */
    if (pl > 1 && pat[0] == '/' && pat[pl - 1] == '/') {
        find_regex_shortcut(r, pat, pl, r->shortcut, &r->shortcut_len);
    } else {
        const char *sc;
        size_t sl;
        find_shortcut(pat, pl, &sc, &sl);
        if (sl > sizeof(r->shortcut)) sl = sizeof(r->shortcut);
        for (size_t i = 0; i < sl; i++) r->shortcut[i] = (char)dc_lower((uint8_t)sc[i]);
        r->shortcut_len = (uint16_t)sl;
    }
    if (r->shortcut_len < 2) r->shortcut_len = 0;
    return r->line_kind = FL_LINE_NET;
}
