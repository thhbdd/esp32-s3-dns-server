/*
 * fl_regex.c - Go RE2 compatible (subset) regex compiler: AST -> NFA -> DFA.
 *
 * See fl_regex.h for the overall design.  Everything here runs on the cold
 * path (rule compilation) except fl_re_match() and the two executors.
 */
#include "fl_regex.h"

#include <stdlib.h>
#include <string.h>

#define RE_MAX_NODES 8192
#define RE_MAX_INSTS 8192      /* while compiling */
#define RE_MAX_NFA_RUN 1024    /* NFA programs executed by the Pike VM */
#define RE_MAX_DFA_NFA 4096    /* largest NFA we try to determinize */
#define RE_MAX_REPEAT 1000
#define RE_INF 0xFFFFu
#define RE_MAX_DEPTH 64

/* ------------------------------------------------------------------------- */
/* byte sets                                                                 */

typedef struct {
    uint8_t b[32];
} bset_t;

static inline void bs_add(bset_t *s, unsigned c) { s->b[c >> 3] |= (uint8_t)(1u << (c & 7)); }
static inline bool bs_has(const bset_t *s, unsigned c) { return (s->b[c >> 3] >> (c & 7)) & 1; }
static void bs_range(bset_t *s, unsigned lo, unsigned hi) {
    for (unsigned c = lo; c <= hi && c < 256; c++) bs_add(s, c);
}
static void bs_or(bset_t *d, const bset_t *s) {
    for (int i = 0; i < 32; i++) d->b[i] |= s->b[i];
}
static void bs_not(bset_t *s) {
    for (int i = 0; i < 32; i++) s->b[i] = (uint8_t)~s->b[i];
}
static void bs_fold(bset_t *s) {
    for (unsigned c = 'a'; c <= 'z'; c++) {
        if (bs_has(s, c) || bs_has(s, c - 32)) {
            bs_add(s, c);
            bs_add(s, c - 32);
        }
    }
}
static int bs_count(const bset_t *s) {
    int n = 0;
    for (int i = 0; i < 32; i++) n += __builtin_popcount(s->b[i]);
    return n;
}

/* ------------------------------------------------------------------------- */
/* AST                                                                       */

enum { N_SET, N_CAT, N_ALT, N_REP, N_BOL, N_EOL, N_WB, N_NWB };

typedef struct {
    uint8_t type;
    uint16_t min, max;
    int32_t set;   /* N_SET: set index */
    int32_t child; /* first child (CAT/ALT/REP) */
    int32_t next;  /* next sibling */
    int32_t last;  /* last child, for O(1) append */
} node_t;

enum { F_I = 1, F_S = 2 };

typedef struct {
    const char *s;
    size_t n, pos;
    unsigned flags;
    node_t *nodes;
    int nn;
    bset_t *sets;
    int ns, scap;
    int err;
    const char *msg;
    int depth;
    bool quote; /* inside \Q...\E */
} parser_t;

static int fail(parser_t *p, int code, const char *msg) {
    if (!p->err) {
        p->err = code;
        p->msg = msg;
    }
    return -1;
}

static int new_node(parser_t *p, int type) {
    if (p->nn >= RE_MAX_NODES) return fail(p, FL_RE_ETOOBIG, "regex too large");
    node_t *n = &p->nodes[p->nn];
    memset(n, 0, sizeof(*n));
    n->type = (uint8_t)type;
    n->child = n->next = n->last = -1;
    n->set = -1;
    return p->nn++;
}

static void add_child(parser_t *p, int parent, int child) {
    node_t *n = &p->nodes[parent];
    if (n->child < 0) {
        n->child = n->last = child;
    } else {
        p->nodes[n->last].next = child;
        n->last = child;
    }
}

static int add_set(parser_t *p, const bset_t *s) {
    for (int i = 0; i < p->ns; i++) {
        if (memcmp(&p->sets[i], s, sizeof(*s)) == 0) return i;
    }
    if (p->ns >= p->scap) {
        int nc = p->scap ? p->scap * 2 : 16;
        bset_t *n = (bset_t *)dc_realloc(p->sets, (size_t)nc * sizeof(bset_t));
        if (!n) return fail(p, FL_RE_ENOMEM, "out of memory");
        p->sets = n;
        p->scap = nc;
    }
    p->sets[p->ns] = *s;
    return p->ns++;
}

static int set_node(parser_t *p, bset_t *s) {
    if (p->flags & F_I) bs_fold(s);
    int si = add_set(p, s);
    if (si < 0) return -1;
    int n = new_node(p, N_SET);
    if (n < 0) return -1;
    p->nodes[n].set = si;
    return n;
}

static int lit_node(parser_t *p, unsigned c) {
    bset_t s;
    memset(&s, 0, sizeof(s));
    bs_add(&s, c);
    return set_node(p, &s);
}

/* Encodes a code point as UTF-8 literal bytes (concatenation). */
static int rune_node(parser_t *p, uint32_t r) {
    if (r < 0x80) return lit_node(p, r);
    uint8_t b[4];
    int k;
    if (r < 0x800) {
        b[0] = (uint8_t)(0xC0 | (r >> 6));
        b[1] = (uint8_t)(0x80 | (r & 0x3F));
        k = 2;
    } else if (r < 0x10000) {
        b[0] = (uint8_t)(0xE0 | (r >> 12));
        b[1] = (uint8_t)(0x80 | ((r >> 6) & 0x3F));
        b[2] = (uint8_t)(0x80 | (r & 0x3F));
        k = 3;
    } else {
        b[0] = (uint8_t)(0xF0 | (r >> 18));
        b[1] = (uint8_t)(0x80 | ((r >> 12) & 0x3F));
        b[2] = (uint8_t)(0x80 | ((r >> 6) & 0x3F));
        b[3] = (uint8_t)(0x80 | (r & 0x3F));
        k = 4;
    }
    int cat = new_node(p, N_CAT);
    if (cat < 0) return -1;
    for (int i = 0; i < k; i++) {
        bset_t s;
        memset(&s, 0, sizeof(s));
        bs_add(&s, b[i]);
        int si = add_set(p, &s);
        if (si < 0) return -1;
        int n = new_node(p, N_SET);
        if (n < 0) return -1;
        p->nodes[n].set = si;
        add_child(p, cat, n);
    }
    return cat;
}

static inline int peek(parser_t *p) { return p->pos < p->n ? (unsigned char)p->s[p->pos] : -1; }
static inline bool more(parser_t *p) { return p->pos < p->n; }

static bool is_digit(int c) { return c >= '0' && c <= '9'; }
static bool is_alnum(int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Perl class escapes: \d \D \s \S \w \W.  Returns true if c was one. */
static bool perl_class(int c, bset_t *s) {
    bset_t t;
    memset(&t, 0, sizeof(t));
    switch (c | 0x20) {
    case 'd':
        bs_range(&t, '0', '9');
        break;
    case 's':
        bs_add(&t, '\t');
        bs_add(&t, '\n');
        bs_add(&t, '\f');
        bs_add(&t, '\r');
        bs_add(&t, ' ');
        break;
    case 'w':
        bs_range(&t, '0', '9');
        bs_range(&t, 'a', 'z');
        bs_range(&t, 'A', 'Z');
        bs_add(&t, '_');
        break;
    default:
        return false;
    }
    if (c >= 'A' && c <= 'Z') bs_not(&t);
    bs_or(s, &t);
    return true;
}

/* Parses a single-character escape after '\\' (p->pos points after it).
 * Returns the code point, or -1 on error (error recorded). */
static long parse_char_escape(parser_t *p) {
    if (!more(p)) return fail(p, FL_RE_ESYNTAX, "trailing backslash"), -1;
    int c = (unsigned char)p->s[p->pos++];
    switch (c) {
    case 'a':
        return 7;
    case 'f':
        return 12;
    case 't':
        return 9;
    case 'n':
        return 10;
    case 'r':
        return 13;
    case 'v':
        return 11;
    case 'x': {
        if (peek(p) == '{') {
            p->pos++;
            long v = 0;
            int nd = 0;
            while (more(p) && peek(p) != '}') {
                int h = hexval(peek(p));
                if (h < 0) return fail(p, FL_RE_ESYNTAX, "bad hex escape"), -1;
                v = v * 16 + h;
                if (v > 0x10FFFF) return fail(p, FL_RE_ESYNTAX, "bad hex escape"), -1;
                p->pos++;
                nd++;
            }
            if (!more(p) || nd == 0) return fail(p, FL_RE_ESYNTAX, "bad hex escape"), -1;
            p->pos++;
            return v;
        }
        if (p->pos + 2 > p->n) return fail(p, FL_RE_ESYNTAX, "bad hex escape"), -1;
        int h1 = hexval((unsigned char)p->s[p->pos]), h2 = hexval((unsigned char)p->s[p->pos + 1]);
        if (h1 < 0 || h2 < 0) return fail(p, FL_RE_ESYNTAX, "bad hex escape"), -1;
        p->pos += 2;
        return h1 * 16 + h2;
    }
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7': {
        /* Go: a single non-zero digit is a backreference (unsupported). */
        if (c != '0' && !(more(p) && peek(p) >= '0' && peek(p) <= '7'))
            return fail(p, FL_RE_ESYNTAX, "backreference"), -1;
        long v = c - '0';
        for (int i = 0; i < 2 && more(p) && peek(p) >= '0' && peek(p) <= '7'; i++)
            v = v * 8 + (p->s[p->pos++] - '0');
        return v;
    }
    default:
        if (c < 0x80 && !is_alnum(c)) return c; /* escaped punctuation */
        return fail(p, FL_RE_ESYNTAX, "invalid escape"), -1;
    }
}

static int parse_alt(parser_t *p);

static const struct {
    const char *name;
    const char *ranges; /* pairs */
} k_posix[] = {
    {"alnum", "09AZaz"}, {"alpha", "AZaz"},    {"ascii", "\x01\x7f"}, {"blank", "\t\t  "},
    {"cntrl", "\x01\x1f\x7f\x7f"}, {"digit", "09"}, {"graph", "!~"},  {"lower", "az"},
    {"print", " ~"},     {"punct", "!/:@[`{~"}, {"space", "\t\r  "}, {"upper", "AZ"},
    {"word", "09AZaz__"}, {"xdigit", "09AFaf"},
};

static int parse_class(parser_t *p) {
    /* p->pos points after '[' */
    bset_t s;
    memset(&s, 0, sizeof(s));
    bool neg = false;
    if (peek(p) == '^') {
        neg = true;
        p->pos++;
    }
    bool first = true;
    while (more(p) && (peek(p) != ']' || first)) {
        first = false;
        /* POSIX class */
        if (peek(p) == '[' && p->pos + 1 < p->n && p->s[p->pos + 1] == ':') {
            size_t q = p->pos + 2;
            bool pneg = false;
            if (q < p->n && p->s[q] == '^') {
                pneg = true;
                q++;
            }
            size_t st = q;
            while (q + 1 < p->n && !(p->s[q] == ':' && p->s[q + 1] == ']')) q++;
            if (q + 1 < p->n) {
                size_t nl = q - st;
                bool found = false;
                for (size_t i = 0; i < DC_ARRAY_SIZE(k_posix); i++) {
                    if (strlen(k_posix[i].name) == nl && memcmp(k_posix[i].name, p->s + st, nl) == 0) {
                        bset_t t;
                        memset(&t, 0, sizeof(t));
                        const char *r = k_posix[i].ranges;
                        size_t rl = strlen(r);
                        if (r[0] == '\x01') { /* ranges starting at 0 are encoded with \x01 */
                            bs_add(&t, 0);
                        }
                        for (size_t j = 0; j + 1 < rl; j += 2)
                            bs_range(&t, (unsigned char)r[j], (unsigned char)r[j + 1]);
                        if (pneg) bs_not(&t);
                        bs_or(&s, &t);
                        found = true;
                        break;
                    }
                }
                if (!found) return fail(p, FL_RE_ESYNTAX, "invalid POSIX class");
                p->pos = q + 2;
                continue;
            }
        }
        long lo;
        if (peek(p) == '\\') {
            p->pos++;
            int c = peek(p);
            if (c == 'p' || c == 'P') return fail(p, FL_RE_EUNSUPPORTED, "unicode class");
            if (c >= 0 && perl_class(c, &s)) {
                p->pos++;
                continue;
            }
            lo = parse_char_escape(p);
            if (lo < 0) return -1;
        } else {
            lo = (unsigned char)p->s[p->pos++];
            if (lo >= 0x80) {
                /* multi-byte rune inside a class: unsupported here (hostnames are ASCII) */
                return fail(p, FL_RE_EUNSUPPORTED, "non-ASCII class");
            }
        }
        long hi = lo;
        if (peek(p) == '-' && p->pos + 1 < p->n && p->s[p->pos + 1] != ']') {
            p->pos++;
            if (peek(p) == '\\') {
                p->pos++;
                hi = parse_char_escape(p);
                if (hi < 0) return -1;
            } else {
                hi = (unsigned char)p->s[p->pos++];
            }
            if (hi < lo) return fail(p, FL_RE_ESYNTAX, "invalid class range");
        }
        if (hi > 0xFF) {
            if (lo > 0x7F) return fail(p, FL_RE_EUNSUPPORTED, "non-ASCII class");
            hi = 0x7F; /* the subject is ASCII: higher runes never occur */
        }
        bs_range(&s, (unsigned)lo, (unsigned)hi);
    }
    if (!more(p)) return fail(p, FL_RE_ESYNTAX, "missing ]");
    p->pos++; /* ']' */
    if (p->flags & F_I) bs_fold(&s);
    if (neg) bs_not(&s);
    int si = add_set(p, &s);
    if (si < 0) return -1;
    int n = new_node(p, N_SET);
    if (n < 0) return -1;
    p->nodes[n].set = si;
    return n;
}

/* Tries to parse {n}, {n,}, {n,m} at p->pos (pointing at '{').
 * Returns 1 and advances on success, 0 if not a repeat (literal '{'),
 * -1 on error. */
static int parse_brace(parser_t *p, unsigned *mn, unsigned *mx) {
    size_t q = p->pos + 1;
    unsigned a = 0, b;
    int nd = 0;
    while (q < p->n && is_digit((unsigned char)p->s[q])) {
        a = a * 10 + (unsigned)(p->s[q] - '0');
        if (a > 100000) a = 100000;
        q++;
        nd++;
    }
    if (!nd || q >= p->n) return 0;
    if (p->s[q] == '}') {
        b = a;
        q++;
    } else if (p->s[q] == ',') {
        q++;
        if (q < p->n && p->s[q] == '}') {
            b = RE_INF;
            q++;
        } else {
            int md = 0;
            b = 0;
            while (q < p->n && is_digit((unsigned char)p->s[q])) {
                b = b * 10 + (unsigned)(p->s[q] - '0');
                if (b > 100000) b = 100000;
                q++;
                md++;
            }
            if (!md || q >= p->n || p->s[q] != '}') return 0;
            q++;
        }
    } else {
        return 0;
    }
    if (a > RE_MAX_REPEAT || (b != RE_INF && (b > RE_MAX_REPEAT || b < a))) {
        fail(p, FL_RE_ESYNTAX, "invalid repeat count");
        return -1;
    }
    p->pos = q;
    *mn = a;
    *mx = b;
    return 1;
}

static int parse_group(parser_t *p) {
    /* p->pos points after '(' */
    unsigned saved = p->flags;
    if (peek(p) == '?') {
        p->pos++;
        int c = peek(p);
        if (c == 'P' || c == '<') {
            if (c == 'P') {
                p->pos++;
                if (peek(p) != '<') return fail(p, FL_RE_ESYNTAX, "invalid named group");
            }
            if (p->pos + 1 < p->n && (p->s[p->pos + 1] == '=' || p->s[p->pos + 1] == '!'))
                return fail(p, FL_RE_ESYNTAX, "lookbehind not supported");
            p->pos++; /* '<' */
            size_t st = p->pos;
            while (more(p) && peek(p) != '>') {
                int d = peek(p);
                if (!(is_alnum(d) || d == '_')) return fail(p, FL_RE_ESYNTAX, "invalid group name");
                p->pos++;
            }
            if (!more(p) || p->pos == st) return fail(p, FL_RE_ESYNTAX, "invalid group name");
            p->pos++; /* '>' */
        } else {
            /* flags: (?flags) or (?flags:re) */
            bool negf = false, any = false;
            unsigned f = p->flags;
            for (;;) {
                if (!more(p)) return fail(p, FL_RE_ESYNTAX, "missing )");
                c = (unsigned char)p->s[p->pos++];
                if (c == 'i') {
                    f = negf ? (f & ~F_I) : (f | F_I);
                    any = true;
                } else if (c == 's') {
                    f = negf ? (f & ~F_S) : (f | F_S);
                    any = true;
                } else if (c == 'm' || c == 'U') {
                    any = true; /* no effect on match/no-match for single-line subjects */
                } else if (c == '-') {
                    if (negf) return fail(p, FL_RE_ESYNTAX, "invalid flags");
                    negf = true;
                    any = false;
                } else if (c == ')') {
                    if (!any && negf) return fail(p, FL_RE_ESYNTAX, "invalid flags"); /* ((?) is fine) */
                    p->flags = f; /* applies to the rest of the enclosing group */
                    return -2;    /* no node */
                } else if (c == ':') {
                    if (negf && !any) return fail(p, FL_RE_ESYNTAX, "invalid flags");
                    p->flags = f;
                    break;
                } else {
                    return fail(p, FL_RE_ESYNTAX, "invalid or unsupported Perl syntax");
                }
            }
        }
    }
    if (++p->depth > RE_MAX_DEPTH) return fail(p, FL_RE_ETOOBIG, "nesting too deep");
    int n = parse_alt(p);
    p->depth--;
    if (n < 0 && p->err) return -1;
    if (peek(p) != ')') return fail(p, FL_RE_ESYNTAX, "missing )");
    p->pos++;
    p->flags = saved;
    return n;
}

/* Returns node index, -1 on error, -2 if the construct produced no node. */
/* one literal character (a whole UTF-8 sequence, so repetition applies to the rune) */
static int literal_char(parser_t *p) {
    int c = (unsigned char)p->s[p->pos];
    int k = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 1;
    if (k == 1) {
        p->pos++;
        return lit_node(p, (unsigned)c);
    }
    int cat = new_node(p, N_CAT);
    if (cat < 0) return -1;
    for (int i = 0; i < k && more(p); i++) {
        int ln = lit_node(p, (unsigned char)p->s[p->pos++]);
        if (ln < 0) return -1;
        add_child(p, cat, ln);
    }
    return cat;
}

static bool at_quote_end(const parser_t *p) {
    return p->pos + 1 < p->n && p->s[p->pos] == '\\' && p->s[p->pos + 1] == 'E';
}

static int parse_atom(parser_t *p) {
    if (p->quote) { /* \Q...\E: one character per atom, like Go (a repetition binds to the last) */
        int ln = literal_char(p);
        if (at_quote_end(p)) {
            p->pos += 2;
            p->quote = false;
        } else if (!more(p)) {
            p->quote = false;
        }
        return ln;
    }
    int c = peek(p);
    switch (c) {
    case '(':
        p->pos++;
        return parse_group(p);
    case '[':
        p->pos++;
        return parse_class(p);
    case '.': {
        p->pos++;
        bset_t s;
        memset(&s, 0xFF, sizeof(s));
        if (!(p->flags & F_S)) s.b['\n' >> 3] &= (uint8_t) ~(1u << ('\n' & 7));
        int si = add_set(p, &s);
        if (si < 0) return -1;
        int n = new_node(p, N_SET);
        if (n >= 0) p->nodes[n].set = si;
        return n;
    }
    case '^':
        p->pos++;
        return new_node(p, N_BOL);
    case '$':
        p->pos++;
        return new_node(p, N_EOL);
    case '*':
    case '+':
    case '?':
        return fail(p, FL_RE_ESYNTAX, "missing argument to repetition operator");
    case '{': {
        unsigned a, b;
        size_t save = p->pos;
        int r = parse_brace(p, &a, &b);
        if (r < 0) return -1;
        if (r > 0) return fail(p, FL_RE_ESYNTAX, "missing argument to repetition operator");
        p->pos = save + 1;
        return lit_node(p, '{');
    }
    case '\\': {
        p->pos++;
        int e = peek(p);
        switch (e) {
        case 'A':
            p->pos++;
            return new_node(p, N_BOL);
        case 'z':
            p->pos++;
            return new_node(p, N_EOL);
        case 'b':
            p->pos++;
            return new_node(p, N_WB);
        case 'B':
            p->pos++;
            return new_node(p, N_NWB);
        case 'p':
        case 'P':
            return fail(p, FL_RE_EUNSUPPORTED, "unicode class");
        case 'C':
        case 'Z':
            return fail(p, FL_RE_ESYNTAX, "invalid escape");
        case 'Q':
            p->pos++;
            if (at_quote_end(p)) { /* empty: no node */
                p->pos += 2;
                return -2;
            }
            if (!more(p)) return -2;
            p->quote = true;
            return parse_atom(p);
        default:
            break;
        }
        if (e >= 0) {
            bset_t s;
            memset(&s, 0, sizeof(s));
            if (perl_class(e, &s)) {
                p->pos++;
                return set_node(p, &s);
            }
        }
        long r = parse_char_escape(p);
        if (r < 0) return -1;
        return rune_node(p, (uint32_t)r);
    }
    default:
        break;
    }
    return literal_char(p);
}

static int parse_repeat(parser_t *p) {
    int atom = parse_atom(p);
    if (atom == -1) return -1;
    if (atom == -2) return -2;
    if (p->quote) return atom; /* the next character is quoted too */
    bool repeated = false;
    for (;;) {
        int c = peek(p);
        unsigned mn, mx;
        if (c == '*') {
            mn = 0;
            mx = RE_INF;
            p->pos++;
        } else if (c == '+') {
            mn = 1;
            mx = RE_INF;
            p->pos++;
        } else if (c == '?') {
            mn = 0;
            mx = 1;
            p->pos++;
        } else if (c == '{') {
            int r = parse_brace(p, &mn, &mx);
            if (r < 0) return -1;
            if (r == 0) break;
        } else {
            break;
        }
        if (repeated) return fail(p, FL_RE_ESYNTAX, "invalid nested repetition operator");
        if (peek(p) == '?') p->pos++; /* non-greedy: irrelevant for matching */
        repeated = true;
        int r = new_node(p, N_REP);
        if (r < 0) return -1;
        p->nodes[r].min = (uint16_t)mn;
        p->nodes[r].max = (uint16_t)mx;
        p->nodes[r].child = atom;
        atom = r;
    }
    return atom;
}

static int parse_concat(parser_t *p) {
    int cat = new_node(p, N_CAT);
    if (cat < 0) return -1;
    while (more(p) && (p->quote || (peek(p) != '|' && peek(p) != ')'))) {
        int a = parse_repeat(p);
        if (a == -1) return -1;
        if (a == -2) continue;
        add_child(p, cat, a);
    }
    return cat;
}

static int parse_alt(parser_t *p) {
    int first = parse_concat(p);
    if (first < 0) return -1;
    if (peek(p) != '|') return first;
    int alt = new_node(p, N_ALT);
    if (alt < 0) return -1;
    add_child(p, alt, first);
    while (peek(p) == '|') {
        p->pos++;
        int c = parse_concat(p);
        if (c < 0) return -1;
        add_child(p, alt, c);
    }
    return alt;
}

/* ------------------------------------------------------------------------- */
/* required literal analysis                                                 */

typedef struct {
    bool exact_ok;
    uint8_t exact_len;
    uint8_t req_len;
    char exact[63];
    char req[63];
} lit_t;

/* Single effective character of a set for a lowercase subject, or -1. */
static int set_single_char(const bset_t *s) {
    int found = -1;
    for (unsigned c = 0; c < 256; c++) {
        if (c >= 'A' && c <= 'Z') continue; /* subject is lowercase */
        if (bs_has(s, c)) {
            if (found >= 0) return -1;
            found = (int)c;
        }
    }
    return found;
}

static void lit_take(lit_t *out, const char *s, int len) {
    if (len > out->req_len && len <= (int)sizeof(out->req)) {
        memcpy(out->req, s, (size_t)len);
        out->req_len = (uint8_t)len;
    }
}

static void analyze(const parser_t *p, int ni, lit_t *out, int depth) {
    memset(out, 0, sizeof(*out));
    const node_t *n = &p->nodes[ni];
    if (depth > RE_MAX_DEPTH) return;
    switch (n->type) {
    case N_BOL:
    case N_EOL:
    case N_WB:
    case N_NWB:
        out->exact_ok = true;
        return;
    case N_SET: {
        int c = set_single_char(&p->sets[n->set]);
        if (c > 0 && c != '\n') {
            out->exact_ok = true;
            out->exact[0] = (char)c;
            out->exact_len = 1;
            out->req[0] = (char)c;
            out->req_len = 1;
        }
        return;
    }
    case N_CAT: {
        char run[63] = {0};
        int rl = 0;
        bool all_exact = true;
        for (int c = n->child; c >= 0; c = p->nodes[c].next) {
            lit_t ci;
            analyze(p, c, &ci, depth + 1);
            if (ci.exact_ok && rl + ci.exact_len <= (int)sizeof(run)) {
                memcpy(run + rl, ci.exact, ci.exact_len);
                rl += ci.exact_len;
                continue;
            }
            if (!ci.exact_ok) all_exact = false;
            lit_take(out, run, rl);
            rl = 0;
            if (ci.exact_ok) { /* too long to append: restart run with it */
                all_exact = false;
                memcpy(run, ci.exact, ci.exact_len);
                rl = ci.exact_len;
            } else {
                lit_take(out, ci.req, ci.req_len);
            }
        }
        lit_take(out, run, rl);
        if (all_exact) {
            out->exact_ok = true;
            memcpy(out->exact, run, (size_t)rl);
            out->exact_len = (uint8_t)rl;
        }
        return;
    }
    case N_ALT:
        return; /* no single required literal */
    case N_REP: {
        if (n->min == 0) return;
        lit_t ci;
        analyze(p, n->child, &ci, depth + 1);
        if (ci.exact_ok) {
            lit_take(out, ci.exact, ci.exact_len);
            if (n->min == n->max && (int)ci.exact_len * n->min <= (int)sizeof(out->exact)) {
                out->exact_ok = true;
                for (int i = 0; i < n->min; i++)
                    memcpy(out->exact + i * ci.exact_len, ci.exact, ci.exact_len);
                out->exact_len = (uint8_t)(ci.exact_len * n->min);
                lit_take(out, out->exact, out->exact_len);
            }
        } else {
            lit_take(out, ci.req, ci.req_len);
        }
        return;
    }
    }
}

/* ------------------------------------------------------------------------- */
/* NFA                                                                       */

enum { OP_CHAR, OP_SET, OP_ANY, OP_ANYNL, OP_SPLIT, OP_JMP, OP_BOL, OP_EOL, OP_WB, OP_NWB, OP_MATCH };

typedef struct {
    uint8_t op;
    uint8_t a;
    uint16_t b;
} inst_t;

typedef struct {
    const parser_t *p;
    inst_t *in;
    int n;
    int err;
    uint8_t *set_map; /* parser set index -> output set index, 0xFF none */
    bset_t *osets;
    int nos;
    bool has_wb;
} emit_t;

static int emit_inst(emit_t *e, uint8_t op, uint8_t a, uint16_t b) {
    if (e->n >= RE_MAX_INSTS) {
        e->err = FL_RE_ETOOBIG;
        return -1;
    }
    e->in[e->n].op = op;
    e->in[e->n].a = a;
    e->in[e->n].b = b;
    return e->n++;
}

static void emit_node(emit_t *e, int ni, int depth) {
    if (e->err) return;
    if (depth > RE_MAX_DEPTH) {
        e->err = FL_RE_ETOOBIG;
        return;
    }
    const node_t *n = &e->p->nodes[ni];
    switch (n->type) {
    case N_BOL:
        emit_inst(e, OP_BOL, 0, 0);
        return;
    case N_EOL:
        emit_inst(e, OP_EOL, 0, 0);
        return;
    case N_WB:
        e->has_wb = true;
        emit_inst(e, OP_WB, 0, 0);
        return;
    case N_NWB:
        e->has_wb = true;
        emit_inst(e, OP_NWB, 0, 0);
        return;
    case N_SET: {
        const bset_t *s = &e->p->sets[n->set];
        int cnt = bs_count(s);
        if (cnt == 256) {
            emit_inst(e, OP_ANY, 0, 0);
        } else if (cnt == 255 && !bs_has(s, '\n')) {
            emit_inst(e, OP_ANYNL, 0, 0);
        } else if (cnt == 1) {
            int c = 0;
            while (!bs_has(s, (unsigned)c)) c++;
            emit_inst(e, OP_CHAR, (uint8_t)c, 0);
        } else if (cnt == 2 && set_single_char(s) >= 'a' && set_single_char(s) <= 'z' &&
                   bs_has(s, (unsigned)set_single_char(s) - 32)) {
            /* case-folded letter {c, C}: the subject is lowercase */
            emit_inst(e, OP_CHAR, (uint8_t)set_single_char(s), 0);
        } else {
            uint8_t m = e->set_map[n->set];
            if (m == 0xFF) {
                if (e->nos >= 255) {
                    e->err = FL_RE_ETOOBIG;
                    return;
                }
                m = (uint8_t)e->nos;
                e->osets[e->nos++] = *s;
                e->set_map[n->set] = m;
            }
            emit_inst(e, OP_SET, m, 0);
        }
        return;
    }
    case N_CAT:
        for (int c = n->child; c >= 0 && !e->err; c = e->p->nodes[c].next) emit_node(e, c, depth + 1);
        return;
    case N_ALT: {
        /* pending JMPs are chained through their b field (0xFFFF terminates) */
        uint16_t chain = 0xFFFF;
        int c = n->child;
        while (c >= 0 && !e->err) {
            int nx = e->p->nodes[c].next;
            if (nx < 0) {
                emit_node(e, c, depth + 1);
                break;
            }
            int sp = emit_inst(e, OP_SPLIT, 0, 0);
            if (sp < 0) return;
            emit_node(e, c, depth + 1);
            int j = emit_inst(e, OP_JMP, 0, chain);
            if (j < 0) return;
            chain = (uint16_t)j;
            e->in[sp].b = (uint16_t)e->n;
            c = nx;
        }
        if (e->err) return;
        while (chain != 0xFFFF) {
            uint16_t nxt = e->in[chain].b;
            e->in[chain].b = (uint16_t)e->n;
            chain = nxt;
        }
        return;
    }
    case N_REP: {
        unsigned mn = n->min, mx = n->max;
        if (mx == RE_INF) {
            if (mn == 0) {
                int l = emit_inst(e, OP_SPLIT, 0, 0);
                if (l < 0) return;
                emit_node(e, n->child, depth + 1);
                emit_inst(e, OP_JMP, 0, (uint16_t)l);
                if (!e->err) e->in[l].b = (uint16_t)e->n;
            } else {
                for (unsigned i = 0; i + 1 < mn && !e->err; i++) emit_node(e, n->child, depth + 1);
                int l = e->n;
                emit_node(e, n->child, depth + 1);
                emit_inst(e, OP_SPLIT, 0, (uint16_t)l);
                /* SPLIT: primary pc+1 (exit), alternative b (loop) */
            }
        } else {
            for (unsigned i = 0; i < mn && !e->err; i++) emit_node(e, n->child, depth + 1);
            uint16_t chain = 0xFFFF; /* SPLITs chained through b until patched */
            unsigned k = mx - mn;
            for (unsigned i = 0; i < k && !e->err; i++) {
                int sp = emit_inst(e, OP_SPLIT, 0, chain);
                if (sp < 0) return;
                chain = (uint16_t)sp;
                emit_node(e, n->child, depth + 1);
            }
            if (e->err) return;
            while (chain != 0xFFFF) {
                uint16_t nxt = e->in[chain].b;
                e->in[chain].b = (uint16_t)e->n;
                chain = nxt;
            }
        }
        return;
    }
    }
}

/* ------------------------------------------------------------------------- */
/* executors                                                                 */

static inline bool inst_matches(const inst_t *in, const uint8_t *sets, uint8_t c) {
    switch (in->op) {
    case OP_CHAR:
        return in->a == c;
    case OP_SET:
        return (sets[(size_t)in->a * 32 + (c >> 3)] >> (c & 7)) & 1;
    case OP_ANY:
        return true;
    case OP_ANYNL:
        return c != '\n';
    default:
        return false;
    }
}

static inline bool is_word(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

typedef struct {
    uint16_t *mark;
    uint16_t *stack;
} pike_ws_t;

/* Adds pc and its epsilon closure to list; returns true on MATCH. */
static bool pike_add(const inst_t *ins, pike_ws_t *ws, uint16_t gen, uint16_t *list, int *len,
                     unsigned pc0, const uint8_t *s, size_t n, size_t pos) {
    int sp = 0;
    ws->stack[sp++] = (uint16_t)pc0;
    while (sp) {
        unsigned pc = ws->stack[--sp];
        if (ws->mark[pc] == gen) continue;
        ws->mark[pc] = gen;
        const inst_t *in = &ins[pc];
        switch (in->op) {
        case OP_JMP:
            ws->stack[sp++] = in->b;
            break;
        case OP_SPLIT:
            ws->stack[sp++] = in->b;
            ws->stack[sp++] = (uint16_t)(pc + 1);
            break;
        case OP_BOL:
            if (pos == 0) ws->stack[sp++] = (uint16_t)(pc + 1);
            break;
        case OP_EOL:
            if (pos == n) ws->stack[sp++] = (uint16_t)(pc + 1);
            break;
        case OP_WB:
        case OP_NWB: {
            bool a = pos > 0 && is_word(s[pos - 1]);
            bool b = pos < n && is_word(s[pos]);
            if ((a != b) == (in->op == OP_WB)) ws->stack[sp++] = (uint16_t)(pc + 1);
            break;
        }
        case OP_MATCH:
            return true;
        default:
            list[(*len)++] = (uint16_t)pc;
            break;
        }
    }
    return false;
}

static bool pike_run(const uint8_t *prog, const uint8_t *s, size_t n) {
    unsigned ninst = dc_ld16(prog + 2);
    const inst_t *ins = (const inst_t *)(prog + 8);
    const uint8_t *sets = prog + 8 + (size_t)ninst * 4;
    if (ninst == 0 || ninst > RE_MAX_NFA_RUN) return false;
    /* lists (2 x ninst) + marks (ninst) + stack (2 x ninst + 4), all u16 */
    size_t need = ((size_t)ninst * 5 + 4) * sizeof(uint16_t);
    uint16_t local[400];
    uint16_t *mem = need <= sizeof(local) ? local : (uint16_t *)dc_malloc(need);
    if (!mem) return false;
    pike_ws_t wsv = {.mark = mem + 2 * ninst, .stack = mem + 3 * ninst};
    pike_ws_t *ws = &wsv;
    memset(ws->mark, 0, sizeof(uint16_t) * ninst);
    uint16_t gen = 1;
    int clen = 0, nlen;
    uint16_t *cl = mem, *nl = mem + ninst;
    bool hit = pike_add(ins, ws, gen, cl, &clen, 0, s, n, 0);
    for (size_t pos = 0; pos < n && !hit; pos++) {
        gen++;
        if (gen == 0) {
            memset(ws->mark, 0, sizeof(uint16_t) * ninst);
            gen = 1;
        }
        nlen = 0;
        uint8_t c = s[pos];
        for (int i = 0; i < clen && !hit; i++) {
            const inst_t *in = &ins[cl[i]];
            if (inst_matches(in, sets, c) && pike_add(ins, ws, gen, nl, &nlen, cl[i] + 1u, s, n, pos + 1))
                hit = true;
        }
        if (!hit && pike_add(ins, ws, gen, nl, &nlen, 0, s, n, pos + 1)) hit = true;
        uint16_t *t = cl;
        cl = nl;
        nl = t;
        clen = nlen;
    }
    if (mem != local) dc_free(mem);
    return hit;
}

/* DFA program: 'D', nclasses, u16 nstates, start, hiclass, 0, 0,
 * cmap[128] (classes of ASCII bytes; bytes >= 0x80 use hiclass),
 * acc[nstates] (bit0 accept now, bit1 accept at end), trans[nstates][nclasses] */
static bool dfa_run(const uint8_t *prog, const uint8_t *s, size_t n) {
    unsigned nc = prog[1];
    unsigned st = prog[4];
    unsigned hi = prog[5];
    unsigned ns = dc_ld16(prog + 2);
    const uint8_t *cmap = prog + 8;
    const uint8_t *acc = cmap + 128;
    const uint8_t *tr = acc + ns;
    if (acc[st] & 1) return true;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = s[i];
        st = tr[st * nc + (b < 128 ? cmap[b] : hi)];
        if (acc[st] & 1) return true;
        if (st == 0) return false;
    }
    return (acc[st] & 2) != 0;
}

bool fl_re_match(const uint8_t *prog, const uint8_t *s, size_t n) {
    if (prog[0] == 'D') return dfa_run(prog, s, n);
    if (prog[0] == 'N') return pike_run(prog, s, n);
    return false;
}

bool fl_re_validate(const uint8_t *prog, size_t avail, size_t *prog_len) {
    if (avail < 8) return false;
    if (prog[0] == 'D') {
        unsigned nc = prog[1], ns = dc_ld16(prog + 2), st = prog[4];
        if (!nc || !ns || ns > 256 || st >= ns || prog[5] >= nc) return false;
        size_t len = 8 + 128 + ns + (size_t)ns * nc;
        if (len > avail) return false;
        const uint8_t *cmap = prog + 8;
        for (int i = 0; i < 128; i++)
            if (cmap[i] >= nc) return false;
        const uint8_t *tr = prog + 8 + 128 + ns;
        for (size_t i = 0; i < (size_t)ns * nc; i++)
            if (tr[i] >= ns) return false;
        if (prog_len) *prog_len = len;
        return true;
    }
    if (prog[0] == 'N') {
        unsigned ni = dc_ld16(prog + 2), nsets = dc_ld16(prog + 4);
        if (!ni || ni > RE_MAX_NFA_RUN || nsets > 255) return false;
        size_t len = 8 + (size_t)ni * 4 + (size_t)nsets * 32;
        if (len > avail) return false;
        const inst_t *ins = (const inst_t *)(prog + 8);
        bool has_match = false;
        for (unsigned i = 0; i < ni; i++) {
            if (ins[i].op > OP_MATCH) return false;
            if ((ins[i].op == OP_SPLIT || ins[i].op == OP_JMP) && ins[i].b >= ni) return false;
            if (ins[i].op == OP_SET && ins[i].a >= nsets) return false;
            if (ins[i].op != OP_MATCH && ins[i].op != OP_JMP && i + 1 >= ni) return false;
            if (ins[i].op == OP_MATCH) has_match = true;
        }
        if (!has_match) return false;
        if (prog_len) *prog_len = len;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------------- */
/* DFA construction                                                          */

typedef struct {
    const inst_t *in;
    int ninst;
    const bset_t *sets;
    uint16_t *mark;
    uint16_t gen;
    uint16_t *stack;
    uint16_t *tmp;  /* closure output */
    int tlen;
    bool match;
} clos_t;

static void clos_reset(clos_t *c) {
    c->gen++;
    if (c->gen == 0) {
        memset(c->mark, 0, sizeof(uint16_t) * (size_t)c->ninst);
        c->gen = 1;
    }
    c->tlen = 0;
    c->match = false;
}

/* Closure from pc; follows BOL only if at_begin, and EOL only if at_end.
 * Collects consuming instructions and (when !at_end) pending EOL insts. */
static void clos_add(clos_t *c, unsigned pc0, bool at_begin, bool at_end) {
    int sp = 0;
    c->stack[sp++] = (uint16_t)pc0;
    while (sp) {
        unsigned pc = c->stack[--sp];
        if (c->mark[pc] == c->gen) continue;
        c->mark[pc] = c->gen;
        const inst_t *in = &c->in[pc];
        switch (in->op) {
        case OP_JMP:
            c->stack[sp++] = in->b;
            break;
        case OP_SPLIT:
            c->stack[sp++] = in->b;
            c->stack[sp++] = (uint16_t)(pc + 1);
            break;
        case OP_BOL:
            if (at_begin) c->stack[sp++] = (uint16_t)(pc + 1);
            break;
        case OP_EOL:
            if (at_end)
                c->stack[sp++] = (uint16_t)(pc + 1);
            else
                c->tmp[c->tlen++] = (uint16_t)pc;
            break;
        case OP_MATCH:
            c->match = true;
            break;
        default:
            c->tmp[c->tlen++] = (uint16_t)pc;
            break;
        }
    }
}

static int cmp_u16(const void *a, const void *b) {
    return (int)*(const uint16_t *)a - (int)*(const uint16_t *)b;
}

typedef struct {
    uint32_t off; /* into setbuf (u16 units) */
    uint16_t len;
    uint8_t flags;
} dstate_t;

static int build_dfa(const inst_t *in, int ninst, const bset_t *sets, unsigned max_states,
                     dc_buf_t *out) {
    int rc = FL_RE_ETOOBIG;
    if (ninst > RE_MAX_DFA_NFA || max_states < 2) return FL_RE_ETOOBIG;
    if (max_states > 256) max_states = 256;

    /* byte classes */
    uint8_t cls[256];
    memset(cls, 0, sizeof(cls));
    int ncls = 1;
    for (int i = 0; i < ninst; i++) {
        uint8_t op = in[i].op;
        if (op != OP_CHAR && op != OP_SET && op != OP_ANYNL) continue;
        int16_t tbl[512];
        for (int k = 0; k < ncls * 2; k++) tbl[k] = -1;
        int nn = 0;
        for (int b = 0; b < 256; b++) {
            bool inp = op == OP_CHAR ? (b == in[i].a) : op == OP_ANYNL ? (b != '\n') : bs_has(&sets[in[i].a], (unsigned)b);
            int k = cls[b] * 2 + (inp ? 1 : 0);
            if (tbl[k] < 0) tbl[k] = (int16_t)nn++;
            cls[b] = (uint8_t)tbl[k];
        }
        if (nn > 255) return FL_RE_ETOOBIG;
        ncls = nn;
    }
    /* bytes >= 0x80 must share one class (the program stores a 128-entry map) */
    for (int b = 129; b < 256; b++)
        if (cls[b] != cls[128]) return FL_RE_ETOOBIG;
    uint8_t rep[256];
    for (int b = 255; b >= 0; b--) rep[cls[b]] = (uint8_t)b;

    clos_t c;
    memset(&c, 0, sizeof(c));
    c.in = in;
    c.ninst = ninst;
    c.sets = sets;
    c.mark = (uint16_t *)dc_calloc((size_t)ninst, sizeof(uint16_t));
    c.stack = (uint16_t *)dc_malloc(sizeof(uint16_t) * (size_t)(ninst * 2 + 4));
    c.tmp = (uint16_t *)dc_malloc(sizeof(uint16_t) * (size_t)(ninst + 4));
    uint16_t *startn = (uint16_t *)dc_malloc(sizeof(uint16_t) * (size_t)(ninst + 4));
    dstate_t *st = (dstate_t *)dc_calloc(max_states, sizeof(dstate_t));
    uint8_t *trans = (uint8_t *)dc_calloc((size_t)max_states * (size_t)ncls, 1);
    dc_buf_t sb; /* concatenated sorted state sets */
    dc_buf_init(&sb);
    int nstartn = 0;
    bool startn_match = false;
    if (!c.mark || !c.stack || !c.tmp || !startn || !st || !trans) {
        rc = FL_RE_ENOMEM;
        goto out;
    }

    /* closure of the start for positions > 0 (BOL blocked) */
    clos_reset(&c);
    clos_add(&c, 0, false, false);
    nstartn = c.tlen;
    startn_match = c.match;
    memcpy(startn, c.tmp, sizeof(uint16_t) * (size_t)c.tlen);

    int nst = 1; /* state 0 = dead */
    st[0].off = 0;
    st[0].len = 0;
    st[0].flags = 0;

    /* helper to intern the current closure c.tmp as a state */
#define INTERN(result)                                                                          \
    do {                                                                                        \
        qsort(c.tmp, (size_t)c.tlen, sizeof(uint16_t), cmp_u16);                               \
        int _u = 0;                                                                             \
        for (int _i = 0; _i < c.tlen; _i++)                                                     \
            if (_u == 0 || c.tmp[_u - 1] != c.tmp[_i]) c.tmp[_u++] = c.tmp[_i];                 \
        c.tlen = _u;                                                                            \
        uint8_t _fl = c.match ? 1 : 0;                                                          \
        int _found = -1;                                                                        \
        if (!c.tlen && !_fl) _found = 0;                                                        \
        for (int _s = 1; _s < nst && _found < 0; _s++) {                                        \
            if (st[_s].len == c.tlen && (st[_s].flags & 1) == _fl &&                            \
                memcmp(sb.data + (size_t)st[_s].off * 2, c.tmp, (size_t)c.tlen * 2) == 0)       \
                _found = _s;                                                                    \
        }                                                                                       \
        if (_found < 0) {                                                                       \
            if (nst >= (int)max_states) {                                                       \
                rc = FL_RE_ETOOBIG;                                                             \
                goto out;                                                                       \
            }                                                                                   \
            st[nst].off = (uint32_t)(sb.len / 2);                                               \
            st[nst].len = (uint16_t)c.tlen;                                                     \
            st[nst].flags = _fl;                                                                \
            if (!dc_buf_append(&sb, c.tmp, (size_t)c.tlen * 2)) {                               \
                rc = FL_RE_ENOMEM;                                                              \
                goto out;                                                                       \
            }                                                                                   \
            _found = nst++;                                                                     \
        }                                                                                       \
        (result) = _found;                                                                      \
    } while (0)

    int start;
    clos_reset(&c);
    clos_add(&c, 0, true, false);
    INTERN(start);

    for (int s = 1; s < nst; s++) {
        if (st[s].flags & 1) continue; /* accepting states are terminal */
        for (int k = 0; k < ncls; k++) {
            uint8_t b = rep[k];
            clos_reset(&c);
            const uint16_t *set = (const uint16_t *)(sb.data + (size_t)st[s].off * 2);
            int slen = st[s].len;
            for (int i = 0; i < slen; i++) {
                unsigned pc = set[i];
                if (inst_matches(&in[pc], (const uint8_t *)sets, b)) clos_add(&c, pc + 1, false, false);
            }
            for (int i = 0; i < nstartn; i++) {
                if (c.mark[startn[i]] != c.gen) {
                    c.mark[startn[i]] = c.gen;
                    c.tmp[c.tlen++] = startn[i];
                }
            }
            if (startn_match) c.match = true;
            int t;
            INTERN(t);
            trans[(size_t)s * ncls + k] = (uint8_t)t;
        }
    }
#undef INTERN

    /* accept-at-end flags */
    for (int s = 1; s < nst; s++) {
        if (st[s].flags & 1) continue;
        const uint16_t *set = (const uint16_t *)(sb.data + (size_t)st[s].off * 2);
        clos_reset(&c);
        for (int i = 0; i < st[s].len; i++) {
            if (in[set[i]].op == OP_EOL) clos_add(&c, set[i] + 1u, false, true);
        }
        if (c.match) st[s].flags |= 2;
    }

    /* serialize */
    {
        uint8_t hdr[8] = {'D', (uint8_t)ncls, 0, 0, (uint8_t)start, cls[128], 0, 0};
        dc_st16(hdr + 2, (uint16_t)nst);
        bool ok = dc_buf_append(out, hdr, 8) && dc_buf_append(out, cls, 128);
        for (int s = 0; s < nst && ok; s++) ok = dc_buf_put8(out, st[s].flags);
        if (ok) ok = dc_buf_append(out, trans, (size_t)nst * (size_t)ncls);
        rc = ok ? nst : FL_RE_ENOMEM;
    }

out:
    dc_free(c.mark);
    dc_free(c.stack);
    dc_free(c.tmp);
    dc_free(startn);
    dc_free(st);
    dc_free(trans);
    dc_buf_free(&sb);
    return rc;
}

/* ------------------------------------------------------------------------- */

int fl_re_compile(const char *re, size_t len, unsigned flags, unsigned max_dfa_states,
                  dc_buf_t *out, fl_re_info_t *info, const char **err) {
    static const char *const k_nomem = "out of memory";
    parser_t p;
    memset(&p, 0, sizeof(p));
    p.s = re;
    p.n = len;
    p.flags = (flags & FL_RE_ICASE) ? F_I : 0;
    p.nodes = (node_t *)dc_malloc(sizeof(node_t) * RE_MAX_NODES);
    if (info) memset(info, 0, sizeof(*info));
    if (!p.nodes) {
        if (err) *err = k_nomem;
        return FL_RE_ENOMEM;
    }
    int rc = FL_RE_OK;
    emit_t e;
    memset(&e, 0, sizeof(e));

    int root = parse_alt(&p);
    if (!p.err && more(&p)) fail(&p, FL_RE_ESYNTAX, "unexpected )");
    if (p.err || root < 0) {
        rc = p.err ? p.err : FL_RE_ESYNTAX;
        if (err) *err = p.msg ? p.msg : "syntax error";
        goto done;
    }

    if (info) {
        lit_t li;
        analyze(&p, root, &li, 0);
        const char *s = li.exact_ok && li.exact_len >= li.req_len ? li.exact : li.req;
        int l = li.exact_ok && li.exact_len >= li.req_len ? li.exact_len : li.req_len;
        memcpy(info->req, s, (size_t)l);
        info->req_len = (uint8_t)l;
    }

    e.p = &p;
    e.in = (inst_t *)dc_malloc(sizeof(inst_t) * RE_MAX_INSTS);
    e.set_map = (uint8_t *)dc_malloc((size_t)(p.ns > 0 ? p.ns : 1));
    e.osets = (bset_t *)dc_malloc(sizeof(bset_t) * 256);
    if (!e.in || !e.set_map || !e.osets) {
        rc = FL_RE_ENOMEM;
        if (err) *err = k_nomem;
        goto done;
    }
    memset(e.set_map, 0xFF, (size_t)(p.ns > 0 ? p.ns : 1));
    emit_node(&e, root, 0);
    emit_inst(&e, OP_MATCH, 0, 0);
    if (e.err) {
        rc = e.err;
        if (err) *err = rc == FL_RE_ETOOBIG ? "regex too large for device" : k_nomem;
        goto done;
    }

    size_t before = out->len;
    int dfa = FL_RE_ETOOBIG;
    if (!(flags & FL_RE_PREFER_NFA) && !e.has_wb && max_dfa_states >= 2)
        dfa = build_dfa(e.in, e.n, e.osets, max_dfa_states, out);
    if (dfa > 0) {
        if (info) info->dfa_states = (uint16_t)dfa;
    } else {
        out->len = before;
        if (dfa == FL_RE_ENOMEM) {
            rc = dfa;
            if (err) *err = k_nomem;
            goto done;
        }
        if (e.n > RE_MAX_NFA_RUN) {
            rc = FL_RE_ETOOBIG;
            if (err) *err = "regex too large for device";
            goto done;
        }
        uint8_t hdr[8] = {'N', 0, 0, 0, 0, 0, 0, 0};
        dc_st16(hdr + 2, (uint16_t)e.n);
        dc_st16(hdr + 4, (uint16_t)e.nos);
        bool ok = dc_buf_append(out, hdr, 8);
        for (int i = 0; i < e.n && ok; i++) {
            uint8_t t[4] = {e.in[i].op, e.in[i].a, 0, 0};
            dc_st16(t + 2, e.in[i].b);
            ok = dc_buf_append(out, t, 4);
        }
        /* Instructions are read in place as inst_t; layout must match. */
        _Static_assert(sizeof(inst_t) == 4, "inst_t layout");
        if (ok) ok = dc_buf_append(out, e.osets, (size_t)e.nos * 32);
        if (!ok) {
            rc = FL_RE_ENOMEM;
            if (err) *err = k_nomem;
            goto done;
        }
    }

done:
    dc_free(p.nodes);
    dc_free(p.sets);
    dc_free(e.in);
    dc_free(e.set_map);
    dc_free(e.osets);
    return rc;
}
