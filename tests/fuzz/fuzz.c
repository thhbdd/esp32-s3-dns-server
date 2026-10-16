/*
 * fuzz.c - randomized robustness tests (no libFuzzer needed).
 *
 *   fuzz TARGET SECONDS [SEED]     TARGET: wire parsers regex rules image cache server all
 *
 * Build with -DSANITIZE=ON (host/CMakeLists.txt) so that memory errors and
 * undefined behaviour abort.  Each target also checks invariants (round
 * trips, cache contents, answers to well-formed queries).
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dns_cache.h"
#include "dns_local.h"
#include "dns_server.h"
#include "dns_wire.h"
#include "fl_filter.h"
#include "fl_regex.h"

static uint64_t g_rng;
static uint32_t rnd(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 11);
}
static uint32_t rn(uint32_t n) { return n ? rnd() % n : 0; }
static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

#define FAIL(...)                                    \
    do {                                             \
        fprintf(stderr, "INVARIANT FAILED: ");       \
        fprintf(stderr, __VA_ARGS__);                \
        fprintf(stderr, "\n");                       \
        abort();                                     \
    } while (0)

static void hexdump(const char *what, const uint8_t *b, size_t n) {
    fprintf(stderr, "%s (%zu bytes): ", what, n);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}

/* a server answer: parses, or is a header-only error (malformed queries) */
static bool valid_answer(const uint8_t *b, size_t n) {
    dns_resp_t r;
    if (n >= DNS_HDR_LEN && (b[2] & 0x80) && dc_be16(b + 4) == 0 && dc_be16(b + 6) == 0 && dc_be16(b + 8) == 0)
        return (b[3] & 0xF) != 0 && dc_be16(b + 10) <= 1;
    return dns_parse_response(b, n, &r) == 0;
}

/* ---- mutation --------------------------------------------------------------------- */

static size_t mutate(uint8_t *b, size_t n, size_t cap) {
    static const uint8_t interesting[] = {0, 1, 0x3F, 0x40, 0x7F, 0x80, 0xC0, 0xC1, 0xFF, 12, 41, 5, 28, 65};
    unsigned ops = 1 + rn(6);
    for (unsigned k = 0; k < ops; k++) {
        switch (rn(8)) {
        case 0: if (n) b[rn((uint32_t)n)] ^= (uint8_t)(1u << rn(8)); break;
        case 1: if (n) b[rn((uint32_t)n)] = (uint8_t)rnd(); break;
        case 2: if (n) b[rn((uint32_t)n)] = interesting[rn(sizeof(interesting))]; break;
        case 3: if (n) n = rn((uint32_t)n + 1); break; /* truncate */
        case 4: /* insert */
            if (n < cap) {
                size_t at = rn((uint32_t)n + 1);
                memmove(b + at + 1, b + at, n - at);
                b[at] = (uint8_t)rnd();
                n++;
            }
            break;
        case 5: /* delete */
            if (n) {
                size_t at = rn((uint32_t)n);
                memmove(b + at, b + at + 1, n - at - 1);
                n--;
            }
            break;
        case 6: /* duplicate a chunk */
            if (n > 2) {
                size_t a = rn((uint32_t)n), l = 1 + rn((uint32_t)(n - a));
                if (n + l <= cap) {
                    memmove(b + a + l, b + a, n - a);
                    n += l;
                }
            }
            break;
        default: /* 16-bit field */
            if (n > 1) {
                size_t at = rn((uint32_t)n - 1);
                dc_wbe16(b + at, (uint16_t)(rn(3) ? rn(16) : rnd()));
            }
        }
    }
    return n;
}

static const char *k_labels[] = {"ads", "example", "com", "net", "tracker", "cdn", "a", "www", "x", "test", "lan",
                                 "home", "evil", "ok", "sub", "doubleclick", "xn--fiq228c", "1", "0", "_dmarc"};

static size_t rand_name(char *o, size_t cap) {
    unsigned nl = 1 + rn(5);
    size_t p = 0;
    for (unsigned i = 0; i < nl && p + 70 < cap; i++) {
        if (i) o[p++] = '.';
        if (rn(5) == 0) {
            unsigned l = 1 + rn(rn(8) == 0 ? 63 : 12);
            for (unsigned k = 0; k < l; k++) o[p++] = "abcdefghijklmnopqrstuvwxyz0123456789-_"[rn(38)];
        } else {
            const char *s = k_labels[rn(sizeof(k_labels) / sizeof(k_labels[0]))];
            size_t l = strlen(s);
            memcpy(o + p, s, l);
            p += l;
        }
    }
    o[p] = 0;
    return p;
}

static size_t mkq(uint8_t *b, uint16_t id, const char *name, uint16_t qt, bool edns) {
    memset(b, 0, 12);
    dc_wbe16(b, id);
    dc_wbe16(b + 2, DNS_F_RD);
    dc_wbe16(b + 4, 1);
    dc_wbe16(b + 10, edns ? 1 : 0);
    int nl = fl_name_to_wire(name, strlen(name), b + 12, 256);
    if (nl < 0) nl = fl_name_to_wire("example.com", 11, b + 12, 256);
    size_t o = 12 + (size_t)nl;
    dc_wbe16(b + o, qt);
    dc_wbe16(b + o + 2, 1);
    o += 4;
    if (edns) {
        b[o] = 0;
        dc_wbe16(b + o + 1, 41);
        dc_wbe16(b + o + 3, 1232);
        dc_wbe32(b + o + 5, rn(2) ? 0x8000u : 0);
        dc_wbe16(b + o + 9, 0);
        o += 11;
    }
    return o;
}

static const uint16_t k_types[] = {1, 28, 5, 65, 16, 15, 33, 12, 6, 255, 64, 2};

/* a plausible answer to query q (compression pointers, CNAME chains, hints) */
static size_t mkans(const uint8_t *q, size_t ql, uint8_t *out, size_t cap) {
    dns_query_t pq;
    if (dns_parse_query(q, ql, &pq) != DNS_PARSE_OK) return 0;
    dns_buf_t b = {out, cap, 0, false};
    dns_resp_begin(&b, &pq, rn(8) == 0 ? (uint8_t)rn(6) : 0, rn(4) == 0);
    unsigned an = 0, ns = 0, ar = 0, n = rn(6);
    uint8_t tgt[256];
    char tn[200];
    rand_name(tn, sizeof(tn));
    int tl = fl_name_to_wire(tn, strlen(tn), tgt, sizeof(tgt));
    for (unsigned i = 0; i < n; i++) {
        uint32_t ttl = rn(3) == 0 ? rnd() : rn(1000);
        switch (rn(5)) {
        case 0:
            if (tl > 0) {
                dns_resp_rr(&b, DNS_T_CNAME, ttl, tgt, (uint16_t)tl);
                an++;
            }
            break;
        case 1: {
            uint8_t ip[4] = {(uint8_t)rn(256), 2, 3, (uint8_t)rn(256)};
            if (tl > 0 && rn(2))
                dns_resp_rr_named(&b, tgt, (size_t)tl, DNS_T_A, ttl, ip, 4);
            else
                dns_resp_rr(&b, DNS_T_A, ttl, ip, 4);
            an++;
            break;
        }
        case 2: {
            uint8_t ip[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = (uint8_t)rn(256)};
            dns_resp_rr(&b, DNS_T_AAAA, ttl, ip, 16);
            an++;
            break;
        }
        case 3: { /* HTTPS with hints */
            uint8_t rd[64] = {0, 1, 0, 0, 4, 0, 8, 6, 6, 6, 6, 1, 2, 3, 4, 0, 6, 0, 16, 0x20, 1};
            dns_resp_rr(&b, DNS_T_HTTPS, ttl, rd, (uint16_t)(sizeof(rd) - rn(50)));
            an++;
            break;
        }
        default:
            dns_resp_soa(&b, &pq, ttl);
            ns++;
        }
    }
    if (pq.has_edns || rn(4) == 0) {
        dns_resp_opt(&b, 1232, rn(2), (uint8_t)(rn(8) == 0 ? rn(3) : 0));
        ar++;
    }
    size_t len = dns_resp_end(&b, (uint16_t)an, (uint16_t)ns, (uint16_t)ar);
    if (len && rn(10) == 0) dc_wbe16(out + 2, (uint16_t)(dc_be16(out + 2) | DNS_F_TC));
    return len;
}

/* ---- wire ----------------------------------------------------------------------------- */

static bool ans_cb(void *arg, uint16_t t, const char *h, size_t hl) {
    (void)t;
    (void)arg;
    if (strlen(h) != hl) FAIL("walk: length mismatch");
    return rn(20) == 0;
}

static void fuzz_wire(double secs) {
    uint8_t seed[4096], b[8192], out[8192];
    double end = now_s() + secs;
    unsigned long it = 0;
    while (now_s() < end) {
        for (int k = 0; k < 200; k++, it++) {
            char name[300];
            rand_name(name, sizeof(name));
            size_t ql = mkq(seed, (uint16_t)rnd(), name, k_types[rn(12)], rn(2));
            size_t sl = rn(2) ? mkans(seed, ql, b, sizeof(b)) : 0;
            size_t n;
            if (sl) {
                memcpy(seed, b, sl);
                n = sl;
            } else {
                memcpy(b, seed, ql);
                n = ql;
            }
            if (rn(10)) n = mutate(b, n, sizeof(b));
            dns_query_t q;
            int pr = dns_parse_query(b, n, &q);
            if (pr != DNS_PARSE_DROP) {
                size_t e = dns_make_error(out, sizeof(out), b, n, &q, DNS_RC_SERVFAIL);
                if (e) {
                    dns_resp_t r;
                    /* (without a question section the response is header only) */
                    if (dc_be16(out + 4) == 1 && dns_parse_response(out, e, &r)) FAIL("error response does not parse");
                }
                if (pr == DNS_PARSE_OK && q.host_ok && strlen(q.host) != q.host_len) FAIL("host length");
            }
            dns_resp_t r;
            if (dns_parse_response(b, n, &r) == 0) {
                dns_walk_answers(b, n, &r, ans_cb, NULL);
                memcpy(out, b, n);
                dns_adjust_ttls(out, n, &r, rnd(), rn(100), rn(2) ? 0 : rn(1000));
                dns_resp_t r2;
                if (dns_parse_response(out, n, &r2)) FAIL("TTL adjustment broke the message");
            }
            uint8_t nm[DNS_MAX_NAME];
            for (int j = 0; j < 4 && n; j++) {
                size_t off = rn((uint32_t)n);
                int l = dns_read_name(b, n, &off, nm, rn(2));
                if (l > DNS_MAX_NAME || (l >= 0 && off > n)) FAIL("read_name bounds");
                off = rn((uint32_t)n);
                if (dns_skip_name(b, n, &off) == 0 && off > n) FAIL("skip_name bounds");
            }
        }
    }
    printf("wire: %lu messages\n", it);
}

/* ---- text parsers ----------------------------------------------------------------------------- */

static void rand_str(char *o, size_t cap, const char *alpha) {
    size_t l = rn((uint32_t)cap - 1), na = strlen(alpha);
    for (size_t i = 0; i < l; i++) o[i] = alpha[rn((uint32_t)na)];
    o[l] = 0;
}

static void fuzz_parsers(double secs) {
    double end = now_s() + secs;
    unsigned long it = 0;
    static const char *types[] = {"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "HTTPS", "SVCB", "PTR", "NS", "CAA", "X"};
    while (now_s() < end) {
        for (int k = 0; k < 500; k++, it++) {
            char s[128], f[64];
            rand_str(s, rn(2) ? 48 : 128, rn(2) ? "0123456789.:abcdef%/[]" : "0123456789.:/x");
            dc_ip_t ip, ip2;
            if (dc_ip_parse_z(s, &ip)) {
                dc_ip_format(&ip, f, sizeof(f));
                if (!dc_ip_parse_z(f, &ip2) || !dc_ip_equal(&ip, &ip2)) FAIL("ip round trip '%s' -> '%s'", s, f);
            }
            dc_prefix_t p;
            if (dc_prefix_parse(s, strlen(s), &p)) {
                if (p.bits > (p.ip.family == 4 ? 32 : 128)) FAIL("prefix bits");
                if (!dc_prefix_contains(&p, &p.ip)) FAIL("prefix does not contain its address");
            }
            dns_upstream_cfg_t u;
            const char *err;
            rand_str(s, 100, "udptclshtp:/.[]@0123456789abcdefghijklmnoqrsuvwxyz-");
            if (dns_upstream_parse(s, &u, &err) && (u.port == 0 || !u.text[0])) FAIL("upstream parse '%s'", s);
            /* names */
            uint8_t w[300];
            char back[1100];
            rand_str(s, 128, "abc.\\0123456789-_*");
            int wl = fl_name_to_wire(s, strlen(s), w, sizeof(w));
            if (wl > 0) {
                if (wl > 255) FAIL("wire name too long");
                int bl = fl_name_from_wire(w, (size_t)wl, back, sizeof(back));
                if (bl >= 0) {
                    uint8_t w2[300];
                    int wl2 = fl_name_to_wire(back, (size_t)bl, w2, sizeof(w2));
                    if (wl2 != wl) FAIL("name round trip");
                }
            }
            uint8_t rw[64];
            for (size_t i = 0; i < sizeof(rw); i++) rw[i] = (uint8_t)rnd();
            fl_name_from_wire(rw, rn(64), back, sizeof(back));
            /* rdata encoding */
            uint8_t rd[700];
            uint16_t rl;
            rand_str(s, 100, "0123456789. abcdef:\"=,alpnipv4hint-mandatory");
            fl_encode_rdata(types[rn(12)], s, rd, sizeof(rd), &rl, &err);
        }
        /* local records */
        dns_local_t *l = dns_local_new();
        for (int k = 0; k < 50; k++) {
            char d[200], v[100];
            rand_name(d, sizeof(d));
            if (rn(4) == 0) {
                memmove(d + 2, d, strlen(d) + 1);
                d[0] = '*';
                d[1] = '.';
            }
            static const char *vals[] = {"192.168.1.1", "fd00::1", "nas.home", "10 mx.home", "\"txt\"", "-",
                                         "0 5 80 srv.home", "1 . alpn=h2", "bad"};
            snprintf(v, sizeof(v), "%s", vals[rn(9)]);
            const char *err;
            dns_local_add(l, d, types[rn(12)], rn(1000), v, &err);
        }
        dns_local_seal(l);
        for (int k = 0; k < 100; k++) {
            char h[200];
            size_t hl = rand_name(h, sizeof(h));
            dns_lentry_t e;
            if (dns_local_lookup(l, h, hl, &e) && (!e.n || !e.recs)) FAIL("local entry without records");
        }
        dns_local_free(l);
    }
    printf("parsers: %lu rounds\n", it);
}

/* ---- regex ----------------------------------------------------------------------------------- */

static void fuzz_regex(double secs) {
    double end = now_s() + secs;
    unsigned long it = 0, ok = 0;
    static const char *frags[] = {"a", "b", ".", "*", "+", "?", "|", "(", ")", "[a-z]", "[^.]", "\\.", "^", "$",
                                  "{2}", "{1,3}", "(?:", "\\d", "\\w", "\\b", "ads", "x{0,}", "[", "]", "\\", "-"};
    dc_buf_t prog;
    dc_buf_init(&prog);
    while (now_s() < end) {
        for (int k = 0; k < 200; k++, it++) {
            char re[200];
            size_t p = 0;
            unsigned nf = 1 + rn(12);
            for (unsigned i = 0; i < nf; i++) {
                const char *f = frags[rn(sizeof(frags) / sizeof(frags[0]))];
                size_t l = strlen(f);
                if (p + l >= sizeof(re)) break;
                memcpy(re + p, f, l);
                p += l;
            }
            prog.len = 0;
            fl_re_info_t info;
            const char *err;
            if (fl_re_compile(re, p, rn(2) ? 1 : 0, 1 + rn(256), &prog, &info, &err) != 0) continue;
            ok++;
            size_t plen;
            if (!fl_re_validate(prog.data, prog.len, &plen) || plen > prog.len) FAIL("program does not validate: %.*s", (int)p, re);
            for (int j = 0; j < 20; j++) {
                char s[100];
                size_t sl = rand_name(s, sizeof(s));
                bool m = fl_re_match(prog.data, (const uint8_t *)s, sl);
                /* the required literal must be present in every match */
                if (m && info.req_len && !dc_memmem(s, sl, info.req, info.req_len))
                    FAIL("match without required literal '%.*s' re=%.*s s=%s", info.req_len, info.req, (int)p, re, s);
            }
        }
    }
    dc_buf_free(&prog);
    printf("regex: %lu patterns (%lu compiled)\n", it, ok);
}

/* ---- rules ------------------------------------------------------------------------------------- */

static size_t rand_rule(char *o, size_t cap) {
    static const char *pre[] = {"||", "|", "@@||", "", "*.", ".", "://", "0.0.0.0 ", "127.0.0.1 ", ":: ", "/",
                                "!", "#", "@@", "||*.", "|http://", "1.2.3.4 "};
    static const char *suf[] = {"^", "^|", "", "|", "*", "^*", "/"};
    static const char *mods[] = {"$important", "$badfilter", "$dnstype=A", "$dnstype=~AAAA|HTTPS",
                                 "$dnsrewrite=NXDOMAIN", "$dnsrewrite=1.2.3.4", "$dnsrewrite=NOERROR;CNAME;target.test",
                                 "$dnsrewrite=NOERROR;AAAA;::1", "$dnsrewrite", "$client=127.0.0.1",
                                 "$client=~10.0.0.0/8", "$client='kid'", "$ctag=device_phone|~user_child",
                                 "$denyallow=ok.test", "$third-party", "$domain=x.com", "$script", "$match-case",
                                 "$dnstype=", "$=,", "$dnsrewrite=NOERROR;MX;10 mx.test",
                                 "$dnsrewrite=NOERROR;HTTPS;1 . alpn=h2", "$dnsrewrite=REFUSED;;"};
    size_t p = 0;
    const char *a = pre[rn(sizeof(pre) / sizeof(pre[0]))];
    p += (size_t)snprintf(o + p, cap - p, "%s", a);
    if (a[0] == '/' && a[1] == 0) {
        static const char *re[] = {"ads\\d+\\.", "^track", "(ads|ad)\\.example", ".*", "[a-z]{3}\\.test$", "x+y?"};
        p += (size_t)snprintf(o + p, cap - p, "%s/", re[rn(6)]);
    } else {
        char n[200];
        rand_name(n, sizeof(n));
        if (rn(6) == 0) n[rn((uint32_t)strlen(n))] = '*';
        p += (size_t)snprintf(o + p, cap - p, "%s%s", n, suf[rn(sizeof(suf) / sizeof(suf[0]))]);
    }
    unsigned nm = rn(3);
    for (unsigned i = 0; i < nm && p < cap - 60; i++) {
        const char *m = mods[rn(sizeof(mods) / sizeof(mods[0]))];
        p += (size_t)snprintf(o + p, cap - p, "%s%s", i ? "," : "", i ? m + 1 : m);
    }
    if (rn(30) == 0) p = mutate((uint8_t *)o, p, cap - 1);
    o[p] = 0;
    return p;
}

/* compiles text and returns a copy of the raw image (dc_malloc_ext) */
static uint8_t *compile_raw(const char *text, size_t len, uint32_t chunk, uint32_t flags, bool must, size_t *ilen) {
    fl_memstore_t runs, sink;
    fl_memstore_init(&runs, 16u << 20);
    fl_memstore_init(&sink, 16u << 20);
    fl_compile_opts_t o;
    memset(&o, 0, sizeof(o));
    o.runs = &runs.st;
    o.chunk_bytes = chunk;
    fl_compiler_t *c = fl_compile_new(&o);
    fl_compile_begin_source(c, "fuzz", flags);
    /* feed in random pieces: lines may span chunks */
    size_t off = 0;
    while (off < len) {
        size_t n = 1 + rn(400);
        if (off + n > len) n = len - off;
        fl_compile_feed(c, text + off, n);
        off += n;
    }
    fl_compile_end_source(c);
    fl_stats_t st;
    int n = fl_compile_finish(c, &sink.st, &st);
    uint8_t *d = NULL;
    if (n > 0) {
        d = (uint8_t *)dc_malloc_ext((size_t)n);
        memcpy(d, sink.buf.data, (size_t)n);
        *ilen = (size_t)n;
    } else if (must && n != FL_ERR_BINARY) { /* (binary data after rules: the list is rejected) */
        FAIL("compile failed: %s", fl_compile_error(c));
    }
    fl_compile_free(c);
    fl_memstore_free(&runs);
    fl_memstore_free(&sink);
    return d;
}

static fl_image_t *compile_text(const char *text, size_t len, uint32_t chunk, uint32_t flags, bool must) {
    size_t n;
    uint8_t *d = compile_raw(text, len, chunk, flags, must, &n);
    fl_image_t *img = NULL;
    if (d && fl_image_load(d, n, true, &img)) FAIL("compiled image does not load");
    return img;
}

static void explain_nop(void *a, const char *r, const char *s, const char *e) {
    (void)a;
    if (!r || !s || !e) FAIL("explain NULL");
}

static void match_many(fl_set_t *set, int n) {
    for (int j = 0; j < n; j++) {
        char h[300];
        size_t hl = rand_name(h, sizeof(h));
        if (rn(10) == 0) hl = (size_t)snprintf(h, sizeof(h), "%u.%u.%u.%u", rn(256), 2, 3, rn(256));
        fl_client_t cl;
        memset(&cl, 0, sizeof(cl));
        if (rn(2)) dc_ip_parse_z(rn(2) ? "127.0.0.1" : "10.1.2.3", &cl.ip);
        cl.name = rn(3) == 0 ? "kid" : NULL;
        cl.tags = rnd() & ((1u << FL_CTAG_COUNT) - 1);
        fl_req_t rq = {h, (uint16_t)hl, k_types[rn(12)], rn(5) == 0 ? (uint32_t)FL_REQ_REWRITES_ONLY : 0, &cl};
        fl_result_t r;
        fl_match(set, &rq, &r);
        if (r.verdict > FL_V_REWRITE) FAIL("verdict");
        if (r.verdict == FL_V_REWRITE && r.rw_kind == FL_RW_CNAME && !r.cname) FAIL("cname rewrite without target");
        if (r.n_ips > FL_MAX_IPS || r.n_rr > FL_MAX_RRS) FAIL("result bounds");
        if (rn(8) == 0) fl_explain(set, &rq, explain_nop, NULL);
        if (r.has_rule && rn(4) == 0) {
            char t[1200], src[300];
            fl_rule_text(set, &r.rule, h, t, sizeof(t), src, sizeof(src));
        }
    }
}

static void fuzz_rules(double secs) {
    double end = now_s() + secs;
    unsigned long it = 0, rules = 0;
    char *text = malloc(1 << 20);
    while (now_s() < end) {
        it++;
        size_t len = 0;
        unsigned nr = 1 + rn(rn(4) == 0 ? 3000 : 200);
        for (unsigned i = 0; i < nr; i++) {
            len += rand_rule(text + len, 400);
            text[len++] = rn(10) == 0 ? '\r' : '\n';
            if (rn(10) == 0) text[len++] = '\n';
        }
        rules += nr;
        /* small chunks force several sort runs and merges */
        fl_image_t *a = compile_text(text, len, rn(2) ? 4096 : 512 * 1024, rn(8) == 0 ? FL_SRC_ALLOWLIST : 0, true);
        fl_image_t *b2 = NULL;
        if (rn(2)) {
            size_t l2 = 0;
            for (unsigned i = 0; i < 30; i++) {
                l2 += rand_rule(text + len + l2, 400);
                text[len + l2++] = '\n';
            }
            b2 = compile_text(text + len, l2, 4096, 0, true);
        }
        fl_image_t *imgs[2];
        unsigned ni = 0;
        if (a) imgs[ni++] = a;
        if (b2) imgs[ni++] = b2;
        if (!ni) continue;
        fl_set_t *set = fl_set_new(imgs, ni, (uint32_t)it);
        for (unsigned i = 0; i < ni; i++) fl_image_unref(imgs[i]);
        match_many(set, 300);
        fl_set_unref(set);
    }
    free(text);
    printf("rules: %lu compilations, %lu rules\n", it, rules);
}

/* corrupted images must be rejected or be safe to match against */
static void fuzz_image(double secs) {
    char *text = malloc(1 << 20);
    size_t ilen;
    uint8_t *raw = NULL;
    while (!raw) { /* (a list with binary data is rejected: generate another) */
        size_t len = 0;
        for (unsigned i = 0; i < 3000; i++) {
            len += rand_rule(text + len, 400);
            text[len++] = '\n';
        }
        raw = compile_raw(text, len, 64 * 1024, 0, true, &ilen);
    }
    free(text);
    double end = now_s() + secs;
    unsigned long it = 0, loaded = 0;
    while (now_s() < end) {
        it++;
        uint8_t *d = (uint8_t *)dc_malloc_ext(ilen);
        memcpy(d, raw, ilen);
        unsigned nflip = 1 + rn(8);
        for (unsigned k = 0; k < nflip; k++) {
            uint32_t at = 512 + rn((uint32_t)ilen - 512); /* past the CRC protected header */
            d[at] = rn(2) ? (uint8_t)rnd() : (uint8_t)(d[at] ^ (1u << rn(8)));
        }
        fl_image_t *img;
        if (fl_image_load(d, ilen, false, &img)) {
            dc_free(d);
            continue;
        }
        loaded++;
        fl_set_t *set = fl_set_new(&img, 1, 1);
        fl_image_unref(img);
        match_many(set, 200);
        fl_set_unref(set);
    }
    dc_free(raw);
    printf("image: %lu corrupted images, %lu accepted by the validator and matched safely\n", it, loaded);
}

/* ---- cache ---------------------------------------------------------------------------------------- */

static void ttl_zero(uint8_t *m, size_t n) {
    dns_resp_t r;
    if (dns_parse_response(m, n, &r)) FAIL("cached message does not parse");
    dns_adjust_ttls(m, n, &r, 0xFFFFFFFFu, 0, 0);
}

static void fuzz_cache(double secs) {
    double end = now_s() + secs;
    unsigned long it = 0, hits = 0;
    while (now_s() < end) {
        dns_cache_cfg_t cc = {16384 + rn(200000), rn(2) ? 0 : 1u << rn(6), rn(2) ? 0 : 1 + rn(100)};
        dns_cache_t *c = dns_cache_new(&cc);
        /* model: last stored message per key (names n0..n63) */
        static uint8_t model[64][4096];
        static size_t mlen[64];
        static uint32_t mexp[64];
        memset(mlen, 0, sizeof(mlen));
        uint32_t now = 1000;
        for (int op = 0; op < 3000; op++, it++) {
            unsigned k = rn(64);
            char name[32];
            snprintf(name, sizeof(name), "n%u.example", k);
            dns_ckey_t key;
            memset(&key, 0, sizeof(key));
            key.name_len = (uint8_t)fl_name_to_wire(name, strlen(name), key.name, 256);
            key.qtype = 1;
            key.qclass = 1;
            uint8_t q[300], m[4096], out[4096];
            size_t ql = mkq(q, 0, name, 1, false);
            switch (rn(10)) {
            case 0: case 1: case 2: case 3: {
                size_t n = mkans(q, ql, m, sizeof(m));
                dns_resp_t r;
                if (!n || dns_parse_response(m, n, &r)) break;
                dc_wbe16(m, 0);
                uint32_t ttl = 1 + rn(50);
                dns_cache_put(c, &key, m, n, &r, ttl, now);
                memcpy(model[k], m, n);
                mlen[k] = n;
                mexp[k] = now + ttl;
                break;
            }
            case 4: now += rn(10); break;
            case 5: if (rn(50) == 0) { dns_cache_flush(c); memset(mlen, 0, sizeof(mlen)); } break;
            case 6: dns_cache_set_memo(c, &key, rnd(), rnd(), (uint8_t)rn(3)); break;
            default: {
                dns_cache_hit_t hit;
                int g = dns_cache_get(c, &key, out, sizeof(out), now, 30, &hit);
                if (g == DNS_CACHE_MISS) break;
                hits++;
                if (!mlen[k]) FAIL("hit for a key never stored (or flushed)");
                if (hit.len != mlen[k]) FAIL("cached length differs");
                if (g == DNS_CACHE_HIT && now >= mexp[k]) FAIL("expired entry served as fresh");
                uint8_t a[4096];
                memcpy(a, model[k], mlen[k]);
                ttl_zero(a, mlen[k]);
                ttl_zero(out, hit.len);
                if (memcmp(a, out, mlen[k])) FAIL("cached content differs");
            }
            }
        }
        if (rn(2)) {
            dns_cache_cfg_t c2 = {16384 + rn(100000), 1u << rn(5), rn(50)};
            dns_cache_reconfigure(c, &c2);
        }
        dns_cache_free(c);
    }
    printf("cache: %lu operations, %lu hits verified\n", it, hits);
}

/* ---- server ---------------------------------------------------------------------------------------- */

static atomic_int g_up_stop;
static int g_up_udp, g_up_tcp;

/* upstream: answers with mutated (often invalid) messages, sometimes not at all */
static void *up_thread(void *arg) {
    (void)arg;
    uint8_t q[4096], out[8200];
    uint64_t rng = 0x9E3779B97F4A7C15ull;
    while (!atomic_load(&g_up_stop)) {
        struct pollfd pf[2] = {{g_up_udp, POLLIN, 0}, {g_up_tcp, POLLIN, 0}};
        if (poll(pf, 2, 20) <= 0) continue;
        rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
        if (pf[0].revents & POLLIN) {
            struct sockaddr_storage sa;
            socklen_t sl = sizeof(sa);
            ssize_t n = recvfrom(g_up_udp, q, sizeof(q), 0, (struct sockaddr *)&sa, &sl);
            if (n <= 0 || (rng & 15) == 0) continue; /* drop */
            size_t al = mkans(q, (size_t)n, out, sizeof(out));
            if (!al) continue;
            size_t qe = (size_t)n > 12 ? 12 : 0;
            if (qe && (rng >> 8) % 3) { /* keep header+question so the answer is accepted, mutate the rest */
                dns_query_t pq;
                if (dns_parse_query(q, (size_t)n, &pq) == 0) qe = pq.q_end;
                size_t tail = al - qe;
                tail = mutate(out + qe, tail, sizeof(out) - qe);
                al = qe + tail;
            } else if ((rng >> 12) & 1) {
                al = mutate(out, al, sizeof(out));
            }
            sendto(g_up_udp, out, al, 0, (struct sockaddr *)&sa, sl);
            if ((rng >> 20) % 7 == 0) sendto(g_up_udp, out, al, 0, (struct sockaddr *)&sa, sl); /* duplicate */
        }
        if (pf[1].revents & POLLIN) {
            int c = accept(g_up_tcp, NULL, NULL);
            if (c < 0) continue;
            struct timeval tv = {1, 0};
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            uint8_t lb[2];
            if (recv(c, lb, 2, MSG_WAITALL) == 2) {
                size_t l = dc_be16(lb);
                if (l <= sizeof(q) && recv(c, q, l, MSG_WAITALL) == (ssize_t)l) {
                    size_t al = mkans(q, l, out + 2, sizeof(out) - 2);
                    if (al && (rng & 3) == 0) al = mutate(out + 2, al, sizeof(out) - 2);
                    dc_wbe16(out, (uint16_t)al);
                    if (al) send(c, out, al + 2, MSG_NOSIGNAL);
                }
            }
            close(c);
        }
    }
    return NULL;
}

static void fuzz_server(double secs) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_up_udp = socket(AF_INET, SOCK_DGRAM, 0);
    g_up_tcp = socket(AF_INET, SOCK_STREAM, 0);
    bind(g_up_udp, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(g_up_udp, (struct sockaddr *)&sa, &sl);
    int one = 1;
    setsockopt(g_up_tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(g_up_tcp, (struct sockaddr *)&sa, sizeof(sa)) || listen(g_up_tcp, 16)) FAIL("upstream tcp bind");
    pthread_t th;
    pthread_create(&th, NULL, up_thread, NULL);

    dns_config_t cfg;
    dns_config_defaults(&cfg);
    uint16_t port = (uint16_t)(30000 + getpid() % 20000);
    cfg.port = port;
    cfg.listen_v6 = false;
    snprintf(cfg.bind_v4, sizeof(cfg.bind_v4), "127.0.0.1");
    cfg.nup = 0;
    char u[64];
    snprintf(u, sizeof(u), "127.0.0.1:%u", ntohs(sa.sin_port));
    const char *err;
    dns_upstream_parse(u, &cfg.up[cfg.nup++], &err);
    cfg.up_timeout_ms = 150;
    cfg.query_timeout_ms = 400;
    cfg.cache_bytes = 64 * 1024;
    cfg.optimistic = true;
    cfg.qlog_entries = 64;
    cfg.cache_min_ttl = 0;
    dns_server_t *s = dns_server_new(&cfg);
    if (!s || dns_server_start(s)) FAIL("server start");
    const char *rules = "||ads.example^\n@@||ok.ads.example^\n0.0.0.0 tracker.com\n||evil^\n"
                        "||test^$dnsrewrite=NOERROR;CNAME;target.example\n||x^$dnsrewrite=NXDOMAIN\n"
                        "||cdn^$dnsrewrite=NOERROR;A;1.2.3.4\n||2.3.4^\n/^a[0-9]*\\./\n||www.net^$client=127.0.0.1\n";
    fl_image_t *img = compile_text(rules, strlen(rules), 512 * 1024, 0, true);
    fl_set_t *set = fl_set_new(&img, 1, 1);
    fl_image_unref(img);
    dns_server_set_filters(s, set);
    fl_set_unref(set);
    dns_local_t *l = dns_local_new();
    dns_local_add(l, "nas.home", "A", 60, "192.168.1.5", &err);
    dns_local_add(l, "*.lan", "A", 60, "10.0.0.1", &err);
    dns_local_add(l, "alias.home", "CNAME", 60, "nas.home", &err);
    dns_local_add(l, "out.home", "CNAME", 60, "www.example.com", &err);
    dns_server_set_local(s, l);

    int cs = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in srv = sa;
    srv.sin_port = htons(port);
    struct timeval tv = {0, 1000};
    setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    double end = now_s() + secs;
    unsigned long sync_q = 0, udp_q = 0, answers = 0;
    uint8_t *out = malloc(DNS_QUERY_BUF);
    while (now_s() < end) {
        char name[300];
        uint8_t q[600];
        rand_name(name, sizeof(name));
        if (rn(4) == 0) snprintf(name, sizeof(name), "%s", (const char *[]){"nas.home", "alias.home", "out.home", "p.lan",
                                                                         "ads.example", "ok.ads.example", "a12.net",
                                                                         "foo.test"}[rn(8)]);
        uint16_t id = (uint16_t)rnd();
        size_t ql = mkq(q, id, name, k_types[rn(12)], rn(2));
        if (rn(3) == 0) {
            /* synchronous path: always answered (or dropped for malformed input) */
            bool mutated = rn(4) == 0;
            if (mutated) ql = mutate(q, ql, sizeof(q));
            dns_peer_t peer;
            memset(&peer, 0, sizeof(peer));
            peer.transport = (uint8_t)(rn(2) ? DNS_TR_INTERNAL : DNS_TR_DOH);
            dc_ip_parse_z("127.0.0.1", &peer.ip);
            size_t n = dns_server_query(s, &peer, q, ql, out, DNS_QUERY_BUF);
            sync_q++;
            if (n) {
                if (!valid_answer(out, n)) {
                    hexdump("answer", out, n);
                    hexdump("query", q, ql);
                    FAIL("server answer does not parse (sync)");
                }
                if (!mutated && dc_be16(out) != id) FAIL("answer ID mismatch");
                answers++;
            } else if (!mutated) {
                FAIL("well-formed query not answered (%s)", name);
            }
        } else {
            if (rn(4) == 0) ql = mutate(q, ql, sizeof(q));
            sendto(cs, q, ql, 0, (struct sockaddr *)&srv, sizeof(srv));
            udp_q++;
            uint8_t r[4096];
            ssize_t n;
            while ((n = recv(cs, r, sizeof(r), MSG_DONTWAIT)) > 0) {
                if (!valid_answer(r, (size_t)n)) {
                    hexdump("answer", r, (size_t)n);
                    hexdump("last query", q, ql);
                    FAIL("server answer does not parse (udp)");
                }
                answers++;
            }
        }
        if (rn(500) == 0) dns_server_cache_flush(s);
        if (rn(300) == 0) {
            dns_config_t c2 = cfg;
            c2.block_mode = (dns_block_mode_t)rn(5);
            c2.protection = rn(4) != 0;
            c2.optimistic = rn(2);
            c2.cache_bytes = rn(2) ? 64 * 1024 : 32 * 1024;
            dns_server_reconfigure(s, &c2);
        }
    }
    usleep(500000);
    dns_stats_t st;
    dns_server_get_stats(s, &st);
    dns_server_stop(s);
    atomic_store(&g_up_stop, 1);
    pthread_join(th, NULL);
    close(g_up_udp);
    close(g_up_tcp);
    close(cs);
    free(out);
    printf("server: %lu sync + %lu udp queries, %lu answers checked; forwarded %u cached %u failed %u truncated %u\n",
           sync_q, udp_q, answers, st.forwarded, st.cached, st.failed, st.truncated);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: fuzz wire|parsers|regex|rules|image|cache|server|all SECONDS [SEED]\n");
        return 2;
    }
    double secs = atof(argv[2]);
    g_rng = argc > 3 ? strtoull(argv[3], NULL, 0) : (uint64_t)time(NULL) * 2654435761u;
    if (!g_rng) g_rng = 1;
    printf("seed %llu\n", (unsigned long long)g_rng);
    dc_log_level = DC_LOG_ERR;
    const char *t = argv[1];
    bool all = !strcmp(t, "all");
    if (all || !strcmp(t, "wire")) fuzz_wire(secs);
    if (all || !strcmp(t, "parsers")) fuzz_parsers(secs);
    if (all || !strcmp(t, "regex")) fuzz_regex(secs);
    if (all || !strcmp(t, "rules")) fuzz_rules(secs);
    if (all || !strcmp(t, "image")) fuzz_image(secs);
    if (all || !strcmp(t, "cache")) fuzz_cache(secs);
    if (all || !strcmp(t, "server")) fuzz_server(secs);
    return 0;
}
