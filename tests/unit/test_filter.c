/*
 * Unit tests for the filter engine.  Expected results follow AdGuard Home /
 * urlfilter semantics (cross-checked by tools/compat-oracle on real lists).
 * $client and $ctag rules are recognized and skipped at compile time (and
 * counted in st.client_skipped / st.unsupported) rather than stripped into
 * global rules.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fl_filter.h"
#include "fl_internal.h"

static int g_fail, g_pass;

typedef struct {
    const char *rules;
    uint32_t flags;
} src_t;

static fl_image_t *build_ex(const src_t *srcs, int n, uint32_t chunk, fl_stats_t *st_out) {
    fl_memstore_t runs, sink;
    fl_memstore_init(&runs, 64u << 20);
    fl_memstore_init(&sink, 64u << 20);
    fl_compile_opts_t o;
    memset(&o, 0, sizeof(o));
    o.runs = &runs.st;
    o.chunk_bytes = chunk;
    fl_compiler_t *c = fl_compile_new(&o);
    for (int i = 0; i < n; i++) {
        char name[16];
        snprintf(name, sizeof(name), "src%d", i);
        fl_compile_begin_source(c, name, srcs[i].flags);
        fl_compile_feed(c, srcs[i].rules, strlen(srcs[i].rules));
        if (fl_compile_end_source(c)) {
            printf("source rejected\n");
            exit(1);
        }
    }
    fl_stats_t st;
    int len = fl_compile_finish(c, &sink.st, &st);
    if (len < 0) {
        printf("compile failed: %s\n", fl_compile_error(c));
        exit(1);
    }
    if (st_out) *st_out = st;
    uint8_t *data = (uint8_t *)dc_malloc_ext((size_t)len);
    memcpy(data, sink.buf.data, (size_t)len);
    fl_image_t *img;
    int rc = fl_image_load(data, (size_t)len, true, &img);
    if (rc) {
        printf("load failed %d\n", rc);
        exit(1);
    }
    fl_compile_free(c);
    fl_memstore_free(&runs);
    fl_memstore_free(&sink);
    return img;
}

static fl_image_t *build(const src_t *srcs, int n, uint32_t chunk) {
    return build_ex(srcs, n, chunk, NULL);
}

static void fmt(const fl_result_t *r, char *out, size_t cap) {
    size_t o = 0;
    switch (r->verdict) {
    case FL_V_NONE:
        snprintf(out, cap, "NONE");
        break;
    case FL_V_ALLOW:
        snprintf(out, cap, "ALLOW");
        break;
    case FL_V_ALLOWLIST:
        snprintf(out, cap, "ALLOWLIST");
        break;
    case FL_V_BLOCK:
        o = (size_t)snprintf(out, cap, r->hosts_rule && r->n_ips ? "BLOCK_HOSTS" : "BLOCK");
        for (unsigned i = 0; r->hosts_rule && i < r->n_ips; i++) {
            char ip[64];
            dc_ip_format(&r->ips[i], ip, sizeof(ip));
            o += (size_t)snprintf(out + o, cap - o, " %s", ip);
        }
        break;
    case FL_V_REWRITE:
        if (r->rw_kind == FL_RW_CNAME) {
            char nm[300];
            fl_name_from_wire(r->cname, 256, nm, sizeof(nm));
            snprintf(out, cap, "CNAME %s", nm);
        } else if (r->rw_kind == FL_RW_RCODE) {
            snprintf(out, cap, "RCODE %u", r->rcode);
        } else {
            o = (size_t)snprintf(out, cap, "RRS");
            for (unsigned i = 0; i < r->n_rr; i++) {
                o += (size_t)snprintf(out + o, cap - o, " %u:", r->rr[i].type);
                for (unsigned k = 0; k < r->rr[i].rdlen; k++)
                    o += (size_t)snprintf(out + o, cap - o, "%02x", r->rr[i].rdata[k]);
            }
        }
        break;
    }
}

static void expect_set(fl_set_t *set, const char *host, uint16_t qt, const char *ip, const char *name,
                       uint32_t tags, const char *want, const char *what) {
    fl_client_t cl;
    memset(&cl, 0, sizeof(cl));
    if (ip) dc_ip_parse_z(ip, &cl.ip);
    cl.name = name;
    cl.tags = tags;
    fl_req_t rq = {host, (uint16_t)strlen(host), qt, 0, &cl};
    fl_result_t r;
    fl_match(set, &rq, &r);
    char got[512];
    fmt(&r, got, sizeof(got));
    if (strcmp(got, want) != 0) {
        printf("FAIL [%s] %s q%u%s%s: got '%s' want '%s'\n", what, host, qt, ip ? " ip=" : "", ip ? ip : "",
               got, want);
        g_fail++;
    } else {
        g_pass++;
    }
}

static fl_set_t *mkset(const char *rules) {
    src_t s = {rules, 0};
    fl_image_t *im = build(&s, 1, 512 * 1024);
    fl_set_t *set = fl_set_new(&im, 1, 1);
    fl_image_unref(im);
    return set;
}

#define CASE(rules) for (fl_set_t *S = mkset(rules); S; fl_set_unref(S), S = NULL)
#define E(host, qt, want) expect_set(S, host, qt, NULL, NULL, 0, want, __func__)
#define EC(host, qt, ip, name, tags, want) expect_set(S, host, qt, ip, name, tags, want, __func__)

static void test_basic(void) {
    CASE("||example.org^\n") {
        E("example.org", 1, "BLOCK");
        E("www.example.org", 1, "BLOCK");
        E("a.b.example.org", 28, "BLOCK");
        E("example.org.cn", 1, "NONE");
        E("notexample.org", 1, "NONE");
        E("org", 1, "NONE");
    }
    CASE("||example.org^\n@@||www.example.org^\n") {
        E("www.example.org", 1, "ALLOW");
        E("x.www.example.org", 1, "ALLOW");
        E("sub.example.org", 1, "BLOCK");
    }
    CASE("||example.org^$important\n@@||example.org^\n") { E("example.org", 1, "BLOCK"); }
    CASE("||example.org^$important\n@@||example.org^$important\n") { E("example.org", 1, "ALLOW"); }
    CASE("||*.example.com^\n") {
        E("www.example.com", 1, "BLOCK");
        E("example.com", 1, "NONE");
    }
    CASE(".example.com^\n") {
        E("www.example.com", 1, "BLOCK");
        E("example.com", 1, "NONE");
        E("badexample.com", 1, "NONE");
    }
    CASE("|example.com^\n") {
        E("example.com", 1, "BLOCK");
        E("www.example.com", 1, "NONE");
    }
    CASE("://example.com^\n") {
        E("example.com", 1, "BLOCK");
        E("www.example.com", 1, "NONE");
    }
    CASE("example.com^\n") {
        E("badexample.com", 1, "BLOCK");
        E("example.com", 1, "BLOCK");
        E("example.com.cn", 1, "NONE");
    }
    CASE("||example.com\n") {
        E("example.com", 1, "BLOCK");
        E("example.community", 1, "BLOCK");
        E("x.example.com.cn", 1, "BLOCK");
        E("xexample.com", 1, "NONE");
    }
    CASE("||ads.*^\n") {
        E("ads.foo.com", 1, "BLOCK");
        E("x.ads.co", 1, "BLOCK");
        E("bads.foo.com", 1, "NONE");
    }
    CASE("||log-va*.capcutapi.com^\n") {
        E("log-va12.capcutapi.com", 1, "BLOCK");
        E("x.log-va.capcutapi.com", 1, "BLOCK");
        E("xlog-va.capcutapi.com", 1, "NONE");
    }
}

static void test_hosts(void) {
    CASE("example.org\n") {
        E("example.org", 1, "BLOCK_HOSTS 0.0.0.0");
        E("example.org", 28, "BLOCK");
        E("example.org", 15, "BLOCK");
        E("www.example.org", 1, "NONE");
    }
    CASE("0.0.0.0 a.com b.com # comment\n") {
        E("a.com", 1, "BLOCK_HOSTS 0.0.0.0");
        E("b.com", 1, "BLOCK_HOSTS 0.0.0.0");
        E("b.com", 28, "BLOCK");
    }
    CASE("127.0.0.1 x.com\n::1 x.com\n1.2.3.4 x.com\n") {
        E("x.com", 1, "BLOCK_HOSTS 127.0.0.1 1.2.3.4");
        E("x.com", 28, "BLOCK_HOSTS ::1");
    }
    CASE("0.0.0.0 x.com\n@@||x.com^\n") { E("x.com", 1, "ALLOW"); }
    CASE("example\n") {
        E("example", 1, "BLOCK_HOSTS 0.0.0.0");
        E("www.example", 1, "NONE");
    }
}

static void test_modifiers(void) {
    CASE("||example.com^$dnstype=AAAA\n") {
        E("example.com", 28, "BLOCK");
        E("example.com", 1, "NONE");
    }
    CASE("||example.com^$dnstype=~A\n") {
        E("example.com", 28, "BLOCK");
        E("example.com", 15, "BLOCK");
        E("example.com", 1, "NONE");
    }
    /* $client and $ctag rules must be skipped at compile time and never
     * stripped into global rules (which would cause false positives). */
    {
        src_t s = {"||example.com^$client=192.168.1.0/24\n"
                   "||example.com^$client=~192.168.1.5\n"
                   "||example.com^$client='Frank\\'s laptop'\n"
                   "||example.com^$ctag=device_phone\n"
                   "||example.com^$ctag=~user_admin\n"
                   "*$client=1.2.3.4\n"
                   "||kept.com^$dnstype=A\n",
                   0};
        fl_stats_t st;
        fl_image_t *im = build_ex(&s, 1, 512 * 1024, &st);
        fl_set_t *S = fl_set_new(&im, 1, 1);
        fl_image_unref(im);
        if (st.client_skipped != 6 || st.unsupported != 6) {
            printf("FAIL client_skipped=%u unsupported=%u (want 6, 6)\n", st.client_skipped, st.unsupported);
            g_fail++;
        } else {
            g_pass++;
        }
        EC("example.com", 1, "192.168.1.5", "Frank's laptop", 1u << FL_CTAG_DEVICE_PHONE, "NONE");
        EC("example.com", 1, "192.168.1.6", NULL, 0, "NONE");
        EC("anything.com", 1, "1.2.3.4", NULL, 0, "NONE");
        E("kept.com", 1, "BLOCK");
        E("kept.com", 28, "NONE");
        fl_set_unref(S);
    }
    CASE("||*^$denyallow=good.com|better.org\n") {
        E("evil.com", 1, "BLOCK");
        E("good.com", 1, "NONE");
        E("x.good.com", 1, "NONE");
        E("1.2.3.4", 1, "NONE");
    }
    CASE("||ex.com^$third-party\n||ex2.com^$domain=x.com\n||ex3.com^$script\n||ex4.com^$~script\n||ex5.com^$unknownmod\n") {
        E("ex.com", 1, "NONE");
        E("ex2.com", 1, "NONE");
        E("ex3.com", 1, "NONE");
        E("ex4.com", 1, "BLOCK");
        E("ex5.com", 1, "NONE");
    }
    CASE("/^ad[0-9]+\\.example\\.com$/\n/^tracker\\./$dnstype=A\n") {
        E("ad12.example.com", 1, "BLOCK");
        E("xad12.example.com", 1, "NONE");
        E("tracker.foo.net", 1, "BLOCK");
        E("tracker.foo.net", 28, "NONE");
    }
}

static void test_badfilter(void) {
    CASE("||example.org^$badfilter\n||example.org^\n||other.org^\n") {
        E("example.org", 1, "NONE");
        E("other.org", 1, "BLOCK");
    }
    CASE("||example.org^\n||example.org^$important,badfilter\n") { E("example.org", 1, "BLOCK"); }
    CASE("||example.org^$important\n||example.org^$important,badfilter\n") { E("example.org", 1, "NONE"); }
    CASE("||example.org^$client=1.2.3.4\n||example.org^$client=1.2.3.4,badfilter\n") {
        EC("example.org", 1, "1.2.3.4", NULL, 0, "NONE");
    }
    CASE("||example.org^$dnstype=A,badfilter\n||example.org^\n") {
        E("example.org", 1, "NONE");
        E("example.org", 28, "BLOCK");
    }
    CASE("||ads*.example.org^\n||ads*.example.org^$badfilter\n") { E("ads1.example.org", 1, "NONE"); }
    /* cross image: custom rules disable a subscription rule */
    {
        src_t a = {"||example.org^$badfilter\n@@||allowed.net^$badfilter\n", 0};
        src_t b = {"||example.org^\n||allowed.net^\n@@||allowed.net^\n", 0};
        fl_image_t *ims[2] = {build(&a, 1, 65536), build(&b, 1, 65536)};
        fl_set_t *S = fl_set_new(ims, 2, 1);
        fl_image_unref(ims[0]);
        fl_image_unref(ims[1]);
        E("example.org", 1, "NONE");
        E("allowed.net", 1, "BLOCK");
        fl_set_unref(S);
    }
}

static void test_rewrite(void) {
    CASE("||example.com^$dnsrewrite=1.2.3.4\n") {
        E("example.com", 1, "RRS 1:01020304");
        E("example.com", 28, "RRS");
    }
    CASE("||example.com^$dnsrewrite=NOERROR;CNAME;example.net\n") { E("example.com", 1, "CNAME example.net"); }
    CASE("||example.com^$dnsrewrite=REFUSED\n") { E("example.com", 1, "RCODE 5"); }
    CASE("||example.com^$dnsrewrite=1.2.3.4\n||example.com^$dnsrewrite=1.2.3.5\n@@||example.com^$dnsrewrite=1.2.3.4\n") {
        E("example.com", 1, "RRS 1:01020305");
    }
    CASE("||example.com^$dnsrewrite=1.2.3.4\n||example.com^\n@@||example.com^$dnsrewrite\n") {
        E("example.com", 1, "BLOCK");
    }
    CASE("||example.com^\n||example.com^$dnsrewrite=1.2.3.4\n") { E("example.com", 1, "RRS 1:01020304"); }
    CASE("||example.com^$dnsrewrite=example.com\n||example.com^\n") { E("example.com", 1, "BLOCK"); }
    CASE("||example.com^$dnsrewrite=NOERROR;MX;32 mail.example.com\n") {
        E("example.com", 15, "RRS 15:0020046d61696c076578616d706c6503636f6d00");
    }
    CASE("||example.com^$dnsrewrite=NOERROR;TXT;hello world\n") {
        E("example.com", 16, "RRS 16:0b68656c6c6f20776f726c64");
    }
    CASE("||_svctest._tcp.example.com^$dnsrewrite=NOERROR;SRV;30 60 8080 srv.example.com\n") {
        E("_svctest._tcp.example.com", 33, "RRS 33:001e003c1f900373727607" "6578616d706c65" "03636f6d00");
    }
    CASE("||example.com^$dnsrewrite=NOERROR;HTTPS;32 example.com alpn=h3\n") {
        E("example.com", 65, "RRS 65:0020076578616d706c6503636f6d00" "00010003026833");
    }
    CASE("||example.com^$dnsrewrite=1.2.3.4,important\n||example.com^$dnsrewrite=5.6.7.8\n@@||example.com^$dnsrewrite\n") {
        E("example.com", 1, "RRS 1:01020304");
    }
}

static void test_allowlist(void) {
    src_t a[2] = {{"||ads.com^$important\n||track.com^\n", 0}, {"||ads.com^\nsafe.com\n", FL_SRC_ALLOWLIST}};
    fl_image_t *im = build(a, 2, 65536);
    fl_set_t *S = fl_set_new(&im, 1, 1);
    fl_image_unref(im);
    E("ads.com", 1, "ALLOWLIST");
    E("x.ads.com", 1, "ALLOWLIST");
    E("track.com", 1, "BLOCK");
    E("safe.com", 1, "ALLOWLIST");
    fl_set_unref(S);
}

/* ---- randomized index integrity: many runs, compare against a reference ---- */
static uint32_t rng = 12345;
static uint32_t rnd(void) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng;
}

static void rand_label(char *o, int n) {
    static const char a[] = "abcdefghijklmnopqrstuvwxyz0123456789-";
    for (int i = 0; i < n; i++) o[i] = a[rnd() % (i == 0 || i == n - 1 ? 36 : 37)];
    o[n] = 0;
}

static void test_index_random(void) {
    enum { N = 30000 };
    static char hosts[N][64];
    static const char *tlds[] = {"com", "net", "org", "cn", "io", "co.uk", "xyz", "info"};
    dc_buf_t txt;
    dc_buf_init(&txt);
    for (int i = 0; i < N; i++) {
        char l1[20], l2[20];
        rand_label(l1, 3 + (int)(rnd() % 10));
        rand_label(l2, 2 + (int)(rnd() % 8));
        if (rnd() % 3 == 0)
            snprintf(hosts[i], 64, "%s.%s.%s", l2, l1, tlds[rnd() % 8]);
        else
            snprintf(hosts[i], 64, "%s.%s", l1, tlds[rnd() % 8]);
        char line[100];
        int k = snprintf(line, sizeof(line), "%s%s^\n", i % 2 ? "||" : "|", hosts[i]);
        dc_buf_append(&txt, line, (size_t)k);
    }
    dc_buf_put8(&txt, 0);
    src_t s = {(const char *)txt.data, 0};
    fl_image_t *im = build(&s, 1, 16 * 1024); /* small chunks: many runs */
    fl_set_t *S = fl_set_new(&im, 1, 1);
    fl_image_unref(im);
    int bad = 0;
    for (int i = 0; i < N && bad < 10; i++) {
        fl_req_t rq = {hosts[i], (uint16_t)strlen(hosts[i]), 1, 0, NULL};
        fl_result_t r;
        fl_match(S, &rq, &r);
        if (r.verdict != FL_V_BLOCK) {
            printf("FAIL index: %s not blocked\n", hosts[i]);
            bad++;
        }
        char sub[80];
        snprintf(sub, sizeof(sub), "zz.%s", hosts[i]);
        rq.host = sub;
        rq.host_len = (uint16_t)strlen(sub);
        fl_match(S, &rq, &r);
        int want = i % 2 ? FL_V_BLOCK : FL_V_NONE;
        /* the sub-domain may coincide with another exact rule only by chance */
        if (r.verdict != want && want == FL_V_BLOCK) {
            printf("FAIL index: %s want %d got %d\n", sub, want, r.verdict);
            bad++;
        }
    }
    /* random misses */
    int fp = 0;
    for (int i = 0; i < 20000; i++) {
        char h[64], l[20];
        rand_label(l, 12);
        snprintf(h, sizeof(h), "%s.nomatch-%d.test", l, i);
        fl_req_t rq = {h, (uint16_t)strlen(h), 1, 0, NULL};
        fl_result_t r;
        fl_match(S, &rq, &r);
        if (r.verdict != FL_V_NONE) fp++;
    }
    if (fp) {
        printf("FAIL index: %d false positives\n", fp);
        bad++;
    }
    if (bad)
        g_fail += bad;
    else
        g_pass++;
    fl_set_unref(S);
    dc_buf_free(&txt);
}

static void test_reject(void) {
    fl_memstore_t runs;
    fl_memstore_init(&runs, 1u << 20);
    fl_compile_opts_t o;
    memset(&o, 0, sizeof(o));
    o.runs = &runs.st;
    fl_compiler_t *c = fl_compile_new(&o);
    fl_compile_begin_source(c, "html", 0);
    const char *html = "<!DOCTYPE html>\n<html><body>blocked</body></html>\n";
    int rc = fl_compile_feed(c, html, strlen(html));
    if (rc != FL_ERR_HTML) {
        printf("FAIL html not rejected (%d)\n", rc);
        g_fail++;
    } else {
        g_pass++;
    }
    /* the whole list is rejected: later lines report the same */
    rc = fl_compile_end_source(c);
    if (rc != FL_ERR_HTML || fl_compile_error(c)[0]) {
        printf("FAIL html end_source %d '%s'\n", rc, fl_compile_error(c));
        g_fail++;
    } else {
        g_pass++;
    }
    /* binary data after rules of the same list: the build is unusable */
    fl_compile_begin_source(c, "bin", 0);
    const char *bin = "||before.com^\n\x01\x02garbage\n||after.com^\n";
    rc = fl_compile_feed(c, bin, strlen(bin));
    if (rc != FL_ERR_BINARY || !fl_compile_error(c)[0]) {
        printf("FAIL binary mid-list %d '%s'\n", rc, fl_compile_error(c));
        g_fail++;
    } else {
        g_pass++;
    }
    fl_compile_free(c);
    fl_memstore_free(&runs);
}

/* limits: many matching rules, many modifier rules per domain, many generic
 * rules per n-gram, long $badfilter identities, rejected rules */
static void test_limits(void) {
    dc_buf_t t;
    dc_buf_init(&t);
    char line[600];
    /* 70 matching blocking regexes do not crowd out the exception */
    for (int i = 0; i < 70; i++) {
        int n = snprintf(line, sizeof(line), "/(a|z%d)d/\n", i);
        dc_buf_append(&t, line, (size_t)n);
    }
    dc_buf_append(&t, "@@*ker-exam*\n", 13);
    dc_buf_put8(&t, 0);
    CASE((const char *)t.data) {
        E("ads.tracker-example.com", 1, "ALLOW");
        E("ads.other.com", 1, "BLOCK");
    }
    /* 300 modifier rules on one domain: the first 255 are kept, compile succeeds */
    t.len = 0;
    for (int i = 0; i < 300; i++) {
        int n = snprintf(line, sizeof(line), "||example.com^$denyallow=sub%d.example.com\n", i);
        dc_buf_append(&t, line, (size_t)n);
    }
    dc_buf_put8(&t, 0);
    CASE((const char *)t.data) {
        E("example.com", 1, "BLOCK");
        E("other.com", 1, "NONE");
    }
    /* 300 generic rules under one n-gram: the image loads */
    t.len = 0;
    for (int i = 0; i < 300; i++) {
        int n = snprintf(line, sizeof(line), "||tracker*%d^\n", i);
        dc_buf_append(&t, line, (size_t)n);
    }
    dc_buf_put8(&t, 0);
    CASE((const char *)t.data) {
        E("tracker-x.299", 1, "BLOCK");
        E("other.com", 1, "NONE");
    }
    /* conditional $badfilter with an identity longer than 1 KiB */
    t.len = 0;
    for (int pass = 0; pass < 2; pass++) {
        dc_buf_append(&t, "||long.test^$denyallow=", 23);
        for (int i = 0; i < 16; i++) {
            char nm[80];
            memset(nm, 'a' + i, 60);
            strcpy(nm + 60, ".long.test");
            int n = snprintf(line, sizeof(line), "%s%s", i ? "|" : "", nm);
            dc_buf_append(&t, line, (size_t)n);
        }
        if (pass) dc_buf_append(&t, ",dnstype=A,badfilter", 20);
        dc_buf_put8(&t, '\n');
    }
    dc_buf_put8(&t, 0);
    CASE((const char *)t.data) {
        E("long.test", 1, "NONE");
        E("long.test", 28, "BLOCK");
    }
    /* rejected regex rules leave nothing behind in the image */
    {
        fl_memstore_t runs, sink;
        fl_memstore_init(&runs, 16u << 20);
        fl_memstore_init(&sink, 16u << 20);
        fl_compile_opts_t o;
        memset(&o, 0, sizeof(o));
        o.runs = &runs.st;
        fl_compiler_t *c = fl_compile_new(&o);
        fl_compile_begin_source(c, "bad", 0);
        for (int i = 0; i < 2000; i++) {
            int n = snprintf(line, sizeof(line), "/(?=lookahead%d)x/$dnstype=A\n", i);
            fl_compile_feed(c, line, (size_t)n);
        }
        fl_compile_end_source(c);
        fl_stats_t st;
        int len = fl_compile_finish(c, &sink.st, &st);
        if (len <= 0 || len > 64 * 1024) {
            printf("FAIL rejected rules kept in the image (%d bytes)\n", len);
            g_fail++;
        } else {
            g_pass++;
        }
        fl_compile_free(c);
        fl_memstore_free(&runs);
        fl_memstore_free(&sink);
    }
    dc_buf_free(&t);
}

/* Go regexp details and Go strings.TrimSpace */
static void test_syntax(void) {
    CASE("/^x\\Qab\\E*\\.test$/\n") { /* the repetition binds to "b" only */
        E("xa.test", 1, "BLOCK");
        E("xabbb.test", 1, "BLOCK");
        E("xabab.test", 1, "NONE");
    }
    CASE("/^y\\Qa.b\\E\\.test$/\n") { /* quoted metacharacters */
        E("ya.b.test", 1, "BLOCK");
        E("yaxb.test", 1, "NONE");
    }
    CASE("/(?)ok\\.test/\n") {
        E("ok.test", 1, "BLOCK");
    }
    CASE("||ideo.test^\xe3\x80\x80\n\xe2\x80\x83||wide.test^\n") { /* U+3000, U+2003 */
        E("ideo.test", 1, "BLOCK");
        E("wide.test", 1, "BLOCK");
    }
}

int main(void) {
    test_basic();
    test_hosts();
    test_modifiers();
    test_badfilter();
    test_rewrite();
    test_allowlist();
    test_index_random();
    test_reject();
    test_limits();
    test_syntax();
    printf("filter tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
