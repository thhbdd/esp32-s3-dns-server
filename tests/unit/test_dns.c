/*
 * Unit + integration tests for the DNS core: wire codec, cache, local
 * records, upstream parsing and the full server against a fake upstream
 * (UDP + TCP on 127.0.0.1).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns_cache.h"
#include "dns_local.h"
#include "dns_server.h"
#include "dns_wire.h"
#include "fl_filter.h"

static int g_fail, g_pass;

#define CHECK(cond, ...)                                                                                  \
    do {                                                                                                  \
        if (cond) {                                                                                       \
            g_pass++;                                                                                     \
        } else {                                                                                          \
            g_fail++;                                                                                     \
            printf("FAIL %s:%d: ", __func__, __LINE__);                                                   \
            printf(__VA_ARGS__);                                                                          \
            printf("\n");                                                                                 \
        }                                                                                                 \
    } while (0)

/* ---- helpers --------------------------------------------------------------------- */

static size_t mkq(uint8_t *b, uint16_t id, const char *name, uint16_t qt, int edns, bool do_bit) {
    dc_wbe16(b, id);
    dc_wbe16(b + 2, DNS_F_RD);
    dc_wbe16(b + 4, 1);
    dc_wbe16(b + 6, 0);
    dc_wbe16(b + 8, 0);
    dc_wbe16(b + 10, edns ? 1 : 0);
    int nl = fl_name_to_wire(name, strlen(name), b + 12, 256);
    size_t o = 12 + (size_t)nl;
    dc_wbe16(b + o, qt);
    dc_wbe16(b + o + 2, DNS_C_IN);
    o += 4;
    if (edns) {
        b[o] = 0;
        dc_wbe16(b + o + 1, DNS_T_OPT);
        dc_wbe16(b + o + 3, (uint16_t)edns);
        dc_wbe32(b + o + 5, do_bit ? 0x8000u : 0);
        dc_wbe16(b + o + 9, 0);
        o += 11;
    }
    return o;
}

/* "rc=N tc=N aa=N an=[...] ns=N ar=N" with answers "TYPE value" */
static void summarize(const uint8_t *m, size_t n, char *out, size_t cap) {
    dns_resp_t r;
    if (n < 12 || dns_parse_response(m, n, &r)) {
        snprintf(out, cap, "PARSE-ERROR(len=%zu)", n);
        return;
    }
    size_t o = (size_t)snprintf(out, cap, "rc=%u tc=%u an=[", r.rcode, (r.flags & DNS_F_TC) ? 1 : 0);
    size_t off = r.an_off;
    for (unsigned i = 0; i < r.ancount; i++) {
        dns_skip_name(m, n, &off);
        uint16_t type = dc_be16(m + off), rdlen = dc_be16(m + off + 8);
        size_t rd = off + 10;
        char val[300] = "?";
        if (type == DNS_T_A && rdlen == 4) {
            snprintf(val, sizeof(val), "%u.%u.%u.%u", m[rd], m[rd + 1], m[rd + 2], m[rd + 3]);
        } else if (type == DNS_T_AAAA && rdlen == 16) {
            dc_ip_t ip = {6, {0}};
            memcpy(ip.addr, m + rd, 16);
            dc_ip_format(&ip, val, sizeof(val));
        } else if (type == DNS_T_CNAME) {
            uint8_t nm[256];
            size_t p = rd;
            int nl = dns_read_name(m, n, &p, nm, false);
            if (nl > 0) fl_name_from_wire(nm, (size_t)nl, val, sizeof(val));
        } else {
            snprintf(val, sizeof(val), "len%u", rdlen);
        }
        o += (size_t)snprintf(out + o, cap - o, "%s%s %s", i ? "," : "",
                              type == DNS_T_A       ? "A"
                              : type == DNS_T_AAAA  ? "AAAA"
                              : type == DNS_T_CNAME ? "CNAME"
                              : type == DNS_T_TXT   ? "TXT"
                                                    : "T",
                              val);
        off = rd + rdlen;
    }
    snprintf(out + o, cap - o, "] ns=%u ar=%u", r.nscount, r.arcount);
}

static uint32_t first_ttl(const uint8_t *m, size_t n) {
    dns_resp_t r;
    if (dns_parse_response(m, n, &r) || !r.nttl) return 0xFFFFFFFF;
    return dc_be32(m + r.ttl_off[0]);
}

static fl_set_t *mkset(const char *rules) {
    fl_memstore_t runs, sink;
    fl_memstore_init(&runs, 16u << 20);
    fl_memstore_init(&sink, 16u << 20);
    fl_compile_opts_t o;
    memset(&o, 0, sizeof(o));
    o.runs = &runs.st;
    fl_compiler_t *c = fl_compile_new(&o);
    fl_compile_begin_source(c, "test", 0);
    fl_compile_feed(c, rules, strlen(rules));
    fl_compile_end_source(c);
    fl_stats_t st;
    int len = fl_compile_finish(c, &sink.st, &st);
    if (len < 0) {
        printf("compile failed\n");
        exit(1);
    }
    uint8_t *data = (uint8_t *)dc_malloc_ext((size_t)len);
    memcpy(data, sink.buf.data, (size_t)len);
    fl_image_t *img;
    if (fl_image_load(data, (size_t)len, true, &img)) exit(1);
    fl_compile_free(c);
    fl_memstore_free(&runs);
    fl_memstore_free(&sink);
    fl_set_t *set = fl_set_new(&img, 1, 7);
    fl_image_unref(img);
    return set;
}

/* ---- wire --------------------------------------------------------------------------- */

static void test_wire(void) {
    uint8_t q[512], out[512];
    size_t ql = mkq(q, 0x1234, "WwW.Example.COM", DNS_T_A, 1232, true);
    dns_query_t pq;
    CHECK(dns_parse_query(q, ql, &pq) == DNS_PARSE_OK, "parse");
    CHECK(strcmp(pq.host, "www.example.com") == 0, "host %s", pq.host);
    CHECK(pq.has_edns && pq.do_bit && pq.edns_udp == 1232, "edns");
    CHECK(pq.qname[1] == 'W', "case kept");

    /* qdcount 2 -> FORMERR */
    uint8_t bad[512];
    memcpy(bad, q, ql);
    dc_wbe16(bad + 4, 2);
    CHECK(dns_parse_query(bad, ql, &pq) == DNS_PARSE_FORMERR, "formerr");
    /* opcode 2 -> NOTIMP */
    memcpy(bad, q, ql);
    dc_wbe16(bad + 2, (uint16_t)(DNS_F_RD | (2 << 11)));
    CHECK(dns_parse_query(bad, ql, &pq) == DNS_PARSE_NOTIMP, "notimp");
    /* response bit -> drop */
    memcpy(bad, q, ql);
    dc_wbe16(bad + 2, DNS_F_QR);
    CHECK(dns_parse_query(bad, ql, &pq) == DNS_PARSE_DROP, "drop");
    /* EDNS version 1 -> BADVERS with extended rcode in OPT */
    memcpy(bad, q, ql);
    bad[ql - 5] = 1; /* version byte of the OPT TTL field */
    CHECK(dns_parse_query(bad, ql, &pq) == DNS_PARSE_BADVERS, "badvers");
    size_t n = dns_make_error(out, sizeof(out), bad, ql, &pq, DNS_RC_BADVERS);
    dns_resp_t r;
    CHECK(n && dns_parse_response(out, n, &r) == 0 && r.rcode == DNS_RC_BADVERS && r.has_opt, "badvers resp");
    /* compression loop / forward pointer rejected */
    uint8_t loop[64] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1};
    CHECK(dns_parse_query(loop, 18, &pq) == DNS_PARSE_FORMERR, "pointer loop");
    /* truncated input */
    for (size_t k = 0; k < ql; k++) dns_parse_query(q, k, &pq);
    g_pass++;
}

/* ---- upstream parsing ------------------------------------------------------------- */

static void test_upstream_parse(void) {
    dns_upstream_cfg_t u;
    const char *err;
    CHECK(dns_upstream_parse("1.1.1.1", &u, &err) && u.proto == DNS_UP_UDP && u.port == 53 && u.ip.family == 4,
          "plain");
    CHECK(dns_upstream_parse("udp://9.9.9.9:5353", &u, &err) && u.port == 5353, "udp port");
    CHECK(dns_upstream_parse("[2606:4700::1111]:53", &u, &err) && u.ip.family == 6, "v6 port");
    CHECK(dns_upstream_parse("2001:db8::1", &u, &err) && u.ip.family == 6 && u.port == 53, "bare v6");
    CHECK(dns_upstream_parse("tcp://8.8.8.8", &u, &err) && u.proto == DNS_UP_TCP, "tcp");
    CHECK(dns_upstream_parse("tls://dns.google", &u, &err) && u.proto == DNS_UP_DOT && u.port == 853 &&
              strcmp(u.host, "dns.google") == 0 && u.ip.family == 0,
          "dot");
    CHECK(dns_upstream_parse("tls://1.1.1.1@cloudflare-dns.com", &u, &err) && u.ip.family == 4 &&
              strcmp(u.host, "cloudflare-dns.com") == 0,
          "dot ip@name");
    CHECK(dns_upstream_parse("https://dns.alidns.com/dns-query", &u, &err) && u.proto == DNS_UP_DOH &&
              u.port == 443 && strcmp(u.path, "/dns-query") == 0 && strcmp(u.host, "dns.alidns.com") == 0,
          "doh");
    CHECK(dns_upstream_parse("https://1.12.12.12:8443", &u, &err) && u.port == 8443 && u.ip.family == 4 &&
              strcmp(u.path, "/dns-query") == 0,
          "doh ip");
    CHECK(!dns_upstream_parse("dns.google", &u, &err), "udp needs ip");
    CHECK(!dns_upstream_parse("quic://dns.adguard.com", &u, &err), "quic unsupported");
    CHECK(!dns_upstream_parse("1.1.1.1:99999", &u, &err), "bad port");
}

/* ---- local records ------------------------------------------------------------------ */

static void test_local(void) {
    dns_local_t *l = dns_local_new();
    const char *err;
    CHECK(dns_local_add(l, "nas.home", "A", 60, "192.168.1.5", &err) == 0, "add");
    CHECK(dns_local_add(l, "nas.home", "A", 60, "192.168.1.6", &err) == 0, "add2");
    CHECK(dns_local_add(l, "*.lan", "A", 0, "10.0.0.1", &err) == 0, "wild");
    CHECK(dns_local_add(l, "*.x.lan", "A", 0, "10.0.0.2", &err) == 0, "wild2");
    CHECK(dns_local_add(l, "bad", "A", 0, "300.1.1.1", &err) < 0, "bad ip");
    dns_local_seal(l);
    dns_lentry_t e;
    CHECK(dns_local_lookup(l, "nas.home", 8, &e) && e.n == 2, "exact");
    CHECK(!dns_local_lookup(l, "lan", 3, &e), "wild does not match apex");
    CHECK(dns_local_lookup(l, "a.lan", 5, &e) && e.recs[0].rdata[3] == 1, "wild");
    CHECK(dns_local_lookup(l, "b.x.lan", 7, &e) && e.recs[0].rdata[3] == 2, "longest wild");
    dns_local_free(l);
}

/* ---- cache ------------------------------------------------------------------------- */

static size_t mkresp(uint8_t *b, const char *name, uint32_t ttl, uint8_t last) {
    uint8_t q[300];
    size_t ql = mkq(q, 0, name, DNS_T_A, 0, false);
    dns_query_t pq;
    dns_parse_query(q, ql, &pq);
    dns_buf_t bb = {b, 600, 0, false};
    dns_resp_begin(&bb, &pq, 0, false);
    uint8_t ip[4] = {10, 0, 0, last};
    dns_resp_rr(&bb, DNS_T_A, ttl, ip, 4);
    return dns_resp_end(&bb, 1, 0, 0);
}

static void test_cache(void) {
    dns_cache_cfg_t cc = {64 * 1024, 16, 60};
    dns_cache_t *c = dns_cache_new(&cc);
    dns_ckey_t k;
    memset(&k, 0, sizeof(k));
    uint8_t msg[600], out[4096];
    dns_resp_t r;
    dns_cache_hit_t hit;
    char name[64];
    /* fill far beyond capacity: ring wraps, index stays consistent */
    for (int i = 0; i < 5000; i++) {
        snprintf(name, sizeof(name), "host%d.example", i);
        size_t n = mkresp(msg, name, 300, (uint8_t)i);
        dns_parse_response(msg, n, &r);
        k.name_len = (uint8_t)fl_name_to_wire(name, strlen(name), k.name, 256);
        k.qtype = DNS_T_A;
        k.qclass = 1;
        dns_cache_put(c, &k, msg, n, &r, 300, 1000);
    }
    int hits = 0;
    for (int i = 0; i < 5000; i++) {
        snprintf(name, sizeof(name), "host%d.example", i);
        k.name_len = (uint8_t)fl_name_to_wire(name, strlen(name), k.name, 256);
        if (dns_cache_get(c, &k, out, sizeof(out), 1100, 30, &hit) == DNS_CACHE_HIT) {
            hits++;
            if (out[hit.len - 1] != (uint8_t)i) {
                CHECK(0, "wrong entry for %s", name);
                break;
            }
            if (first_ttl(out, hit.len) != 200) {
                CHECK(0, "ttl %u", first_ttl(out, hit.len));
                break;
            }
        }
    }
    CHECK(hits > 300 && hits < 5000, "hits %d", hits);
    /* newest are present */
    snprintf(name, sizeof(name), "host%d.example", 4999);
    k.name_len = (uint8_t)fl_name_to_wire(name, strlen(name), k.name, 256);
    CHECK(dns_cache_get(c, &k, out, sizeof(out), 1100, 30, &hit) == DNS_CACHE_HIT, "newest");
    CHECK(dns_cache_get(c, &k, out, sizeof(out), 1100, 30, &hit) == DNS_CACHE_HIT && hit.l1, "l1 promoted");
    /* expiry + stale window */
    CHECK(dns_cache_get(c, &k, out, sizeof(out), 1350, 30, &hit) == DNS_CACHE_STALE &&
              first_ttl(out, hit.len) == 30,
          "stale");
    CHECK(dns_cache_get(c, &k, out, sizeof(out), 1400, 30, &hit) == DNS_CACHE_MISS, "expired");
    /* memo */
    snprintf(name, sizeof(name), "host%d.example", 4998);
    k.name_len = (uint8_t)fl_name_to_wire(name, strlen(name), k.name, 256);
    dns_cache_set_memo(c, &k, 5, 77, 2);
    CHECK(dns_cache_get(c, &k, out, sizeof(out), 1100, 30, &hit) == DNS_CACHE_HIT && hit.memo == 2 &&
              hit.memo_gen == 5 && hit.memo_fp == 77,
          "memo");
    dns_cache_stats_t st;
    dns_cache_get_stats(c, &st);
    CHECK(st.entries > 0 && st.evictions > 0, "stats");
    dns_cache_reconfigure(c, &cc);
    CHECK(dns_cache_get(c, &k, out, sizeof(out), 1100, 30, &hit) == DNS_CACHE_MISS, "reconfigure flushes");
    /* A rule update releases actual cache allocations, not just entries.
     * Changes to cache settings while the build is running must be honored. */
    dns_cache_set_build_mode(c, true);
    dns_cache_get_stats(c, &st);
    CHECK(st.bytes_total == 0, "build releases L2 allocation (%u)", st.bytes_total);
    CHECK(dns_cache_get(c, &k, out, sizeof(out), 1100, 30, &hit) == DNS_CACHE_MISS,
          "cache bypass while building");
    dns_cache_cfg_t next = {128 * 1024, 16, 90};
    dns_cache_reconfigure(c, &next);
    dns_cache_get_stats(c, &st);
    CHECK(st.bytes_total == 0, "reconfigure during build remains paused");
    dns_cache_set_build_mode(c, true); /* idempotent */
    dns_cache_set_build_mode(c, false);
    dns_cache_get_stats(c, &st);
    CHECK(st.bytes_total == 128 * 1024, "resume latest configured size (%u)", st.bytes_total);
    dns_cache_set_build_mode(c, false); /* idempotent */
    CHECK(dns_cache_get(c, &k, out, sizeof(out), 1100, 30, &hit) == DNS_CACHE_MISS,
          "retired entries cannot reappear");
    dns_cache_free(c);
}

static void test_hist(void) {
    dns_hist_t h;
    memset(&h, 0, sizeof(h));
    extern void dns_hist_add(dns_hist_t * h, uint32_t us);
    for (uint32_t i = 1; i <= 1000; i++) dns_hist_add(&h, i);
    uint32_t p50 = dns_hist_percentile(&h, 50), p99 = dns_hist_percentile(&h, 99);
    CHECK(p50 > 400 && p50 < 600, "p50 %u", p50);
    CHECK(p99 > 850 && p99 < 1100, "p99 %u", p99);
    CHECK(dns_hist_mean(&h) == 500, "mean %u", dns_hist_mean(&h));
}

/* ---- fake upstream ------------------------------------------------------------------ */

typedef struct {
    int udp, tcp;
    uint16_t port;
    atomic_int stop;
    pthread_mutex_t mu;
    char names[64][64];
    int counts[64];
    int n;
    atomic_int servfail; /* "sf." names: SERVFAIL */
    atomic_int changed;  /* "chg." names: new address with TTL 0 */
    atomic_int lower;    /* answers repeat the question in lowercase */
} fake_t;

static void fake_count(fake_t *f, const char *host) {
    pthread_mutex_lock(&f->mu);
    int i;
    for (i = 0; i < f->n; i++)
        if (strcmp(f->names[i], host) == 0) break;
    if (i == f->n && f->n < 64) {
        snprintf(f->names[i], 64, "%.63s", host);
        f->counts[i] = 0;
        f->n++;
    }
    if (i < 64) f->counts[i]++;
    pthread_mutex_unlock(&f->mu);
}

static int fake_get(fake_t *f, const char *host) {
    pthread_mutex_lock(&f->mu);
    int c = 0;
    for (int i = 0; i < f->n; i++)
        if (strcmp(f->names[i], host) == 0) c = f->counts[i];
    pthread_mutex_unlock(&f->mu);
    return c;
}

static bool starts(const char *h, const char *p) { return strncmp(h, p, strlen(p)) == 0; }

/* returns response length, 0 = no answer */
static size_t fake_answer(fake_t *f, const uint8_t *q, size_t ql, uint8_t *out, bool tcp) {
    dns_query_t pq;
    if (dns_parse_query(q, ql, &pq) != DNS_PARSE_OK) return 0;
    fake_count(f, pq.host);
    if (starts(pq.host, "drop.")) return 0;
    if (starts(pq.host, "slow.")) usleep(300000);
    dns_buf_t b = {out, 8192, 0, false};
    uint16_t an = 0, ns = 0;
    if (f->lower) dns_name_lower(pq.qname, pq.qname_len);
    if (starts(pq.host, "nx.")) {
        dns_resp_begin(&b, &pq, DNS_RC_NXDOMAIN, false);
        dns_resp_soa(&b, &pq, 300);
        ns = 1;
    } else if (starts(pq.host, "sf.") && f->servfail) {
        dns_resp_begin(&b, &pq, DNS_RC_SERVFAIL, false);
    } else if (starts(pq.host, "negcn.")) { /* NXDOMAIN after a short-lived CNAME */
        dns_resp_begin(&b, &pq, DNS_RC_NXDOMAIN, false);
        uint8_t tgt[64];
        int tl = fl_name_to_wire("gone.test", 9, tgt, sizeof(tgt));
        dns_resp_rr(&b, DNS_T_CNAME, 1, tgt, (uint16_t)tl);
        an = 1;
        dns_resp_soa(&b, &pq, 300);
        ns = 1;
    } else if (starts(pq.host, "chg.") && pq.qtype == DNS_T_A) {
        dns_resp_begin(&b, &pq, 0, false);
        dns_resp_rr(&b, DNS_T_A, f->changed ? 0 : 1, f->changed ? "\x02\x02\x02\x02" : "\x01\x01\x01\x01", 4);
        an = 1;
    } else if (starts(pq.host, "trunc.") && !tcp) {
        dns_resp_begin(&b, &pq, 0, false);
        dc_wbe16(out + 2, (uint16_t)(dc_be16(out + 2) | DNS_F_TC));
    } else if (starts(pq.host, "cname.")) {
        dns_resp_begin(&b, &pq, 0, false);
        uint8_t tgt[64];
        int tl = fl_name_to_wire("tracker.evil.test", 17, tgt, sizeof(tgt));
        dns_resp_rr(&b, DNS_T_CNAME, 300, tgt, (uint16_t)tl);
        uint8_t ip[4] = {10, 1, 1, 1};
        dns_resp_rr_named(&b, tgt, (size_t)tl, DNS_T_A, 300, ip, 4);
        an = 2;
    } else {
        dns_resp_begin(&b, &pq, 0, false);
        uint32_t ttl = starts(pq.host, "ttl1.") ? 1 : 300;
        if (pq.qtype == DNS_T_A) {
            uint8_t ip[4] = {1, 2, 3, 4};
            if (starts(pq.host, "ip.")) memcpy(ip, "\x06\x06\x06\x06", 4);
            if (starts(pq.host, "trunc.")) memcpy(ip, "\x0a\x09\x09\x09", 4);
            int cnt = starts(pq.host, "big.") ? 60 : 1;
            for (int i = 0; i < cnt; i++) {
                if (cnt > 1) ip[3] = (uint8_t)i;
                dns_resp_rr(&b, DNS_T_A, ttl, ip, 4);
                an++;
            }
        } else if (pq.qtype == DNS_T_AAAA) {
            uint8_t ip[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 1};
            dns_resp_rr(&b, DNS_T_AAAA, ttl, ip, 16);
            an = 1;
        } else {
            dns_resp_soa(&b, &pq, 300);
            ns = 1;
        }
    }
    uint16_t ar = 0;
    if (pq.has_edns) {
        dns_resp_opt(&b, 1232, pq.do_bit, 0);
        ar = 1;
    }
    return dns_resp_end(&b, an, ns, ar);
}

static void *fake_thread(void *arg) {
    fake_t *f = (fake_t *)arg;
    uint8_t q[4096], out[8192];
    while (!f->stop) {
        struct pollfd pf[2] = {{f->udp, POLLIN, 0}, {f->tcp, POLLIN, 0}};
        if (poll(pf, 2, 50) <= 0) continue;
        if (pf[0].revents & POLLIN) {
            struct sockaddr_storage sa;
            socklen_t sl = sizeof(sa);
            ssize_t n = recvfrom(f->udp, q, sizeof(q), 0, (struct sockaddr *)&sa, &sl);
            if (n > 0) {
                size_t r = fake_answer(f, q, (size_t)n, out, false);
                if (r) sendto(f->udp, out, r, 0, (struct sockaddr *)&sa, sl);
            }
        }
        if (pf[1].revents & POLLIN) {
            int c = accept(f->tcp, NULL, NULL);
            if (c >= 0) {
                uint8_t lb[2];
                if (recv(c, lb, 2, MSG_WAITALL) == 2) {
                    size_t l = dc_be16(lb);
                    if (recv(c, q, l, MSG_WAITALL) == (ssize_t)l) {
                        size_t r = fake_answer(f, q, l, out + 2, true);
                        dc_wbe16(out, (uint16_t)r);
                        if (r) send(c, out, r + 2, 0);
                    }
                }
                close(c);
            }
        }
    }
    return NULL;
}

static void fake_start(fake_t *f, pthread_t *th) {
    memset(f, 0, sizeof(*f));
    pthread_mutex_init(&f->mu, NULL);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int tries = 0; tries < 50; tries++) {
        f->udp = socket(AF_INET, SOCK_DGRAM, 0);
        f->tcp = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(f->tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sa.sin_port = 0;
        bind(f->udp, (struct sockaddr *)&sa, sizeof(sa));
        socklen_t sl = sizeof(sa);
        getsockname(f->udp, (struct sockaddr *)&sa, &sl);
        if (bind(f->tcp, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(f->tcp, 16) == 0) break;
        close(f->udp);
        close(f->tcp);
    }
    f->port = ntohs(sa.sin_port);
    pthread_create(th, NULL, fake_thread, f);
}

/* ---- server tests ------------------------------------------------------------------------ */

static uint16_t g_port;

static size_t udp_ask(const uint8_t *q, size_t ql, uint8_t *resp, size_t cap) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(g_port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sendto(fd, q, ql, 0, (struct sockaddr *)&sa, sizeof(sa));
    ssize_t n = recv(fd, resp, cap, 0);
    close(fd);
    return n > 0 ? (size_t)n : 0;
}

static size_t tcp_ask(const uint8_t *q, size_t ql, uint8_t *resp, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(g_port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return 0;
    }
    uint8_t b[600];
    dc_wbe16(b, (uint16_t)ql);
    memcpy(b + 2, q, ql);
    send(fd, b, ql + 2, 0);
    uint8_t lb[2];
    size_t n = 0;
    if (recv(fd, lb, 2, MSG_WAITALL) == 2) {
        n = dc_be16(lb);
        if (n > cap || recv(fd, resp, n, MSG_WAITALL) != (ssize_t)n) n = 0;
    }
    close(fd);
    return n;
}

/* asks over UDP and returns the summary */
static char g_sum[4096];
static uint8_t g_resp[65536];
static size_t g_rlen;
static const char *ask(const char *name, uint16_t qt) {
    uint8_t q[512];
    size_t ql = mkq(q, (uint16_t)(rand() & 0xFFFF), name, qt, 0, false);
    g_rlen = udp_ask(q, ql, g_resp, sizeof(g_resp));
    if (!g_rlen) return "TIMEOUT";
    summarize(g_resp, g_rlen, g_sum, sizeof(g_sum));
    return g_sum;
}

#define EXPECT(name, qt, want)                                                                            \
    do {                                                                                                  \
        const char *got_ = ask(name, qt);                                                                 \
        CHECK(strcmp(got_, want) == 0, "%s q%u: got '%s' want '%s'", name, (unsigned)(qt), got_, want);   \
    } while (0)

static dns_config_t base_cfg(uint16_t up_port) {
    dns_config_t c;
    dns_config_defaults(&c);
    c.port = g_port;
    c.listen_v6 = false;
    snprintf(c.bind_v4, sizeof(c.bind_v4), "127.0.0.1");
    c.nup = 0;
    char u[64];
    snprintf(u, sizeof(u), "127.0.0.1:%u", up_port);
    const char *err;
    dns_upstream_parse(u, &c.up[c.nup++], &err);
    c.up_timeout_ms = 300;
    c.query_timeout_ms = 900;
    c.cache_bytes = 1 << 20;
    c.qlog_entries = 100;
    return c;
}

static void test_server(void) {
    fake_t f;
    pthread_t fth;
    fake_start(&f, &fth);
    g_port = (uint16_t)(20000 + (getpid() % 20000));
    dns_config_t cfg = base_cfg(f.port);
    dns_server_t *s = dns_server_new(&cfg);
    CHECK(s != NULL, "new");
    if (dns_server_start(s) != 0) {
        CHECK(0, "start failed (port %u)", g_port);
        return;
    }
    fl_set_t *set = mkset("||ads.test^\n"
                          "@@||ok.ads.test^\n"
                          "127.0.0.2 hosts.test\n"
                          "||rw.test^$dnsrewrite=NOERROR;A;5.5.5.5\n"
                          "||rwnx.test^$dnsrewrite=NXDOMAIN\n"
                          "||alias.test^$dnsrewrite=target.test\n"
                          "||evil.test^\n"
                          "||6.6.6.6^\n"
                          "||kid.test^$client=127.0.0.1\n");
    dns_server_set_filters(s, set);
    fl_set_unref(set);

    dns_local_t *l = dns_local_new();
    const char *err;
    dns_local_add(l, "nas.home", "A", 60, "192.168.1.5", &err);
    dns_local_add(l, "*.lan", "A", 60, "10.0.0.1", &err);
    dns_local_add(l, "pass.home", "AAAA", 60, "-", &err);
    dns_local_add(l, "pass.home", "A", 60, "192.168.1.7", &err);
    dns_local_add(l, "alias.home", "CNAME", 60, "nas.home", &err);
    dns_local_add(l, "ext.home", "CNAME", 60, "example.test", &err);
    dns_server_set_local(s, l);

    /* forwarding + cache + case */
    EXPECT("example.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
    EXPECT("Example.TEST", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
    CHECK(g_rlen > 13 && g_resp[13] == 'E' && g_resp[21] == 'T', "question case restored");
    CHECK(fake_get(&f, "example.test") == 1, "cached (upstream saw %d)", fake_get(&f, "example.test"));
    EXPECT("example.test", DNS_T_AAAA, "rc=0 tc=0 an=[AAAA 2001:db8::1] ns=0 ar=0");
    EXPECT("example.test", DNS_T_TXT, "rc=0 tc=0 an=[] ns=1 ar=0");

    /* blocking (default mode) */
    EXPECT("ads.test", DNS_T_A, "rc=0 tc=0 an=[A 0.0.0.0] ns=0 ar=0");
    EXPECT("sub.ads.test", DNS_T_AAAA, "rc=0 tc=0 an=[AAAA ::] ns=0 ar=0");
    EXPECT("ads.test", DNS_T_TXT, "rc=0 tc=0 an=[] ns=1 ar=0");
    CHECK(first_ttl(g_resp, g_rlen) == 10, "blocked ttl");
    EXPECT("ok.ads.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
    EXPECT("hosts.test", DNS_T_A, "rc=0 tc=0 an=[A 127.0.0.2] ns=0 ar=0");
    EXPECT("hosts.test", DNS_T_AAAA, "rc=0 tc=0 an=[AAAA ::] ns=0 ar=0");
    CHECK(fake_get(&f, "ads.test") == 0, "blocked never forwarded");

    /* rewrites */
    EXPECT("rw.test", DNS_T_A, "rc=0 tc=0 an=[A 5.5.5.5] ns=0 ar=0");
    EXPECT("rw.test", DNS_T_AAAA, "rc=0 tc=0 an=[] ns=0 ar=0");
    EXPECT("rwnx.test", DNS_T_A, "rc=3 tc=0 an=[] ns=0 ar=0");
    EXPECT("alias.test", DNS_T_A, "rc=0 tc=0 an=[CNAME target.test,A 1.2.3.4] ns=0 ar=0");
    EXPECT("alias.test", DNS_T_A, "rc=0 tc=0 an=[CNAME target.test,A 1.2.3.4] ns=0 ar=0");
    CHECK(fake_get(&f, "target.test") == 1 && fake_get(&f, "alias.test") == 0, "cname rewrite forwarded target");

    /* response filtering: CNAME target and answer IP */
    EXPECT("cname.test", DNS_T_A, "rc=0 tc=0 an=[A 0.0.0.0] ns=0 ar=0");
    EXPECT("cname.test", DNS_T_A, "rc=0 tc=0 an=[A 0.0.0.0] ns=0 ar=0");
    EXPECT("ip.test", DNS_T_A, "rc=0 tc=0 an=[A 0.0.0.0] ns=0 ar=0");
    CHECK(fake_get(&f, "cname.test") == 1, "resp-blocked answer cached");

    /* client-specific rule ($client=127.0.0.1 is skipped at compile time, never turned into global block) */
    EXPECT("kid.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
    {
        uint8_t q[512], out[DNS_QUERY_BUF];
        size_t ql = mkq(q, 77, "kid.test", DNS_T_A, 0, false);
        dns_peer_t peer;
        memset(&peer, 0, sizeof(peer));
        peer.transport = DNS_TR_INTERNAL;
        size_t n = dns_server_query(s, &peer, q, ql, out, sizeof(out));
        summarize(out, n, g_sum, sizeof(g_sum));
        CHECK(strcmp(g_sum, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0") == 0 && dc_be16(out) == 77, "internal: %s",
              g_sum);
    }

    /* local records */
    EXPECT("nas.home", DNS_T_A, "rc=0 tc=0 an=[A 192.168.1.5] ns=0 ar=0");
    EXPECT("nas.home", DNS_T_AAAA, "rc=0 tc=0 an=[] ns=1 ar=0");
    EXPECT("printer.lan", DNS_T_A, "rc=0 tc=0 an=[A 10.0.0.1] ns=0 ar=0");
    EXPECT("pass.home", DNS_T_A, "rc=0 tc=0 an=[A 192.168.1.7] ns=0 ar=0");
    EXPECT("pass.home", DNS_T_AAAA, "rc=0 tc=0 an=[AAAA 2001:db8::1] ns=0 ar=0");
    EXPECT("alias.home", DNS_T_A, "rc=0 tc=0 an=[CNAME nas.home,A 192.168.1.5] ns=0 ar=0");
    EXPECT("ext.home", DNS_T_A, "rc=0 tc=0 an=[CNAME example.test,A 1.2.3.4] ns=0 ar=0");
    CHECK(first_ttl(g_resp, g_rlen) == 60, "local CNAME keeps its TTL (%u)", first_ttl(g_resp, g_rlen));

    /* a name too long to check in text form (binary labels) is refused, not forwarded */
    {
        uint8_t q[512];
        size_t o = 12;
        memset(q, 0, sizeof(q));
        dc_wbe16(q, 4242);
        dc_wbe16(q + 2, DNS_F_RD);
        dc_wbe16(q + 4, 1);
        for (int k = 0; k < 3; k++) {
            q[o++] = 63;
            memset(q + o, 0xFF, 63);
            o += 63;
        }
        memcpy(q + o, "\x03" "ads" "\x04" "test", 10); /* (with the root label) */
        o += 10;
        dc_wbe16(q + o, DNS_T_A);
        dc_wbe16(q + o + 2, DNS_C_IN);
        g_rlen = udp_ask(q, o + 4, g_resp, sizeof(g_resp));
        CHECK(g_rlen >= 12 && (g_resp[3] & 0xF) == DNS_RC_REFUSED, "unfilterable name refused (len %zu rc %d)",
              g_rlen, g_rlen >= 4 ? g_resp[3] & 0xF : -1);
    }

    /* negative answer after a CNAME: cached no longer than the CNAME's TTL */
    EXPECT("negcn.test", DNS_T_A, "rc=3 tc=0 an=[CNAME gone.test] ns=1 ar=0");
    usleep(2100000);
    EXPECT("negcn.test", DNS_T_A, "rc=3 tc=0 an=[CNAME gone.test] ns=1 ar=0");
    CHECK(fake_get(&f, "negcn.test") == 2, "negative TTL = min(CNAME, SOA) (%d)", fake_get(&f, "negcn.test"));

    /* negative caching */
    EXPECT("nx.test", DNS_T_A, "rc=3 tc=0 an=[] ns=1 ar=0");
    EXPECT("nx.test", DNS_T_A, "rc=3 tc=0 an=[] ns=1 ar=0");
    CHECK(fake_get(&f, "nx.test") == 1, "nxdomain cached");

    /* truncation for UDP clients, full answer over TCP / large EDNS */
    EXPECT("big.test", DNS_T_A, "rc=0 tc=1 an=[] ns=0 ar=0");
    {
        uint8_t q[512];
        size_t ql = mkq(q, 9, "big.test", DNS_T_A, 4096, false);
        size_t n = udp_ask(q, ql, g_resp, sizeof(g_resp));
        dns_resp_t r;
        CHECK(n && dns_parse_response(g_resp, n, &r) == 0 && r.ancount == 60 && r.has_opt, "edns big");
        n = tcp_ask(q, ql, g_resp, sizeof(g_resp));
        CHECK(n && dns_parse_response(g_resp, n, &r) == 0 && r.ancount == 60, "tcp big");
        ql = mkq(q, 10, "big.test", DNS_T_A, 0, false);
        n = tcp_ask(q, ql, g_resp, sizeof(g_resp));
        CHECK(n && dns_parse_response(g_resp, n, &r) == 0 && r.ancount == 60 && !r.has_opt, "tcp no edns");
    }

    /* upstream truncated -> TCP retry */
    EXPECT("trunc.test", DNS_T_A, "rc=0 tc=0 an=[A 10.9.9.9] ns=0 ar=0");
    CHECK(fake_get(&f, "trunc.test") == 2, "udp+tcp (%d)", fake_get(&f, "trunc.test"));

    /* EDNS echo: DO bit and our payload size */
    {
        uint8_t q[512];
        size_t ql = mkq(q, 11, "example.test", DNS_T_A, 1400, true);
        size_t n = udp_ask(q, ql, g_resp, sizeof(g_resp));
        dns_resp_t r;
        CHECK(n && dns_parse_response(g_resp, n, &r) == 0 && r.has_opt &&
                  (dc_be32(g_resp + r.opt_off + 5) & 0x8000) && dc_be16(g_resp + r.opt_off + 3) == DNS_EDNS_UDP,
              "edns do");
    }

    /* ANY refused */
    EXPECT("example.test", DNS_T_ANY, "rc=4 tc=0 an=[] ns=0 ar=0");

    /* timeout -> SERVFAIL */
    EXPECT("drop.test", DNS_T_A, "rc=2 tc=0 an=[] ns=0 ar=0");
    CHECK(fake_get(&f, "drop.test") >= 2, "retried (%d)", fake_get(&f, "drop.test"));

    /* coalescing: concurrent identical questions -> one upstream query */
    {
        int fds[20];
        uint8_t q[512];
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(g_port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        for (int i = 0; i < 20; i++) {
            fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
            struct timeval tv = {3, 0};
            setsockopt(fds[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            size_t ql = mkq(q, (uint16_t)(100 + i), "slow.test", DNS_T_A, 0, false);
            sendto(fds[i], q, ql, 0, (struct sockaddr *)&sa, sizeof(sa));
        }
        int ok = 0;
        for (int i = 0; i < 20; i++) {
            uint8_t r[512];
            ssize_t n = recv(fds[i], r, sizeof(r), 0);
            if (n > 12 && dc_be16(r) == 100 + i && (r[3] & 0xF) == 0) ok++;
            close(fds[i]);
        }
        CHECK(ok == 20, "coalesced answers %d", ok);
        CHECK(fake_get(&f, "slow.test") == 1, "one upstream query (%d)", fake_get(&f, "slow.test"));
    }

    /* blocking modes */
    {
        dns_config_t c2 = cfg;
        c2.block_mode = DNS_BLOCK_NXDOMAIN;
        dns_server_reconfigure(s, &c2);
        EXPECT("ads.test", DNS_T_A, "rc=3 tc=0 an=[] ns=1 ar=0");
        CHECK(first_ttl(g_resp, g_rlen) == 10, "blocked SOA ttl");
        c2.blocked_ttl = 0;
        dns_server_reconfigure(s, &c2);
        EXPECT("ads.test", DNS_T_A, "rc=3 tc=0 an=[] ns=1 ar=0");
        CHECK(first_ttl(g_resp, g_rlen) == 0, "blocked TTL 0 stays 0 (%u)", first_ttl(g_resp, g_rlen));
        c2.blocked_ttl = cfg.blocked_ttl;
        c2.block_mode = DNS_BLOCK_REFUSED;
        dns_server_reconfigure(s, &c2);
        EXPECT("ads.test", DNS_T_A, "rc=5 tc=0 an=[] ns=0 ar=0");
        c2.block_mode = DNS_BLOCK_CUSTOM_IP;
        dc_ip_parse_z("192.0.2.1", &c2.custom_v4);
        dns_server_reconfigure(s, &c2);
        EXPECT("ads.test", DNS_T_A, "rc=0 tc=0 an=[A 192.0.2.1] ns=0 ar=0");
        EXPECT("ads.test", DNS_T_AAAA, "rc=0 tc=0 an=[] ns=0 ar=0");
        c2.block_mode = DNS_BLOCK_NULL_IP;
        dns_server_reconfigure(s, &c2);
        EXPECT("ads.test", DNS_T_TXT, "rc=0 tc=0 an=[] ns=0 ar=0");
        EXPECT("hosts.test", DNS_T_A, "rc=0 tc=0 an=[A 0.0.0.0] ns=0 ar=0");
        /* protection off: rewrites still apply, blocking does not */
        c2.block_mode = DNS_BLOCK_DEFAULT;
        c2.protection = false;
        dns_server_reconfigure(s, &c2);
        EXPECT("ads.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
        EXPECT("rw.test", DNS_T_A, "rc=0 tc=0 an=[A 5.5.5.5] ns=0 ar=0");
        EXPECT("cname.test", DNS_T_A, "rc=0 tc=0 an=[CNAME tracker.evil.test,A 10.1.1.1] ns=0 ar=0");
        dns_server_reconfigure(s, &cfg);
    }

    /* setup hotspot (captive portal) mode */
    {
        dc_ip_t ip;
        dc_prefix_t net;
        dc_ip_parse_z("192.168.4.1", &ip);
        dc_prefix_parse("127.0.0.0/8", 11, &net);
        dns_server_set_captive(s, &ip, &net);
        EXPECT("connectivitycheck.gstatic.com", DNS_T_A, "rc=0 tc=0 an=[A 192.168.4.1] ns=0 ar=0");
        EXPECT("ads.test", DNS_T_A, "rc=0 tc=0 an=[A 192.168.4.1] ns=0 ar=0");
        EXPECT("captive.apple.com", DNS_T_AAAA, "rc=0 tc=0 an=[] ns=0 ar=0");
        CHECK(fake_get(&f, "connectivitycheck.gstatic.com") == 0, "captive answers are local");
        dc_prefix_parse("10.0.0.0/8", 10, &net); /* other networks are served normally */
        dns_server_set_captive(s, &ip, &net);
        EXPECT("example.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
        dns_server_set_captive(s, NULL, NULL);
        EXPECT("ads.test", DNS_T_A, "rc=0 tc=0 an=[A 0.0.0.0] ns=0 ar=0");
    }

    /* optimistic cache */
    {
        dns_config_t c3 = cfg;
        c3.optimistic = true;
        dns_server_reconfigure(s, &c3);
        EXPECT("ttl1.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
        usleep(2100000);
        EXPECT("ttl1.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
        CHECK(first_ttl(g_resp, g_rlen) == 30, "stale ttl %u", first_ttl(g_resp, g_rlen));
        usleep(200000);
        CHECK(fake_get(&f, "ttl1.test") == 2, "refreshed (%d)", fake_get(&f, "ttl1.test"));
        /* the record changes to TTL 0: the stale answer must not be served any more */
        EXPECT("chg.test", DNS_T_A, "rc=0 tc=0 an=[A 1.1.1.1] ns=0 ar=0");
        f.changed = 1;
        usleep(2100000);
        EXPECT("chg.test", DNS_T_A, "rc=0 tc=0 an=[A 1.1.1.1] ns=0 ar=0"); /* stale, refresh behind */
        usleep(200000);
        EXPECT("chg.test", DNS_T_A, "rc=0 tc=0 an=[A 2.2.2.2] ns=0 ar=0");
        dns_server_reconfigure(s, &cfg);
    }

    /* cache switched off at runtime */
    {
        dns_config_t c4 = cfg;
        c4.cache_bytes = 0;
        dns_server_reconfigure(s, &c4);
        EXPECT("nocache.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
        EXPECT("nocache.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
        CHECK(fake_get(&f, "nocache.test") == 2, "cache off (%d)", fake_get(&f, "nocache.test"));
        dns_server_reconfigure(s, &cfg);
        EXPECT("nocache.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
        EXPECT("nocache.test", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
        CHECK(fake_get(&f, "nocache.test") == 3, "cache on again (%d)", fake_get(&f, "nocache.test"));
    }

    dns_stats_t st;
    dns_server_get_stats(s, &st);
    CHECK(st.queries > 40 && st.blocked > 5 && st.cached > 3 && st.forwarded > 5 && st.failed >= 1, "stats");
    CHECK(st.cached_us.count > 0 && st.forward_us.count > 0 && st.local_us.count > 0, "hist");
    dns_qlog_t ql[8];
    unsigned nq = dns_server_qlog(s, ql, 8);
    CHECK(nq == 8 && strcmp(ql[0].name, "nocache.test") == 0, "qlog %u %s", nq, nq ? ql[0].name : "");
    printf("  latency: local p50=%uus cached p50=%uus forward p50=%uus\n", dns_hist_percentile(&st.local_us, 50),
           dns_hist_percentile(&st.cached_us, 50), dns_hist_percentile(&st.forward_us, 50));

    dns_server_stop(s);
    f.stop = 1;
    pthread_join(fth, NULL);
    close(f.udp);
    close(f.tcp);
}

/* failover: first upstream is dead */
static void test_failover(void) {
    fake_t f;
    pthread_t fth;
    fake_start(&f, &fth);
    g_port++;
    int dead = socket(AF_INET, SOCK_DGRAM, 0); /* bound but never read */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(dead, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(dead, (struct sockaddr *)&sa, &sl);
    dns_config_t cfg = base_cfg(ntohs(sa.sin_port));
    char u[64];
    snprintf(u, sizeof(u), "127.0.0.1:%u", f.port);
    const char *err;
    dns_upstream_parse(u, &cfg.up[cfg.nup++], &err);
    cfg.cache_bytes = 0;
    cfg.query_timeout_ms = 2000;
    dns_server_t *s = dns_server_new(&cfg);
    if (dns_server_start(s) != 0) {
        CHECK(0, "start");
        return;
    }
    int ok = 0;
    for (int i = 0; i < 10; i++) {
        char name[32];
        snprintf(name, sizeof(name), "f%d.test", i);
        if (strcmp(ask(name, DNS_T_A), "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0") == 0) ok++;
    }
    CHECK(ok == 10, "failover answers %d", ok);
    dns_stats_t st;
    dns_server_get_stats(s, &st);
    CHECK(st.nup == 2 && st.up[1].ok >= 10, "good upstream used (%u)", st.up[1].ok);
    printf("  failover: dead sent=%u timeouts=%u healthy=%d; good ok=%u rtt=%uus\n", st.up[0].sent,
           st.up[0].timeouts, st.up[0].healthy, st.up[1].ok, st.up[1].rtt_us);
    dns_server_stop(s);
    close(dead);
    f.stop = 1;
    pthread_join(fth, NULL);
    close(f.udp);
    close(f.tcp);
}

/* SERVFAIL is retried on another upstream; an upstream that does not keep
 * the question's case (0x20) is detected and still used */
static void test_upstream_answers(void) {
    fake_t a, b;
    pthread_t ta, tb;
    fake_start(&a, &ta);
    fake_start(&b, &tb);
    a.servfail = 1;
    g_port++;
    dns_config_t cfg = base_cfg(a.port);
    char u[64];
    snprintf(u, sizeof(u), "127.0.0.1:%u", b.port);
    const char *err;
    dns_upstream_parse(u, &cfg.up[cfg.nup++], &err);
    cfg.cache_bytes = 0;
    cfg.strategy = DNS_STRAT_LOAD_BALANCE;
    dns_server_t *s = dns_server_new(&cfg);
    if (!s || dns_server_start(s) != 0) {
        CHECK(0, "start");
        return;
    }
    int ok = 0;
    for (int i = 0; i < 10; i++) {
        char name[32];
        snprintf(name, sizeof(name), "sf.n%d.test", i);
        if (strcmp(ask(name, DNS_T_A), "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0") == 0) ok++;
    }
    CHECK(ok == 10, "SERVFAIL retried elsewhere (%d)", ok);
    b.servfail = 1; /* both fail: the SERVFAIL is passed on */
    EXPECT("sf.both.test", DNS_T_A, "rc=2 tc=0 an=[] ns=0 ar=0");
    dns_server_stop(s);

    a.servfail = b.servfail = 0;
    a.lower = 1;
    g_port++;
    cfg = base_cfg(a.port);
    cfg.cache_bytes = 0;
    s = dns_server_new(&cfg);
    if (!s || dns_server_start(s) != 0) {
        CHECK(0, "start");
        return;
    }
    ok = 0;
    for (int i = 0; i < 8; i++) {
        char name[32];
        snprintf(name, sizeof(name), "CaseTest%d.example", i);
        if (strcmp(ask(name, DNS_T_A), "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0") == 0) ok++;
    }
    CHECK(ok >= 4, "case-changing upstream usable after detection (%d)", ok);
    EXPECT("aftercase.example", DNS_T_A, "rc=0 tc=0 an=[A 1.2.3.4] ns=0 ar=0");
    dns_server_stop(s);
    a.stop = b.stop = 1;
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    close(a.udp);
    close(a.tcp);
    close(b.udp);
    close(b.tcp);
}

/* a refusing TCP upstream: failures are counted once and retried with a
 * delay; stopping the server with an idle TCP client returns at once */
static void test_stream_failure_and_stop(void) {
    int closed = socket(AF_INET, SOCK_STREAM, 0); /* bound, never listening: connections are refused */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(closed, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(closed, (struct sockaddr *)&sa, &sl);
    g_port++;
    dns_config_t cfg = base_cfg(1);
    char u[64];
    snprintf(u, sizeof(u), "tcp://127.0.0.1:%u", ntohs(sa.sin_port));
    const char *err;
    cfg.nup = 0;
    dns_upstream_parse(u, &cfg.up[cfg.nup++], &err);
    cfg.cache_bytes = 0;
    dns_server_t *s = dns_server_new(&cfg);
    if (!s || dns_server_start(s) != 0) {
        CHECK(0, "start");
        return;
    }
    EXPECT("refused.test", DNS_T_A, "rc=2 tc=0 an=[] ns=0 ar=0");
    dns_stats_t st;
    dns_server_get_stats(s, &st);
    CHECK(st.up[0].sent >= 2 && st.up[0].sent <= 5, "retries bounded (%u)", st.up[0].sent);
    CHECK(st.up[0].errors + st.up[0].timeouts == st.up[0].sent, "each attempt counted once (%u+%u of %u)",
          st.up[0].errors, st.up[0].timeouts, st.up[0].sent);

    int c = socket(AF_INET, SOCK_STREAM, 0); /* idle client connection */
    struct sockaddr_in ca;
    memset(&ca, 0, sizeof(ca));
    ca.sin_family = AF_INET;
    ca.sin_port = htons(g_port);
    ca.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(connect(c, (struct sockaddr *)&ca, sizeof(ca)) == 0, "tcp connect");
    usleep(100000);
    uint64_t t0 = dc_time_ms();
    dns_server_stop(s);
    CHECK(dc_time_ms() - t0 < 2000, "stop with an idle TCP client (%u ms)", (unsigned)(dc_time_ms() - t0));
    close(c);
    close(closed);
}

int main(void) {
    srand((unsigned)getpid());
    test_wire();
    test_upstream_parse();
    test_local();
    test_cache();
    test_hist();
    test_server();
    test_failover();
    test_upstream_answers();
    test_stream_failure_and_stop();
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
