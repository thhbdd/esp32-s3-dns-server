/*
 * dnsbench - DNS performance tester for Linux (no dependencies).
 *
 * Measures throughput and latency of a DNS server (e.g. the ESP32-S3 DNS
 * server) by sending many queries over UDP or TCP.
 *
 *   closed loop (max throughput):  dnsbench -s 192.168.1.53 -c 64 -d 10
 *   open loop (latency at a rate): dnsbench -s 192.168.1.53 -r 2000 -d 30
 *   cache-hit path:                dnsbench -s 192.168.1.53 --scenario cache
 *   cache-miss / upstream path:    dnsbench -s 192.168.1.53 --scenario miss -r 300
 *   own query list:                dnsbench -s 192.168.1.53 -f names.txt
 *   fake upstream for the device:  dnsbench --responder 0.0.0.0:5300 --delay 2
 *
 * Build: cc -O2 -pthread -o dnsbench dnsbench.c -lm
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define VERSION "1.0"
#define MAX_THREADS 64
#define MAX_TCP_CONNS 16
#define IDS 65536

/* ---- utilities ------------------------------------------------------------------- */

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static inline uint64_t rng_next(uint64_t *s) { /* xorshift64* */
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static uint32_t fnv(const uint8_t *p, size_t n) {
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x01000193u;
    return h;
}

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline void wbe16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void die(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));
#include <stdarg.h>
static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "dnsbench: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(2);
}

/* a whole-number option within [lo, hi] */
static long num_arg(const char *s, long lo, long hi, const char *what) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < lo || v > hi) die("%s: expected a number %ld..%ld, got '%s'", what, lo, hi, s);
    return v;
}

/* presentation name -> wire (lowercase not enforced).  Returns length or -1. */
static int name_to_wire(const char *s, uint8_t *out, size_t cap) {
    size_t o = 0, n = strlen(s);
    if (n && s[n - 1] == '.') n--;
    if (!n) {
        out[0] = 0;
        return 1;
    }
    size_t i = 0;
    while (i <= n) {
        size_t start = i;
        while (i < n && s[i] != '.') i++;
        size_t l = i - start;
        if (!l || l > 63 || o + 1 + l + 1 > cap || o + 1 + l + 1 > 255) return -1;
        out[o++] = (uint8_t)l;
        memcpy(out + o, s + start, l);
        o += l;
        i++;
    }
    out[o++] = 0;
    return (int)o;
}

static const struct {
    const char *n;
    uint16_t t;
} g_types[] = {{"A", 1},     {"NS", 2},     {"CNAME", 5},  {"SOA", 6},   {"PTR", 12}, {"MX", 15},
               {"TXT", 16},  {"AAAA", 28},  {"SRV", 33},   {"DS", 43},   {"DNSKEY", 48},
               {"SVCB", 64}, {"HTTPS", 65}, {"ANY", 255}, {"CAA", 257}};

static uint16_t type_code(const char *s) {
    for (size_t i = 0; i < sizeof(g_types) / sizeof(g_types[0]); i++)
        if (strcasecmp(s, g_types[i].n) == 0) return g_types[i].t;
    if (strncasecmp(s, "TYPE", 4) == 0) return (uint16_t)atoi(s + 4);
    return 0;
}

/* ---- latency histogram (microseconds, 32 buckets per octave) ------------------------ */

#define H_SUB 32
#define H_LIN 64 /* 0..63 us exact */
#define H_OCT 22 /* up to ~2^28 us */
#define H_N (H_LIN + H_OCT * H_SUB)

typedef struct {
    uint64_t b[H_N];
    uint64_t n, sum, min, max;
} hist_t;

static unsigned h_idx(uint64_t us) {
    if (us < H_LIN) return (unsigned)us;
    unsigned o = 63u - (unsigned)__builtin_clzll(us); /* >= 6 */
    unsigned sub = (unsigned)((us >> (o - 5)) & (H_SUB - 1));
    unsigned idx = H_LIN + (o - 6) * H_SUB + sub;
    return idx < H_N ? idx : H_N - 1;
}
static double h_val(unsigned idx) {
    if (idx < H_LIN) return idx;
    unsigned o = (idx - H_LIN) / H_SUB + 6, sub = (idx - H_LIN) % H_SUB;
    double lo = (double)((uint64_t)(H_SUB + sub) << (o - 5));
    return lo + (double)(1ull << (o - 5)) / 2;
}
static void h_add(hist_t *h, uint64_t us) {
    h->b[h_idx(us)]++;
    if (!h->n || us < h->min) h->min = us;
    if (us > h->max) h->max = us;
    h->n++;
    h->sum += us;
}
static void h_merge(hist_t *d, const hist_t *s) {
    for (unsigned i = 0; i < H_N; i++) d->b[i] += s->b[i];
    if (s->n && (!d->n || s->min < d->min)) d->min = s->min;
    if (s->max > d->max) d->max = s->max;
    d->n += s->n;
    d->sum += s->sum;
}
static double h_pct(const hist_t *h, double pct) {
    if (!h->n) return 0;
    uint64_t want = (uint64_t)ceil((double)h->n * pct / 100.0), acc = 0;
    if (!want) want = 1;
    for (unsigned i = 0; i < H_N; i++) {
        acc += h->b[i];
        if (acc >= want) {
            double v = h_val(i);
            if (v < (double)h->min) v = (double)h->min;
            if (v > (double)h->max) v = (double)h->max;
            return v;
        }
    }
    return (double)h->max;
}

/* ---- configuration ------------------------------------------------------------------ */

typedef struct {
    uint8_t wire[256];
    uint8_t wlen;
    uint16_t qtype;
} qent_t;

enum { SC_LIST = 0, SC_CACHE, SC_MISS, SC_MIXED };

static struct {
    struct sockaddr_storage sa;
    socklen_t salen;
    char server_text[300];
    int conc, threads, duration_s, interval_s, timeout_ms, warmup;
    double rate;
    uint64_t count;
    bool tcp, edns, do_bit, no_rd, json, quiet, random_order, histogram;
    uint16_t edns_size;
    int scenario;
    char domain[200];
    uint8_t dom_wire[256];
    int dom_wlen;
    int miss_pct;
    qent_t *list;
    size_t nlist;
    struct {
        uint16_t t;
        unsigned w;
    } mix[16];
    unsigned nmix, mix_total;
    int tcp_conns;
    unsigned max_out;
} C;

static atomic_bool g_stop;
static void on_sig(int sig) {
    (void)sig;
    atomic_store(&g_stop, true);
}

/* popular names (cache scenario / defaults) */
static const char *g_popular[] = {
    "baidu.com", "www.baidu.com", "qq.com", "www.qq.com", "weixin.qq.com", "taobao.com", "www.taobao.com",
    "tmall.com", "jd.com", "www.jd.com", "alipay.com", "aliyun.com", "bilibili.com", "www.bilibili.com",
    "zhihu.com", "www.zhihu.com", "weibo.com", "douyin.com", "163.com", "www.163.com", "126.com", "sina.com.cn",
    "sohu.com", "csdn.net", "ctrip.com", "meituan.com", "pinduoduo.com", "xiaomi.com", "mi.com", "huawei.com",
    "vivo.com.cn", "oppo.com", "iqiyi.com", "youku.com", "kuaishou.com", "toutiao.com", "360.cn", "so.com",
    "bing.com", "www.bing.com", "microsoft.com", "www.microsoft.com", "apple.com", "www.apple.com",
    "icloud.com", "github.com", "api.github.com", "raw.githubusercontent.com", "gitee.com", "google.com",
    "www.google.com", "youtube.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "wikipedia.org",
    "en.wikipedia.org", "amazon.com", "www.amazon.com", "netflix.com", "cloudflare.com", "one.one.one.one",
    "dns.google", "openai.com", "stackoverflow.com", "reddit.com", "linkedin.com", "yahoo.com", "office.com",
    "outlook.com", "live.com", "msn.com", "steamcommunity.com", "store.steampowered.com", "epicgames.com",
    "nvidia.com", "intel.com", "amd.com", "adobe.com", "zoom.us", "dropbox.com", "spotify.com", "tiktok.com",
    "whatsapp.com", "telegram.org", "speedtest.net", "fast.com", "ntp.aliyun.com", "time.windows.com",
    "connectivitycheck.gstatic.com", "captive.apple.com", "www.msftconnecttest.com", "ubuntu.com",
    "archive.ubuntu.com", "debian.org", "mirrors.aliyun.com", "mirrors.tuna.tsinghua.edu.cn", "pypi.org",
    "registry.npmjs.org", "docker.io", "registry-1.docker.io", "espressif.com", "dl.espressif.com"};

static void add_name(qent_t **arr, size_t *n, size_t *cap, const char *name, uint16_t t) {
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 256;
        *arr = (qent_t *)realloc(*arr, *cap * sizeof(qent_t));
        if (!*arr) die("out of memory");
    }
    qent_t *e = &(*arr)[*n];
    int l = name_to_wire(name, e->wire, sizeof(e->wire));
    if (l < 0) {
        fprintf(stderr, "dnsbench: skipping invalid name '%s'\n", name);
        return;
    }
    e->wlen = (uint8_t)l;
    e->qtype = t;
    (*n)++;
}

static void load_file(const char *path) {
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) die("cannot open %s: %s", path, strerror(errno));
    char line[1024];
    size_t cap = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == '\n' || *p == '\r') continue;
        char name[512], type[32] = "";
        int k = sscanf(p, "%511s %31s", name, type);
        if (k < 1) continue;
        uint16_t t = 0;
        if (k == 2) t = type_code(type);
        add_name(&C.list, &C.nlist, &cap, name, t); /* t = 0: use -t / --mix */
    }
    if (f != stdin) fclose(f);
    if (!C.nlist) die("no names in %s", path);
}

/* ---- query building / parsing -------------------------------------------------------- */

static uint16_t pick_type(uint64_t *rng, uint16_t fixed) {
    if (fixed) return fixed;
    if (C.nmix == 1) return C.mix[0].t;
    unsigned r = (unsigned)(rng_next(rng) % C.mix_total);
    for (unsigned i = 0; i < C.nmix; i++) {
        if (r < C.mix[i].w) return C.mix[i].t;
        r -= C.mix[i].w;
    }
    return C.mix[0].t;
}

/* builds the next query; returns its length */
static size_t build_query(uint8_t *b, uint16_t id, uint64_t *rng, uint64_t *seq, bool list_only, size_t *qend) {
    const uint8_t *wire;
    size_t wl;
    uint16_t t;
    uint8_t tmp[256];
    bool miss = !list_only && (C.scenario == SC_MISS ||
                               (C.scenario == SC_MIXED && (int)(rng_next(rng) % 100) < C.miss_pct));
    if (miss) {
        static const char al[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        uint64_t r = rng_next(rng);
        tmp[0] = 10;
        for (int i = 0; i < 10; i++) {
            tmp[1 + i] = (uint8_t)al[r % 36];
            r /= 36;
            if (i == 5) r = rng_next(rng);
        }
        memcpy(tmp + 11, C.dom_wire, (size_t)C.dom_wlen);
        wire = tmp;
        wl = 11 + (size_t)C.dom_wlen;
        t = pick_type(rng, 0);
    } else {
        size_t i = C.random_order ? (size_t)(rng_next(rng) % C.nlist) : (size_t)((*seq)++ % C.nlist);
        wire = C.list[i].wire;
        wl = C.list[i].wlen;
        t = pick_type(rng, C.list[i].qtype);
    }
    wbe16(b, id);
    wbe16(b + 2, C.no_rd ? 0 : 0x0100);
    wbe16(b + 4, 1);
    wbe16(b + 6, 0);
    wbe16(b + 8, 0);
    wbe16(b + 10, C.edns ? 1 : 0);
    memcpy(b + 12, wire, wl);
    size_t o = 12 + wl;
    wbe16(b + o, t);
    wbe16(b + o + 2, 1);
    o += 4;
    *qend = o;
    if (C.edns) {
        b[o] = 0;
        wbe16(b + o + 1, 41);
        wbe16(b + o + 3, C.edns_size);
        b[o + 5] = 0;
        b[o + 6] = 0;
        b[o + 7] = C.do_bit ? 0x80 : 0;
        b[o + 8] = 0;
        wbe16(b + o + 9, 0);
        o += 11;
    }
    return o;
}

/* question section end offset, or 0 */
static size_t question_end(const uint8_t *m, size_t n) {
    size_t p = 12;
    while (p < n) {
        uint8_t l = m[p];
        if (l == 0) {
            p++;
            return p + 4 <= n ? p + 4 : 0;
        }
        if (l & 0xC0) return 0;
        p += 1 + (size_t)l;
    }
    return 0;
}

/* ---- per-thread state ------------------------------------------------------------------- */

typedef struct {
    int idx;
    pthread_t th;
    uint64_t rng, seq;
    /* outstanding queries by ID */
    uint64_t *sent;  /* send time (ns), 0 = free */
    uint32_t *qhash; /* question hash for validation */
    uint8_t *conn;   /* TCP connection index */
    uint16_t next_id;
    unsigned out, conc;
    double rate;
    uint64_t limit; /* max queries for this thread (0 = unlimited) */
    /* sockets */
    int fd;
    int tfd[MAX_TCP_CONNS];
    uint8_t *tbuf[MAX_TCP_CONNS];
    size_t tlen[MAX_TCP_CONNS];
    int ntcp;
    /* results */
    hist_t h;
    _Atomic uint64_t sent_n, recv_n, timeouts, lat_sum_us, errors;
    uint64_t rcode[6]; /* NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED; other in [5]+ */
    uint64_t rc_other, tc, empty, mismatched, reconnects;
    uint64_t unanswered; /* still in flight when the run ended (interrupted) */
    bool measuring;
    uint64_t t_end, t_last; /* end of the run, last answer */
} th_t;

static th_t *g_th;

static int open_udp(void) {
    int fd = socket(C.sa.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) die("socket: %s", strerror(errno));
    int sz = 8 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    if (connect(fd, (struct sockaddr *)&C.sa, C.salen) < 0) die("connect: %s", strerror(errno));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

static int open_tcp(void) {
    int fd = socket(C.sa.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&C.sa, C.salen) < 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

static void handle_resp(th_t *t, const uint8_t *m, size_t n, uint64_t now) {
    if (n < 12 || !(m[2] & 0x80)) return;
    uint16_t id = be16(m);
    if (!t->sent[id]) return; /* late (already timed out) or stray */
    size_t qe = question_end(m, n);
    if (!qe || be16(m + 4) != 1) return;
    uint32_t qh = 0x811c9dc5u;
    /* the server may echo the question in a different case: compare lowercase */
    for (size_t i = 12; i < qe; i++) {
        uint8_t c = m[i];
        if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
        qh = (qh ^ c) * 0x01000193u;
    }
    if (qh != t->qhash[id]) {
        t->mismatched++;
        return;
    }
    uint64_t us = (now - t->sent[id]) / 1000;
    t->sent[id] = 0;
    t->out--;
    if (!t->measuring) return;
    t->t_last = now;
    h_add(&t->h, us);
    atomic_fetch_add_explicit(&t->recv_n, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&t->lat_sum_us, us, memory_order_relaxed);
    unsigned rc = m[3] & 0xF;
    if (rc < 6)
        t->rcode[rc]++;
    else
        t->rc_other++;
    if (m[2] & 0x02) t->tc++;
    if (rc == 0 && be16(m + 6) == 0) t->empty++;
}

static void tcp_fail_conn(th_t *t, int ci);

static bool send_one(th_t *t, uint64_t now) {
    uint8_t q[512];
    if (t->out >= 65000) return false;
    uint16_t id = t->next_id;
    for (unsigned k = 0; t->sent[id]; k++) {
        if (k > 65535) return false;
        id++;
    }
    t->next_id = (uint16_t)(id + 1);
    size_t qe;
    size_t ql = build_query(q, id, &t->rng, &t->seq, !t->measuring, &qe);
    /* lowercase hash (responses are compared case-insensitively) */
    uint32_t h2 = 0x811c9dc5u;
    for (size_t i = 12; i < qe; i++) {
        uint8_t c = q[i];
        if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
        h2 = (h2 ^ c) * 0x01000193u;
    }
    if (C.tcp) {
        int ci = (int)(id % (unsigned)t->ntcp);
        if (t->tfd[ci] < 0) {
            t->tfd[ci] = open_tcp();
            t->reconnects++;
            if (t->tfd[ci] < 0) {
                atomic_fetch_add(&t->errors, 1);
                return false;
            }
        }
        uint8_t fb[520];
        wbe16(fb, (uint16_t)ql);
        memcpy(fb + 2, q, ql);
        ssize_t w = send(t->tfd[ci], fb, ql + 2, MSG_NOSIGNAL);
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return false; /* send buffer full: later */
        if (w != (ssize_t)(ql + 2)) { /* error, or half a frame: the stream is unusable */
            tcp_fail_conn(t, ci);
            atomic_fetch_add(&t->errors, 1);
            return false;
        }
        t->conn[id] = (uint8_t)ci;
    } else {
        ssize_t w = send(t->fd, q, ql, 0);
        if (w < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS && errno != ECONNREFUSED)
                atomic_fetch_add(&t->errors, 1);
            else if (errno == ECONNREFUSED)
                atomic_fetch_add(&t->errors, 1);
            return false;
        }
    }
    t->sent[id] = now ? now : 1;
    t->qhash[id] = h2;
    t->out++;
    if (t->measuring) atomic_fetch_add_explicit(&t->sent_n, 1, memory_order_relaxed);
    return true;
}

static void tcp_fail_conn(th_t *t, int ci) {
    close(t->tfd[ci]);
    t->tfd[ci] = -1;
    t->tlen[ci] = 0;
    for (unsigned id = 0; id < IDS; id++)
        if (t->sent[id] && t->conn[id] == ci) {
            t->sent[id] = 0;
            t->out--;
            if (t->measuring) atomic_fetch_add(&t->errors, 1);
        }
}

static void recv_all(th_t *t) {
    uint8_t buf[65536 + 2];
    uint64_t now = now_ns();
    if (!C.tcp) {
        for (int k = 0; k < 256; k++) {
            ssize_t n = recv(t->fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                if (n < 0 && errno == ECONNREFUSED) atomic_fetch_add(&t->errors, 1);
                break;
            }
            handle_resp(t, buf, (size_t)n, now);
        }
        return;
    }
    for (int ci = 0; ci < t->ntcp; ci++) {
        if (t->tfd[ci] < 0) continue;
        for (;;) {
            ssize_t n = recv(t->tfd[ci], t->tbuf[ci] + t->tlen[ci], 65536 + 2 - t->tlen[ci], 0);
            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                tcp_fail_conn(t, ci); /* server closed: outstanding queries are lost */
                break;
            }
            if (n < 0) break;
            t->tlen[ci] += (size_t)n;
            size_t p = 0;
            while (t->tlen[ci] - p >= 2) {
                size_t l = be16(t->tbuf[ci] + p);
                if (t->tlen[ci] - p < 2 + l) break;
                handle_resp(t, t->tbuf[ci] + p + 2, l, now);
                p += 2 + l;
            }
            memmove(t->tbuf[ci], t->tbuf[ci] + p, t->tlen[ci] - p);
            t->tlen[ci] -= p;
        }
    }
}

static void scan_timeouts(th_t *t, uint64_t now) {
    uint64_t lim = (uint64_t)C.timeout_ms * 1000000ull;
    if (!t->out) return;
    for (unsigned id = 0; id < IDS; id++)
        if (t->sent[id] && now - t->sent[id] > lim) {
            t->sent[id] = 0;
            t->out--;
            if (t->measuring) atomic_fetch_add_explicit(&t->timeouts, 1, memory_order_relaxed);
        }
}

static void wait_io(th_t *t, uint64_t max_wait_ns) {
    struct pollfd pf[MAX_TCP_CONNS + 1];
    int n = 0;
    if (C.tcp) {
        for (int ci = 0; ci < t->ntcp; ci++)
            if (t->tfd[ci] >= 0) {
                pf[n].fd = t->tfd[ci];
                pf[n].events = POLLIN;
                n++;
            }
    } else {
        pf[n].fd = t->fd;
        pf[n].events = POLLIN;
        n++;
    }
    struct timespec ts = {(time_t)(max_wait_ns / 1000000000ull), (long)(max_wait_ns % 1000000000ull)};
    if (n)
        ppoll(pf, (nfds_t)n, &ts, NULL);
    else
        nanosleep(&ts, NULL);
}

/* runs the load until `end` (ns) or the per-thread limit */
static void run_phase(th_t *t, uint64_t end, uint64_t limit, bool closed, unsigned conc, double rate) {
    uint64_t start = now_ns(), sent = 0, last_scan = start;
    double interval = rate > 0 ? 1e9 / rate : 0;
    double next = (double)start;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        uint64_t now = now_ns();
        bool done_sending = now >= end || (limit && sent >= limit);
        if (done_sending && !t->out) break;
        if (done_sending && now >= end + (uint64_t)C.timeout_ms * 1000000ull) break;
        if (!done_sending) {
            if (closed) {
                while (t->out < conc && (!limit || sent < limit) && send_one(t, now)) sent++;
            } else {
                while ((double)now >= next && (!limit || sent < limit) && t->out < C.max_out) {
                    if (send_one(t, now)) sent++;
                    next += interval;
                }
                if ((double)now - next > 1e9) next = (double)now; /* cannot keep up: no burst */
            }
        }
        recv_all(t);
        now = now_ns();
        if (now - last_scan > 50000000ull) {
            scan_timeouts(t, now);
            last_scan = now;
        }
        uint64_t wait = 1000000; /* 1 ms */
        if (!closed && !done_sending) {
            double d = next - (double)now;
            wait = d <= 0 ? 0 : (d < 1e6 ? (uint64_t)d : 1000000);
        }
        if (closed && !done_sending && t->out < conc) wait = 0;
        if (wait) wait_io(t, wait);
    }
    scan_timeouts(t, now_ns());
    if (t->measuring) t->unanswered += t->out; /* (interrupted runs) */
}

static void *thread_main(void *arg) {
    th_t *t = (th_t *)arg;
    if (!C.tcp) t->fd = open_udp();
    /* warm-up: every list name once (fills the server cache) */
    if (C.warmup) {
        t->measuring = false;
        uint64_t per = (C.nlist + (size_t)C.threads - 1) / (size_t)C.threads;
        t->seq = (uint64_t)t->idx * per;
        unsigned wc = t->conc ? (t->conc < 16 ? t->conc : 16) : 4; /* (open loop: conc is unused) */
        run_phase(t, now_ns() + 30ull * 1000000000ull, per, true, wc, 0);
        uint64_t wend = now_ns() + (uint64_t)C.timeout_ms * 1000000ull;
        while (t->out && now_ns() < wend) {
            recv_all(t);
            wait_io(t, 1000000);
        }
        scan_timeouts(t, UINT64_MAX / 2);
    }
    t->seq = (uint64_t)t->idx * 7919u;
    t->measuring = true;
    return NULL;
}

static _Atomic uint64_t g_t0;
static atomic_int g_done;
static pthread_barrier_t g_bar;

static void *thread_run(void *arg) {
    th_t *t = (th_t *)arg;
    thread_main(t);
    pthread_barrier_wait(&g_bar);
    if (t->idx == 0) atomic_store(&g_t0, now_ns());
    pthread_barrier_wait(&g_bar);
    uint64_t end = atomic_load(&g_t0) + (uint64_t)C.duration_s * 1000000000ull;
    if (C.count) end = UINT64_MAX / 2;
    run_phase(t, end, t->limit, C.rate <= 0, t->conc, t->rate);
    t->t_end = now_ns();
    atomic_fetch_add(&g_done, 1);
    return NULL;
}

/* ---- responder (fake upstream) ---------------------------------------------------------- */

static struct {
    int delay_ms, ttl, threads;
    struct sockaddr_storage sa;
    socklen_t salen;
    _Atomic uint64_t answered;
    int nx_pct;
} R;

typedef struct {
    uint64_t due;
    struct sockaddr_storage to;
    socklen_t tolen;
    uint16_t len;
    uint8_t msg[600];
} rq_t;

static size_t responder_answer(const uint8_t *q, size_t n, uint8_t *out, uint64_t *rng) {
    if (n < 12 || (q[2] & 0x80) || be16(q + 4) != 1) return 0;
    size_t qe = question_end(q, n);
    if (!qe || qe > 400) return 0;
    uint16_t qtype = be16(q + qe - 4);
    bool edns = be16(q + 10) >= 1;
    bool do_bit = false;
    if (edns && qe + 11 <= n && q[qe] == 0 && be16(q + qe + 1) == 41) do_bit = (q[qe + 7] & 0x80) != 0;
    memcpy(out, q, qe);
    bool nx = R.nx_pct && (int)(rng_next(rng) % 100) < R.nx_pct;
    out[2] = (uint8_t)(0x84 | (q[2] & 0x01)); /* QR AA RD */
    out[3] = (uint8_t)(0x80 | (nx ? 3 : 0));   /* RA */
    wbe16(out + 6, 0);
    wbe16(out + 8, 0);
    wbe16(out + 10, 0);
    size_t o = qe;
    uint32_t h = fnv(q + 12, qe - 12);
    if (!nx && (qtype == 1 || qtype == 28)) {
        out[o++] = 0xC0;
        out[o++] = 12;
        wbe16(out + o, qtype);
        wbe16(out + o + 2, 1);
        uint32_t ttl = (uint32_t)R.ttl;
        out[o + 4] = (uint8_t)(ttl >> 24);
        out[o + 5] = (uint8_t)(ttl >> 16);
        out[o + 6] = (uint8_t)(ttl >> 8);
        out[o + 7] = (uint8_t)ttl;
        o += 8;
        if (qtype == 1) {
            wbe16(out + o, 4);
            out[o + 2] = 198;
            out[o + 3] = (uint8_t)(18 + ((h >> 16) & 1));
            out[o + 4] = (uint8_t)(h >> 8);
            out[o + 5] = (uint8_t)(h | 1);
            o += 6;
        } else {
            wbe16(out + o, 16);
            static const uint8_t pfx[8] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0};
            memcpy(out + o + 2, pfx, 8);
            memcpy(out + o + 10, &h, 4);
            memset(out + o + 14, 0, 3);
            out[o + 17] = 1;
            o += 18;
        }
        wbe16(out + 6, 1);
    }
    if (edns) {
        out[o] = 0;
        wbe16(out + o + 1, 41);
        wbe16(out + o + 3, 1232);
        out[o + 5] = 0;
        out[o + 6] = 0;
        out[o + 7] = do_bit ? 0x80 : 0;
        out[o + 8] = 0;
        wbe16(out + o + 9, 0);
        o += 11;
        wbe16(out + 10, 1);
    }
    return o;
}

static void *responder_thread(void *arg) {
    (void)arg;
    int fd = socket(R.sa.ss_family, SOCK_DGRAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int sz = 8 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    if (bind(fd, (struct sockaddr *)&R.sa, R.salen) < 0) die("responder bind: %s", strerror(errno));
    uint64_t rng = now_ns() ^ (uint64_t)(uintptr_t)&fd;
    size_t qcap = 65536, qh = 0, qn = 0;
    rq_t *queue = R.delay_ms ? (rq_t *)calloc(qcap, sizeof(rq_t)) : NULL;
    if (R.delay_ms && !queue) die("out of memory");
    uint8_t in[4096];
    while (!atomic_load(&g_stop)) {
        int to = 100;
        uint64_t now = now_ns();
        while (qn && queue[qh].due <= now) {
            rq_t *e = &queue[qh];
            sendto(fd, e->msg, e->len, 0, (struct sockaddr *)&e->to, e->tolen);
            atomic_fetch_add_explicit(&R.answered, 1, memory_order_relaxed);
            qh = (qh + 1) % qcap;
            qn--;
        }
        if (qn) {
            uint64_t d = queue[qh].due - now;
            to = (int)(d / 1000000);
        }
        struct pollfd pf = {fd, POLLIN, 0};
        if (poll(&pf, 1, to) <= 0) continue;
        for (int k = 0; k < 256; k++) {
            struct sockaddr_storage from;
            socklen_t fl = sizeof(from);
            ssize_t n = recvfrom(fd, in, sizeof(in), MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
            if (n <= 0) break;
            if (R.delay_ms && qn < qcap) {
                rq_t *e = &queue[(qh + qn) % qcap];
                size_t l = responder_answer(in, (size_t)n, e->msg, &rng);
                if (!l) continue;
                e->len = (uint16_t)l;
                e->to = from;
                e->tolen = fl;
                e->due = now_ns() + (uint64_t)R.delay_ms * 1000000ull;
                qn++;
            } else if (!R.delay_ms) {
                uint8_t out[600];
                size_t l = responder_answer(in, (size_t)n, out, &rng);
                if (l) {
                    sendto(fd, out, l, 0, (struct sockaddr *)&from, fl);
                    atomic_fetch_add_explicit(&R.answered, 1, memory_order_relaxed);
                }
            }
        }
    }
    free(queue);
    close(fd);
    return NULL;
}

/* ---- address parsing ---------------------------------------------------------------- */

static void parse_addr(const char *s, uint16_t defport, struct sockaddr_storage *sa, socklen_t *sl, char *text,
                       size_t tcap) {
    char host[256] = "", port[16];
    snprintf(port, sizeof(port), "%u", defport);
    if (s[0] && strspn(s, "0123456789") == strlen(s)) { /* just a port: all addresses / this host */
        snprintf(port, sizeof(port), "%s", s);
    } else if (s[0] == '[') {
        const char *rb = strchr(s, ']');
        if (!rb) die("invalid address %s", s);
        snprintf(host, sizeof(host), "%.*s", (int)(rb - s - 1), s + 1);
        if (rb[1] == ':') snprintf(port, sizeof(port), "%s", rb + 2);
    } else {
        const char *c = strchr(s, ':');
        if (c && !strchr(c + 1, ':')) {
            snprintf(host, sizeof(host), "%.*s", (int)(c - s), s);
            snprintf(port, sizeof(port), "%s", c + 1);
        } else {
            snprintf(host, sizeof(host), "%s", s);
        }
    }
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    int e = getaddrinfo(host[0] ? host : NULL, port, &hints, &res);
    if (e) die("cannot resolve %s: %s", s, gai_strerror(e));
    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *sl = (socklen_t)res->ai_addrlen;
    char ip[INET6_ADDRSTRLEN];
    getnameinfo(res->ai_addr, res->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
    snprintf(text, tcap, sa->ss_family == AF_INET6 ? "[%s]:%s" : "%s:%s", ip, port);
    freeaddrinfo(res);
}

static int run_responder(const char *addr) {
    char text[300];
    parse_addr(addr, 5300, &R.sa, &R.salen, text, sizeof(text));
    if (R.threads < 1) R.threads = 2;
    if (R.threads > MAX_THREADS) R.threads = MAX_THREADS;
    if (R.ttl < 0) R.ttl = 300;
    printf("dnsbench responder on %s (udp), delay %d ms, ttl %d, %d threads, NXDOMAIN %d%%\n", text, R.delay_ms,
           R.ttl, R.threads, R.nx_pct);
    printf("answers: A -> 198.18.x.y / 198.19.x.y, AAAA -> 2001:db8::/32, other types -> NODATA\n");
    fflush(stdout);
    pthread_t th[MAX_THREADS];
    for (int i = 0; i < R.threads; i++) pthread_create(&th[i], NULL, responder_thread, NULL);
    uint64_t last = 0;
    while (!atomic_load(&g_stop)) {
        sleep(1);
        uint64_t a = atomic_load(&R.answered);
        if (a != last) printf("%" PRIu64 " answers/s (total %" PRIu64 ")\n", a - last, a);
        fflush(stdout);
        last = a;
    }
    for (int i = 0; i < R.threads; i++) pthread_join(th[i], NULL);
    return 0;
}

/* ---- single query (dig-like) ------------------------------------------------------------ */

static size_t read_name(const uint8_t *m, size_t n, size_t off, char *out, size_t cap, size_t *next) {
    size_t o = 0, p = off;
    int hops = 0;
    bool jumped = false;
    out[0] = 0;
    while (p < n) {
        uint8_t l = m[p];
        if ((l & 0xC0) == 0xC0) {
            if (p + 1 >= n || ++hops > 32) break;
            if (!jumped && next) *next = p + 2;
            jumped = true;
            p = (size_t)((l & 0x3F) << 8 | m[p + 1]);
            continue;
        }
        if (l == 0) {
            if (!jumped && next) *next = p + 1;
            if (!o && cap > 1) out[o++] = '.';
            out[o] = 0;
            return o;
        }
        if (p + 1 + l > n) break;
        for (unsigned i = 0; i < l && o + 5 < cap; i++) {
            uint8_t c = m[p + 1 + i];
            if (c > 32 && c < 127 && c != '.')
                out[o++] = (char)c;
            else
                o += (size_t)snprintf(out + o, cap - o, "\\%03u", c);
        }
        if (o + 2 < cap) out[o++] = '.';
        p += 1 + (size_t)l;
    }
    out[o] = 0;
    if (next && !jumped) *next = n;
    return o;
}

static const char *type_name(uint16_t t, char *buf) {
    for (size_t i = 0; i < sizeof(g_types) / sizeof(g_types[0]); i++)
        if (g_types[i].t == t) return g_types[i].n;
    if (t == 41) return "OPT";
    if (t == 46) return "RRSIG";
    sprintf(buf, "TYPE%u", t);
    return buf;
}

static int run_query(const char *name) {
    uint8_t q[512], r[65536];
    uint64_t rng = now_ns();
    qent_t e;
    int wl = name_to_wire(name, e.wire, sizeof(e.wire));
    if (wl < 0) die("invalid name %s", name);
    e.wlen = (uint8_t)wl;
    e.qtype = C.mix[0].t;
    C.list = &e;
    C.nlist = 1;
    C.scenario = SC_LIST;
    uint64_t seq = 0;
    size_t qe;
    uint16_t id = (uint16_t)rng_next(&rng);
    size_t ql = build_query(q, id, &rng, &seq, true, &qe);
    int fd = socket(C.sa.ss_family, C.tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    struct timeval tv = {C.timeout_ms / 1000, (C.timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr *)&C.sa, C.salen) < 0) die("connect: %s", strerror(errno));
    uint64_t t0 = now_ns();
    ssize_t n;
    if (C.tcp) {
        uint8_t fb[520];
        wbe16(fb, (uint16_t)ql);
        memcpy(fb + 2, q, ql);
        if (send(fd, fb, ql + 2, 0) != (ssize_t)(ql + 2)) die("send failed");
        uint8_t lb[2];
        if (recv(fd, lb, 2, MSG_WAITALL) != 2) die("no answer (timeout)");
        n = recv(fd, r, be16(lb), MSG_WAITALL);
    } else {
        send(fd, q, ql, 0);
        n = recv(fd, r, sizeof(r), 0);
    }
    uint64_t t1 = now_ns();
    close(fd);
    if (n < 12) die("no answer from %s (%s)", C.server_text, n < 0 ? strerror(errno) : "short");
    static const char *rcodes[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
    unsigned rc = r[3] & 0xF;
    printf(";; %s from %s in %.3f ms, id %u%s\n", rc < 6 ? rcodes[rc] : "RCODE?", C.server_text,
           (double)(t1 - t0) / 1e6, be16(r), be16(r) == id ? "" : " (ID MISMATCH)");
    printf(";; flags:%s%s%s%s%s%s%s  QUERY %u, ANSWER %u, AUTHORITY %u, ADDITIONAL %u\n", r[2] & 0x80 ? " qr" : "",
           r[2] & 0x04 ? " aa" : "", r[2] & 0x02 ? " tc" : "", r[2] & 0x01 ? " rd" : "", r[3] & 0x80 ? " ra" : "",
           r[3] & 0x20 ? " ad" : "", r[3] & 0x10 ? " cd" : "", be16(r + 4), be16(r + 6), be16(r + 8), be16(r + 10));
    size_t off = question_end(r, (size_t)n);
    if (!off) return 1;
    const char *sect[] = {"ANSWER", "AUTHORITY", "ADDITIONAL"};
    for (int sct = 0; sct < 3; sct++) {
        unsigned cnt = be16(r + 6 + 2 * sct);
        if (cnt) printf("\n;; %s SECTION:\n", sect[sct]);
        for (unsigned i = 0; i < cnt && off < (size_t)n; i++) {
            char owner[1100], val[1400], tb[16];
            size_t p;
            read_name(r, (size_t)n, off, owner, sizeof(owner), &p);
            if (p + 10 > (size_t)n) return 1;
            uint16_t type = be16(r + p), cls = be16(r + p + 2), rdl = be16(r + p + 8);
            uint32_t ttl = (uint32_t)r[p + 4] << 24 | (uint32_t)r[p + 5] << 16 | (uint32_t)r[p + 6] << 8 | r[p + 7];
            size_t rd = p + 10;
            if (rd + rdl > (size_t)n) return 1;
            val[0] = 0;
            if (type == 1 && rdl == 4)
                inet_ntop(AF_INET, r + rd, val, sizeof(val));
            else if (type == 28 && rdl == 16)
                inet_ntop(AF_INET6, r + rd, val, sizeof(val));
            else if (type == 5 || type == 2 || type == 12)
                read_name(r, (size_t)n, rd, val, sizeof(val), NULL);
            else if (type == 6) {
                size_t q2, q3;
                char mn[300], rn[300];
                read_name(r, (size_t)n, rd, mn, sizeof(mn), &q2);
                read_name(r, (size_t)n, q2, rn, sizeof(rn), &q3);
                if (q3 + 20 <= (size_t)n)
                    snprintf(val, sizeof(val), "%s %s %u ...", mn, rn,
                             (unsigned)((uint32_t)r[q3] << 24 | (uint32_t)r[q3 + 1] << 16 | (uint32_t)r[q3 + 2] << 8 |
                                        r[q3 + 3]));
            } else if (type == 41) {
                snprintf(val, sizeof(val), "udp=%u version=%u do=%u", cls, r[p + 5], (r[p + 6] & 0x80) ? 1 : 0);
            } else if (type == 16) {
                size_t k = 0, o2 = 0;
                while (k < rdl && o2 + 4 < sizeof(val)) {
                    unsigned l = r[rd + k++];
                    o2 += (size_t)snprintf(val + o2, sizeof(val) - o2, "\"%.*s\" ", (int)(l <= rdl - k ? l : rdl - k),
                                           (const char *)r + rd + k);
                    k += l;
                }
            } else {
                size_t o2 = (size_t)snprintf(val, sizeof(val), "\\# %u ", rdl);
                for (unsigned k = 0; k < rdl && o2 + 3 < sizeof(val); k++)
                    o2 += (size_t)snprintf(val + o2, sizeof(val) - o2, "%02x", r[rd + k]);
            }
            if (type == 41)
                printf("; OPT %s\n", val);
            else
                printf("%-32s %7u IN %-6s %s\n", owner, ttl, type_name(type, tb), val);
            off = rd + rdl;
        }
    }
    return 0;
}

/* ---- report ---------------------------------------------------------------------------- */

static void usage(void) {
    printf(
        "dnsbench " VERSION " - DNS server performance tester\n\n"
        "usage: dnsbench -s SERVER[:PORT] [options]\n"
        "       dnsbench --responder [ADDR:]PORT [--delay MS] [--ttl S] [--nxdomain PCT]\n\n"
        "load:\n"
        "  -s, --server ADDR       server address (default 127.0.0.1:53)\n"
        "  -c, --concurrency N     closed loop: N queries in flight (default 32)\n"
        "  -r, --rate QPS          open loop: send at a fixed rate instead (latency under load)\n"
        "  -d, --duration SEC      test length (default 10)\n"
        "  -n, --count N           stop after N queries instead of a duration\n"
        "  -T, --threads N         sender threads (default: 1 per 64 in flight, max 8)\n"
        "  -w, --timeout MS        query timeout (default 2000)\n"
        "      --tcp               use DNS over TCP (pipelined, persistent connections)\n"
        "      --tcp-conns N       TCP connections per thread (default 1)\n"
        "queries:\n"
        "  -f, --file PATH         names to query, one per line: 'name [TYPE]' ('-' = stdin)\n"
        "  -t, --type TYPE         query type (default A)\n"
        "  -m, --mix SPEC          type mix, e.g. A:70,AAAA:25,HTTPS:5\n"
        "      --scenario NAME     cache  : popular names, warmed up first (cache-hit path)\n"
        "                          miss   : random sub-domains (always forwarded, cache-miss path)\n"
        "                          mixed  : popular names + --miss-pct %% random names\n"
        "      --domain NAME       parent of the random names (default dnsbench.invalid)\n"
        "      --miss-pct N        share of random names in 'mixed' (default 20)\n"
        "      --random            pick list names randomly instead of round robin\n"
        "      --warmup            query every list name once before measuring\n"
        "  -e, --edns              add an EDNS(0) OPT record (payload size 1232)\n"
        "      --edns-size N       EDNS(0) payload size (implies -e)\n"
        "      --do                set the DNSSEC OK bit (implies -e)\n"
        "      --no-rd             clear the RD bit\n"
        "output:\n"
        "  -i, --interval SEC      progress every SEC seconds (default 1, 0 = off)\n"
        "      --histogram         print the latency distribution\n"
        "      --json              machine readable summary\n"
        "  -q, --quiet             only the summary\n"
        "      --query NAME        send one query (-t TYPE, --tcp, -e) and print the answer\n\n"
        "examples:\n"
        "  dnsbench -s 192.168.1.53 -c 64 -d 10                 # maximum throughput\n"
        "  dnsbench -s 192.168.1.53 -r 1000 -d 30 --histogram   # latency at 1000 qps\n"
        "  dnsbench -s 192.168.1.53 --scenario cache -c 32      # cached answers\n"
        "  dnsbench -s 192.168.1.53 --scenario miss -r 200      # upstream path\n"
        "  dnsbench --responder 0.0.0.0:5300                     # fake upstream on this PC\n");
}

static void parse_mix(const char *s) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", s);
    C.nmix = 0;
    C.mix_total = 0;
    for (char *tok = strtok(buf, ","); tok && C.nmix < 16; tok = strtok(NULL, ",")) {
        char *colon = strchr(tok, ':');
        unsigned w = 1;
        if (colon) {
            *colon = 0;
            w = (unsigned)num_arg(colon + 1, 0, 1000000, "type mix weight");
        }
        uint16_t t = type_code(tok);
        if (!t) die("unknown type %s", tok);
        if (!w) continue;
        C.mix[C.nmix].t = t;
        C.mix[C.nmix].w = w;
        C.nmix++;
        C.mix_total += w;
    }
    if (!C.nmix) die("empty type mix");
}

int main(int argc, char **argv) {
    const char *server = "127.0.0.1", *file = NULL, *responder = NULL, *qname = NULL;
    C.conc = 32;
    C.duration_s = 10;
    C.interval_s = 1;
    C.timeout_ms = 2000;
    C.edns_size = 1232;
    C.miss_pct = 20;
    C.tcp_conns = 1;
    C.max_out = 60000;
    snprintf(C.domain, sizeof(C.domain), "dnsbench.invalid");
    parse_mix("A");
    enum { O_TCP = 256, O_SCEN, O_DOMAIN, O_MISS, O_RANDOM, O_WARM, O_DO, O_NORD, O_HIST, O_JSON, O_RESP, O_DELAY,
           O_TTL, O_NX, O_TCPC, O_QUERY, O_EDNSZ };
    static const struct option lo[] = {{"server", 1, 0, 's'},     {"concurrency", 1, 0, 'c'}, {"rate", 1, 0, 'r'},
                                       {"duration", 1, 0, 'd'},   {"count", 1, 0, 'n'},       {"threads", 1, 0, 'T'},
                                       {"timeout", 1, 0, 'w'},    {"file", 1, 0, 'f'},        {"type", 1, 0, 't'},
                                       {"mix", 1, 0, 'm'},        {"edns", 0, 0, 'e'},        {"interval", 1, 0, 'i'},
                                       {"quiet", 0, 0, 'q'},      {"help", 0, 0, 'h'},        {"tcp", 0, 0, O_TCP},
                                       {"scenario", 1, 0, O_SCEN}, {"domain", 1, 0, O_DOMAIN}, {"miss-pct", 1, 0, O_MISS},
                                       {"random", 0, 0, O_RANDOM}, {"warmup", 0, 0, O_WARM},   {"do", 0, 0, O_DO},
                                       {"no-rd", 0, 0, O_NORD},   {"histogram", 0, 0, O_HIST}, {"json", 0, 0, O_JSON},
                                       {"responder", 1, 0, O_RESP}, {"delay", 1, 0, O_DELAY}, {"ttl", 1, 0, O_TTL},
                                       {"nxdomain", 1, 0, O_NX},  {"tcp-conns", 1, 0, O_TCPC}, {"query", 1, 0, O_QUERY},
                                       {"edns-size", 1, 0, O_EDNSZ}, {0, 0, 0, 0}};
    int o;
    R.ttl = -1;
    while ((o = getopt_long(argc, argv, "s:c:r:d:n:T:w:f:t:m:ei:qh", lo, NULL)) != -1) {
        switch (o) {
        case 's': server = optarg; break;
        case 'c': C.conc = (int)num_arg(optarg, 1, 60000, "-c"); break;
        case 'r': {
            char *end;
            C.rate = strtod(optarg, &end);
            if (end == optarg || *end || C.rate <= 0 || C.rate > 1e7) die("-r: expected a rate > 0, got '%s'", optarg);
            break;
        }
        case 'd': C.duration_s = (int)num_arg(optarg, 1, 86400 * 7, "-d"); break;
        case 'n': C.count = (uint64_t)num_arg(optarg, 1, 2000000000L, "-n"); break;
        case 'T': C.threads = R.threads = (int)num_arg(optarg, 1, MAX_THREADS, "-T"); break;
        case 'w': C.timeout_ms = (int)num_arg(optarg, 1, 600000, "-w"); break;
        case 'f': file = optarg; break;
        case 't': parse_mix(optarg); break;
        case 'm': parse_mix(optarg); break;
        case 'e': C.edns = true; break;
        case O_EDNSZ: C.edns = true; C.edns_size = (uint16_t)num_arg(optarg, 512, 65535, "--edns-size"); break;
        case 'i': C.interval_s = (int)num_arg(optarg, 0, 3600, "-i"); break;
        case 'q': C.quiet = true; break;
        case O_TCP: C.tcp = true; break;
        case O_TCPC: C.tcp_conns = (int)num_arg(optarg, 1, MAX_TCP_CONNS, "--tcp-conns"); break;
        case O_QUERY: qname = optarg; break;
        case O_SCEN:
            if (!strcmp(optarg, "cache")) C.scenario = SC_CACHE;
            else if (!strcmp(optarg, "miss")) C.scenario = SC_MISS;
            else if (!strcmp(optarg, "mixed")) C.scenario = SC_MIXED;
            else die("unknown scenario %s (cache, miss, mixed)", optarg);
            break;
        case O_DOMAIN: snprintf(C.domain, sizeof(C.domain), "%s", optarg); break;
        case O_MISS: C.miss_pct = (int)num_arg(optarg, 0, 100, "--miss-pct"); break;
        case O_RANDOM: C.random_order = true; break;
        case O_WARM: C.warmup = 1; break;
        case O_DO: C.do_bit = C.edns = true; break;
        case O_NORD: C.no_rd = true; break;
        case O_HIST: C.histogram = true; break;
        case O_JSON: C.json = true; C.quiet = true; break;
        case O_RESP: responder = optarg; break;
        case O_DELAY: R.delay_ms = (int)num_arg(optarg, 0, 60000, "--delay"); break;
        case O_TTL: R.ttl = (int)num_arg(optarg, 0, 604800, "--ttl"); break;
        case O_NX: R.nx_pct = (int)num_arg(optarg, 0, 100, "--nxdomain"); break;
        case 'h':
        default: usage(); return o == 'h' ? 0 : 2;
        }
    }
    if (optind < argc) die("unexpected argument '%s' (the server is given with -s)", argv[optind]);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);
    if (responder) return run_responder(responder);

    parse_addr(server, 53, &C.sa, &C.salen, C.server_text, sizeof(C.server_text));
    if (qname) return run_query(qname);
    if ((C.dom_wlen = name_to_wire(C.domain, C.dom_wire, sizeof(C.dom_wire) - 12)) < 0) die("invalid --domain");
    if (file) {
        load_file(file);
    } else {
        size_t cap = 0;
        for (size_t i = 0; i < sizeof(g_popular) / sizeof(g_popular[0]); i++)
            add_name(&C.list, &C.nlist, &cap, g_popular[i], 0);
    }
    if (C.scenario == SC_CACHE) C.warmup = 1;
    if (C.conc < 1) C.conc = 1;
    if (C.tcp_conns < 1) C.tcp_conns = 1;
    if (C.tcp_conns > MAX_TCP_CONNS) C.tcp_conns = MAX_TCP_CONNS;
    if (!C.threads) {
        C.threads = C.rate > 0 ? (C.rate > 50000 ? 4 : 1) : (C.conc + 63) / 64;
        if (C.threads > 8) C.threads = 8;
    }
    if (C.threads < 1) C.threads = 1;
    if (C.threads > MAX_THREADS) C.threads = MAX_THREADS;
    if (C.rate <= 0 && C.conc < C.threads) C.threads = C.conc;
    if (C.count && C.count < (uint64_t)C.threads) C.threads = (int)C.count; /* (every thread gets queries) */
    if (C.scenario == SC_MISS) C.warmup = 0;

    g_th = (th_t *)calloc((size_t)C.threads, sizeof(th_t));
    uint64_t seed = now_ns() ^ (uint64_t)getpid() << 32;
    for (int i = 0; i < C.threads; i++) {
        th_t *t = &g_th[i];
        t->idx = i;
        t->rng = seed + (uint64_t)i * 0x9E3779B97F4A7C15ull;
        rng_next(&t->rng);
        t->seq = (uint64_t)i * 7919u;
        t->sent = (uint64_t *)calloc(IDS, sizeof(uint64_t));
        t->qhash = (uint32_t *)calloc(IDS, sizeof(uint32_t));
        t->conn = (uint8_t *)calloc(IDS, 1);
        t->next_id = (uint16_t)rng_next(&t->rng);
        t->conc = (unsigned)(C.conc / C.threads + (i < C.conc % C.threads ? 1 : 0));
        t->rate = C.rate / C.threads;
        if (C.count) t->limit = C.count / (uint64_t)C.threads + ((uint64_t)i < C.count % (uint64_t)C.threads ? 1 : 0);
        t->fd = -1;
        t->ntcp = C.tcp ? C.tcp_conns : 0;
        for (int k = 0; k < MAX_TCP_CONNS; k++) t->tfd[k] = -1;
        for (int k = 0; k < t->ntcp; k++) t->tbuf[k] = (uint8_t *)malloc(65536 + 2);
        if (!t->sent || !t->qhash || !t->conn) die("out of memory");
    }
    if (!C.quiet) {
        printf("dnsbench %s -> %s over %s\n", VERSION, C.server_text, C.tcp ? "TCP" : "UDP");
        if (C.rate > 0)
            printf("open loop: %.0f qps", C.rate);
        else
            printf("closed loop: %d in flight", C.conc);
        printf(", %d thread(s), ", C.threads);
        if (C.count)
            printf("%" PRIu64 " queries", C.count);
        else
            printf("%d s", C.duration_s);
        const char *sc[] = {"list", "cache", "miss", "mixed"};
        printf(", scenario %s (%zu names%s)\n", sc[C.scenario], C.nlist,
               C.scenario == SC_MISS || C.scenario == SC_MIXED ? ", random names under " : "");
        if (C.scenario == SC_MISS || C.scenario == SC_MIXED) printf("  random names: *.%s\n", C.domain);
        if (C.warmup) printf("warming up the cache...\n");
        fflush(stdout);
    }
    pthread_barrier_init(&g_bar, NULL, (unsigned)C.threads);
    for (int i = 0; i < C.threads; i++) pthread_create(&g_th[i].th, NULL, thread_run, &g_th[i]);

    /* progress */
    uint64_t last_recv = 0, last_lat = 0, last_sent = 0, last_to = 0;
    uint64_t t_prev = 0;
    bool running = true;
    while (running) {
        usleep(100000);
        running = atomic_load(&g_done) < C.threads;
        if (!running) break;
        uint64_t t0 = atomic_load(&g_t0);
        if (!t0 || !C.interval_s || C.quiet) continue;
        uint64_t now = now_ns();
        if (!t_prev) t_prev = t0;
        if (now - t_prev < (uint64_t)C.interval_s * 1000000000ull) continue;
        uint64_t s = 0, r = 0, l = 0, to = 0;
        for (int i = 0; i < C.threads; i++) {
            s += atomic_load(&g_th[i].sent_n);
            r += atomic_load(&g_th[i].recv_n);
            l += atomic_load(&g_th[i].lat_sum_us);
            to += atomic_load(&g_th[i].timeouts);
        }
        double dt = (double)(now - t_prev) / 1e9;
        printf("[%6.1fs] sent %8.0f/s  answered %8.0f/s  avg %7.3f ms  timeouts %" PRIu64 "\n",
               (double)(now - t0) / 1e9, (double)(s - last_sent) / dt, (double)(r - last_recv) / dt,
               r > last_recv ? (double)(l - last_lat) / (double)(r - last_recv) / 1000.0 : 0.0, to - last_to);
        fflush(stdout);
        last_sent = s;
        last_recv = r;
        last_lat = l;
        last_to = to;
        t_prev = now;
    }
    uint64_t t_end = 0, t_last = 0;
    for (int i = 0; i < C.threads; i++) {
        pthread_join(g_th[i].th, NULL);
        if (g_th[i].t_end > t_end) t_end = g_th[i].t_end;
        if (g_th[i].t_last > t_last) t_last = g_th[i].t_last;
    }

    /* summary */
    hist_t h;
    memset(&h, 0, sizeof(h));
    uint64_t sent = 0, recv = 0, to = 0, err = 0, rc[6] = {0}, rco = 0, tc = 0, empty = 0, mism = 0, lost = 0;
    for (int i = 0; i < C.threads; i++) {
        th_t *t = &g_th[i];
        h_merge(&h, &t->h);
        sent += t->sent_n;
        recv += t->recv_n;
        to += t->timeouts;
        err += t->errors;
        for (int k = 0; k < 6; k++) rc[k] += t->rcode[k];
        rco += t->rc_other;
        tc += t->tc;
        empty += t->empty;
        mism += t->mismatched;
        lost += t->unanswered;
    }
    /* the load phase lasts --duration (-n: until the last answer); the final
     * wait for stragglers is not counted */
    double secs = (double)(t_end - atomic_load(&g_t0)) / 1e9;
    if (!C.count && !atomic_load(&g_stop) && secs > C.duration_s) secs = C.duration_s;
    if (C.count && t_last > atomic_load(&g_t0)) secs = (double)(t_last - atomic_load(&g_t0)) / 1e9;
    if (secs <= 0) secs = 1e-9;
    double qps = (double)recv / secs;
    if (C.json) {
        printf("{\"server\":\"%s\",\"transport\":\"%s\",\"mode\":\"%s\",\"concurrency\":%d,\"rate\":%.0f,"
               "\"threads\":%d,\"seconds\":%.3f,\"sent\":%" PRIu64 ",\"answered\":%" PRIu64 ",\"timeouts\":%" PRIu64
               ",\"errors\":%" PRIu64 ",\"unanswered\":%" PRIu64 ",\"qps\":%.1f,"
               "\"rcode\":{\"NOERROR\":%" PRIu64 ",\"FORMERR\":%" PRIu64 ",\"SERVFAIL\":%" PRIu64
               ",\"NXDOMAIN\":%" PRIu64 ",\"NOTIMP\":%" PRIu64 ",\"REFUSED\":%" PRIu64 ",\"other\":%" PRIu64
               "},\"truncated\":%" PRIu64 ",\"nodata\":%" PRIu64 ",\"latency_ms\":{\"min\":%.3f,\"avg\":%.3f,"
               "\"p50\":%.3f,\"p90\":%.3f,\"p95\":%.3f,\"p99\":%.3f,\"p999\":%.3f,\"max\":%.3f}}\n",
               C.server_text, C.tcp ? "tcp" : "udp", C.rate > 0 ? "open" : "closed", C.conc, C.rate, C.threads, secs,
               sent, recv, to, err, lost, qps, rc[0], rc[1], rc[2], rc[3], rc[4], rc[5], rco, tc, empty,
               (double)h.min / 1000, h.n ? (double)h.sum / (double)h.n / 1000 : 0, h_pct(&h, 50) / 1000,
               h_pct(&h, 90) / 1000, h_pct(&h, 95) / 1000, h_pct(&h, 99) / 1000, h_pct(&h, 99.9) / 1000,
               (double)h.max / 1000);
        return to && !recv ? 1 : 0;
    }
    printf("\n==== dnsbench summary: %s (%s) ====\n", C.server_text, C.tcp ? "TCP" : "UDP");
    printf("duration          %.2f s\n", secs);
    printf("queries sent      %" PRIu64 "\n", sent);
    printf("answers           %" PRIu64 " (%.2f%%)\n", recv, sent ? 100.0 * (double)recv / (double)sent : 0.0);
    printf("timeouts          %" PRIu64 " (%.2f%%)\n", to, sent ? 100.0 * (double)to / (double)sent : 0.0);
    if (err) printf("send/conn errors  %" PRIu64 "\n", err);
    if (lost) printf("unanswered        %" PRIu64 " (still in flight when the run was stopped)\n", lost);
    if (mism) printf("mismatched        %" PRIu64 " (answer did not match the question)\n", mism);
    printf("throughput        %.1f answers/s\n", qps);
    printf("rcodes            NOERROR %" PRIu64 "  NXDOMAIN %" PRIu64 "  SERVFAIL %" PRIu64 "  REFUSED %" PRIu64
           "  NOTIMP %" PRIu64 "  FORMERR %" PRIu64 "  other %" PRIu64 "\n",
           rc[0], rc[3], rc[2], rc[5], rc[4], rc[1], rco);
    printf("NOERROR no answer %" PRIu64 "   truncated (TC) %" PRIu64 "\n", empty, tc);
    printf("latency (ms)      min %.3f  avg %.3f  max %.3f\n", (double)h.min / 1000,
           h.n ? (double)h.sum / (double)h.n / 1000 : 0, (double)h.max / 1000);
    printf("percentiles (ms)  p50 %.3f  p90 %.3f  p95 %.3f  p99 %.3f  p99.9 %.3f\n", h_pct(&h, 50) / 1000,
           h_pct(&h, 90) / 1000, h_pct(&h, 95) / 1000, h_pct(&h, 99) / 1000, h_pct(&h, 99.9) / 1000);
    if (C.histogram && h.n) {
        printf("\nlatency distribution:\n");
        /* group into ~quarter-octave rows */
        uint64_t maxc = 0;
        unsigned step = H_SUB / 4;
        for (unsigned i = 0; i < H_N; i += (i < H_LIN ? 8 : step)) {
            uint64_t c = 0;
            unsigned w = i < H_LIN ? 8 : step;
            for (unsigned k = i; k < i + w && k < H_N; k++) c += h.b[k];
            if (c > maxc) maxc = c;
        }
        for (unsigned i = 0; i < H_N; i += (i < H_LIN ? 8 : step)) {
            uint64_t c = 0;
            unsigned w = i < H_LIN ? 8 : step;
            for (unsigned k = i; k < i + w && k < H_N; k++) c += h.b[k];
            if (!c) continue;
            double from = i < H_LIN ? i : h_val(i) - (h_val(i + 1) - h_val(i)) / 2;
            int bar = (int)(50.0 * (double)c / (double)maxc);
            printf("  >= %9.3f ms %10" PRIu64 " %6.2f%% |%.*s\n", from / 1000, c, 100.0 * (double)c / (double)h.n,
                   bar, "##################################################");
        }
    }
    return to && !recv ? 1 : 0;
}
