/*
 * dnsd_host - the ESP32-S3 DNS server core running on Linux.
 *
 * Same code as the firmware (dns_core + fl_filter + dc_base), useful to
 * test filter lists and settings on a PC and to profile the query path.
 *
 *   dnsd_host -p 5353 -u 223.5.5.5 -r adguard_dns.txt -L local.txt
 *   dnsd_host -p 5353 -u 127.0.0.1:5300 -i filters.img --stats 1
 */
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dns_server.h"
#include "fl_filter.h"

static volatile sig_atomic_t g_stop;
static void on_sig(int s) {
    (void)s;
    g_stop = 1;
}

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) {
        fclose(f);
        return NULL;
    }
    char *b = (char *)malloc((size_t)n + 1);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        b = NULL;
    }
    fclose(f);
    if (b) {
        b[n] = 0;
        *len = (size_t)n;
    }
    return b;
}

typedef struct {
    const char *path;
    uint32_t flags;
} src_t;

static fl_image_t *compile_lists(const src_t *srcs, int n) {
    fl_memstore_t runs, sink;
    fl_memstore_init(&runs, 64u << 20);
    fl_memstore_init(&sink, 64u << 20);
    fl_compile_opts_t o;
    memset(&o, 0, sizeof(o));
    o.runs = &runs.st;
    fl_compiler_t *c = fl_compile_new(&o);
    for (int i = 0; i < n; i++) {
        size_t len;
        char *data = read_file(srcs[i].path, &len);
        if (!data) {
            fprintf(stderr, "cannot read %s\n", srcs[i].path);
            exit(1);
        }
        const char *base = strrchr(srcs[i].path, '/');
        fl_compile_begin_source(c, base ? base + 1 : srcs[i].path, srcs[i].flags);
        fl_compile_feed(c, data, len);
        if (fl_compile_end_source(c) < 0) fprintf(stderr, "warning: %s rejected (not a filter list?)\n", srcs[i].path);
        free(data);
        const fl_stats_t *st = fl_compile_source_stats(c, i);
        if (st)
            printf("  %-28s %7u lines: %u hosts, %u network, %u invalid, %u unsupported\n", srcs[i].path, st->lines,
                   st->host_rules, st->net_rules, st->invalid, st->unsupported);
    }
    fl_stats_t st;
    int len = fl_compile_finish(c, &sink.st, &st);
    if (len < 0) {
        fprintf(stderr, "compile failed: %s\n", fl_compile_error(c));
        exit(1);
    }
    printf("  image %.2f MiB, %u keys, %u generic rules, %u ms\n", len / 1048576.0, st.keys, st.generic,
           st.compile_ms);
    uint8_t *img_data = (uint8_t *)dc_malloc_ext((size_t)len);
    memcpy(img_data, sink.buf.data, (size_t)len);
    fl_image_t *img;
    if (fl_image_load(img_data, (size_t)len, true, &img)) {
        fprintf(stderr, "image load failed\n");
        exit(1);
    }
    fl_compile_free(c);
    fl_memstore_free(&runs);
    fl_memstore_free(&sink);
    return img;
}

static fl_image_t *load_image(const char *path) {
    size_t len;
    char *data = read_file(path, &len);
    if (!data) {
        fprintf(stderr, "cannot read %s\n", path);
        exit(1);
    }
    uint8_t *d = (uint8_t *)dc_malloc_ext(len);
    memcpy(d, data, len);
    free(data);
    fl_image_t *img;
    if (fl_image_load(d, len, true, &img)) {
        fprintf(stderr, "%s: not a valid filter image\n", path);
        exit(1);
    }
    return img;
}

/* local records file: "domain TYPE value [ttl]" per line */
static dns_local_t *load_local(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot read %s\n", path);
        exit(1);
    }
    dns_local_t *l = dns_local_new();
    char line[1024];
    int ln = 0;
    while (fgets(line, sizeof(line), f)) {
        ln++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        size_t pl = strlen(p);
        while (pl && (p[pl - 1] == '\n' || p[pl - 1] == '\r' || p[pl - 1] == ' ' || p[pl - 1] == '\t')) p[--pl] = 0;
        if (!*p || *p == '#') continue; /* (also Windows line ends) */
        char dom[300], type[16], val[600];
        unsigned ttl = 300;
        int k = sscanf(p, "%299s %15s %599[^\n]", dom, type, val);
        if (k < 3) {
            fprintf(stderr, "%s:%d: expected 'domain TYPE value'\n", path, ln);
            continue;
        }
        /* optional trailing ttl=N */
        char *t = strstr(val, " ttl=");
        if (t) {
            ttl = (unsigned)atoi(t + 5);
            *t = 0;
        }
        const char *err;
        if (dns_local_add(l, dom, type, ttl, val, &err) < 0) fprintf(stderr, "%s:%d: %s\n", path, ln, err);
    }
    fclose(f);
    return l;
}

static void usage(void) {
    printf("dnsd_host - ESP32-S3 DNS server core on Linux\n\n"
           "  -p, --port N           listen port (default 5353)\n"
           "  -b, --bind ADDR        IPv4 listen address (default 0.0.0.0)\n"
           "  -u, --upstream ADDR    upstream server (repeatable): 1.1.1.1, tcp://9.9.9.9, ...\n"
           "  -r, --rules FILE       filter list (repeatable, AdGuard / hosts syntax)\n"
           "  -a, --allowlist FILE   allowlist (repeatable)\n"
           "  -i, --image FILE       precompiled filter image (from flc)\n"
           "  -L, --local FILE       local records: 'domain TYPE value [ttl=N]' per line\n"
           "      --cache MB         cache size (default 16)\n"
           "      --block-mode M     default | nullip | nxdomain | refused\n"
           "      --strategy S       fastest | load_balance | parallel\n"
           "      --optimistic       serve expired answers while refreshing\n"
           "      --any-client       accept queries from any address (default: private only)\n"
           "      --workers N        UDP receive threads (default 2)\n"
           "      --stats SEC        print statistics every SEC seconds (default 5, 0 = off)\n"
           "  -q, --quiet\n");
}

static void print_stats(dns_server_t *s, double secs, uint32_t *last_q) {
    dns_stats_t st;
    dns_server_get_stats(s, &st);
    uint32_t dq = st.queries - *last_q;
    *last_q = st.queries;
    uint64_t hits = (uint64_t)st.cache.l1_hits + st.cache.l2_hits + st.cache.stale_hits;
    uint64_t look = hits + st.cache.misses;
    printf("qps %.0f | total %u: fwd %u cached %u blocked %u resp-blocked %u rewritten %u local %u failed %u "
           "dropped %u | cache %u entries, hit %.1f%% (L1 %u) | pending %u\n",
           dq / secs, st.queries, st.forwarded, st.cached, st.blocked, st.resp_blocked, st.rewritten, st.local,
           st.failed, st.dropped + st.ratelimited, st.cache.entries, look ? 100.0 * (double)hits / (double)look : 0,
           st.cache.l1_hits, st.pending);
    printf("    latency p50/p99 us: local %u/%u  cached %u/%u  forwarded %u/%u",
           dns_hist_percentile(&st.local_us, 50), dns_hist_percentile(&st.local_us, 99),
           dns_hist_percentile(&st.cached_us, 50), dns_hist_percentile(&st.cached_us, 99),
           dns_hist_percentile(&st.forward_us, 50), dns_hist_percentile(&st.forward_us, 99));
    for (unsigned i = 0; i < st.nup; i++)
        printf(" | %s: rtt %.1fms ok %u to %u%s", st.up[i].text, st.up[i].rtt_us / 1000.0, st.up[i].ok,
               st.up[i].timeouts, st.up[i].healthy ? "" : " DOWN");
    printf("\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    dns_config_t cfg;
    dns_config_defaults(&cfg);
    cfg.port = 5353;
    cfg.listen_v6 = false;
    cfg.nup = 0;
    src_t srcs[FL_MAX_SOURCES];
    int nsrc = 0;
    const char *image = NULL, *local = NULL;
    int stats = 5;
    bool quiet = false;
    enum { O_CACHE = 256, O_BM, O_STRAT, O_OPT, O_ANY, O_WORK, O_STATS };
    static const struct option lo[] = {{"port", 1, 0, 'p'},       {"bind", 1, 0, 'b'},       {"upstream", 1, 0, 'u'},
                                       {"rules", 1, 0, 'r'},      {"allowlist", 1, 0, 'a'},  {"image", 1, 0, 'i'},
                                       {"local", 1, 0, 'L'},      {"cache", 1, 0, O_CACHE},  {"block-mode", 1, 0, O_BM},
                                       {"strategy", 1, 0, O_STRAT}, {"optimistic", 0, 0, O_OPT},
                                       {"any-client", 0, 0, O_ANY}, {"workers", 1, 0, O_WORK},
                                       {"stats", 1, 0, O_STATS},  {"quiet", 0, 0, 'q'},      {"help", 0, 0, 'h'},
                                       {0, 0, 0, 0}};
    int o;
    while ((o = getopt_long(argc, argv, "p:b:u:r:a:i:L:qh", lo, NULL)) != -1) {
        const char *err;
        switch (o) {
        case 'p': cfg.port = (uint16_t)atoi(optarg); break;
        case 'b': snprintf(cfg.bind_v4, sizeof(cfg.bind_v4), "%s", optarg); break;
        case 'u':
            if (cfg.nup >= DNS_MAX_UPSTREAMS || !dns_upstream_parse(optarg, &cfg.up[cfg.nup], &err)) {
                fprintf(stderr, "upstream %s: %s\n", optarg, cfg.nup >= DNS_MAX_UPSTREAMS ? "too many" : err);
                return 2;
            }
            cfg.nup++;
            break;
        case 'r':
        case 'a':
            if (nsrc >= FL_MAX_SOURCES) {
                fprintf(stderr, "at most %d lists\n", FL_MAX_SOURCES);
                return 2;
            }
            srcs[nsrc].path = optarg;
            srcs[nsrc].flags = o == 'a' ? FL_SRC_ALLOWLIST : 0;
            nsrc++;
            break;
        case 'i': image = optarg; break;
        case 'L': local = optarg; break;
        case O_CACHE: {
            int mb = atoi(optarg);
            if (mb < 0 || mb > 2047) {
                fprintf(stderr, "--cache: 0..2047 MiB\n");
                return 2;
            }
            cfg.cache_bytes = (uint32_t)mb << 20;
            break;
        }
        case O_BM:
            if (!strcmp(optarg, "default")) cfg.block_mode = DNS_BLOCK_DEFAULT;
            else if (!strcmp(optarg, "nullip")) cfg.block_mode = DNS_BLOCK_NULL_IP;
            else if (!strcmp(optarg, "nxdomain")) cfg.block_mode = DNS_BLOCK_NXDOMAIN;
            else if (!strcmp(optarg, "refused")) cfg.block_mode = DNS_BLOCK_REFUSED;
            else {
                fprintf(stderr, "unknown block mode\n");
                return 2;
            }
            break;
        case O_STRAT:
            if (!strcmp(optarg, "fastest")) cfg.strategy = DNS_STRAT_FASTEST;
            else if (!strcmp(optarg, "load_balance") || !strcmp(optarg, "loadbalance"))
                cfg.strategy = DNS_STRAT_LOAD_BALANCE;
            else if (!strcmp(optarg, "parallel")) cfg.strategy = DNS_STRAT_PARALLEL;
            else {
                fprintf(stderr, "unknown strategy\n");
                return 2;
            }
            break;
        case O_OPT: cfg.optimistic = true; break;
        case O_ANY: cfg.local_only = false; break;
        case O_WORK: cfg.udp_workers = (uint8_t)atoi(optarg); break;
        case O_STATS: stats = atoi(optarg); break;
        case 'q': quiet = true; break;
        default: usage(); return o == 'h' ? 0 : 2;
        }
    }
    if (!cfg.nup) {
        const char *err;
        dns_upstream_parse("223.5.5.5", &cfg.up[cfg.nup++], &err);
    }
    if (quiet) dc_log_level = DC_LOG_WARN;
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);

    fl_image_t *imgs[2];
    unsigned nimg = 0;
    if (nsrc) {
        printf("compiling %d list(s)...\n", nsrc);
        imgs[nimg++] = compile_lists(srcs, nsrc);
    }
    if (image) imgs[nimg++] = load_image(image);

    dns_server_t *s = dns_server_new(&cfg);
    if (!s) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    if (nimg) {
        fl_set_t *set = fl_set_new(imgs, nimg, 1);
        for (unsigned i = 0; i < nimg; i++) fl_image_unref(imgs[i]);
        dns_server_set_filters(s, set);
        fl_set_unref(set);
    }
    if (local) {
        dns_local_t *l = load_local(local);
        printf("%u local record(s)\n", dns_local_count(l));
        dns_server_set_local(s, l);
    }
    if (dns_server_start(s) != 0) {
        fprintf(stderr, "cannot start (port %u in use? ports < 1024 need root)\n", cfg.port);
        return 1;
    }
    uint32_t lastq = 0;
    uint64_t last = dc_time_ms();
    while (!g_stop) {
        usleep(100000);
        if (stats > 0 && dc_time_ms() - last >= (uint64_t)stats * 1000) {
            uint64_t now = dc_time_ms();
            print_stats(s, (double)(now - last) / 1000.0, &lastq);
            last = now;
        }
    }
    printf("\nstopping\n");
    uint64_t now = dc_time_ms();
    print_stats(s, now > last ? (double)(now - last) / 1000.0 : 1.0, &lastq); /* (rate since the last report) */
    dns_server_stop(s);
    return 0;
}
