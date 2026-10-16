/*
 * flc - host-side tool for the filter engine.
 *
 *   flc compile -o out.img [--allow L] [--chunk KB] [--runs-file F] list...
 *   flc info    image
 *   flc query   image host [qtype] [--ip A] [--name N] [--tags t1,t2]
 *   flc batch   image            (stdin: "host qtype [ip] [name] [tags]")
 *   flc bench   image hostfile [iterations]
 *
 * "--allow L" marks the following list as an allowlist.  Several images can
 * be combined with "+" (e.g. custom.img+subs.img) like on the device.
 * The batch output format is shared with tools/compat-oracle for
 * differential testing against AdGuard's urlfilter.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "fl_filter.h"

static int usage(void) {
    fprintf(stderr,
            "usage:\n"
            "  flc compile -o out.img [--allow LIST] [--chunk KB] [--staging KB] [--runs-file F] LIST...\n"
            "  flc info IMAGE[+IMAGE...]\n"
            "  flc query IMAGE[+IMAGE...] HOST [QTYPE] [--ip IP] [--name N] [--tags a,b]\n"
            "  flc batch IMAGE[+IMAGE...]   (stdin lines: host qtype [ip|-] [name|-] [tags|-])\n"
            "  flc bench IMAGE[+IMAGE...] HOSTFILE [ITER]\n");
    return 2;
}

/* ---- file-backed store (exercises the external sort like a flash partition) */
typedef struct {
    fl_store_t st;
    FILE *f;
} filestore_t;

static int fs_write(fl_store_t *s, uint32_t off, const void *buf, size_t len) {
    filestore_t *fs = (filestore_t *)s;
    if ((uint64_t)off + len > s->capacity) return FL_ERR_FULL;
    if (fseek(fs->f, off, SEEK_SET) || fwrite(buf, 1, len, fs->f) != len) return FL_ERR_IO;
    return 0;
}
static int fs_read(fl_store_t *s, uint32_t off, void *buf, size_t len) {
    filestore_t *fs = (filestore_t *)s;
    if (fseek(fs->f, off, SEEK_SET) || fread(buf, 1, len, fs->f) != len) return FL_ERR_IO;
    return 0;
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) {
        fclose(f);
        return NULL;
    }
    uint8_t *b = (uint8_t *)dc_malloc_ext((size_t)n + 1);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) {
        dc_free(b);
        b = NULL;
    }
    fclose(f);
    if (b) *len = (size_t)n;
    return b;
}

static void print_stats(const fl_stats_t *s) {
    printf("  lines            %u\n", s->lines);
    printf("  comments/empty   %u\n", s->empty_comment);
    printf("  cosmetic         %u\n", s->cosmetic);
    printf("  hosts rules      %u\n", s->host_rules);
    printf("  network rules    %u\n", s->net_rules);
    printf("    plain index    %u\n", s->plain);
    printf("    with modifiers %u\n", s->complex_domain);
    printf("    patterns       %u (regex %u, dfa %u, nfa %u)\n", s->generic, s->regex, s->dfa, s->nfa);
    printf("    dnsrewrite     %u\n", s->dnsrewrite);
    printf("    badfilter      %u (negated at compile time: %u)\n", s->badfilter, s->negated);
    printf("  invalid          %u\n", s->invalid);
    printf("  not for DNS      %u\n", s->not_dns);
    printf("  never matching   %u\n", s->never_match);
    printf("  too wide         %u\n", s->too_wide);
    printf("  unsupported      %u ($client/$ctag skipped: %u)\n", s->unsupported, s->client_skipped);
    printf("  too long         %u\n", s->too_long);
    printf("  distinct keys    %u\n", s->keys);
    printf("  image bytes      %u (%.3f MiB)\n", s->image_bytes, s->image_bytes / 1048576.0);
    printf("  sort runs        %u (compactions %u), staging peak %u bytes\n", s->runs, s->compactions,
           s->staging_peak);
    printf("  compile time     %u ms\n", s->compile_ms);
}

static int cmd_compile(int argc, char **argv) {
    const char *out = NULL, *runs_file = NULL;
    uint32_t chunk = 512, staging_kb = 0;
    const char *lists[64];
    uint32_t flags[64];
    int nl = 0;
    uint32_t next_flag = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--chunk") && i + 1 < argc) chunk = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--runs-file") && i + 1 < argc) runs_file = argv[++i];
        else if (!strcmp(argv[i], "--staging") && i + 1 < argc) staging_kb = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--allow")) next_flag = FL_SRC_ALLOWLIST;
        else if (nl < 64) {
            lists[nl] = argv[i];
            flags[nl++] = next_flag;
            next_flag = 0;
        }
    }
    if (!out || !nl) return usage();

    fl_memstore_t mem;
    filestore_t fst;
    fl_store_t *runs;
    if (runs_file) {
        memset(&fst, 0, sizeof(fst));
        fst.f = fopen(runs_file, "w+b");
        if (!fst.f) {
            perror(runs_file);
            return 1;
        }
        fst.st.write = fs_write;
        fst.st.read = fs_read;
        fst.st.capacity = staging_kb ? staging_kb * 1024u : 0x7FFFF000u;
        runs = &fst.st;
    } else {
        fl_memstore_init(&mem, staging_kb ? staging_kb * 1024u : 0x7FFFF000u);
        runs = &mem.st;
    }
    fl_compile_opts_t o;
    memset(&o, 0, sizeof(o));
    o.chunk_bytes = chunk * 1024;
    o.runs = runs;
    o.generation = (uint32_t)time(NULL);
    fl_compiler_t *c = fl_compile_new(&o);
    if (!c) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    char *buf = (char *)malloc(65536);
    if (!buf) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    for (int i = 0; i < nl; i++) {
        FILE *f = fopen(lists[i], "rb");
        if (!f) {
            perror(lists[i]);
            free(buf);
            return 1;
        }
        const char *base = strrchr(lists[i], '/');
        fl_compile_begin_source(c, base ? base + 1 : lists[i], flags[i]);
        size_t n;
        while ((n = fread(buf, 1, 65536, f)) > 0) {
            int rc = fl_compile_feed(c, buf, n);
            if (rc) {
                fprintf(stderr, "compile failed (%s): %s\n", lists[i], fl_compile_error(c));
                fclose(f);
                free(buf);
                return 1;
            }
        }
        fclose(f);
        int rc = fl_compile_end_source(c);
        if (rc) {
            fprintf(stderr, "source %s rejected (%d)\n", lists[i], rc);
            free(buf);
            return 1;
        }
    }
    free(buf);

    fl_memstore_t sink;
    fl_memstore_init(&sink, 64u << 20);
    fl_stats_t st;
    int len = fl_compile_finish(c, &sink.st, &st);
    if (len < 0) {
        fprintf(stderr, "finish failed (%d): %s\n", len, fl_compile_error(c));
        return 1;
    }
    FILE *fo = fopen(out, "wb");
    if (!fo || fwrite(sink.buf.data, 1, (size_t)len, fo) != (size_t)len) {
        perror(out);
        return 1;
    }
    fclose(fo);
    printf("wrote %s:\n", out);
    print_stats(&st);
    for (int i = 0; i < nl; i++) {
        const fl_stats_t *ps = fl_compile_source_stats(c, i);
        if (ps)
            printf("  [%d] %-28s lines=%u rules=%u invalid=%u unsupported=%u (client_skipped=%u)\n", i, lists[i],
                   ps->lines, ps->host_rules + ps->net_rules, ps->invalid, ps->unsupported, ps->client_skipped);
    }
    fl_compile_free(c);
    fl_memstore_free(&sink);
    if (runs_file)
        fclose(fst.f);
    else
        fl_memstore_free(&mem);
    return 0;
}

static fl_set_t *open_set(const char *spec) {
    char *s = strdup(spec);
    fl_image_t *imgs[8];
    unsigned ni = 0;
    for (char *tok = strtok(s, "+"); tok && ni < 8; tok = strtok(NULL, "+")) {
        size_t len;
        uint8_t *d = read_file(tok, &len);
        if (!d) {
            perror(tok);
            exit(1);
        }
        int rc = fl_image_load(d, len, true, &imgs[ni]);
        if (rc) {
            fprintf(stderr, "%s: invalid image (%d)\n", tok, rc);
            exit(1);
        }
        ni++;
    }
    free(s);
    fl_set_t *set = fl_set_new(imgs, ni, 1);
    for (unsigned i = 0; i < ni; i++) fl_image_unref(imgs[i]);
    if (!set) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    return set;
}

static int cmd_info(const char *path) {
    size_t len;
    uint8_t *d = read_file(path, &len);
    if (!d) {
        perror(path);
        return 1;
    }
    fl_image_t *im;
    int rc = fl_image_load(d, len, true, &im);
    if (rc) {
        fprintf(stderr, "invalid image (%d)\n", rc);
        return 1;
    }
    printf("image %s (generation %u, CRC verified):\n", path, fl_image_generation(im));
    print_stats(fl_image_stats(im));
    fl_image_unref(im);
    return 0;
}

static uint32_t parse_tags(const char *s) {
    if (!s || !*s || !strcmp(s, "-")) return 0;
    uint32_t m = 0;
    char *cp = strdup(s);
    for (char *t = strtok(cp, ","); t; t = strtok(NULL, ",")) {
        int b = fl_ctag_from_name(t, strlen(t));
        if (b >= 0) m |= 1u << b;
    }
    free(cp);
    return m;
}

/* Canonical one-line representation of a match result, shared with the Go
 * compat-oracle so the two implementations can be diffed line by line. */
static void format_result(const fl_result_t *r, char *out, size_t cap) {
    size_t o = 0;
    switch (r->verdict) {
    case FL_V_NONE:
        snprintf(out, cap, "NONE");
        return;
    case FL_V_ALLOW:
        snprintf(out, cap, "ALLOW");
        return;
    case FL_V_ALLOWLIST:
        snprintf(out, cap, "ALLOWLIST");
        return;
    case FL_V_BLOCK:
        o = (size_t)snprintf(out, cap, "BLOCK%s", r->hosts_rule ? " hosts" : "");
        for (unsigned i = 0; i < r->n_ips; i++) {
            char b[64];
            dc_ip_format(&r->ips[i], b, sizeof(b));
            o += (size_t)snprintf(out + o, cap - o, " %s", b);
        }
        return;
    case FL_V_REWRITE:
        o = (size_t)snprintf(out, cap, "REWRITE rc=%u", r->rcode);
        if (r->rw_kind == FL_RW_CNAME && r->cname) {
            char nm[300];
            fl_name_from_wire(r->cname, 256, nm, sizeof(nm));
            o += (size_t)snprintf(out + o, cap - o, " cname=%s", nm);
        }
        for (unsigned i = 0; i < r->n_rr; i++) {
            o += (size_t)snprintf(out + o, cap - o, " rr=%u:", r->rr[i].type);
            for (unsigned k = 0; k < r->rr[i].rdlen; k++)
                o += (size_t)snprintf(out + o, cap - o, "%02x", r->rr[i].rdata[k]);
        }
        return;
    }
}

static void explain_cb(void *arg, const char *rule, const char *src, const char *eff) {
    (void)arg;
    printf("  match  %-18s  %-48s  [%s]\n", eff, rule, src);
}

static int cmd_query(int argc, char **argv) {
    if (argc < 2) return usage();
    fl_set_t *set = open_set(argv[0]);
    const char *host = argv[1];
    uint16_t qt = 1;
    const char *ip = NULL, *name = NULL, *tags = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--ip") && i + 1 < argc) ip = argv[++i];
        else if (!strcmp(argv[i], "--name") && i + 1 < argc) name = argv[++i];
        else if (!strcmp(argv[i], "--tags") && i + 1 < argc) tags = argv[++i];
        else {
            uint16_t t = fl_rr_type_code(argv[i]);
            if (t) qt = t;
        }
    }
    fl_client_t cl;
    memset(&cl, 0, sizeof(cl));
    if (ip) dc_ip_parse_z(ip, &cl.ip);
    cl.name = name;
    cl.tags = parse_tags(tags);
    fl_req_t rq = {host, (uint16_t)strlen(host), qt, 0, &cl};
    fl_result_t res;
    uint64_t t0 = dc_time_us();
    fl_match(set, &rq, &res);
    uint64_t dt = dc_time_us() - t0;
    char s[512], rtxt[512], stxt[128];
    format_result(&res, s, sizeof(s));
    printf("result: %s  (%llu us)\n", s, (unsigned long long)dt);
    if (res.has_rule && fl_rule_text(set, &res.rule, host, rtxt, sizeof(rtxt), stxt, sizeof(stxt)))
        printf("winner: %s  [%s]\n", rtxt, stxt);
    fl_explain(set, &rq, explain_cb, NULL);
    fl_set_unref(set);
    return 0;
}

static int cmd_batch(const char *spec) {
    fl_set_t *set = open_set(spec);
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (!line[0] || line[0] == '#') continue;
        char *save = NULL;
        char *host = strtok_r(line, " \t", &save);
        char *qts = strtok_r(NULL, " \t", &save);
        char *ips = strtok_r(NULL, " \t", &save);
        char *nms = strtok_r(NULL, " \t", &save);
        char *tgs = strtok_r(NULL, " \t", &save);
        if (!host || !qts) continue;
        uint16_t qt = fl_rr_type_code(qts);
        if (!qt) qt = (uint16_t)atoi(qts);
        fl_client_t cl;
        memset(&cl, 0, sizeof(cl));
        if (ips && strcmp(ips, "-")) dc_ip_parse_z(ips, &cl.ip);
        if (nms && strcmp(nms, "-")) cl.name = nms;
        cl.tags = parse_tags(tgs);
        fl_req_t rq = {host, (uint16_t)strlen(host), qt, 0, &cl};
        fl_result_t res;
        fl_match(set, &rq, &res);
        char out[512];
        format_result(&res, out, sizeof(out));
        puts(out);
    }
    fl_set_unref(set);
    return 0;
}

static int cmd_bench(int argc, char **argv) {
    if (argc < 2) return usage();
    fl_set_t *set = open_set(argv[0]);
    size_t len;
    uint8_t *raw = read_file(argv[1], &len);
    if (!raw) {
        perror(argv[1]);
        return 1;
    }
    raw[len] = 0;
    unsigned cap = 65536, nh = 0;
    char **hosts = (char **)malloc(cap * sizeof(char *));
    uint16_t *hlens = (uint16_t *)malloc(cap * sizeof(uint16_t));
    for (char *p = strtok((char *)raw, "\r\n"); p; p = strtok(NULL, "\r\n")) {
        if (!*p || *p == '#') continue;
        if (nh == cap) {
            cap *= 2;
            hosts = (char **)realloc(hosts, cap * sizeof(char *));
            hlens = (uint16_t *)realloc(hlens, cap * sizeof(uint16_t));
        }
        hosts[nh] = p;
        hlens[nh] = (uint16_t)strlen(p);
        nh++;
    }
    int iter = argc >= 3 ? atoi(argv[2]) : 50;
    if (iter < 1) iter = 1;
    unsigned blocked = 0;
    uint64_t t0 = dc_time_us();
    for (int it = 0; it < iter; it++) {
        for (unsigned i = 0; i < nh; i++) {
            fl_req_t rq = {hosts[i], hlens[i], (i & 1) ? 1 : 28, 0, NULL};
            fl_result_t r;
            fl_match(set, &rq, &r);
            if (r.verdict == FL_V_BLOCK) blocked++;
        }
    }
    uint64_t dt = dc_time_us() - t0;
    double q = (double)nh * iter;
    printf("%u hosts x %d = %.0f queries in %.2f ms: %.2f us/query (%.0f q/s), %u blocked\n", nh, iter, q,
           dt / 1000.0, dt / q, q * 1e6 / dt, blocked / (unsigned)iter);
    free(hosts);
    free(hlens);
    dc_free(raw);
    fl_set_unref(set);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    if (!strcmp(argv[1], "compile")) return cmd_compile(argc - 2, argv + 2);
    if (!strcmp(argv[1], "info") && argc >= 3) return cmd_info(argv[2]);
    if (!strcmp(argv[1], "query")) return cmd_query(argc - 2, argv + 2);
    if (!strcmp(argv[1], "batch") && argc >= 3) return cmd_batch(argv[2]);
    if (!strcmp(argv[1], "bench")) return cmd_bench(argc - 2, argv + 2);
    return usage();
}
