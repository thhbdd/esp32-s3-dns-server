/* dns_config.c - configuration defaults and upstream address parsing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dc_util.h"
#include "dns_server.h"

void dns_config_defaults(dns_config_t *c) {
    memset(c, 0, sizeof(*c));
    c->port = 53;
    c->listen_v4 = true;
    c->listen_v6 = true;
    c->tcp = true;
#ifdef ESP_PLATFORM
    c->udp_workers = 1; /* lwIP: one receiver per socket */
    c->tcp_workers = 1;
    c->cache_bytes = 2u << 20;
    c->cache_l1 = 32;
    c->qlog_entries = 256;
#else
    c->udp_workers = 2;
    c->tcp_workers = 4;
    c->cache_bytes = 16u << 20;
    c->cache_l1 = 1024;
    c->qlog_entries = 10000;
#endif
    c->local_only = true;
    c->ratelimit = 0;
    c->refuse_any = true;
    c->protection = true;
    c->block_mode = DNS_BLOCK_DEFAULT;
    c->blocked_ttl = 10;
    c->optimistic = false;
    c->optimistic_max_age = 43200;
    c->strategy = DNS_STRAT_FASTEST;
    c->up_timeout_ms = 1500;
    c->query_timeout_ms = 4000;
    const char *def[] = {"223.5.5.5", "119.29.29.29"};
    for (unsigned i = 0; i < 2; i++) {
        const char *err;
        if (dns_upstream_parse(def[i], &c->up[c->nup], &err)) c->nup++;
    }
}

static bool parse_port(const char *s, size_t n, uint16_t *port) {
    if (!n || n > 5) return false;
    unsigned v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + (unsigned)(s[i] - '0');
    }
    if (!v || v > 65535) return false;
    *port = (uint16_t)v;
    return true;
}

/* host part: "1.2.3.4", "1.2.3.4:53", "[::1]:53", "::1", "name", "name:853",
 * optionally "IP@name" (fixed address for a TLS/HTTPS server name). */
static bool parse_hostport(const char *s, size_t n, dns_upstream_cfg_t *u, bool need_ip, const char **err) {
    const char *at = memchr(s, '@', n);
    if (at) {
        if (!dc_ip_parse(s, (size_t)(at - s), &u->ip)) {
            *err = "invalid address before '@'";
            return false;
        }
        n -= (size_t)(at + 1 - s);
        s = at + 1;
    }
    if (!n) {
        *err = "missing host";
        return false;
    }
    const char *host = s;
    size_t hl = n;
    if (s[0] == '[') {
        const char *rb = memchr(s, ']', n);
        if (!rb) {
            *err = "missing ']'";
            return false;
        }
        host = s + 1;
        hl = (size_t)(rb - s - 1);
        size_t rest = n - (size_t)(rb + 1 - s);
        if (rest) {
            if (rb[1] != ':' || !parse_port(rb + 2, rest - 1, &u->port)) {
                *err = "invalid port";
                return false;
            }
        }
    } else {
        const char *colon = memchr(s, ':', n);
        const char *colon2 = colon ? memchr(colon + 1, ':', n - (size_t)(colon + 1 - s)) : NULL;
        if (colon && !colon2) { /* host:port (a bare IPv6 address has several colons) */
            hl = (size_t)(colon - s);
            if (!parse_port(colon + 1, n - hl - 1, &u->port)) {
                *err = "invalid port";
                return false;
            }
        }
    }
    dc_ip_t ip;
    if (dc_ip_parse(host, hl, &ip)) {
        if (!at) u->ip = ip;
        if (!u->host[0]) {
            if (hl >= sizeof(u->host)) hl = sizeof(u->host) - 1;
            memcpy(u->host, host, hl);
            u->host[hl] = 0;
        }
        return true;
    }
    if (need_ip && !at) {
        *err = "plain DNS upstreams need an IP address";
        return false;
    }
    if (hl == 0 || hl >= sizeof(u->host)) {
        *err = "invalid host name";
        return false;
    }
    for (size_t i = 0; i < hl; i++) {
        char c = host[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) {
            *err = "invalid host name";
            return false;
        }
    }
    memcpy(u->host, host, hl);
    u->host[hl] = 0;
    return true;
}

bool dns_upstream_parse(const char *in, dns_upstream_cfg_t *u, const char **err) {
    memset(u, 0, sizeof(*u));
    *err = NULL;
    while (*in == ' ' || *in == '\t') in++;
    size_t n = strlen(in);
    while (n && (in[n - 1] == ' ' || in[n - 1] == '\t' || in[n - 1] == '\r' || in[n - 1] == '\n')) n--;
    if (!n || n >= sizeof(u->text)) {
        *err = n ? "too long" : "empty";
        return false;
    }
    memcpy(u->text, in, n);
    u->text[n] = 0;
    const char *s = in;
    struct {
        const char *pfx;
        dns_up_proto_t proto;
        uint16_t port;
    } schemes[] = {{"udp://", DNS_UP_UDP, 53}, {"tcp://", DNS_UP_TCP, 53}, {"tls://", DNS_UP_DOT, 853},
                   {"https://", DNS_UP_DOH, 443}};
    u->proto = DNS_UP_UDP;
    u->port = 53;
    for (unsigned i = 0; i < 4; i++) {
        size_t pl = strlen(schemes[i].pfx);
        if (n > pl && dc_strnieq(s, schemes[i].pfx, pl)) {
            u->proto = schemes[i].proto;
            u->port = schemes[i].port;
            s += pl;
            n -= pl;
            break;
        }
    }
    if (strstr(u->text, "://") && (size_t)(s - in) == 0) {
        *err = "unsupported scheme (use udp://, tcp://, tls:// or https://)";
        return false;
    }
    size_t hn = n;
    if (u->proto == DNS_UP_DOH) {
        const char *slash = memchr(s, '/', n);
        if (slash) {
            hn = (size_t)(slash - s);
            size_t pl = n - hn;
            if (pl >= sizeof(u->path)) {
                *err = "path too long";
                return false;
            }
            memcpy(u->path, slash, pl);
            u->path[pl] = 0;
        }
        if (!u->path[0]) strcpy(u->path, "/dns-query");
    }
    bool need_ip = u->proto == DNS_UP_UDP || u->proto == DNS_UP_TCP;
    if (!parse_hostport(s, hn, u, need_ip, err)) return false;
    return true;
}
