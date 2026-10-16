#include "dc_net.h"

#include <stdio.h>
#include <string.h>

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse4(const char *s, size_t n, uint8_t out[4]) {
    size_t i = 0;
    for (int f = 0; f < 4; f++) {
        if (i >= n || s[i] < '0' || s[i] > '9') return false;
        unsigned v = 0;
        size_t st = i;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + (unsigned)(s[i] - '0');
            if (v > 255) return false;
            i++;
        }
        if (i - st > 1 && s[st] == '0') return false; /* leading zero */
        out[f] = (uint8_t)v;
        if (f < 3) {
            if (i >= n || s[i] != '.') return false;
            i++;
        }
    }
    return i == n;
}

static bool parse6(const char *s, size_t n, uint8_t out[16]) {
    uint8_t ip[16];
    memset(ip, 0, sizeof(ip));
    int ellipsis = -1;
    size_t i = 0;
    int k = 0; /* bytes written */
    if (n >= 2 && s[0] == ':' && s[1] == ':') {
        ellipsis = 0;
        i = 2;
        if (i == n) {
            memset(out, 0, 16);
            return true;
        }
    }
    while (i < n) {
        /* hex group or embedded ipv4 */
        size_t st = i;
        unsigned v = 0;
        int nd = 0;
        while (i < n && hexv(s[i]) >= 0) {
            v = v * 16 + (unsigned)hexv(s[i]);
            i++;
            nd++;
            if (nd > 4) return false;
        }
        if (nd == 0) return false;
        if (i < n && s[i] == '.') {
            /* embedded IPv4 must be last and fit */
            if (k > 12) return false;
            if (!parse4(s + st, n - st, ip + k)) return false;
            k += 4;
            i = n;
            break;
        }
        if (k > 14) return false;
        ip[k++] = (uint8_t)(v >> 8);
        ip[k++] = (uint8_t)v;
        if (i == n) break;
        if (s[i] != ':') return false;
        i++;
        if (i < n && s[i] == ':') {
            if (ellipsis >= 0) return false;
            ellipsis = k;
            i++;
            if (i == n) break;
        } else if (i == n) {
            return false; /* trailing single colon */
        }
    }
    if (k < 16) {
        if (ellipsis < 0) return false;
        int tail = k - ellipsis;
        memmove(ip + 16 - tail, ip + ellipsis, (size_t)tail);
        memset(ip + ellipsis, 0, (size_t)(16 - k));
    } else if (ellipsis >= 0) {
        return false; /* "::" must stand for at least one group */
    }
    memcpy(out, ip, 16);
    return true;
}

bool dc_ip_parse(const char *s, size_t n, dc_ip_t *out) {
    memset(out, 0, sizeof(*out));
    if (n == 0 || n > 64) return false;
    bool has_colon = memchr(s, ':', n) != NULL;
    if (!has_colon) {
        if (!parse4(s, n, out->addr)) return false;
        out->family = 4;
        return true;
    }
    const char *pct = (const char *)memchr(s, '%', n);
    size_t m = n;
    if (pct) {
        m = (size_t)(pct - s);
        if (m + 1 >= n) return false; /* empty zone */
    }
    if (!parse6(s, m, out->addr)) return false;
    out->family = 6;
    return true;
}

bool dc_ip_parse_z(const char *s, dc_ip_t *out) { return dc_ip_parse(s, strlen(s), out); }

size_t dc_ip_format(const dc_ip_t *ip, char *buf, size_t cap) {
    if (ip->family == 4) {
        int r = snprintf(buf, cap, "%u.%u.%u.%u", ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3]);
        return r > 0 ? (size_t)r : 0;
    }
    if (ip->family != 6) {
        if (cap) buf[0] = 0;
        return 0;
    }
    uint16_t g[8];
    for (int i = 0; i < 8; i++) g[i] = (uint16_t)((ip->addr[2 * i] << 8) | ip->addr[2 * i + 1]);
    /* IPv4-mapped */
    if (!g[0] && !g[1] && !g[2] && !g[3] && !g[4] && g[5] == 0xffff) {
        int r = snprintf(buf, cap, "::ffff:%u.%u.%u.%u", ip->addr[12], ip->addr[13], ip->addr[14],
                         ip->addr[15]);
        return r > 0 ? (size_t)r : 0;
    }
    int best = -1, bestlen = 0;
    for (int i = 0; i < 8;) {
        if (g[i]) {
            i++;
            continue;
        }
        int j = i;
        while (j < 8 && !g[j]) j++;
        if (j - i > bestlen && j - i >= 2) {
            best = i;
            bestlen = j - i;
        }
        i = j;
    }
    size_t o = 0;
    char tmp[48];
    for (int i = 0; i < 8; i++) {
        if (i == best) {
            tmp[o++] = ':';
            if (i == 0) tmp[o++] = ':';
            i += bestlen - 1;
            continue;
        }
        o += (size_t)snprintf(tmp + o, sizeof(tmp) - o, "%x", g[i]);
        if (i < 7) tmp[o++] = ':';
    }
    tmp[o] = 0;
    return (size_t)snprintf(buf, cap, "%s", tmp);
}

bool dc_prefix_parse(const char *s, size_t n, dc_prefix_t *out) {
    const char *sl = (const char *)memchr(s, '/', n);
    if (!sl) return false;
    if (!dc_ip_parse(s, (size_t)(sl - s), &out->ip)) return false;
    if (memchr(s, '%', (size_t)(sl - s))) return false; /* zones not allowed in prefixes */
    size_t i = (size_t)(sl - s) + 1;
    if (i >= n) return false;
    unsigned b = 0;
    size_t st = i;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
        b = b * 10 + (unsigned)(s[i] - '0');
        if (b > 128) return false;
        i++;
    }
    if (i != n || i == st || (i - st > 1 && s[st] == '0')) return false;
    unsigned maxb = out->ip.family == 4 ? 32 : 128;
    if (b > maxb) return false;
    out->bits = (uint8_t)b;
    /* mask host bits */
    unsigned nbytes = maxb / 8;
    for (unsigned k = 0; k < nbytes; k++) {
        unsigned lo = k * 8;
        if (lo >= b)
            out->ip.addr[k] = 0;
        else if (b - lo < 8)
            out->ip.addr[k] &= (uint8_t)(0xFF << (8 - (b - lo)));
    }
    return true;
}

bool dc_prefix_contains(const dc_prefix_t *p, const dc_ip_t *ip) {
    if (p->ip.family != ip->family || (ip->family != 4 && ip->family != 6)) return false;
    unsigned b = p->bits;
    if (b > (ip->family == 4 ? 32u : 128u)) return false;
    unsigned full = b / 8;
    if (memcmp(p->ip.addr, ip->addr, full) != 0) return false;
    unsigned rem = b % 8;
    if (!rem) return true;
    uint8_t m = (uint8_t)(0xFF << (8 - rem));
    return (p->ip.addr[full] & m) == (ip->addr[full] & m);
}

bool dc_ip_equal(const dc_ip_t *a, const dc_ip_t *b) {
    if (a->family != b->family) return false;
    return memcmp(a->addr, b->addr, a->family == 4 ? 4 : 16) == 0;
}

bool dc_ip_unmap4(dc_ip_t *ip) {
    static const uint8_t pfx[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (ip->family != 6 || memcmp(ip->addr, pfx, 12) != 0) return false;
    memmove(ip->addr, ip->addr + 12, 4);
    memset(ip->addr + 4, 0, 12);
    ip->family = 4;
    return true;
}

bool dc_ip_is_local(const dc_ip_t *ip) {
    const uint8_t *a = ip->addr;
    if (ip->family == 4) {
        if (a[0] == 10 || a[0] == 127) return true;
        if (a[0] == 172 && (a[1] & 0xF0) == 16) return true;
        if (a[0] == 192 && a[1] == 168) return true;
        if (a[0] == 169 && a[1] == 254) return true;
        if (a[0] == 100 && (a[1] & 0xC0) == 64) return true; /* CGNAT 100.64/10 */
        return false;
    }
    if (ip->family == 6) {
        static const uint8_t lo[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        if (memcmp(a, lo, 16) == 0) return true;
        if ((a[0] & 0xFE) == 0xFC) return true;               /* fc00::/7 ULA */
        if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return true; /* fe80::/10 */
        dc_ip_t t = *ip;
        if (dc_ip_unmap4(&t)) return dc_ip_is_local(&t);
        return false;
    }
    return false;
}
