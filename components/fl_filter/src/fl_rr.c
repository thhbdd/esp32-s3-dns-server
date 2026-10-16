/*
 * fl_rr.c - $dnsrewrite value parsing (urlfilter rules/dnsrewrite.go) and
 * pre-encoding of the answer RDATA (AdGuard Home dnsforward/dnsrewrite.go,
 * svcbmsg.go).  Encoding happens once at compile time, the query path only
 * copies bytes.
 */
#include <stdio.h>
#include <string.h>

#include "fl_internal.h"

static bool all_upper(const char *s, size_t n) {
    if (!n) return false;
    for (size_t i = 0; i < n; i++)
        if (s[i] < 'A' || s[i] > 'Z') return false;
    return true;
}

/* Go strconv.ParseUint(s, 10, 16) */
static bool parse_u16(const char *s, size_t n, uint16_t *out) {
    if (!n) return false;
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + (uint32_t)(s[i] - '0');
        if (v > 0xFFFF) return false;
    }
    *out = (uint16_t)v;
    return true;
}

static bool put(fl_rw_t *rw, const void *d, size_t n) {
    if (rw->rdlen + n > sizeof(rw->rdata)) return false;
    memcpy(rw->rdata + rw->rdlen, d, n);
    rw->rdlen = (uint16_t)(rw->rdlen + n);
    return true;
}
static bool put16(fl_rw_t *rw, uint16_t v) {
    uint8_t b[2];
    dc_wbe16(b, v);
    return put(rw, b, 2);
}
static bool put_name(fl_rw_t *rw, const char *s, size_t n) {
    uint8_t w[256];
    int wl = fl_name_to_wire(s, n, w, sizeof(w));
    return wl > 0 && put(rw, w, (size_t)wl);
}

static int b64v(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* padded=true: base64.StdEncoding, false: RawStdEncoding */
static int b64_decode(const char *s, size_t n, uint8_t *out, size_t cap, bool padded) {
    if (padded) {
        if (n % 4) return -1;
        size_t pad = 0;
        while (pad < 2 && n > pad && s[n - 1 - pad] == '=') pad++;
        n -= pad;
        if (pad && ((n + pad) % 4)) return -1;
    } else {
        if (memchr(s, '=', n)) return -1;
        if (n % 4 == 1) return -1;
    }
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64v((unsigned char)s[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    /* Go rejects non-zero trailing bits only in strict mode; default allows */
    return (int)o;
}

static int svcb_key_code(const char *k, size_t n) {
    static const struct {
        const char *n;
        int c;
    } keys[] = {{"mandatory", 0}, {"alpn", 1},     {"no-default-alpn", 2}, {"port", 3},
                {"ipv4hint", 4},  {"ech", 5},      {"ipv6hint", 6},        {"dohpath", 7},
                {"echconfig", 5}};
    for (size_t i = 0; i < DC_ARRAY_SIZE(keys); i++)
        if (strlen(keys[i].n) == n && memcmp(keys[i].n, k, n) == 0) return keys[i].c;
    return -1;
}

/* mandatory accepts only keys from strToSVCBKey (no dohpath) */
static int svcb_mandatory_code(const char *k, size_t n) {
    if (n == 7 && memcmp(k, "dohpath", 7) == 0) return -1;
    return svcb_key_code(k, n);
}

typedef struct {
    int8_t key;
    uint8_t nl;
    uint16_t vl;
    const char *v;
    const char *name;
} svcp_t;

static int parse_svcb(const char *val, size_t vn, fl_rw_t *rw, const char **err) {
    /* strings.Split(valStr, " ") */
    const char *f[64];
    uint16_t fl[64];
    size_t nf = 0, st = 0;
    for (size_t i = 0; i <= vn; i++) {
        if (i == vn || val[i] == ' ') {
            if (nf >= 64) {
                *err = "too many svcb fields";
                return -2;
            }
            f[nf] = val + st;
            fl[nf++] = (uint16_t)(i - st);
            st = i + 1;
        }
    }
    if (nf < 2) {
        *err = "invalid svcb: need at least two fields";
        return -1;
    }
    uint16_t prio;
    if (!parse_u16(f[0], fl[0], &prio)) {
        *err = "invalid svcb priority";
        return -1;
    }
    if (!(fl[1] == 1 && f[1][0] == '.') && !fl_valid_hostname(f[1], fl[1])) {
        *err = "invalid svcb target";
        return -1;
    }
    /* params: Go map => duplicate keys: last one wins; unknown keys ignored */
    svcp_t ps[16];
    size_t np = 0;
    for (size_t i = 2; i < nf; i++) {
        const char *eq = (const char *)memchr(f[i], '=', fl[i]);
        if (!eq || memchr(eq + 1, '=', fl[i] - (size_t)(eq + 1 - f[i]))) {
            *err = "invalid svcb param";
            return -1;
        }
        size_t kl = (size_t)(eq - f[i]);
        int kc = svcb_key_code(f[i], kl);
        if (kc < 0) continue; /* unknown keys are ignored */
        svcp_t p = {(int8_t)kc, (uint8_t)kl, (uint16_t)(fl[i] - kl - 1), eq + 1, f[i]};
        bool replaced = false;
        for (size_t j = 0; j < np; j++) {
            if (ps[j].nl == kl && memcmp(ps[j].name, f[i], kl) == 0) {
                ps[j] = p;
                replaced = true;
            }
        }
        if (!replaced && np < 16) ps[np++] = p;
    }
    rw->rdlen = 0;
    if (!put16(rw, prio)) goto toolong;
    if (fl[1] == 1 && f[1][0] == '.') {
        uint8_t z = 0;
        if (!put(rw, &z, 1)) goto toolong;
    } else if (!put_name(rw, f[1], fl[1])) {
        goto toolong;
    }
    /* encode valid params sorted by key code; ech and echconfig both map to 5
     * (the later one in map iteration order wins in AdGuard: undefined, we
     * prefer "ech"). */
    for (int key = 0; key <= 7; key++) {
        const svcp_t *sel = NULL;
        for (size_t j = 0; j < np; j++) {
            if (ps[j].key != key) continue;
            if (!sel || (ps[j].nl == 3)) sel = &ps[j]; /* "ech" over "echconfig" */
        }
        if (!sel) continue;
        uint8_t v[512];
        int vl = -1;
        switch (key) {
        case 0: { /* mandatory: single key */
            int c = svcb_mandatory_code(sel->v, sel->vl);
            if (c >= 0) {
                dc_wbe16(v, (uint16_t)c);
                vl = 2;
            }
            break;
        }
        case 1: /* alpn: the whole value is one alpn-id */
            if (sel->vl <= 255) {
                v[0] = (uint8_t)sel->vl;
                memcpy(v + 1, sel->v, sel->vl);
                vl = (int)sel->vl + 1;
            }
            break;
        case 2:
            vl = 0;
            break;
        case 3: {
            uint16_t port;
            if (parse_u16(sel->v, sel->vl, &port)) {
                dc_wbe16(v, port);
                vl = 2;
            }
            break;
        }
        case 4: {
            dc_ip_t ip;
            if (dc_ip_parse(sel->v, sel->vl, &ip) && !memchr(sel->v, '%', sel->vl)) {
                if (ip.family == 4 || dc_ip_unmap4(&ip)) {
                    memcpy(v, ip.addr, 4);
                    vl = 4;
                }
            }
            break;
        }
        case 5: {
            bool padded = sel->nl != 3; /* echconfig uses StdEncoding */
            vl = b64_decode(sel->v, sel->vl, v, sizeof(v), padded);
            break;
        }
        case 6: {
            dc_ip_t ip;
            if (dc_ip_parse(sel->v, sel->vl, &ip) && !memchr(sel->v, '%', sel->vl)) {
                if (ip.family == 4) {
                    memset(v, 0, 10);
                    v[10] = v[11] = 0xff;
                    memcpy(v + 12, ip.addr, 4);
                } else {
                    memcpy(v, ip.addr, 16);
                }
                vl = 16;
            }
            break;
        }
        case 7:
            if (sel->vl <= sizeof(v)) {
                memcpy(v, sel->v, sel->vl);
                vl = (int)sel->vl;
            }
            break;
        }
        if (vl < 0) continue; /* invalid value: ignored like AdGuard */
        if (!put16(rw, (uint16_t)key) || !put16(rw, (uint16_t)vl) || !put(rw, v, (size_t)vl))
            goto toolong;
    }
    return 0;
toolong:
    *err = "rewrite value too long";
    return -2;
}

/* miekg/dns TXT string escapes: \DDD and \X */
static int txt_encode(const char *s, size_t n, fl_rw_t *rw) {
    uint8_t buf[512];
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = (uint8_t)s[i];
        if (b == '\\' && i + 1 < n) {
            if (i + 3 < n + 0 && s[i + 1] >= '0' && s[i + 1] <= '9' && s[i + 2] >= '0' &&
                s[i + 2] <= '9' && s[i + 3] >= '0' && s[i + 3] <= '9') {
                unsigned v = (unsigned)(s[i + 1] - '0') * 100 + (unsigned)(s[i + 2] - '0') * 10 +
                             (unsigned)(s[i + 3] - '0');
                b = (uint8_t)v;
                i += 3;
            } else {
                b = (uint8_t)s[++i];
            }
        }
        if (o >= sizeof(buf)) return -2;
        buf[o++] = b;
    }
    rw->rdlen = 0;
    /* split into <=255 byte character-strings */
    size_t p = 0;
    do {
        size_t c = o - p > 255 ? 255 : o - p;
        uint8_t l = (uint8_t)c;
        if (!put(rw, &l, 1) || !put(rw, buf + p, c)) return -2;
        p += c;
    } while (p < o);
    return 0;
}

int fl_rewrite_parse(const char *s, size_t n, fl_rw_t *rw, const char **err) {
    memset(rw, 0, offsetof(fl_rw_t, rdata));
    *err = NULL;
    const char *sc1 = (const char *)memchr(s, ';', n);
    if (!sc1) {
        /* short form */
        if (n == 0) {
            rw->kind = FLRW_EMPTY;
            return 0;
        }
        if (all_upper(s, n)) {
            int rc = -1;
            if (n == 7 && memcmp(s, "NOERROR", 7) == 0) rc = 0;
            else if (n == 8 && memcmp(s, "SERVFAIL", 8) == 0) rc = 2;
            else if (n == 8 && memcmp(s, "NXDOMAIN", 8) == 0) rc = 3;
            else if (n == 7 && memcmp(s, "REFUSED", 7) == 0) rc = 5;
            if (rc < 0) {
                *err = "unknown dnsrewrite keyword";
                return -1;
            }
            /* DNSRewrite{RCode: 0} equals the empty rewrite */
            rw->kind = rc == 0 ? FLRW_EMPTY : FLRW_RCODE;
            rw->rcode = (uint8_t)rc;
            return 0;
        }
        dc_ip_t ip;
        if (dc_ip_parse(s, n, &ip)) {
            rw->kind = FLRW_RR;
            rw->rrtype = ip.family == 4 ? 1 : 28;
            put(rw, ip.addr, ip.family == 4 ? 4 : 16);
            return 0;
        }
        if (!fl_valid_hostname(s, n)) {
            *err = "invalid shorthand hostname";
            return -1;
        }
        rw->kind = FLRW_CNAME;
        if (!put_name(rw, s, n)) {
            *err = "invalid cname";
            return -1;
        }
        return 0;
    }
    const char *sc2 = (const char *)memchr(sc1 + 1, ';', n - (size_t)(sc1 + 1 - s));
    if (!sc2) {
        *err = "invalid dnsrewrite: expected zero or two delimiters";
        return -1;
    }
    const char *rcs = s;
    size_t rcl = (size_t)(sc1 - s);
    const char *rrs = sc1 + 1;
    size_t rrl = (size_t)(sc2 - rrs);
    const char *val = sc2 + 1;
    size_t vl = n - (size_t)(val - s);

    int rcode = fl_rcode_from_name(rcs, rcl);
    if (rcode < 0) {
        *err = "unknown rcode";
        return -1;
    }
    if (rcode != 0 || (rrl == 0 && vl == 0)) {
        if (rcode > 15) {
            *err = "extended rcode not supported";
            return -2;
        }
        rw->kind = rcode == 0 ? FLRW_EMPTY : FLRW_RCODE;
        rw->rcode = (uint8_t)rcode;
        return 0;
    }
    if ((rrl == 4 && dc_strnieq(rrs, "none", 4)) || (rrl == 8 && dc_strnieq(rrs, "reserved", 8))) {
        *err = "dns rr type is none or reserved";
        return -1;
    }
    uint16_t rr = fl_rrtype_from_name(rrs, rrl);
    if (!rr) {
        *err = "dns rr type is invalid";
        return -1;
    }
    rw->rrtype = rr;
    rw->kind = FLRW_RR;
    switch (rr) {
    case 1: { /* A */
        dc_ip_t ip;
        if (!dc_ip_parse(val, vl, &ip) || ip.family != 4) {
            *err = "not a valid ipv4";
            return -1;
        }
        put(rw, ip.addr, 4);
        return 0;
    }
    case 28: { /* AAAA */
        dc_ip_t ip;
        if (!dc_ip_parse(val, vl, &ip) || ip.family != 6) {
            *err = "not a valid ipv6";
            return -1;
        }
        put(rw, ip.addr, 16);
        return 0;
    }
    case 5: /* CNAME */
        if (!fl_valid_hostname(val, vl)) {
            *err = "invalid cname host";
            return -1;
        }
        rw->kind = FLRW_CNAME;
        rw->rrtype = 0;
        if (!put_name(rw, val, vl)) {
            *err = "invalid cname";
            return -1;
        }
        return 0;
    case 15: { /* MX: SplitN(" ", 2) */
        const char *sp = (const char *)memchr(val, ' ', vl);
        uint16_t pref;
        if (!sp) {
            *err = "invalid mx";
            return -1;
        }
        if (!parse_u16(val, (size_t)(sp - val), &pref)) {
            *err = "invalid mx preference";
            return -1;
        }
        const char *ex = sp + 1;
        size_t exl = vl - (size_t)(ex - val);
        if (!fl_valid_hostname(ex, exl)) {
            *err = "invalid mx exchange";
            return -1;
        }
        if (!put16(rw, pref) || !put_name(rw, ex, exl)) {
            *err = "invalid mx";
            return -1;
        }
        return 0;
    }
    case 12: { /* PTR */
        size_t l = vl;
        if (l && val[l - 1] == '.') l--;
        if (!fl_valid_hostname(val, l)) {
            *err = "invalid ptr host";
            return -1;
        }
        if (!put_name(rw, val, l)) {
            *err = "invalid ptr";
            return -1;
        }
        return 0;
    }
    case 16: { /* TXT */
        int r = txt_encode(val, vl, rw);
        if (r) *err = "txt value too long";
        return r;
    }
    case 64:
    case 65:
        return parse_svcb(val, vl, rw, err);
    case 33: { /* SRV: Split(" "), >= 4 fields */
        const char *f[4];
        size_t fl[4];
        size_t nf = 0, st = 0;
        for (size_t i = 0; i <= vl && nf < 4; i++) {
            if (i == vl || val[i] == ' ') {
                f[nf] = val + st;
                fl[nf++] = i - st;
                st = i + 1;
            }
        }
        if (nf < 4) {
            *err = "invalid srv: need four fields";
            return -1;
        }
        uint16_t pr, w, port;
        if (!parse_u16(f[0], fl[0], &pr) || !parse_u16(f[1], fl[1], &w) ||
            !parse_u16(f[2], fl[2], &port)) {
            *err = "invalid srv number";
            return -1;
        }
        bool root = fl[3] == 1 && f[3][0] == '.';
        if (!root && !fl_valid_hostname(f[3], fl[3])) {
            *err = "invalid srv target";
            return -1;
        }
        put16(rw, pr);
        put16(rw, w);
        put16(rw, port);
        if (root) {
            uint8_t z = 0;
            put(rw, &z, 1);
        } else if (!put_name(rw, f[3], fl[3])) {
            *err = "invalid srv target";
            return -1;
        }
        return 0;
    }
    default:
        /* AdGuard accepts the rule but has no value handler: answers nothing */
        rw->kind = FLRW_NORR;
        return 0;
    }
}

uint16_t fl_rr_type_code(const char *name) { return fl_rrtype_from_name(name, strlen(name)); }

/* CAA: "flags tag value" (value may be quoted) - RFC 8659 */
static int caa_encode(const char *v, fl_rw_t *rw, const char **err) {
    unsigned flags = 0;
    const char *p = v;
    while (*p == ' ') p++;
    if (*p < '0' || *p > '9') goto bad;
    while (*p >= '0' && *p <= '9') flags = flags * 10 + (unsigned)(*p++ - '0');
    if (flags > 255 || *p != ' ') goto bad;
    while (*p == ' ') p++;
    const char *tag = p;
    while (*p && *p != ' ') p++;
    size_t tl = (size_t)(p - tag);
    if (!tl || tl > 15) goto bad;
    for (size_t i = 0; i < tl; i++) {
        char ch = tag[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))) goto bad;
    }
    while (*p == ' ') p++;
    size_t vl = strlen(p);
    if (vl >= 2 && p[0] == '"' && p[vl - 1] == '"') {
        p++;
        vl -= 2;
    }
    rw->rdlen = 0;
    uint8_t h[2] = {(uint8_t)flags, (uint8_t)tl};
    if (!put(rw, h, 2) || !put(rw, tag, tl) || !put(rw, p, vl)) {
        *err = "CAA value too long";
        return -1;
    }
    return 0;
bad:
    *err = "CAA must be: <flags> <tag> <value>";
    return -1;
}

int fl_encode_rdata(const char *type, const char *value, uint8_t *out, size_t cap, uint16_t *rdlen,
                    const char **err) {
    fl_rw_t rw;
    const char *tmp_err;
    if (!err) err = &tmp_err;
    uint16_t t = fl_rrtype_from_name(type, strlen(type));
    if (!t) {
        *err = "unknown record type";
        return -1;
    }
    size_t vl = strlen(value);
    if (vl > 1000) {
        *err = "value too long";
        return -1;
    }
    memset(&rw, 0, offsetof(fl_rw_t, rdata));
    int rc = 0;
    if (t == 257) {
        rc = caa_encode(value, &rw, err);
    } else if (t == 2) { /* NS */
        size_t l = vl;
        if (l && value[l - 1] == '.') l--;
        if (!fl_valid_hostname(value, l)) {
            *err = "invalid host name";
            return -1;
        }
        if (!put_name(&rw, value, l)) {
            *err = "invalid host name";
            return -1;
        }
    } else if (t == 1 || t == 28 || t == 5 || t == 12 || t == 15 || t == 16 || t == 33 || t == 64 || t == 65) {
        char *buf = (char *)dc_malloc(1100);
        if (!buf) {
            *err = "out of memory";
            return -1;
        }
        int bl = snprintf(buf, 1100, "NOERROR;%s;%s", type, value);
        rc = fl_rewrite_parse(buf, bl > 0 ? (size_t)bl : 0, &rw, err);
        dc_free(buf);
        if (rc == 0 && rw.kind == FLRW_CNAME) rw.rrtype = 5;
    } else {
        *err = "record type not supported for local records";
        return -1;
    }
    if (rc) return -1;
    if (rw.rdlen > cap) {
        *err = "record too long";
        return -1;
    }
    memcpy(out, rw.rdata, rw.rdlen);
    *rdlen = rw.rdlen;
    return t;
}
