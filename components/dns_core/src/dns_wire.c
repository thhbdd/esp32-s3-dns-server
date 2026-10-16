/* dns_wire.c - bounds-checked DNS message codec (see dns_wire.h). */
#include "dns_wire.h"

#include <string.h>

#include "dc_util.h"
#include "fl_filter.h"

#define MAX_PTR_HOPS 64

int dns_read_name(const uint8_t *msg, size_t len, size_t *off, uint8_t *out, bool lower) {
    /* After a compression pointer at position p, the name continues at an
     * earlier position and must also end before p (it refers to a complete
     * earlier name): names never overlap the data that follows them. */
    size_t p = *off, o = 0, limit = len;
    bool jumped = false;
    int hops = 0;
    for (;;) {
        if (p >= limit) return -1;
        uint8_t l = msg[p];
        if ((l & 0xC0) == 0xC0) {
            if (p + 1 >= limit) return -1;
            size_t ptr = ((size_t)(l & 0x3F) << 8) | msg[p + 1];
            if (!jumped) *off = p + 2;
            jumped = true;
            if (ptr >= p || ++hops > MAX_PTR_HOPS) return -1; /* must point backwards */
            limit = p;
            p = ptr;
            continue;
        }
        if (l & 0xC0) return -1; /* extended label types */
        if (l == 0) {
            if (o + 1 > DNS_MAX_NAME) return -1;
            out[o++] = 0;
            if (!jumped) *off = p + 1;
            return (int)o;
        }
        if (p + 1 + l > limit || o + 1 + l + 1 > DNS_MAX_NAME) return -1;
        out[o++] = l;
        for (unsigned i = 0; i < l; i++) out[o + i] = lower ? dc_lower(msg[p + 1 + i]) : msg[p + 1 + i];
        o += l;
        p += 1 + (size_t)l;
    }
}

int dns_skip_name(const uint8_t *msg, size_t len, size_t *off) {
    size_t p = *off;
    unsigned total = 0;
    for (;;) {
        if (p >= len) return -1;
        uint8_t l = msg[p];
        if ((l & 0xC0) == 0xC0) {
            if (p + 1 >= len) return -1;
            *off = p + 2;
            return 0;
        }
        if (l & 0xC0) return -1;
        if (l == 0) {
            *off = p + 1;
            return 0;
        }
        total += 1u + l;
        if (total > DNS_MAX_NAME) return -1;
        p += 1 + (size_t)l;
    }
}

void dns_name_lower(uint8_t *name, size_t len) {
    size_t i = 0;
    while (i < len && name[i]) {
        unsigned l = name[i];
        for (unsigned k = 1; k <= l && i + k < len; k++) name[i + k] = dc_lower(name[i + k]);
        i += 1 + l;
    }
}

/* ---- queries ----------------------------------------------------------------- */

static int skip_rrs(const uint8_t *msg, size_t len, size_t *off, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        if (dns_skip_name(msg, len, off)) return -1;
        if (*off + 10 > len) return -1;
        uint16_t rdlen = dc_be16(msg + *off + 8);
        *off += 10;
        if (*off + rdlen > len) return -1;
        *off += rdlen;
    }
    return 0;
}

int dns_parse_query(const uint8_t *msg, size_t len, dns_query_t *q) {
    q->q_end = 0;
    q->has_edns = false;
    q->do_bit = false;
    q->edns_udp = DNS_DEFAULT_UDP;
    q->edns_version = 0;
    q->host_ok = false;
    q->host_len = 0;
    q->qname_len = 0;
    if (len < DNS_HDR_LEN) return DNS_PARSE_DROP;
    q->id = dc_be16(msg);
    q->flags = dc_be16(msg + 2);
    if (q->flags & DNS_F_QR) return DNS_PARSE_DROP;
    if (DNS_OPCODE(q->flags) != 0) return DNS_PARSE_NOTIMP;
    uint16_t qd = dc_be16(msg + 4), an = dc_be16(msg + 6), ns = dc_be16(msg + 8), ar = dc_be16(msg + 10);
    if (qd != 1) return DNS_PARSE_FORMERR;
    size_t off = DNS_HDR_LEN;
    int nl = dns_read_name(msg, len, &off, q->qname, false);
    if (nl < 0 || off + 4 > len) return DNS_PARSE_FORMERR;
    q->qname_len = (uint16_t)nl;
    q->qtype = dc_be16(msg + off);
    q->qclass = dc_be16(msg + off + 2);
    off += 4;
    q->q_end = (uint16_t)off;
    if (skip_rrs(msg, len, &off, (unsigned)an + ns)) return DNS_PARSE_FORMERR;
    for (unsigned i = 0; i < ar; i++) {
        size_t name_off = off;
        if (dns_skip_name(msg, len, &off) || off + 10 > len) return DNS_PARSE_FORMERR;
        uint16_t type = dc_be16(msg + off);
        uint16_t cls = dc_be16(msg + off + 2);
        uint32_t ttl = dc_be32(msg + off + 4);
        uint16_t rdlen = dc_be16(msg + off + 8);
        off += 10;
        if (off + rdlen > len) return DNS_PARSE_FORMERR;
        if (type == DNS_T_OPT) {
            if (q->has_edns || msg[name_off] != 0) return DNS_PARSE_FORMERR;
            q->has_edns = true;
            q->edns_udp = cls < DNS_DEFAULT_UDP ? DNS_DEFAULT_UDP : cls;
            q->edns_version = (uint8_t)(ttl >> 16);
            q->do_bit = (ttl & 0x8000) != 0;
            for (size_t p = off; p + 4 <= off + rdlen;) { /* options must be well formed */
                uint16_t ol = dc_be16(msg + p + 2);
                if (p + 4 + ol > off + rdlen) return DNS_PARSE_FORMERR;
                p += 4 + (size_t)ol;
            }
        }
        off += rdlen;
    }
    int hl = fl_name_from_wire(q->qname, q->qname_len, q->host, sizeof(q->host));
    if (hl >= 0) {
        q->host_ok = true;
        q->host_len = (uint16_t)hl;
    }
    if (q->has_edns && q->edns_version != 0) return DNS_PARSE_BADVERS;
    return DNS_PARSE_OK;
}

/* ---- responses ------------------------------------------------------------------- */

int dns_parse_response(const uint8_t *msg, size_t len, dns_resp_t *r) {
    memset(r, 0, offsetof(dns_resp_t, ttl_off));
    r->ttl_overflow = false;
    r->an_off = 0;
    r->end = 0;
    if (len < DNS_HDR_LEN || len > 0xFFFF) return -1;
    r->flags = dc_be16(msg + 2);
    if (!(r->flags & DNS_F_QR)) return -1;
    r->qdcount = dc_be16(msg + 4);
    r->ancount = dc_be16(msg + 6);
    r->nscount = dc_be16(msg + 8);
    r->arcount = dc_be16(msg + 10);
    r->rcode = DNS_RCODE(r->flags);
    r->min_ttl = 0xFFFFFFFFu;
    if (r->qdcount != 1) return -1;
    size_t off = DNS_HDR_LEN;
    if (dns_skip_name(msg, len, &off) || off + 4 > len) return -1;
    off += 4;
    r->an_off = (uint16_t)off;
    unsigned total = (unsigned)r->ancount + r->nscount + r->arcount;
    for (unsigned i = 0; i < total; i++) {
        size_t rr_off = off;
        if (dns_skip_name(msg, len, &off) || off + 10 > len) return -1;
        uint16_t type = dc_be16(msg + off);
        uint32_t ttl = dc_be32(msg + off + 4);
        uint16_t rdlen = dc_be16(msg + off + 8);
        size_t ttl_pos = off + 4;
        off += 10;
        if (off + rdlen > len) return -1;
        bool in_ar = i >= (unsigned)r->ancount + r->nscount;
        bool in_ns = !in_ar && i >= r->ancount;
        if (type == DNS_T_OPT && in_ar) {
            if (r->has_opt) return -1;
            r->has_opt = true;
            r->opt_off = (uint16_t)rr_off;
            r->opt_len = (uint16_t)(off + rdlen - rr_off);
            r->rcode = (uint8_t)(r->rcode | ((ttl >> 24) << 4));
        } else {
            if (ttl > 0x7FFFFFFFu) ttl = 0; /* RFC 2181 section 8 */
            if (ttl < r->min_ttl) r->min_ttl = ttl;
            if (r->nttl < DNS_MAX_TTL_OFFS)
                r->ttl_off[r->nttl++] = (uint16_t)ttl_pos;
            else
                r->ttl_overflow = true;
            if (in_ns && type == DNS_T_SOA) {
                size_t p = off;
                if (dns_skip_name(msg, off + rdlen, &p) == 0 && dns_skip_name(msg, off + rdlen, &p) == 0 &&
                    p + 20 <= off + rdlen) {
                    uint32_t minimum = dc_be32(msg + p + 16);
                    r->has_soa = true;
                    r->soa_neg_ttl = ttl < minimum ? ttl : minimum;
                }
            }
        }
        off += rdlen;
    }
    r->end = (uint16_t)off;
    return 0;
}

static size_t fmt_ip(const uint8_t *a, int fam, char *out, size_t cap) {
    dc_ip_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.family = (uint8_t)fam;
    memcpy(ip.addr, a, fam == 4 ? 4 : 16);
    dc_ip_unmap4(&ip); /* Go's net.IP.String prints mapped addresses dotted */
    return dc_ip_format(&ip, out, cap);
}

bool dns_walk_answers(const uint8_t *msg, size_t len, const dns_resp_t *r, dns_ans_cb cb, void *arg) {
    size_t off = r->an_off;
    char host[DNS_HOST_MAX];
    for (unsigned i = 0; i < r->ancount; i++) {
        if (dns_skip_name(msg, len, &off) || off + 10 > len) return false;
        uint16_t type = dc_be16(msg + off);
        uint16_t rdlen = dc_be16(msg + off + 8);
        off += 10;
        if (off + rdlen > len) return false;
        size_t rd = off;
        off += rdlen;
        if (type == DNS_T_CNAME) {
            uint8_t nm[DNS_MAX_NAME];
            size_t p = rd;
            int nl = dns_read_name(msg, len, &p, nm, true);
            if (nl < 0) continue;
            int hl = fl_name_from_wire(nm, (size_t)nl, host, sizeof(host));
            if (hl > 0 && cb(arg, type, host, (size_t)hl)) return true;
        } else if (type == DNS_T_A && rdlen == 4) {
            size_t hl = fmt_ip(msg + rd, 4, host, sizeof(host));
            if (cb(arg, type, host, hl)) return true;
        } else if (type == DNS_T_AAAA && rdlen == 16) {
            size_t hl = fmt_ip(msg + rd, 6, host, sizeof(host));
            if (cb(arg, type, host, hl)) return true;
        } else if (type == DNS_T_HTTPS && rdlen >= 3) {
            size_t p = rd + 2, end = rd + rdlen;
            if (dns_skip_name(msg, end, &p)) continue;
            while (p + 4 <= end) {
                uint16_t key = dc_be16(msg + p), vl = dc_be16(msg + p + 2);
                p += 4;
                if (p + vl > end) break;
                if (key == 4)
                    for (size_t k = 0; k + 4 <= vl; k += 4) {
                        size_t hl = fmt_ip(msg + p + k, 4, host, sizeof(host));
                        if (cb(arg, type, host, hl)) return true;
                    }
                if (key == 6)
                    for (size_t k = 0; k + 16 <= vl; k += 16) {
                        size_t hl = fmt_ip(msg + p + k, 6, host, sizeof(host));
                        if (cb(arg, type, host, hl)) return true;
                    }
                p += vl;
            }
        }
    }
    return false;
}

static void walk_ttls(uint8_t *msg, size_t len, const dns_resp_t *r, uint32_t age, uint32_t mn,
                      uint32_t mx) {
    size_t off = r->an_off;
    unsigned total = (unsigned)r->ancount + r->nscount + r->arcount;
    for (unsigned i = 0; i < total; i++) {
        if (dns_skip_name(msg, len, &off) || off + 10 > len) return;
        uint16_t type = dc_be16(msg + off);
        uint16_t rdlen = dc_be16(msg + off + 8);
        if (type != DNS_T_OPT) {
            uint32_t t = dc_be32(msg + off + 4);
            if (t > 0x7FFFFFFFu) t = 0;
            t = t > age ? t - age : 0;
            if (mn && t < mn) t = mn;
            if (mx && t > mx) t = mx;
            dc_wbe32(msg + off + 4, t);
        }
        off += 10 + (size_t)rdlen;
    }
}

void dns_adjust_ttls(uint8_t *msg, size_t len, const dns_resp_t *r, uint32_t age, uint32_t mn,
                     uint32_t mx) {
    if (r->ttl_overflow) {
        walk_ttls(msg, len, r, age, mn, mx);
        return;
    }
    for (unsigned i = 0; i < r->nttl; i++) {
        uint8_t *p = msg + r->ttl_off[i];
        uint32_t t = dc_be32(p);
        if (t > 0x7FFFFFFFu) t = 0;
        t = t > age ? t - age : 0;
        if (mn && t < mn) t = mn;
        if (mx && t > mx) t = mx;
        dc_wbe32(p, t);
    }
}

/* ---- building ---------------------------------------------------------------------- */

static void put(dns_buf_t *b, const void *d, size_t n) {
    if (b->len + n > b->cap) {
        b->overflow = true;
        return;
    }
    memcpy(b->buf + b->len, d, n);
    b->len += n;
}
static void put16(dns_buf_t *b, uint16_t v) {
    uint8_t t[2];
    dc_wbe16(t, v);
    put(b, t, 2);
}
static void put32(dns_buf_t *b, uint32_t v) {
    uint8_t t[4];
    dc_wbe32(t, v);
    put(b, t, 4);
}

void dns_resp_begin_raw(dns_buf_t *b, uint16_t id, uint16_t qflags, const uint8_t *qname, size_t qlen,
                        uint16_t qtype, uint16_t qclass, uint8_t rcode, bool ad) {
    b->len = 0;
    b->overflow = false;
    uint16_t f = DNS_F_QR | DNS_F_RA | (qflags & (DNS_F_RD | DNS_F_CD)) | (rcode & 0xF);
    if (ad) f |= DNS_F_AD;
    put16(b, id);
    put16(b, f);
    put16(b, 1);
    put16(b, 0);
    put16(b, 0);
    put16(b, 0);
    put(b, qname, qlen);
    put16(b, qtype);
    put16(b, qclass);
}

void dns_resp_begin(dns_buf_t *b, const dns_query_t *q, uint8_t rcode, bool ad) {
    dns_resp_begin_raw(b, q->id, q->flags, q->qname, q->qname_len, q->qtype, q->qclass, rcode, ad);
}

void dns_resp_rr(dns_buf_t *b, uint16_t type, uint32_t ttl, const void *rdata, uint16_t rdlen) {
    put16(b, 0xC00C);
    put16(b, type);
    put16(b, DNS_C_IN);
    put32(b, ttl);
    put16(b, rdlen);
    put(b, rdata, rdlen);
}

void dns_resp_rr_named(dns_buf_t *b, const uint8_t *owner, size_t olen, uint16_t type, uint32_t ttl,
                       const void *rdata, uint16_t rdlen) {
    put(b, owner, olen);
    put16(b, type);
    put16(b, DNS_C_IN);
    put32(b, ttl);
    put16(b, rdlen);
    put(b, rdata, rdlen);
}

void dns_resp_soa(dns_buf_t *b, const dns_query_t *q, uint32_t ttl) {
    dns_resp_soa_raw(b, q->qname, q->qname_len, ttl);
}

void dns_resp_soa_raw(dns_buf_t *b, const uint8_t *qname, size_t qlen, uint32_t ttl) {
    static const uint8_t mname[] = "\x19" "fake-for-negative-caching" "\x07" "adguard" "\x03" "com";
    uint8_t rd[DNS_MAX_NAME * 2 + 40];
    size_t o = 0;
    memcpy(rd, mname, sizeof(mname)); /* includes the terminating root byte */
    o += sizeof(mname);
    static const uint8_t hm[] = "\x0ahostmaster";
    if (qlen > 1 && qlen + sizeof(hm) - 1 <= DNS_MAX_NAME) {
        memcpy(rd + o, hm, sizeof(hm) - 1);
        o += sizeof(hm) - 1;
        memcpy(rd + o, qname, qlen);
        o += qlen;
    } else {
        memcpy(rd + o, hm, sizeof(hm)); /* "hostmaster." */
        o += sizeof(hm);
    }
    static const uint32_t nums[5] = {100500, 1800, 900, 604800, 86400};
    for (int i = 0; i < 5; i++) {
        dc_wbe32(rd + o, nums[i]);
        o += 4;
    }
    dns_resp_rr(b, DNS_T_SOA, ttl, rd, (uint16_t)o);
}

void dns_resp_opt(dns_buf_t *b, uint16_t udp, bool do_bit, uint8_t ext_rcode) {
    uint8_t z = 0;
    put(b, &z, 1);
    put16(b, DNS_T_OPT);
    put16(b, udp);
    put32(b, ((uint32_t)ext_rcode << 24) | (do_bit ? 0x8000u : 0));
    put16(b, 0);
}

size_t dns_resp_end(dns_buf_t *b, uint16_t an, uint16_t ns, uint16_t ar) {
    if (b->overflow || b->len < DNS_HDR_LEN) return 0;
    dc_wbe16(b->buf + 6, an);
    dc_wbe16(b->buf + 8, ns);
    dc_wbe16(b->buf + 10, ar);
    return b->len;
}

size_t dns_make_error(uint8_t *out, size_t cap, const uint8_t *query, size_t qlen, const dns_query_t *q,
                      uint8_t rcode) {
    if (qlen < DNS_HDR_LEN || cap < DNS_HDR_LEN) return 0;
    dns_buf_t b = {out, cap, 0, false};
    uint16_t qf = dc_be16(query + 2);
    uint16_t f = DNS_F_QR | DNS_F_RA | (qf & (DNS_F_RD | DNS_F_CD | 0x7800)) | (rcode & 0xF);
    put(&b, query, 2);
    put16(&b, f);
    bool with_q = q && q->q_end > DNS_HDR_LEN && q->q_end <= qlen && q->qname_len;
    put16(&b, with_q ? 1 : 0);
    put16(&b, 0);
    put16(&b, 0);
    put16(&b, 0);
    if (with_q) { /* the decoded name: the query may use a compression pointer */
        put(&b, q->qname, q->qname_len);
        put16(&b, q->qtype);
        put16(&b, q->qclass);
    }
    bool opt = q && q->has_edns;
    if (opt) dns_resp_opt(&b, DNS_EDNS_UDP, q->do_bit, (uint8_t)(rcode >> 4));
    return dns_resp_end(&b, 0, 0, opt ? 1 : 0);
}

size_t dns_make_query(uint8_t *out, size_t cap, uint16_t id, const uint8_t *qname, size_t qnlen,
                      uint16_t qtype, uint16_t qclass, bool cd, bool do_bit, bool edns) {
    dns_buf_t b = {out, cap, 0, false};
    put16(&b, id);
    put16(&b, (uint16_t)(DNS_F_RD | (cd ? DNS_F_CD : 0) | DNS_F_AD));
    put16(&b, 1);
    put16(&b, 0);
    put16(&b, 0);
    put16(&b, edns ? 1 : 0);
    size_t at = b.len;
    put(&b, qname, qnlen);
    if (!b.overflow) dns_name_lower(out + at, qnlen);
    put16(&b, qtype);
    put16(&b, qclass);
    if (edns) dns_resp_opt(&b, DNS_EDNS_UDP, do_bit, 0);
    return b.overflow ? 0 : b.len;
}
