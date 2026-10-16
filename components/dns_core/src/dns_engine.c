/*
 * dns_engine.c - the query pipeline.
 *
 *   parse -> access control -> rate limit -> local records -> filtering
 *         -> cache (+ response-filter memo) -> forward
 *
 * Blocked / rewritten answers are synthesized exactly like AdGuard Home
 * (internal/dnsforward: genDNSFilterMessage, genForBlockingMode,
 * filterDNSRewrite, processFilteringAfterResponse, filterDNSResponse).
 *
 * Cached messages are normalized upstream answers: ID 0, no OPT record,
 * TTLs clamped.  Per client the ID, the question case, header flags, the
 * OPT record and UDP truncation are applied when the answer is sent.
 */
#include <stdlib.h>
#include <string.h>

#include "dns_internal.h"

/* ---- policy ----------------------------------------------------------------- */

static bool access_ok(const dns_config_t *cfg, const dns_peer_t *p) {
    if (p->transport == DNS_TR_INTERNAL || !cfg->local_only) return true;
    if (dc_ip_is_local(&p->ip)) return true;
    for (unsigned i = 0; i < cfg->nallow; i++)
        if (dc_prefix_contains(&cfg->allow[i], &p->ip)) return true;
    return false;
}

/* token bucket per client address (IPv6: per /64) */
static bool ratelimit_ok(dns_server_t *s, uint32_t rate, const dc_ip_t *ip0) {
    dc_ip_t ip = *ip0;
    if (ip.family == 6) memset(ip.addr + 8, 0, 8);
    if (rate > 1000000) rate = 1000000;
    uint32_t h = dc_fmix32(dc_fnv32(ip.addr, ip.family == 4 ? 4 : 16) ^ ip.family) & (DNS_RL_SLOTS - 1);
    uint32_t now = dc_time_ms(), cap = rate * 1000u;
    dc_mutex_lock(s->rlmu);
    rl_slot_t *sl = &s->rl[h];
    if (!dc_ip_equal(&sl->ip, &ip)) {
        sl->ip = ip;
        sl->tokens = cap;
    } else {
        uint64_t t = (uint64_t)sl->tokens + (uint64_t)(now - sl->last_ms) * rate;
        sl->tokens = t > cap ? cap : (uint32_t)t;
    }
    sl->last_ms = now;
    bool ok = sl->tokens >= 1000;
    if (ok) sl->tokens -= 1000;
    dc_mutex_unlock(s->rlmu);
    return ok;
}

/* ---- message helpers ------------------------------------------------------------ */

static void syn_begin(dns_buf_t *b, const cq_t *cq, uint8_t rcode) {
    dns_resp_begin_raw(b, cq->id, cq->flags, cq->qname, cq->qname_len, cq->qtype, cq->qclass, rcode, false);
}

/* Drops trailing records until the message fits `limit`.  Keeps every
 * answer/authority record or falls back to an empty TC=1 response. */
static size_t truncate_msg(uint8_t *buf, size_t len, size_t limit) {
    unsigned an = dc_be16(buf + 6), ns = dc_be16(buf + 8), ar = dc_be16(buf + 10);
    size_t off = DNS_HDR_LEN;
    if (dc_be16(buf + 4) != 1 || dns_skip_name(buf, len, &off) || off + 4 > len) return 0;
    off += 4;
    size_t q_end = off, keep_end = off;
    unsigned keep = 0, total = an + ns + ar;
    for (unsigned i = 0; i < total; i++) {
        if (dns_skip_name(buf, len, &off) || off + 10 > len) break;
        size_t e = off + 10 + dc_be16(buf + off + 8);
        if (e > len || e > limit) break;
        off = e;
        keep = i + 1;
        keep_end = e;
    }
    if (keep >= an + ns) {
        dc_wbe16(buf + 10, (uint16_t)(keep - an - ns));
        return keep_end;
    }
    dc_wbe16(buf + 2, (uint16_t)(dc_be16(buf + 2) | DNS_F_TC));
    dc_wbe16(buf + 6, 0);
    dc_wbe16(buf + 8, 0);
    dc_wbe16(buf + 10, 0);
    return q_end;
}

/* Fits a message (without OPT) to the client's transport and appends our OPT
 * record if the client used EDNS(0).  In place; returns the new length. */
static size_t fit_and_opt(const cq_t *cq, uint8_t *buf, size_t len, size_t cap, uint8_t ext_rcode) {
    if (!len) return 0;
    size_t optlen = cq->has_edns ? 11 : 0;
    size_t limit = 65535;
    if (cq->transport == DNS_TR_UDP) {
        limit = cq->has_edns ? cq->edns_udp : DNS_DEFAULT_UDP;
        if (limit > DNS_MSG_MAX) limit = DNS_MSG_MAX;
    }
    if (len + optlen > limit) len = truncate_msg(buf, len, limit - optlen);
    if (!len || len + optlen > cap) return 0;
    if (optlen) {
        uint8_t *p = buf + len;
        p[0] = 0;
        dc_wbe16(p + 1, DNS_T_OPT);
        dc_wbe16(p + 3, DNS_EDNS_UDP);
        dc_wbe32(p + 5, ((uint32_t)ext_rcode << 24) | (cq->do_bit ? 0x8000u : 0));
        dc_wbe16(p + 9, 0);
        dc_wbe16(buf + 10, (uint16_t)(dc_be16(buf + 10) + 1));
        len += 11;
    }
    return len;
}

static size_t syn_error(const cq_t *cq, uint8_t rcode, uint8_t *out, size_t cap) {
    dns_buf_t b = {out, cap, 0, false};
    syn_begin(&b, cq, rcode);
    return fit_and_opt(cq, out, dns_resp_end(&b, 0, 0, 0), cap, (uint8_t)(rcode >> 4));
}

/* AdGuard Home genDNSFilterMessage (requests blocked by rules or responses
 * blocked by response filtering). */
static size_t syn_blocked(const dns_config_t *cfg, const cq_t *cq, const fl_result_t *r, uint8_t *out,
                          size_t cap) {
    static const uint8_t zero[16] = {0};
    dns_buf_t b = {out, cap, 0, false};
    uint32_t ttl = cfg->blocked_ttl;
    uint16_t an = 0, ns = 0, qt = cq->qtype;
    if (qt != DNS_T_A && qt != DNS_T_AAAA) {
        syn_begin(&b, cq, DNS_RC_NOERROR);
        if (cfg->block_mode != DNS_BLOCK_NULL_IP) { /* NODATA */
            dns_resp_soa_raw(&b, cq->qname, cq->qname_len, ttl);
            ns = 1;
        }
    } else {
        int fam = qt == DNS_T_A ? 4 : 6;
        uint16_t al = qt == DNS_T_A ? 4 : 16;
        switch (cfg->block_mode) {
        case DNS_BLOCK_CUSTOM_IP: {
            const dc_ip_t *ip = qt == DNS_T_A ? &cfg->custom_v4 : &cfg->custom_v6;
            syn_begin(&b, cq, DNS_RC_NOERROR);
            if (ip->family == fam) {
                dns_resp_rr(&b, qt, ttl, ip->addr, al);
                an = 1;
            }
            break;
        }
        case DNS_BLOCK_NXDOMAIN:
            syn_begin(&b, cq, DNS_RC_NXDOMAIN);
            dns_resp_soa_raw(&b, cq->qname, cq->qname_len, ttl);
            ns = 1;
            break;
        case DNS_BLOCK_REFUSED:
            syn_begin(&b, cq, DNS_RC_REFUSED);
            break;
        case DNS_BLOCK_DEFAULT:
            if (r && r->n_ips) { /* /etc/hosts rules answer with their addresses */
                syn_begin(&b, cq, DNS_RC_NOERROR);
                for (unsigned i = 0; i < r->n_ips; i++)
                    if (r->ips[i].family == fam) {
                        dns_resp_rr(&b, qt, ttl, r->ips[i].addr, al);
                        an++;
                    }
                break;
            }
            /* fall through */
        default: /* null IP */
            syn_begin(&b, cq, DNS_RC_NOERROR);
            dns_resp_rr(&b, qt, ttl, zero, al);
            an = 1;
            break;
        }
    }
    return fit_and_opt(cq, out, dns_resp_end(&b, an, ns, 0), cap, 0);
}

/* AdGuard Home filterDNSRewrite ($dnsrewrite with an RCODE or records) */
static size_t syn_rewrite(const dns_config_t *cfg, const cq_t *cq, const fl_result_t *r, uint8_t *out,
                          size_t cap) {
    dns_buf_t b = {out, cap, 0, false};
    if (r->rw_kind == FL_RW_RCODE) {
        syn_begin(&b, cq, r->rcode);
        return fit_and_opt(cq, out, dns_resp_end(&b, 0, 0, 0), cap, (uint8_t)(r->rcode >> 4));
    }
    syn_begin(&b, cq, DNS_RC_NOERROR);
    for (unsigned i = 0; i < r->n_rr; i++) dns_resp_rr(&b, r->rr[i].type, cfg->blocked_ttl, r->rr[i].rdata, r->rr[i].rdlen);
    return fit_and_opt(cq, out, dns_resp_end(&b, r->n_rr, 0, 0), cap, 0);
}

/* wire length of an uncompressed, validated name */
static size_t wire_len(const uint8_t *n) {
    size_t i = 0;
    while (n[i] && i < DNS_MAX_NAME) i += 1 + (size_t)n[i];
    return i + 1;
}

/* appends a record whole or not at all: 1, or -1 when it does not fit */
static int put_rr(dns_buf_t *b, const uint8_t *owner, size_t olen, uint16_t type, uint32_t ttl, const void *rd,
                  uint16_t rdlen) {
    size_t before = b->len;
    dns_resp_rr_named(b, owner, olen, type, ttl, rd, rdlen);
    if (!b->overflow) return 1;
    b->len = before;
    b->overflow = false;
    return -1;
}

/* Copies one RR with every name decompressed (owner and the names inside
 * RDATA of the classic types).  Returns 1 when copied, 0 when skipped (not
 * class IN) or -1 on a malformed record or when the buffer is full. */
static int copy_rr(const uint8_t *msg, size_t n, size_t *off, dns_buf_t *b) {
    uint8_t owner[DNS_MAX_NAME];
    int ol = dns_read_name(msg, n, off, owner, false);
    if (ol < 0 || *off + 10 > n) return -1;
    uint16_t type = dc_be16(msg + *off), cls = dc_be16(msg + *off + 2);
    uint32_t ttl = dc_be32(msg + *off + 4);
    uint16_t rdlen = dc_be16(msg + *off + 8);
    size_t rd = *off + 10;
    if (rd + rdlen > n) return -1;
    *off = rd + rdlen;
    if (cls != DNS_C_IN) return 0; /* (not produced for IN questions) */
    uint8_t tmp[DNS_MAX_NAME * 2 + 32];
    size_t pre = 0, names = 0, tl = 0;
    switch (type) {
    case DNS_T_CNAME:
    case DNS_T_NS:
    case DNS_T_PTR:
    case 39: /* DNAME */
        names = 1;
        break;
    case DNS_T_MX:
        pre = 2;
        names = 1;
        break;
    case DNS_T_SRV:
        pre = 6;
        names = 1;
        break;
    case DNS_T_SOA:
        names = 2;
        break;
    default:
        return put_rr(b, owner, (size_t)ol, type, ttl, msg + rd, rdlen);
    }
    if (pre > rdlen) return -1;
    memcpy(tmp, msg + rd, pre);
    tl = pre;
    size_t p = rd + pre;
    for (size_t k = 0; k < names; k++) {
        int nl = dns_read_name(msg, rd + rdlen, &p, tmp + tl, false);
        if (nl < 0) return -1;
        tl += (size_t)nl;
    }
    if (type == DNS_T_SOA) {
        if (p + 20 > rd + rdlen) return -1;
        memcpy(tmp + tl, msg + p, 20);
        tl += 20;
    }
    return put_rr(b, owner, (size_t)ol, type, ttl, tmp, (uint16_t)tl);
}

/* AdGuard Home processFilteringAfterResponse for CNAME rewrites: restore the
 * original question and prepend "orig CNAME target" when there are answers. */
static size_t cname_wrap(const cq_t *cq, const uint8_t *target, size_t tlen, uint32_t ttl, const uint8_t *msg,
                         size_t n, uint8_t *out, size_t cap) {
    dns_resp_t r;
    if (dns_parse_response(msg, n, &r)) return 0;
    dns_buf_t b = {out, cap, 0, false};
    syn_begin(&b, cq, (uint8_t)(r.rcode & 0xF));
    if (b.len >= 4) dc_wbe16(out + 2, r.flags); /* keep the upstream flags; fixed up by the caller */
    uint16_t an = 0;
    if (r.ancount) {
        dns_resp_rr(&b, DNS_T_CNAME, ttl, target, (uint16_t)tlen);
        an++;
        size_t off = r.an_off;
        for (unsigned i = 0; i < r.ancount; i++) {
            int k = copy_rr(msg, n, &off, &b);
            if (k < 0) break;
            an = (uint16_t)(an + k);
        }
    }
    return dns_resp_end(&b, an, 0, 0);
}

/* Turns a normalized upstream/cached message into the answer for one client. */
static size_t finish_upstream(const cq_t *cq, const uint8_t *msg, size_t n, uint8_t *out, size_t cap,
                              uint8_t ext, uint32_t cname_ttl, const uint8_t *target, size_t tlen) {
    size_t len;
    if (cq->cname_rw) {
        len = cname_wrap(cq, target, tlen, cname_ttl, msg, n, out, cap);
        if (!len) return 0;
    } else {
        if (n > cap || DNS_HDR_LEN + (size_t)cq->qname_len > n) return 0;
        if (msg != out) memcpy(out, msg, n);
        memcpy(out + DNS_HDR_LEN, cq->qname, cq->qname_len); /* restore the client's case */
        len = n;
    }
    dc_wbe16(out, cq->id);
    uint16_t f = dc_be16(out + 2);
    uint16_t nf = (uint16_t)(DNS_F_QR | DNS_F_RA | (f & (DNS_F_AA | DNS_F_TC | 0xF)) |
                             (cq->flags & (DNS_F_RD | DNS_F_CD)));
    if ((f & DNS_F_AD) && (cq->do_bit || (cq->flags & DNS_F_AD))) nf |= DNS_F_AD; /* RFC 6840 5.8 */
    dc_wbe16(out + 2, nf);
    return fit_and_opt(cq, out, len, cap, ext);
}

/* ---- response filtering (AdGuard Home filterDNSResponse) ------------------------ */

typedef struct {
    const fl_set_t *set;
    fl_result_t *res;
} rf_t;

static bool rf_cb(void *arg, uint16_t type, const char *host, size_t hl) {
    rf_t *rf = (rf_t *)arg;
    fl_req_t rq = {host, (uint16_t)hl, type, 0, NULL};
    fl_match(rf->set, &rq, rf->res);
    return rf->res->verdict == FL_V_BLOCK;
}

static bool resp_blocked(const view_t *v, const uint8_t *msg, size_t n, fl_result_t *res) {
    dns_resp_t r;
    if (dns_parse_response(msg, n, &r) || !r.ancount) return false;
    rf_t rf = {v->filters, res};
    return dns_walk_answers(msg, n, &r, rf_cb, &rf);
}

/* ---- local records ------------------------------------------------------------------ */

enum { L_NONE = 0, L_ANSWERED, L_FORWARD };

static int find_type(const dns_lentry_t *e, uint16_t qtype, const dns_lrec_t **cname) {
    int found = 0;
    *cname = NULL;
    for (unsigned i = 0; i < e->n; i++) {
        const dns_lrec_t *r = &e->recs[i];
        if (r->type == qtype) {
            if (r->passthrough) return -1;
            found++;
        } else if (r->type == DNS_T_CNAME && !r->passthrough && !*cname) {
            *cname = r;
        }
    }
    return found;
}

static int try_local(const view_t *v, const cq_t *cq, const char *host, size_t hl, uint8_t *out, size_t cap,
                     size_t *olen, uint8_t *target, size_t *tlen, uint32_t *cname_ttl) {
    const dns_local_t *l = v->local->l;
    dns_lentry_t e;
    if (!dns_local_lookup(l, host, hl, &e)) return L_NONE;
    const dns_lrec_t *cn;
    int nf = find_type(&e, cq->qtype, &cn);
    if (nf < 0) return L_NONE;
    dns_buf_t b = {out, cap, 0, false};
    syn_begin(&b, cq, DNS_RC_NOERROR);
    uint16_t an = 0, ns = 0;
    if (nf > 0) {
        for (unsigned i = 0; i < e.n; i++)
            if (e.recs[i].type == cq->qtype) {
                dns_resp_rr(&b, cq->qtype, e.recs[i].ttl, e.recs[i].rdata, e.recs[i].rdlen);
                an++;
            }
    } else if (cn) {
        /* follow local CNAMEs; answer "orig CNAME final" + final records
         * (AdGuard Home rewrites), or forward the final name */
        const dns_lrec_t *hop = cn;
        uint32_t cttl = cn->ttl;
        for (int depth = 0;; depth++) {
            char th[DNS_HOST_MAX];
            int thl = fl_name_from_wire(hop->rdata, hop->rdlen, th, sizeof(th));
            dns_lentry_t e2;
            const dns_lrec_t *cn2 = NULL;
            int nf2 = 0;
            bool known = thl >= 0 && depth < 8 && dns_local_lookup(l, th, (size_t)thl, &e2);
            if (known) nf2 = find_type(&e2, cq->qtype, &cn2);
            if (!known || nf2 < 0) {
                memcpy(target, hop->rdata, hop->rdlen);
                *tlen = hop->rdlen;
                *cname_ttl = cttl;
                return L_FORWARD;
            }
            if (nf2 > 0) {
                dns_resp_rr(&b, DNS_T_CNAME, cttl, hop->rdata, hop->rdlen);
                an++;
                for (unsigned i = 0; i < e2.n; i++)
                    if (e2.recs[i].type == cq->qtype) {
                        dns_resp_rr_named(&b, hop->rdata, hop->rdlen, cq->qtype, e2.recs[i].ttl, e2.recs[i].rdata,
                                          e2.recs[i].rdlen);
                        an++;
                    }
                break;
            }
            if (!cn2) { /* the final name exists locally without this type */
                dns_resp_rr(&b, DNS_T_CNAME, cttl, hop->rdata, hop->rdlen);
                an++;
                break;
            }
            hop = cn2;
        }
    } else {
        /* the name is local but has no record of this type: NODATA */
        dns_resp_soa_raw(&b, cq->qname, cq->qname_len, e.recs[0].ttl); /* (entries have >= 1 record) */
        ns = 1;
    }
    *olen = fit_and_opt(cq, out, dns_resp_end(&b, an, ns, 0), cap, 0);
    return L_ANSWERED;
}

/* RFC 6303-style local empty reverse zones.  Resolve configured local PTR
 * records and explicit filter rules first; never leak other private reverse
 * lookups to public upstream DNS.  No additional heap allocations. */
static bool reverse_zone_matches(const char *name, size_t len, const char *zone) {
    size_t zlen = strlen(zone);
    return len >= zlen && memcmp(name + len - zlen, zone, zlen) == 0 &&
           (len == zlen || name[len - zlen - 1] == '.');
}

/* e.g. 7.31.172.in-addr.arpa: check the decimal label before 172. */
static bool reverse_zone_octet_range(const char *name, size_t len, const char *zone,
                                     unsigned low, unsigned high) {
    size_t zlen = strlen(zone);
    if (!reverse_zone_matches(name, len, zone) || len <= zlen + 1) return false;
    size_t end = len - zlen - 1;
    size_t begin = end;
    while (begin && name[begin - 1] != '.') begin--;
    if (end == begin || end - begin > 3) return false;
    unsigned val = 0;
    for (size_t i = begin; i < end; i++) {
        if (name[i] < '0' || name[i] > '9') return false;
        val = val * 10u + (unsigned)(name[i] - '0');
    }
    return val >= low && val <= high;
}

static bool private_reverse_ptr(const char *name, size_t len) {
    static const char *const zones[] = {
        "0.in-addr.arpa",           /* 0/8 (this network) */
        "10.in-addr.arpa",          /* RFC 1918: 10/8 */
        "127.in-addr.arpa",         /* loopback */
        "254.169.in-addr.arpa",     /* IPv4 link-local: 169.254/16 */
        "168.192.in-addr.arpa",     /* RFC 1918: 192.168/16 */
        "c.f.ip6.arpa",            /* IPv6 ULA: fc00::/7 */
        "d.f.ip6.arpa",
        "8.e.f.ip6.arpa",          /* IPv6 link-local: fe80::/10 */
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
    };
    for (size_t i = 0; i < sizeof(zones) / sizeof(zones[0]); i++)
        if (reverse_zone_matches(name, len, zones[i])) return true;
    return reverse_zone_octet_range(name, len, "172.in-addr.arpa", 16, 31) ||
           reverse_zone_octet_range(name, len, "100.in-addr.arpa", 64, 127); /* CGNAT: 100.64/10 */
}

/* ---- pipeline --------------------------------------------------------------------------- */

static void make_key(dns_ckey_t *k, const uint8_t *name, size_t nl, const cq_t *cq) {
    memcpy(k->name, name, nl);
    dns_name_lower(k->name, nl);
    k->name_len = (uint8_t)nl;
    k->qtype = cq->qtype;
    k->qclass = cq->qclass;
    k->flags = (uint8_t)((cq->do_bit ? DNS_CK_DO : 0) | ((cq->flags & DNS_F_CD) ? DNS_CK_CD : 0));
}

static inline uint32_t now_s(void) { return (uint32_t)(dc_time_us() / 1000000u); }

static void count_qtype(dns_server_t *s, uint16_t qt) {
    if (qt == DNS_T_A)
        DNS_STAT_INC(s, qtype_a);
    else if (qt == DNS_T_AAAA)
        DNS_STAT_INC(s, qtype_aaaa);
    else if (qt == DNS_T_HTTPS)
        DNS_STAT_INC(s, qtype_https);
    else
        DNS_STAT_INC(s, qtype_other);
}

int dns_handle(dns_server_t *s, qctx_t *c) {
    view_t *v = dns_view_get(s);
    const dns_config_t *cfg = &v->cfg;
    int ret = H_DONE;
    c->out_len = 0;
    DNS_STAT_INC(s, queries);
    switch (c->peer.transport) {
    case DNS_TR_UDP: DNS_STAT_INC(s, udp); break;
    case DNS_TR_TCP: DNS_STAT_INC(s, tcp); break;
    case DNS_TR_DOT: DNS_STAT_INC(s, dot); break;
    case DNS_TR_DOH: DNS_STAT_INC(s, doh); break;
    default: break;
    }
    if (!access_ok(cfg, &c->peer)) {
        DNS_STAT_INC(s, dropped);
        dns_view_put(v);
        return H_DROP;
    }
    if (cfg->ratelimit && c->peer.transport != DNS_TR_INTERNAL && !ratelimit_ok(s, cfg->ratelimit, &c->peer.ip)) {
        DNS_STAT_INC(s, ratelimited);
        dns_view_put(v);
        return H_DROP;
    }

    dns_query_t q;
    int pr = dns_parse_query(c->msg, c->len, &q);
    if (pr != DNS_PARSE_OK) {
        DNS_STAT_INC(s, malformed);
        if (pr == DNS_PARSE_DROP) {
            DNS_STAT_INC(s, dropped);
            dns_view_put(v);
            return H_DROP;
        }
        uint8_t rc = pr == DNS_PARSE_NOTIMP ? DNS_RC_NOTIMP : pr == DNS_PARSE_BADVERS ? DNS_RC_BADVERS : DNS_RC_FORMERR;
        c->out_len = dns_make_error(c->out, c->cap, c->msg, c->len, &q, rc);
        dns_view_put(v);
        return c->out_len ? H_DONE : H_DROP;
    }

    cq_t cq;
    cq.id = q.id;
    cq.flags = q.flags;
    cq.qtype = q.qtype;
    cq.qclass = q.qclass;
    memcpy(cq.qname, q.qname, q.qname_len);
    cq.qname_len = (uint8_t)q.qname_len;
    cq.has_edns = q.has_edns;
    cq.do_bit = q.do_bit;
    cq.edns_udp = q.edns_udp;
    cq.transport = c->peer.transport;
    cq.ip = c->peer.ip;
    cq.resp_filter = false;
    cq.cname_rw = false;
    cq.rw_ttl = cfg->blocked_ttl;
    cq.result = 0xFF;
    cq.path = P_LOCAL;
    cq.t0 = c->t0;
    count_qtype(s, q.qtype);

    if (cfg->refuse_any && q.qtype == DNS_T_ANY) {
        c->out_len = syn_error(&cq, DNS_RC_NOTIMP, c->out, c->cap);
        cq.result = DNS_QL_REFUSED;
        goto done;
    }

    /* forwarded name (differs for CNAME rewrites) */
    uint8_t fname[DNS_MAX_NAME];
    size_t fname_len = q.qname_len;
    memcpy(fname, q.qname, q.qname_len);

    /* 0. setup hotspot: answer everything with our own address */
    if (v->captive && cq.transport != DNS_TR_INTERNAL && dc_prefix_contains(&v->captive_net, &cq.ip)) {
        dns_buf_t b = {c->out, c->cap, 0, false};
        syn_begin(&b, &cq, DNS_RC_NOERROR);
        uint16_t an = 0;
        if (cq.qtype == DNS_T_A && v->captive_ip.family == 4) {
            dns_resp_rr(&b, DNS_T_A, 1, v->captive_ip.addr, 4);
            an = 1;
        }
        c->out_len = fit_and_opt(&cq, c->out, dns_resp_end(&b, an, 0, 0), c->cap, 0);
        cq.result = DNS_QL_LOCAL;
        goto done;
    }

    /* 1. local records: highest priority, independent of protection */
    if (v->local && q.host_ok) {
        size_t tl = 0;
        int lr = try_local(v, &cq, q.host, q.host_len, c->out, c->cap, &c->out_len, fname, &tl, &cq.rw_ttl);
        if (lr == L_ANSWERED) {
            cq.result = DNS_QL_LOCAL;
            goto done;
        }
        if (lr == L_FORWARD) {
            fname_len = tl;
            cq.cname_rw = true;
            cq.result = DNS_QL_LOCAL;
            goto lookup;
        }
    }

    /* 2. filtering.  A name whose text form is too long to check (binary
     * labels written as \DDD) is refused rather than passed unchecked. */
    if (v->filters && cfg->protection && (!q.host_ok || q.host_len > FL_MAX_HOST)) {
        c->out_len = syn_error(&cq, DNS_RC_REFUSED, c->out, c->cap);
        cq.result = DNS_QL_REFUSED;
        goto done;
    }
    if (v->filters && q.host_ok) {
        fl_req_t rq = {q.host, q.host_len, q.qtype, cfg->protection ? 0u : (uint32_t)FL_REQ_REWRITES_ONLY, NULL};
        fl_result_t fr;
        fl_match(v->filters, &rq, &fr);
        switch (fr.verdict) {
        case FL_V_BLOCK:
            c->out_len = syn_blocked(cfg, &cq, &fr, c->out, c->cap);
            cq.result = DNS_QL_BLOCKED;
            goto done;
        case FL_V_REWRITE:
            if (fr.rw_kind == FL_RW_CNAME) {
                fname_len = wire_len(fr.cname);
                memcpy(fname, fr.cname, fname_len);
                cq.cname_rw = true;
                cq.result = DNS_QL_REWRITTEN;
                break;
            }
            c->out_len = syn_rewrite(cfg, &cq, &fr, c->out, c->cap);
            cq.result = DNS_QL_REWRITTEN;
            goto done;
        case FL_V_ALLOW:
        case FL_V_ALLOWLIST:
            cq.result = DNS_QL_ALLOWED;
            break;
        default:
            cq.resp_filter = cfg->protection;
            break;
        }
    }

lookup:;
    /* Unconfigured private-address PTRs are local NXDOMAIN, not public DNS
     * lookups.  Local records and user rules above retain precedence, while
     * an explicit CNAME rewrite is allowed to resolve its target normally. */
    if (q.qclass == DNS_C_IN && q.qtype == DNS_T_PTR && q.host_ok && !cq.cname_rw &&
        private_reverse_ptr(q.host, q.host_len)) {
        c->out_len = syn_error(&cq, DNS_RC_NXDOMAIN, c->out, c->cap);
        cq.result = DNS_QL_LOCAL;
        goto done;
    }
    /* 3. cache */
    dns_ckey_t key;
    make_key(&key, fname, fname_len, &cq);
    uint32_t khash = dns_ckey_hash(&key);
    if (s->cache) {
        dns_cache_hit_t hit;
        uint8_t *buf = c->out;
        uint8_t *tmp = NULL;
        if (cq.cname_rw) buf = tmp = (uint8_t *)dc_malloc(DNS_MSG_MAX);
        int cr = buf ? dns_cache_get(s->cache, &key, buf, DNS_MSG_MAX, now_s(), DNS_STALE_TTL, &hit) : DNS_CACHE_MISS;
        if (cr != DNS_CACHE_MISS) {
            bool blocked = false;
            fl_result_t fr;
            if (cq.resp_filter && v->filters) {
                if (hit.memo && hit.memo_gen == v->fgen && hit.memo_fp == 1) {
                    blocked = hit.memo == 2 && resp_blocked(v, buf, hit.len, &fr);
                } else {
                    blocked = resp_blocked(v, buf, hit.len, &fr);
                    dns_cache_set_memo(s->cache, &key, v->fgen, 1, blocked ? 2 : 1);
                }
            }
            if (blocked) {
                c->out_len = syn_blocked(cfg, &cq, &fr, c->out, c->cap);
                cq.result = DNS_QL_RESP_BLOCKED;
            } else {
                c->out_len = finish_upstream(&cq, buf, hit.len, c->out, c->cap, (uint8_t)(hit.rcode >> 4),
                                             cq.rw_ttl, key.name, key.name_len);
                if (cq.result == 0xFF) cq.result = DNS_QL_CACHED;
            }
            dc_free(tmp);
            cq.path = P_CACHE;
            if (cr == DNS_CACHE_STALE) { /* optimistic: answer now, refresh behind */
                DNS_STAT_INC(s, stale_served);
                waiter_t *w = dns_waiter_alloc(s);
                if (w) {
                    w->kind = W_REFRESH;
                    w->sync = NULL;
                    w->cq = cq;
                    dns_forward(s, &key, khash, w);
                }
            }
            if (!c->out_len) {
                c->out_len = syn_error(&cq, DNS_RC_SERVFAIL, c->out, c->cap);
                cq.result = DNS_QL_FAILED;
            }
            goto done;
        }
        dc_free(tmp);
    }

    /* 4. forward */
    {
        cq.path = P_FWD;
        if (cq.result == 0xFF) cq.result = DNS_QL_FORWARDED;
        waiter_t *w = dns_waiter_alloc(s);
        if (w) {
            w->kind = c->sync ? W_SYNC : W_UDP;
            w->sock = c->sock;
            w->salen = 0;
            if (c->sa && c->salen <= sizeof(w->sa)) {
                memcpy(&w->sa, c->sa, c->salen);
                w->salen = c->salen;
            }
            w->sync = c->sync;
            w->sync_ticket = c->sync_ticket;
            w->cq = cq;
            if (dns_forward(s, &key, khash, w) == 0) {
                dns_view_put(v);
                return H_PENDING;
            }
        }
        c->out_len = syn_error(&cq, DNS_RC_SERVFAIL, c->out, c->cap);
        cq.result = DNS_QL_FAILED;
    }

done:
    if (!c->out_len) ret = H_DROP;
    dns_stat_query(s, &cq, c->out_len >= 4 ? (uint8_t)(c->out[3] & 0xF) : DNS_RC_SERVFAIL, 0xFF);
    dns_view_put(v);
    return ret;
}

/* ---- upstream completion ----------------------------------------------------------- */

static void deliver(dns_server_t *s, waiter_t *w, const uint8_t *msg, size_t len) {
    if (w->kind == W_UDP) {
        if (len && w->salen) sendto(w->sock, (const char *)msg, len, 0, (const struct sockaddr *)&w->sa, w->salen);
    } else if (w->kind == W_SYNC) {
        dns_sync_deliver(s, w, msg, len);
    }
}

void dns_complete(dns_server_t *s, waiter_t *ws, const dns_ckey_t *key, const uint8_t *resp, size_t len,
                  uint8_t up_idx) {
    view_t *v = dns_view_get(s);
    const dns_config_t *cfg = &v->cfg;
    bool ok = false;
    uint8_t ext = 0;
    size_t nlen = 0;
    size_t ocap = (resp ? 2 * len : 0) + 1024;
    uint8_t *norm = (uint8_t *)dc_malloc((resp ? len : 0) + ocap);
    uint8_t *out = norm ? norm + (resp ? len : 0) : NULL;
    dns_resp_t r;
    if (norm && resp && len >= DNS_HDR_LEN) {
        memcpy(norm, resp, len);
        nlen = len;
        if (dns_parse_response(norm, nlen, &r) == 0) {
            ext = (uint8_t)(r.rcode >> 4);
            if (r.has_opt) { /* normalize: our own OPT is added per client */
                size_t end = (size_t)r.opt_off + r.opt_len;
                memmove(norm + r.opt_off, norm + end, nlen - end);
                nlen -= r.opt_len;
                dc_wbe16(norm + 10, (uint16_t)(dc_be16(norm + 10) - 1));
            }
            dc_wbe16(norm, 0);
            ok = dns_parse_response(norm, nlen, &r) == 0;
            if (ok) nlen = r.end; /* drop trailing garbage: our OPT goes right after the last RR */
            r.rcode = (uint8_t)(r.rcode | (ext << 4));
        }
    }
    if (ok) {
        dns_adjust_ttls(norm, nlen, &r, 0, cfg->cache_min_ttl, cfg->cache_max_ttl);
        uint32_t ttl = 0;
        bool definite = r.rcode == DNS_RC_NOERROR || r.rcode == DNS_RC_NXDOMAIN;
        if (r.rcode == DNS_RC_NOERROR && r.ancount && !r.has_soa) {
            ttl = r.min_ttl == 0xFFFFFFFFu ? 0 : r.min_ttl;
        } else if (definite && r.has_soa) { /* negative (RFC 2308), maybe after a CNAME chain */
            ttl = r.soa_neg_ttl < r.min_ttl ? r.soa_neg_ttl : r.min_ttl;
        }
        if (ttl) {
            if (cfg->cache_min_ttl && ttl < cfg->cache_min_ttl) ttl = cfg->cache_min_ttl;
            if (cfg->cache_max_ttl && ttl > cfg->cache_max_ttl) ttl = cfg->cache_max_ttl;
        }
        if (ttl && s->cache && !(r.flags & DNS_F_TC) && nlen <= DNS_MSG_MAX)
            dns_cache_put(s->cache, key, norm, nlen, &r, ttl, now_s());
        else
            ttl = 0;
        /* a definite answer that cannot be cached replaces an older cached
         * one (which optimistic caching would keep serving otherwise) */
        if (!ttl && definite && s->cache) dns_cache_del(s->cache, key);
        uint8_t memo = 0;
        for (waiter_t *w = ws; w; w = w->next) {
            if (w->kind == W_REFRESH) continue;
            cq_t *cq = &w->cq;
            size_t olen;
            bool blocked = false;
            fl_result_t fr;
            if (cq->resp_filter && v->filters) {
                if (memo) {
                    blocked = memo == 2 && resp_blocked(v, norm, nlen, &fr);
                } else {
                    blocked = resp_blocked(v, norm, nlen, &fr);
                    memo = blocked ? 2 : 1;
                    if (ttl) dns_cache_set_memo(s->cache, key, v->fgen, 1, memo);
                }
            }
            if (blocked) {
                olen = syn_blocked(cfg, cq, &fr, out, ocap);
                cq->result = DNS_QL_RESP_BLOCKED;
            } else {
                olen = finish_upstream(cq, norm, nlen, out, ocap, ext, cq->rw_ttl, key->name, key->name_len);
            }
            if (!olen) {
                olen = syn_error(cq, DNS_RC_SERVFAIL, out, ocap);
                cq->result = DNS_QL_FAILED;
            }
            deliver(s, w, out, olen);
            dns_stat_query(s, cq, olen >= 4 ? (uint8_t)(out[3] & 0xF) : DNS_RC_SERVFAIL, up_idx);
        }
    } else {
        uint8_t local[600];
        for (waiter_t *w = ws; w; w = w->next) {
            if (w->kind == W_REFRESH) continue;
            w->cq.result = DNS_QL_FAILED;
            size_t olen = syn_error(&w->cq, DNS_RC_SERVFAIL, local, sizeof(local));
            deliver(s, w, local, olen);
            dns_stat_query(s, &w->cq, DNS_RC_SERVFAIL, 0xFF);
        }
    }
    dc_free(norm);
    dns_view_put(v);
    dns_waiter_free_list(s, ws);
}
