/*
 * dns_wire.h - bounds-checked DNS message parsing and building.
 *
 * Every parser here treats input as hostile: lengths are checked, name
 * compression pointers must point backwards and are limited in number, and
 * no function reads outside [msg, msg + len).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dc_net.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_HDR_LEN 12
#define DNS_MAX_NAME 255   /* wire length incl. root */
#define DNS_HOST_MAX 512   /* presentation buffer (escapes may expand) */
#define DNS_DEFAULT_UDP 512
#define DNS_EDNS_UDP 1232  /* our advertised EDNS(0) payload size (DNS flag day 2020) */
#define DNS_MAX_TTL_OFFS 48

enum { DNS_T_A = 1, DNS_T_NS = 2, DNS_T_CNAME = 5, DNS_T_SOA = 6, DNS_T_PTR = 12, DNS_T_MX = 15,
       DNS_T_TXT = 16, DNS_T_AAAA = 28, DNS_T_SRV = 33, DNS_T_OPT = 41, DNS_T_DS = 43,
       DNS_T_RRSIG = 46, DNS_T_DNSKEY = 48, DNS_T_SVCB = 64, DNS_T_HTTPS = 65, DNS_T_ANY = 255,
       DNS_T_CAA = 257 };
enum { DNS_C_IN = 1 };
enum { DNS_RC_NOERROR = 0, DNS_RC_FORMERR = 1, DNS_RC_SERVFAIL = 2, DNS_RC_NXDOMAIN = 3,
       DNS_RC_NOTIMP = 4, DNS_RC_REFUSED = 5, DNS_RC_BADVERS = 16 };

/* header flag bits (host order of the 16-bit flags word) */
#define DNS_F_QR 0x8000
#define DNS_F_AA 0x0400
#define DNS_F_TC 0x0200
#define DNS_F_RD 0x0100
#define DNS_F_RA 0x0080
#define DNS_F_AD 0x0020
#define DNS_F_CD 0x0010
#define DNS_OPCODE(f) (((f) >> 11) & 0xF)
#define DNS_RCODE(f) ((f) & 0xF)

/* ---- queries -------------------------------------------------------------- */

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint8_t qname[DNS_MAX_NAME]; /* uncompressed wire, case as sent */
    uint16_t qname_len;
    char host[DNS_HOST_MAX]; /* lowercase presentation without trailing dot */
    uint16_t host_len;
    bool host_ok;            /* presentation fit into the buffer */
    uint16_t qtype, qclass;
    uint16_t q_end;          /* offset just after the question */
    /* EDNS(0) */
    bool has_edns;
    uint16_t edns_udp;
    uint8_t edns_version;
    bool do_bit;
} dns_query_t;

enum {
    DNS_PARSE_OK = 0,
    DNS_PARSE_DROP = -1,   /* not a query / too short: ignore silently */
    DNS_PARSE_FORMERR = -2,
    DNS_PARSE_NOTIMP = -3,
    DNS_PARSE_BADVERS = -4,
};

int dns_parse_query(const uint8_t *msg, size_t len, dns_query_t *q);

/* Reads a (possibly compressed) name at *off into wire form (lowercase if
 * lower=true).  Advances *off past the name in the message.  Returns the
 * wire length or -1. */
int dns_read_name(const uint8_t *msg, size_t len, size_t *off, uint8_t *out, bool lower);
/* Skips a name without decoding.  Returns 0 or -1. */
int dns_skip_name(const uint8_t *msg, size_t len, size_t *off);
/* Lowercases wire-format name in place. */
void dns_name_lower(uint8_t *name, size_t len);

/* ---- responses -------------------------------------------------------------- */

typedef struct {
    uint16_t flags;
    uint16_t qdcount, ancount, nscount, arcount;
    uint8_t rcode;              /* incl. extended bits from OPT */
    uint32_t min_ttl;           /* over answer+authority+additional (non-OPT) RRs */
    bool has_soa;
    uint32_t soa_neg_ttl;       /* min(SOA TTL, SOA MINIMUM) from authority */
    bool has_opt;
    uint16_t opt_off, opt_len;  /* OPT RR position */
    uint16_t nttl;
    uint16_t ttl_off[DNS_MAX_TTL_OFFS];
    bool ttl_overflow;          /* more RRs than ttl_off can hold */
    uint16_t an_off;            /* start of the answer section */
    uint16_t end;               /* end of the last RR (trailing bytes are ignored) */
} dns_resp_t;

int dns_parse_response(const uint8_t *msg, size_t len, dns_resp_t *r);

/* Iterates answer RRs for response filtering: calls cb(type, host) with the
 * CNAME target / A / AAAA address / HTTPS hint addresses as text.
 * Stops and returns true when cb returns true. */
typedef bool (*dns_ans_cb)(void *arg, uint16_t type, const char *host, size_t hl);
bool dns_walk_answers(const uint8_t *msg, size_t len, const dns_resp_t *r, dns_ans_cb cb, void *arg);

/* Rewrites every TTL listed in r (or walks the message if overflowed),
 * subtracting `age` seconds (floored at 0) and capping at max_ttl if
 * max_ttl != 0. */
void dns_adjust_ttls(uint8_t *msg, size_t len, const dns_resp_t *r, uint32_t age, uint32_t min_ttl,
                     uint32_t max_ttl);

/* ---- building ------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool overflow;
} dns_buf_t;

/* Starts a response for q: header (ID, RD, CD copied; QR, RA set) + question
 * (case preserved). */
void dns_resp_begin(dns_buf_t *b, const dns_query_t *q, uint8_t rcode, bool ad);
void dns_resp_begin_raw(dns_buf_t *b, uint16_t id, uint16_t qflags, const uint8_t *qname, size_t qlen,
                        uint16_t qtype, uint16_t qclass, uint8_t rcode, bool ad);
/* Appends an RR owned by the question name (compression pointer 0xC00C). */
void dns_resp_rr(dns_buf_t *b, uint16_t type, uint32_t ttl, const void *rdata, uint16_t rdlen);
/* Appends an RR with an explicit owner (wire name, no compression). */
void dns_resp_rr_named(dns_buf_t *b, const uint8_t *owner, size_t olen, uint16_t type, uint32_t ttl,
                       const void *rdata, uint16_t rdlen);
void dns_resp_soa(dns_buf_t *b, const dns_query_t *q, uint32_t ttl); /* AdGuard-style negative SOA */
void dns_resp_soa_raw(dns_buf_t *b, const uint8_t *qname, size_t qlen, uint32_t ttl);
void dns_resp_opt(dns_buf_t *b, uint16_t udp, bool do_bit, uint8_t ext_rcode);
/* Finalizes counts. Returns length or 0 on overflow. */
size_t dns_resp_end(dns_buf_t *b, uint16_t an, uint16_t ns, uint16_t ar);
/* Minimal error response (header + question, optional OPT). */
size_t dns_make_error(uint8_t *out, size_t cap, const uint8_t *query, size_t qlen, const dns_query_t *q,
                      uint8_t rcode);

/* Builds an upstream query: random ID, RD, CD as given, lowercase name,
 * EDNS(0) with our payload size and the DO bit.  Returns length. */
size_t dns_make_query(uint8_t *out, size_t cap, uint16_t id, const uint8_t *qname, size_t qnlen,
                      uint16_t qtype, uint16_t qclass, bool cd, bool do_bit, bool edns);

#ifdef __cplusplus
}
#endif
