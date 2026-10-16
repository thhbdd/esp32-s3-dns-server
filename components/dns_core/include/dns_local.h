/*
 * dns_local.h - local DNS records ("DNS rewrites" table).
 *
 * Highest priority like AdGuard Home's rewrites: checked before filtering.
 * Names are exact ("nas.home.arpa") or wildcards ("*.home.arpa": any
 * sub-domain, not the domain itself; the longest wildcard wins).  An entry
 * can carry several records of any supported type.  A record value of "-"
 * means "this type is not answered locally" (pass to upstream).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dns_local dns_local_t;

typedef struct {
    uint16_t type;
    uint16_t rdlen;
    uint32_t ttl;
    bool passthrough;
    const uint8_t *rdata;
} dns_lrec_t;

typedef struct {
    const dns_lrec_t *recs;
    unsigned n;
} dns_lentry_t;

dns_local_t *dns_local_new(void);
void dns_local_free(dns_local_t *l);
/* domain: "name" or "*.suffix"; type: "A", "AAAA", "CNAME", ...; value "-" =
 * pass through.  Returns 0 or -1 with err. */
int dns_local_add(dns_local_t *l, const char *domain, const char *type, uint32_t ttl, const char *value,
                  const char **err);
/* Finalizes after all adds (builds lookup structures).  Returns 0, or -1
 * when out of memory (the table is then unchanged and can only be freed). */
int dns_local_seal(dns_local_t *l);
unsigned dns_local_count(const dns_local_t *l);
/* host: lowercase presentation without trailing dot. */
bool dns_local_lookup(const dns_local_t *l, const char *host, size_t hl, dns_lentry_t *out);

#ifdef __cplusplus
}
#endif
