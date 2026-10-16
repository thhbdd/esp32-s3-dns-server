/*
 * dc_net.h - IP address parsing/formatting and prefix matching.
 *
 * Addresses are kept in a 16-byte buffer; IPv4 uses the first 4 bytes.
 * The parser follows Go's netip.ParseAddr rules (strict dotted decimal,
 * no leading zeros, RFC 4291 IPv6 text form, optional %zone).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t family; /* 4 or 6, 0 = invalid */
    uint8_t addr[16];
} dc_ip_t;

typedef struct {
    dc_ip_t ip;
    uint8_t bits;
} dc_prefix_t;

bool dc_ip_parse(const char *s, size_t n, dc_ip_t *out);
bool dc_ip_parse_z(const char *s, dc_ip_t *out); /* NUL terminated */
/* Writes a canonical textual form (RFC 5952 for IPv6). Returns length. */
size_t dc_ip_format(const dc_ip_t *ip, char *buf, size_t cap);
/* "a.b.c.d/n" or "x::/n".  Host bits are masked. */
bool dc_prefix_parse(const char *s, size_t n, dc_prefix_t *out);
bool dc_prefix_contains(const dc_prefix_t *p, const dc_ip_t *ip);
bool dc_ip_equal(const dc_ip_t *a, const dc_ip_t *b);
/* ::ffff:a.b.c.d -> a.b.c.d (in place); returns true if converted */
bool dc_ip_unmap4(dc_ip_t *ip);
/* Private, loopback, link-local, ULA, CGNAT ranges ("trusted LAN"). */
bool dc_ip_is_local(const dc_ip_t *ip);

#ifdef __cplusplus
}
#endif
