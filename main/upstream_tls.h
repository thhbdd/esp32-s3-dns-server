/*
 * upstream_tls.h - encrypted upstream transports for the DNS core.
 *
 *   DoT (RFC 7858): one persistent TLS connection per upstream, queries
 *       pipelined and answered out of order; TLS session resumption on
 *       reconnect; idle connections closed after 60 s.
 *   DoH (RFC 8484): HTTP/1.1 keep-alive POSTs, two connections per upstream.
 *
 * Host names are resolved with the bootstrap servers (see net.c); the
 * "IP@name" upstream form skips resolution.
 */
#pragma once

#include "dns_server.h"

void tls_upstreams_init(dns_server_t *srv);
/* (Re)creates the workers for the DoT/DoH upstreams of `c`. */
void tls_upstreams_config(const dns_config_t *c);
