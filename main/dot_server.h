/* Optional DNS-over-TLS listener. No task or TLS buffers until enabled and
 * a server certificate/key have been installed. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "dns_server.h"

void dot_server_set_enabled(bool enabled);
void dot_server_start(dns_server_t *dns, uint16_t port, bool ipv6);
void dot_server_reload_cert(void);
bool dot_server_running(void);
