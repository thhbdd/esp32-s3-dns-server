/* Low-memory DNS-over-TLS server (RFC 7858 + RFC 7766 framing).
 * One internal-RAM task, at most one TLS peer at a time. Idle when disabled:
 * no task, sockets or PEM buffers. ESP-TLS allocates the large TLS objects
 * from the regular heap (with PSRAM enabled in sdkconfig).
 */
#include "dot_server.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include "app_config.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#define DOT_STACK 10240
#define DOT_MAX_REQUESTS 64
#define DOT_IDLE_US (30000000LL)
#define DOT_READ_TIMEOUT_US (5000000LL)
static const char *TAG = "dot";
static dns_server_t *g_dns;
static uint16_t g_port;
static volatile bool g_enabled, g_running, g_task_active;
static volatile unsigned g_reload;
static bool g_ipv6;

void dot_server_set_enabled(bool enabled) { g_enabled = enabled; }
bool dot_server_running(void) { return g_running; }
/* Credentials are loaded separately for each new connection. Breaking the
 * current session applies updated certificates without a second TLS task. */
void dot_server_reload_cert(void) { ++g_reload; }

static void set_peer(dns_peer_t *p, const struct sockaddr_storage *a) {
    memset(p, 0, sizeof(*p));
    p->transport = DNS_TR_DOT;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)a;
        p->ip.family = 4;
        memcpy(p->ip.addr, &v4->sin_addr, 4);
        p->port = ntohs(v4->sin_port);
    } else if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)a;
        p->ip.family = 6;
        memcpy(p->ip.addr, &v6->sin6_addr, 16);
        p->port = ntohs(v6->sin6_port);
        dc_ip_unmap4(&p->ip);
    }
}

static bool read_n(esp_tls_t *tls, uint8_t *buf, size_t count) {
    int64_t until = esp_timer_get_time() + DOT_READ_TIMEOUT_US;
    while (count && g_enabled && esp_timer_get_time() < until) {
        int n = esp_tls_conn_read(tls, buf, count);
        if (n > 0) { buf += n; count -= (size_t)n; continue; }
        if (n != ESP_TLS_ERR_SSL_WANT_READ && n != ESP_TLS_ERR_SSL_WANT_WRITE) return false;
        vTaskDelay(1);
    }
    return count == 0;
}

static bool write_n(esp_tls_t *tls, const uint8_t *buf, size_t count) {
    int64_t until = esp_timer_get_time() + DOT_READ_TIMEOUT_US;
    while (count && g_enabled && esp_timer_get_time() < until) {
        int n = esp_tls_conn_write(tls, buf, count);
        if (n > 0) { buf += n; count -= (size_t)n; continue; }
        if (n != ESP_TLS_ERR_SSL_WANT_READ && n != ESP_TLS_ERR_SSL_WANT_WRITE) return false;
        vTaskDelay(1);
    }
    return count == 0;
}

static void process_peer(int fd, const struct sockaddr_storage *addr) {
    size_t cert_len = 0, key_len = 0;
    char *cert = app_blob_load("tls_cert", &cert_len);
    char *key = app_blob_load("tls_key", &key_len);
    if (!cert || !key || !cert_len || !key_len) { free(cert); free(key); close(fd); return; }
    esp_tls_t *tls = esp_tls_init();
    if (!tls) { free(cert); free(key); close(fd); return; }
    esp_tls_cfg_server_t cfg = {
        .servercert_buf = (const unsigned char *)cert,
        .servercert_bytes = (unsigned int)cert_len + 1,
        .serverkey_buf = (const unsigned char *)key,
        .serverkey_bytes = (unsigned int)key_len + 1,
        .tls_handshake_timeout_ms = 5000,
    };
    bool ok = esp_tls_server_session_create(&cfg, fd, tls) == 0;
    free(cert); free(key);
    if (ok) {
        uint8_t *q = malloc(DNS_QUERY_BUF);
        uint8_t *resp = malloc(DNS_QUERY_BUF);
        dns_peer_t peer;
        set_peer(&peer, addr);
        unsigned generation = g_reload;
        int64_t until = esp_timer_get_time() + DOT_IDLE_US;
        if (q && resp) for (unsigned k = 0; k < DOT_MAX_REQUESTS && g_enabled && g_reload == generation; k++) {
            if (esp_timer_get_time() >= until) break;
            uint8_t head[2];
            if (!read_n(tls, head, sizeof(head))) break;
            size_t n = ((size_t)head[0] << 8) | head[1];
            if (n < 12 || n > DNS_QUERY_BUF) break;
            if (!read_n(tls, q, n)) break;
            size_t m = dns_server_query(g_dns, &peer, q, n, resp, DNS_QUERY_BUF);
            if (!m || m > 65535) break;
            head[0] = (uint8_t)(m >> 8);
            head[1] = (uint8_t)m;
            if (!write_n(tls, head, 2) || !write_n(tls, resp, m)) break;
            until = esp_timer_get_time() + DOT_IDLE_US;
        }
        free(q); free(resp);
    }
    /* The ESP-TLS destroy path owns the accepted socket. */
    esp_tls_server_session_delete(tls);
}

static int listen_socket(void) {
    int family = g_ipv6 ? AF_INET6 : AF_INET;
    int s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (family == AF_INET6) {
        int v6only = 0;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        struct sockaddr_in6 addr = {.sin6_family = AF_INET6, .sin6_port = htons(g_port)};
        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(s); return -1; }
    } else {
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(g_port),
                                   .sin_addr.s_addr = htonl(INADDR_ANY)};
        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(s); return -1; }
    }
    if (listen(s, 2) < 0) { close(s); return -1; }
    return s;
}

static void dot_task(void *arg) {
    (void)arg;
    int s = listen_socket();
    if (s < 0) {
        ESP_LOGE(TAG, "could not listen on TCP/%u", (unsigned)g_port);
        g_task_active = false;
        vTaskDelete(NULL);
        return;
    }
    g_running = true;
    ESP_LOGI(TAG, "DNS-over-TLS listening on TCP/%u", (unsigned)g_port);
    while (g_enabled) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s, &readfds);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 250000};
        if (select(s + 1, &readfds, NULL, NULL, &tv) <= 0) continue;
        struct sockaddr_storage a;
        socklen_t len = sizeof(a);
        int fd = accept(s, (struct sockaddr *)&a, &len);
        if (fd < 0) continue;
        struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        process_peer(fd, &a);
    }
    close(s);
    g_running = false;
    g_task_active = false;
    vTaskDelete(NULL);
}

void dot_server_start(dns_server_t *dns, uint16_t port, bool ipv6) {
    if (!g_enabled || g_task_active || !dns) return;
    /* Without a certificate there is no socket and no resident task. */
    size_t n = 0;
    char *cert = app_blob_load("tls_cert", &n);
    bool have_cert = cert && n;
    free(cert);
    if (!have_cert) return;
    g_dns = dns;
    g_port = port ? port : 853;
    g_ipv6 = ipv6;
    g_task_active = true;
    if (xTaskCreate(dot_task, "dns-dot", DOT_STACK, NULL, 4, NULL) != pdPASS) {
        g_task_active = false;
        ESP_LOGE(TAG, "cannot allocate DoT worker task");
    }
}
