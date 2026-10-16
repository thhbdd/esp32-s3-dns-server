/* upstream_tls.c - DoT and DoH upstream transports (see upstream_tls.h). */
#include "upstream_tls.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "dc_port.h"
#include "dc_util.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "esp_vfs_eventfd.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include "esp_heap_caps.h"
#include "lwip/sockets.h"

static const char *TAG = "tlsup";

#define QLEN 48
#define MAX_INFLIGHT 64
#define IDLE_CLOSE_MS 60000
#define DOH_WORKERS 2
#define RESP_MAX 16384
/* worker stacks in PSRAM: safe because code runs from PSRAM (no cache
 * disable during flash writes); keeps internal RAM for Wi-Fi and lwIP */
#define TASK_CAPS (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)

typedef struct {
    uint32_t ticket;
    uint16_t len;
    uint8_t q[DNS_MAX_NAME + 32];
} treq_t;

typedef struct {
    dns_upstream_cfg_t cfg;
    QueueHandle_t q;
    int efd;
    volatile bool stop;
    char name[16];
} worker_t;

static dns_server_t *g_srv;
static SemaphoreHandle_t g_mu;
static worker_t *g_w[DNS_MAX_UPSTREAMS][DOH_WORKERS];
static uint32_t g_rr;

static uint32_t now_ms(void) { return dc_time_ms(); }

static void fail_queue(worker_t *w) {
    treq_t *r;
    while (xQueueReceive(w->q, &r, 0) == pdTRUE)
        if (r) {
            dns_server_fail(g_srv, r->ticket);
            free(r);
        }
}

static void worker_free(worker_t *w) {
    fail_queue(w);
    vQueueDelete(w->q);
    if (w->efd >= 0) close(w->efd);
    free(w);
}

static const char *target_host(const worker_t *w, char *buf, size_t cap) {
    if (w->cfg.ip.family) {
        dc_ip_format(&w->cfg.ip, buf, cap);
        return buf;
    }
    return w->cfg.host;
}

/* ---- DoT ------------------------------------------------------------------------------ */

typedef struct {
    uint16_t id;
    uint32_t ticket;
    uint32_t t;
} infl_t;

typedef struct {
    esp_tls_t *tls;
    esp_tls_client_session_t *sess;
    int fd;
    infl_t infl[MAX_INFLIGHT];
    int ninfl;
    uint8_t *rbuf;
    size_t rlen;
    uint32_t last_act, retry_at, backoff;
} dot_t;

static void dot_close(worker_t *w, dot_t *d, bool fail) {
    if (d->tls) {
        esp_tls_conn_destroy(d->tls);
        d->tls = NULL;
    }
    d->fd = -1;
    d->rlen = 0;
    for (int i = 0; fail && i < d->ninfl; i++) dns_server_fail(g_srv, d->infl[i].ticket);
    d->ninfl = 0;
}

static bool dot_connect(worker_t *w, dot_t *d) {
    if (d->retry_at && (int32_t)(now_ms() - d->retry_at) < 0) return false;
    char ipb[48];
    const char *host = target_host(w, ipb, sizeof(ipb));
    esp_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.timeout_ms = 5000;
    cfg.common_name = w->cfg.host[0] ? w->cfg.host : NULL;
#ifdef CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS
    cfg.client_session = d->sess;
#endif
    esp_tls_t *tls = esp_tls_init();
    if (!tls) return false;
    uint32_t t0 = now_ms();
    if (esp_tls_conn_new_sync(host, (int)strlen(host), w->cfg.port, &cfg, tls) != 1) {
        esp_tls_conn_destroy(tls);
        d->backoff = d->backoff ? (d->backoff * 2 > 30000 ? 30000 : d->backoff * 2) : 1000;
        d->retry_at = now_ms() + d->backoff;
        ESP_LOGW(TAG, "%s: TLS connection failed (retry in %u ms)", w->cfg.text, (unsigned)d->backoff);
        return false;
    }
    d->backoff = 0;
    d->retry_at = 0;
#ifdef CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS
    if (d->sess) esp_tls_free_client_session(d->sess);
    d->sess = esp_tls_get_client_session(tls);
#endif
    d->tls = tls;
    esp_tls_get_conn_sockfd(tls, &d->fd);
    int one = 1;
    setsockopt(d->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    fcntl(d->fd, F_SETFL, fcntl(d->fd, F_GETFL, 0) | O_NONBLOCK);
    d->last_act = now_ms();
    ESP_LOGI(TAG, "%s: connected in %u ms", w->cfg.text, (unsigned)(now_ms() - t0));
    return true;
}

static bool dot_write(dot_t *d, const uint8_t *b, size_t n) {
    uint32_t t0 = now_ms();
    while (n) {
        int k = esp_tls_conn_write(d->tls, b, n);
        if (k > 0) {
            b += k;
            n -= (size_t)k;
            continue;
        }
        if (k != ESP_TLS_ERR_SSL_WANT_WRITE && k != ESP_TLS_ERR_SSL_WANT_READ) return false;
        if (now_ms() - t0 > 3000) return false;
        vTaskDelay(1);
    }
    return true;
}

static void dot_read(worker_t *w, dot_t *d) {
    for (;;) {
        if (d->rlen == RESP_MAX + 2) { /* oversized frame */
            dot_close(w, d, true);
            return;
        }
        int k = esp_tls_conn_read(d->tls, d->rbuf + d->rlen, RESP_MAX + 2 - d->rlen);
        if (k == ESP_TLS_ERR_SSL_WANT_READ || k == ESP_TLS_ERR_SSL_WANT_WRITE) return;
        if (k <= 0) { /* closed by the server or error: unanswered queries fail over */
            dot_close(w, d, true);
            return;
        }
        d->rlen += (size_t)k;
        d->last_act = now_ms();
        size_t p = 0;
        while (d->rlen - p >= 2) {
            size_t l = dc_be16(d->rbuf + p);
            if (d->rlen - p < 2 + l) break;
            const uint8_t *m = d->rbuf + p + 2;
            if (l >= DNS_HDR_LEN) {
                uint16_t id = dc_be16(m);
                for (int i = 0; i < d->ninfl; i++)
                    if (d->infl[i].id == id) {
                        uint32_t t = d->infl[i].ticket;
                        d->infl[i] = d->infl[--d->ninfl];
                        dns_server_deliver(g_srv, t, m, l);
                        break;
                    }
            }
            p += 2 + l;
        }
        memmove(d->rbuf, d->rbuf + p, d->rlen - p);
        d->rlen -= p;
    }
}

static void dot_task(void *arg) {
    worker_t *w = (worker_t *)arg;
    dot_t *d = calloc(1, sizeof(dot_t));
    if (d) d->rbuf = malloc(RESP_MAX + 2);
    if (!d || !d->rbuf) goto out;
    d->fd = -1;
    while (!w->stop) {
        treq_t *r;
        while (!w->stop && xQueueReceive(w->q, &r, 0) == pdTRUE) {
            if (!r) continue;
            bool ok = d->tls || dot_connect(w, d);
            if (ok) {
                uint8_t fr[2 + sizeof(r->q)];
                dc_wbe16(fr, r->len);
                memcpy(fr + 2, r->q, r->len);
                ok = dot_write(d, fr, r->len + 2u);
                if (!ok) dot_close(w, d, true);
            }
            if (ok) {
                if (d->ninfl == MAX_INFLIGHT) { /* the oldest one has long been retried elsewhere */
                    memmove(d->infl, d->infl + 1, sizeof(infl_t) * (MAX_INFLIGHT - 1));
                    d->ninfl--;
                }
                d->infl[d->ninfl].id = dc_be16(r->q);
                d->infl[d->ninfl].ticket = r->ticket;
                d->infl[d->ninfl].t = now_ms();
                d->ninfl++;
                d->last_act = now_ms();
            } else {
                dns_server_fail(g_srv, r->ticket);
            }
            free(r);
        }
        if (d->tls && esp_tls_get_bytes_avail(d->tls) > 0) {
            dot_read(w, d);
            continue;
        }
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(w->efd, &rs);
        int maxfd = w->efd;
        if (d->tls && d->fd >= 0) {
            FD_SET(d->fd, &rs);
            if (d->fd > maxfd) maxfd = d->fd;
        }
        struct timeval tv = {1, 0};
        int n = select(maxfd + 1, &rs, NULL, NULL, &tv);
        if (n > 0 && FD_ISSET(w->efd, &rs)) {
            uint64_t v;
            read(w->efd, &v, sizeof(v));
        }
        if (n > 0 && d->tls && d->fd >= 0 && FD_ISSET(d->fd, &rs)) dot_read(w, d);
        /* housekeeping */
        uint32_t now = now_ms();
        for (int i = 0; i < d->ninfl;)
            if (now - d->infl[i].t > 10000)
                d->infl[i] = d->infl[--d->ninfl];
            else
                i++;
        if (d->tls && !d->ninfl && now - d->last_act > IDLE_CLOSE_MS) dot_close(w, d, false);
    }
out:
    if (d) {
        dot_close(w, d, true);
#ifdef CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS
        if (d->sess) esp_tls_free_client_session(d->sess);
#endif
        free(d->rbuf);
        free(d);
    }
    worker_free(w);
    vTaskDeleteWithCaps(NULL);
}

/* ---- DoH ------------------------------------------------------------------------------- */

typedef struct {
    uint8_t *buf;
    size_t len;
    bool overflow;
} body_t;

static esp_err_t doh_ev(esp_http_client_event_t *e) {
    body_t *b = (body_t *)e->user_data;
    if (e->event_id == HTTP_EVENT_ON_DATA && b) {
        if (b->len + (size_t)e->data_len > RESP_MAX) {
            b->overflow = true;
        } else {
            memcpy(b->buf + b->len, e->data, (size_t)e->data_len);
            b->len += (size_t)e->data_len;
        }
    }
    return ESP_OK;
}

static esp_http_client_handle_t doh_client(worker_t *w, body_t *body) {
    char ipb[48], url[300];
    const char *host = target_host(w, ipb, sizeof(ipb));
    bool v6 = strchr(host, ':') != NULL;
    snprintf(url, sizeof(url), "https://%s%s%s:%u%s", v6 ? "[" : "", host, v6 ? "]" : "", w->cfg.port,
             w->cfg.path[0] ? w->cfg.path : "/dns-query");
    esp_http_client_config_t hc;
    memset(&hc, 0, sizeof(hc));
    hc.url = url;
    hc.method = HTTP_METHOD_POST;
    hc.crt_bundle_attach = esp_crt_bundle_attach;
    hc.keep_alive_enable = true;
    hc.timeout_ms = 5000;
    hc.buffer_size = 2048;
    hc.buffer_size_tx = 1024;
    hc.event_handler = doh_ev;
    hc.user_data = body;
    hc.user_agent = "esp32s3-dns/1.0";
    if (w->cfg.ip.family && w->cfg.host[0]) hc.common_name = w->cfg.host;
    esp_http_client_handle_t cl = esp_http_client_init(&hc);
    if (cl) {
        esp_http_client_set_header(cl, "Content-Type", "application/dns-message");
        esp_http_client_set_header(cl, "Accept", "application/dns-message");
    }
    return cl;
}

static void doh_task(void *arg) {
    worker_t *w = (worker_t *)arg;
    body_t body = {malloc(RESP_MAX), 0, false};
    esp_http_client_handle_t cl = NULL;
    uint32_t last = now_ms(), retry_at = 0, backoff = 0;
    while (!w->stop && body.buf) {
        treq_t *r;
        if (xQueueReceive(w->q, &r, pdMS_TO_TICKS(1000)) != pdTRUE) {
            if (cl && now_ms() - last > IDLE_CLOSE_MS) {
                esp_http_client_cleanup(cl);
                cl = NULL;
            }
            continue;
        }
        if (!r) continue;
        if (retry_at && (int32_t)(now_ms() - retry_at) < 0) { /* recent failure: fail over at once */
            dns_server_fail(g_srv, r->ticket);
            free(r);
            continue;
        }
        bool ok = false;
        /* a kept-alive connection the server has closed meanwhile fails on
         * first use: then once more on a new connection */
        for (int attempt = 0, reused = cl != NULL; attempt < 2 && !ok; attempt++) {
            if (!cl) cl = doh_client(w, &body);
            if (!cl) break;
            body.len = 0;
            body.overflow = false;
            esp_http_client_set_post_field(cl, (const char *)r->q, r->len);
            esp_err_t e = esp_http_client_perform(cl);
            int status = esp_http_client_get_status_code(cl);
            ok = e == ESP_OK && status == 200 && !body.overflow && body.len >= DNS_HDR_LEN;
            if (ok) {
                dns_server_deliver(g_srv, r->ticket, body.buf, body.len);
                backoff = 0;
                retry_at = 0;
            } else if (e != ESP_OK) {
                esp_http_client_cleanup(cl);
                cl = NULL;
                if (reused && attempt == 0) continue;
                ESP_LOGW(TAG, "%s: %s", w->cfg.text, esp_err_to_name(e));
                backoff = backoff ? (backoff * 2 > 30000 ? 30000 : backoff * 2) : 1000;
                retry_at = now_ms() + backoff;
            } else {
                ESP_LOGW(TAG, "%s: HTTP %d", w->cfg.text, status);
                break;
            }
        }
        if (!ok) dns_server_fail(g_srv, r->ticket);
        last = now_ms();
        free(r);
    }
    if (cl) esp_http_client_cleanup(cl);
    free(body.buf);
    worker_free(w);
    vTaskDeleteWithCaps(NULL);
}

/* ---- glue ------------------------------------------------------------------------------- */

static int submit(void *ctx, int up, uint32_t ticket, const uint8_t *q, size_t len) {
    if (up < 0 || up >= DNS_MAX_UPSTREAMS || len > sizeof(((treq_t *)0)->q)) return -1;
    treq_t *r = malloc(sizeof(treq_t));
    if (!r) return -1;
    r->ticket = ticket;
    r->len = (uint16_t)len;
    memcpy(r->q, q, len);
    int rc = -1;
    xSemaphoreTake(g_mu, portMAX_DELAY);
    worker_t *w = g_w[up][0];
    if (!w) {
        w = g_w[up][1];
    } else if (g_w[up][1]) { /* DoH: the less busy connection */
        worker_t *w2 = g_w[up][1];
        UBaseType_t a = uxQueueMessagesWaiting(w->q), b = uxQueueMessagesWaiting(w2->q);
        if (b < a || (a == b && (g_rr++ & 1))) w = w2;
    }
    if (w && xQueueSend(w->q, &r, 0) == pdTRUE) {
        rc = 0;
        if (w->efd >= 0) {
            uint64_t one = 1;
            write(w->efd, &one, sizeof(one));
        }
    }
    xSemaphoreGive(g_mu);
    if (rc) free(r);
    return rc;
}

static void stop_worker(worker_t *w) {
    /* wake it first: once `stop` is set the worker may free itself */
    treq_t *nil = NULL;
    xQueueSend(w->q, &nil, 0);
    if (w->efd >= 0) {
        uint64_t one = 1;
        write(w->efd, &one, sizeof(one));
    }
    w->stop = true;
}

static worker_t *start_worker(int up, const dns_upstream_cfg_t *c, int k) {
    worker_t *w = calloc(1, sizeof(worker_t));
    if (!w) return NULL;
    w->cfg = *c;
    w->efd = -1;
    w->q = xQueueCreate(QLEN, sizeof(treq_t *));
    if (!w->q) {
        free(w);
        return NULL;
    }
    snprintf(w->name, sizeof(w->name), "%s%d.%d", c->proto == DNS_UP_DOT ? "dot" : "doh", up, k);
    BaseType_t ok;
    if (c->proto == DNS_UP_DOT) {
        w->efd = eventfd(0, 0);
        if (w->efd < 0) {
            vQueueDelete(w->q);
            free(w);
            return NULL;
        }
        ok = xTaskCreatePinnedToCoreWithCaps(dot_task, w->name, 12288, w, DC_PRIO_HIGH - 1, NULL, tskNO_AFFINITY,
                                             TASK_CAPS);
    } else {
        ok = xTaskCreatePinnedToCoreWithCaps(doh_task, w->name, 12288, w, DC_PRIO_HIGH - 2, NULL, tskNO_AFFINITY,
                                             TASK_CAPS);
    }
    if (ok != pdPASS) {
        if (w->efd >= 0) close(w->efd);
        vQueueDelete(w->q);
        free(w);
        return NULL;
    }
    return w;
}

void tls_upstreams_init(dns_server_t *srv) {
    g_srv = srv;
    g_mu = xSemaphoreCreateMutex();
    esp_vfs_eventfd_config_t ec = ESP_VFS_EVENTD_CONFIG_DEFAULT();
    ec.max_fds = DNS_MAX_UPSTREAMS + 2;
    esp_vfs_eventfd_register(&ec);
    dns_up_ops_t ops = {submit, NULL};
    dns_server_set_transport(srv, DNS_UP_DOT, &ops);
    dns_server_set_transport(srv, DNS_UP_DOH, &ops);
}

void tls_upstreams_config(const dns_config_t *c) {
    xSemaphoreTake(g_mu, portMAX_DELAY);
    for (int i = 0; i < DNS_MAX_UPSTREAMS; i++) {
        const dns_upstream_cfg_t *u = i < c->nup ? &c->up[i] : NULL;
        bool tls = u && (u->proto == DNS_UP_DOT || u->proto == DNS_UP_DOH);
        worker_t *cur = g_w[i][0] ? g_w[i][0] : g_w[i][1];
        if (cur && tls && cur->cfg.proto == u->proto && !strcmp(cur->cfg.text, u->text))
            continue; /* unchanged: keep the connections */
        for (int k = 0; k < DOH_WORKERS; k++)
            if (g_w[i][k]) {
                stop_worker(g_w[i][k]);
                g_w[i][k] = NULL;
            }
        if (!tls) continue;
        for (int k = 0; k < (u->proto == DNS_UP_DOH ? DOH_WORKERS : 1); k++) g_w[i][k] = start_worker(i, u, k);
    }
    xSemaphoreGive(g_mu);
}
