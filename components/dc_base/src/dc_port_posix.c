/* POSIX implementation of dc_port.h (Linux host builds). */
#ifndef ESP_PLATFORM

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "dc_port.h"

int dc_log_level = DC_LOG_INFO;

uint64_t dc_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

uint32_t dc_wall_time(void) { return (uint32_t)time(NULL); }

void dc_random_fill(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len) {
        ssize_t n = getrandom(p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            /* extremely unlikely; fall back to a time-seeded generator */
            for (size_t i = 0; i < len; i++) p[i] = (uint8_t)(rand() ^ (dc_time_us() >> (i & 7)));
            return;
        }
        p += n;
        len -= (size_t)n;
    }
}

uint32_t dc_random32(void) {
    /* buffered to avoid a syscall per call */
    static __thread uint32_t pool[64];
    static __thread unsigned left;
    if (!left) {
        dc_random_fill(pool, sizeof(pool));
        left = 64;
    }
    return pool[--left];
}

void *dc_malloc(size_t n) { return malloc(n ? n : 1); }
void *dc_calloc(size_t n, size_t sz) { return calloc(n ? n : 1, sz ? sz : 1); }
void *dc_realloc(void *p, size_t n) { return realloc(p, n ? n : 1); }
void *dc_malloc_ext(size_t n) { return malloc(n ? n : 1); }
void *dc_calloc_ext(size_t n, size_t sz) { return calloc(n ? n : 1, sz ? sz : 1); }
void *dc_realloc_ext(void *p, size_t n) { return realloc(p, n ? n : 1); }
void *dc_malloc_int(size_t n) { return malloc(n ? n : 1); }
void dc_free(void *p) { free(p); }

struct dc_mutex {
    pthread_mutex_t m;
};

dc_mutex_t *dc_mutex_new(void) {
    dc_mutex_t *m = (dc_mutex_t *)malloc(sizeof(*m));
    if (m) pthread_mutex_init(&m->m, NULL);
    return m;
}
void dc_mutex_free(dc_mutex_t *m) {
    if (!m) return;
    pthread_mutex_destroy(&m->m);
    free(m);
}
void dc_mutex_lock(dc_mutex_t *m) { pthread_mutex_lock(&m->m); }
void dc_mutex_unlock(dc_mutex_t *m) { pthread_mutex_unlock(&m->m); }

struct dc_sem {
    pthread_mutex_t m;
    pthread_cond_t c;
    int v;
};

dc_sem_t *dc_sem_new(void) {
    dc_sem_t *s = (dc_sem_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    pthread_mutex_init(&s->m, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&s->c, &ca);
    pthread_condattr_destroy(&ca);
    return s;
}
void dc_sem_free(dc_sem_t *s) {
    if (!s) return;
    pthread_cond_destroy(&s->c);
    pthread_mutex_destroy(&s->m);
    free(s);
}
void dc_sem_give(dc_sem_t *s) {
    pthread_mutex_lock(&s->m);
    s->v = 1;
    pthread_cond_signal(&s->c);
    pthread_mutex_unlock(&s->m);
}
bool dc_sem_take(dc_sem_t *s, uint32_t timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&s->m);
    while (!s->v) {
        if (pthread_cond_timedwait(&s->c, &s->m, &ts) == ETIMEDOUT) break;
    }
    bool ok = s->v != 0;
    s->v = 0;
    pthread_mutex_unlock(&s->m);
    return ok;
}

typedef struct {
    dc_thread_fn fn;
    void *arg;
    char name[16];
} thread_start_t;

static void *thread_tramp(void *p) {
    thread_start_t st = *(thread_start_t *)p;
    free(p);
    if (st.name[0]) pthread_setname_np(pthread_self(), st.name); /* (a detached thread may be gone already) */
    st.fn(st.arg);
    return NULL;
}

int dc_thread_start(dc_thread_fn fn, void *arg, const char *name, uint32_t stack, int prio,
                    int core) {
    (void)prio;
    (void)core;
    thread_start_t *st = (thread_start_t *)malloc(sizeof(*st));
    if (!st) return -1;
    st->fn = fn;
    st->arg = arg;
    snprintf(st->name, sizeof(st->name), "%s", name ? name : "");
    pthread_attr_t a;
    pthread_attr_init(&a);
    if (stack < 65536) stack = 65536;
    pthread_attr_setstacksize(&a, stack);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    int rc = pthread_create(&t, &a, thread_tramp, st);
    pthread_attr_destroy(&a);
    if (rc) {
        free(st);
        return -1;
    }
    return 0;
}

void dc_sleep_ms(uint32_t ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
}

void dc_log(dc_log_level_t lvl, const char *tag, const char *fmt, ...) {
    if ((int)lvl > dc_log_level) return;
    static const char lv[] = "?EWID";
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "%c [%s] %s\n", lv[lvl < 5 ? lvl : 0], tag, buf);
}

#endif /* !ESP_PLATFORM */
