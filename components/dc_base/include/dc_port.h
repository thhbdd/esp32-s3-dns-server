/*
 * dc_port.h - minimal platform abstraction shared by all portable components.
 *
 * The portable code (filter engine, DNS core, server I/O) only talks to the
 * platform through this header.  Two implementations exist:
 *   - src/dc_port_esp.c    ESP-IDF / FreeRTOS (ESP32-S3)
 *   - src/dc_port_posix.c  Linux (host tests, simulator, tools)
 */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- time ---------------------------------------------------------------- */
uint64_t dc_time_us(void); /* monotonic microseconds */
static inline uint32_t dc_time_ms(void) { return (uint32_t)(dc_time_us() / 1000u); }
uint32_t dc_wall_time(void); /* unix seconds, 0 if not synchronized */

/* ---- randomness (cryptographically strong where the platform allows) ------ */
uint32_t dc_random32(void);
void dc_random_fill(void *buf, size_t len);

/* ---- memory ----------------------------------------------------------------
 * dc_malloc*      : general purpose (platform default policy)
 * dc_malloc_ext*  : large / cold data, prefer external PSRAM
 * dc_malloc_int   : small hot data that must live in internal SRAM
 * All are released with dc_free().
 */
void *dc_malloc(size_t n);
void *dc_calloc(size_t n, size_t sz);
void *dc_realloc(void *p, size_t n);
void *dc_malloc_ext(size_t n);
void *dc_calloc_ext(size_t n, size_t sz);
void *dc_realloc_ext(void *p, size_t n);
void *dc_malloc_int(size_t n);
void dc_free(void *p);

/* Largest block currently allocatable from external RAM (0 if none). */

/* ---- synchronisation ------------------------------------------------------- */
typedef struct dc_mutex dc_mutex_t;
dc_mutex_t *dc_mutex_new(void);
void dc_mutex_free(dc_mutex_t *m);
void dc_mutex_lock(dc_mutex_t *m);
void dc_mutex_unlock(dc_mutex_t *m);

typedef struct dc_sem dc_sem_t; /* binary semaphore */
dc_sem_t *dc_sem_new(void);
void dc_sem_free(dc_sem_t *s);
void dc_sem_give(dc_sem_t *s);
bool dc_sem_take(dc_sem_t *s, uint32_t timeout_ms);

/* ---- threads --------------------------------------------------------------- */
typedef void (*dc_thread_fn)(void *arg);
enum { DC_PRIO_LOW = 2, DC_PRIO_MID = 5, DC_PRIO_HIGH = 10, DC_PRIO_RT = 15 };
enum { DC_CORE_ANY = -1 };
/* Returns 0 on success. stack is in bytes. */
int dc_thread_start(dc_thread_fn fn, void *arg, const char *name, uint32_t stack, int prio,
                    int core);
void dc_sleep_ms(uint32_t ms);

/* ---- logging --------------------------------------------------------------- */
typedef enum { DC_LOG_ERR = 1, DC_LOG_WARN, DC_LOG_INFO, DC_LOG_DEBUG } dc_log_level_t;
extern int dc_log_level;
void dc_log(dc_log_level_t lvl, const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#define DC_LOGE(tag, ...) dc_log(DC_LOG_ERR, tag, __VA_ARGS__)
#define DC_LOGW(tag, ...) dc_log(DC_LOG_WARN, tag, __VA_ARGS__)
#define DC_LOGI(tag, ...) dc_log(DC_LOG_INFO, tag, __VA_ARGS__)
#define DC_LOGD(tag, ...)                                                                       \
    do {                                                                                        \
        if (dc_log_level >= DC_LOG_DEBUG) dc_log(DC_LOG_DEBUG, tag, __VA_ARGS__);               \
    } while (0)

#define DC_LIKELY(x) __builtin_expect(!!(x), 1)
#define DC_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define DC_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#ifdef __cplusplus
}
#endif
