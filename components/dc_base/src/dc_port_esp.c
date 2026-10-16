/* ESP-IDF / FreeRTOS implementation of dc_port.h (ESP32-S3). */
#ifdef ESP_PLATFORM

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "dc_port.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include "sdkconfig.h"

int dc_log_level = DC_LOG_INFO;

uint64_t dc_time_us(void) { return (uint64_t)esp_timer_get_time(); }

uint32_t dc_wall_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    /* treat anything before 2024 as "not synchronised" */
    return tv.tv_sec > 1704067200 ? (uint32_t)tv.tv_sec : 0;
}

uint32_t dc_random32(void) { return esp_random(); }
void dc_random_fill(void *buf, size_t len) { esp_fill_random(buf, len); }

#define CAP_EXT (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#define CAP_INT (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)

/* Standard malloc/calloc/realloc honour CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL (4 KiB)
 * and CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL (configured reserve pool), placing small
 * objects in internal SRAM and large buffers (>4 KiB) in PSRAM without draining
 * the Wi-Fi / lwIP DMA reserve pool. */
void *dc_malloc(size_t n) { return malloc(n ? n : 1); }
void *dc_calloc(size_t n, size_t sz) { return calloc(n ? n : 1, sz ? sz : 1); }
void *dc_realloc(void *p, size_t n) { return realloc(p, n ? n : 1); }
void *dc_malloc_ext(size_t n) { return heap_caps_malloc_prefer(n ? n : 1, 2, CAP_EXT, CAP_INT); }
void *dc_calloc_ext(size_t n, size_t sz) {
    return heap_caps_calloc_prefer(n ? n : 1, sz ? sz : 1, 2, CAP_EXT, CAP_INT);
}
void *dc_realloc_ext(void *p, size_t n) {
    return heap_caps_realloc_prefer(p, n ? n : 1, 2, CAP_EXT, CAP_INT);
}
void *dc_malloc_int(size_t n) { return heap_caps_malloc(n ? n : 1, CAP_INT); }
void dc_free(void *p) { heap_caps_free(p); }

struct dc_mutex {
    SemaphoreHandle_t h;
    StaticSemaphore_t buf;
};

dc_mutex_t *dc_mutex_new(void) {
    dc_mutex_t *m = (dc_mutex_t *)heap_caps_malloc(sizeof(*m), CAP_INT);
    if (!m) return NULL;
    m->h = xSemaphoreCreateMutexStatic(&m->buf);
    return m;
}
void dc_mutex_free(dc_mutex_t *m) {
    if (!m) return;
    vSemaphoreDelete(m->h);
    heap_caps_free(m);
}
void dc_mutex_lock(dc_mutex_t *m) { xSemaphoreTake(m->h, portMAX_DELAY); }
void dc_mutex_unlock(dc_mutex_t *m) { xSemaphoreGive(m->h); }

struct dc_sem {
    SemaphoreHandle_t h;
    StaticSemaphore_t buf;
};

dc_sem_t *dc_sem_new(void) {
    dc_sem_t *s = (dc_sem_t *)heap_caps_malloc(sizeof(*s), CAP_INT);
    if (!s) return NULL;
    s->h = xSemaphoreCreateBinaryStatic(&s->buf);
    return s;
}
void dc_sem_free(dc_sem_t *s) {
    if (!s) return;
    vSemaphoreDelete(s->h);
    heap_caps_free(s);
}
void dc_sem_give(dc_sem_t *s) { xSemaphoreGive(s->h); }
bool dc_sem_take(dc_sem_t *s, uint32_t timeout_ms) {
    return xSemaphoreTake(s->h, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

typedef struct {
    dc_thread_fn fn;
    void *arg;
    bool ext_stack;
} thread_start_t;

static void task_tramp(void *p) {
    thread_start_t st = *(thread_start_t *)p;
    heap_caps_free(p);
    st.fn(st.arg);
    if (st.ext_stack)
        vTaskDeleteWithCaps(NULL);
    else
        vTaskDelete(NULL);
}

/* All task stacks are allocated in internal SRAM: ESP-IDF spi_flash / esp_mmu_map
 * freeze the cache and use the calling stack as a bounce buffer when writing PSRAM data. */
int dc_thread_start(dc_thread_fn fn, void *arg, const char *name, uint32_t stack, int prio,
                    int core) {
    thread_start_t *st = (thread_start_t *)heap_caps_malloc(sizeof(*st), CAP_INT);
    if (!st) return -1;
    st->fn = fn;
    st->arg = arg;
    st->ext_stack = false;
    BaseType_t c = core < 0 ? tskNO_AFFINITY : core;
    if (xTaskCreatePinnedToCore(task_tramp, name, stack, st, prio, NULL, c) != pdPASS) {
        ESP_LOGE("dc-task", "%s: task creation failed", name);
        heap_caps_free(st);
        return -1;
    }
    return 0;
}

void dc_sleep_ms(uint32_t ms) { vTaskDelay(ms ? pdMS_TO_TICKS(ms) : 1); }
void dc_log(dc_log_level_t lvl, const char *tag, const char *fmt, ...) {
    if ((int)lvl > dc_log_level) return;
    esp_log_level_t el = lvl == DC_LOG_ERR    ? ESP_LOG_ERROR
                         : lvl == DC_LOG_WARN ? ESP_LOG_WARN
                         : lvl == DC_LOG_INFO ? ESP_LOG_INFO
                                              : ESP_LOG_DEBUG;
    va_list ap;
    va_start(ap, fmt);
    char buf[256];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ESP_LOG_LEVEL(el, tag, "%s", buf);
}

#endif /* ESP_PLATFORM */
