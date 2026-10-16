/*
 * dc_util.h - small portable helpers: varints, hashes, CRC32, growable buffers.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dc_port.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- little-endian load/store -------------------------------------------- */
static inline uint16_t dc_ld16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | (b[1] << 8));
}
static inline uint32_t dc_ld32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static inline uint64_t dc_ld64(const void *p) {
    return (uint64_t)dc_ld32(p) | ((uint64_t)dc_ld32((const uint8_t *)p + 4) << 32);
}
static inline void dc_st16(void *p, uint16_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
}
static inline void dc_st32(void *p, uint32_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}
static inline void dc_st64(void *p, uint64_t v) {
    dc_st32(p, (uint32_t)v);
    dc_st32((uint8_t *)p + 4, (uint32_t)(v >> 32));
}
/* network (big-endian) order, used by the DNS wire code */
static inline uint16_t dc_be16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)((b[0] << 8) | b[1]);
}
static inline uint32_t dc_be32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
static inline void dc_wbe16(void *p, uint16_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}
static inline void dc_wbe32(void *p, uint32_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

/* ---- varints (LEB128, unsigned) -------------------------------------------- */
static inline size_t dc_varint_put(uint8_t *p, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) {
        p[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    p[n++] = (uint8_t)v;
    return n;
}
/* Unchecked decode for trusted (validated) data.  Returns new pointer. */
static inline const uint8_t *dc_varint_get(const uint8_t *p, uint64_t *out) {
    uint64_t v = 0;
    unsigned shift = 0;
    for (;;) {
        uint8_t b = *p++;
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 63) break;
    }
    *out = v;
    return p;
}
/* Bounds-checked decode.  Returns NULL on overrun. */
const uint8_t *dc_varint_get_safe(const uint8_t *p, const uint8_t *end, uint64_t *out);

/* ---- hashing ------------------------------------------------------------------ */
#define DC_FNV32_INIT 0x811c9dc5u
static inline uint32_t dc_fnv32_step(uint32_t h, uint8_t c) { return (h ^ c) * 0x01000193u; }
static inline uint32_t dc_fnv32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = DC_FNV32_INIT;
    for (size_t i = 0; i < len; i++) h = dc_fnv32_step(h, p[i]);
    return h;
}
static inline uint32_t dc_fmix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}
uint32_t dc_crc32(uint32_t crc, const void *data, size_t len);

/* ---- ASCII helpers --------------------------------------------------------------- */
extern const uint8_t dc_lower_tab[256];
static inline uint8_t dc_lower(uint8_t c) { return dc_lower_tab[c]; }
bool dc_strnieq(const char *a, const char *b, size_t n);
const void *dc_memmem(const void *hay, size_t hlen, const void *needle, size_t nlen);
size_t dc_strlcpy(char *dst, const char *src, size_t cap);

/* ---- growable byte buffer ----------------------------------------------------------
 * Uses external RAM (PSRAM) on the device because buffers can become large.
 */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
    bool oom; /* sticky allocation failure flag */
} dc_buf_t;

void dc_buf_init(dc_buf_t *b);
void dc_buf_free(dc_buf_t *b);
bool dc_buf_reserve(dc_buf_t *b, size_t extra);
bool dc_buf_append(dc_buf_t *b, const void *data, size_t len);
static inline bool dc_buf_put8(dc_buf_t *b, uint8_t v) { return dc_buf_append(b, &v, 1); }
bool dc_buf_put16(dc_buf_t *b, uint16_t v);
bool dc_buf_put32(dc_buf_t *b, uint32_t v);
bool dc_buf_putv(dc_buf_t *b, uint64_t v);
bool dc_buf_zero(dc_buf_t *b, size_t n);
bool dc_buf_align(dc_buf_t *b, size_t align);

#ifdef __cplusplus
}
#endif
