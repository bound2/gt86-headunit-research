/* SPDX-License-Identifier: GPL-3.0-only */
/* Local OpenH264 2.6.0 private-header override, NOT an upstream implementation.
 * Its non-GNU branch casts arbitrary byte positions to aligned integer pointers.
 * Use native-endian memcpy for every load/store, including the alignment-hinted
 * variants. Preserve macro names expected by the pinned codec; never change the
 * source checkout, compiler identity or sanitizer coverage to hide those loads.
 */
#ifndef ___LD_ST_MACROS___
#define ___LD_ST_MACROS___
#include <stdint.h>
#include <string.h>

static inline uint16_t gt86_h264_load16(const void *p) { uint16_t v; memcpy(&v, p, sizeof(v)); return v; }
static inline uint32_t gt86_h264_load32(const void *p) { uint32_t v; memcpy(&v, p, sizeof(v)); return v; }
static inline uint64_t gt86_h264_load64(const void *p) { uint64_t v; memcpy(&v, p, sizeof(v)); return v; }
static inline void gt86_h264_store16(void *p, uint16_t v) { memcpy(p, &v, sizeof(v)); }
static inline void gt86_h264_store32(void *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
static inline void gt86_h264_store64(void *p, uint64_t v) { memcpy(p, &v, sizeof(v)); }

#define LD16(a) gt86_h264_load16(a)
#define LD32(a) gt86_h264_load32(a)
#define LD64(a) gt86_h264_load64(a)
#define ST16(a, b) gt86_h264_store16(a, (uint16_t)(b))
#define ST32(a, b) gt86_h264_store32(a, (uint32_t)(b))
#define ST64(a, b) gt86_h264_store64(a, (uint64_t)(b))
#define LD16A2 LD16
#define LD32A2 LD32
#define LD32A4 LD32
#define LD64A2 LD64
#define LD64A4 LD64
#define LD64A8 LD64
#define ST16A2 ST16
#define ST32A2 ST32
#define ST32A4 ST32
#define ST64A2 ST64
#define ST64A4 ST64
#define ST64A8 ST64
#define INTD16 LD16
#define INTD32 LD32
#define INTD64 LD64
#endif
