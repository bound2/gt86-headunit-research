/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PAIR_TLV_H
#define GT86_PAIR_TLV_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PAIR_TLV_MAX_WIRE 8192u
#define PAIR_TLV_MAX_ITEMS 32u
typedef struct pair_tlv { uint8_t type; const uint8_t *data; size_t size; } pair_tlv;
/* Complete bounded TLV8 bodies, not incremental transport. Decode joins only
 * adjacent same-type fragments whose predecessor length was 255. ff/00 breaks
 * adjacency and is not a returned value; other type ff lengths reject. Distinct
 * repeated types remain ordered, and get rejects ambiguity. All output values
 * borrow caller arena, never input. Validate first; failures leave arena/items
 * unchanged and count/written zero. All argument storage must be disjoint.
 */
int pair_tlv_decode(const uint8_t *, size_t, pair_tlv *, size_t item_capacity,
                    uint8_t *arena, size_t arena_capacity, size_t *count);
int pair_tlv_get(const pair_tlv *, size_t count, uint8_t type, pair_tlv *);
/* Type ff reserved. Adjacent distinct values of the same type are separated by
 * ff/00; long values split into <=255-byte fragments. out=NULL/capacity=0
 * measures only. Encode input is limited to 32 items and 8192 encoded bytes.
 */
int pair_tlv_encode(const pair_tlv *, size_t count, uint8_t *, size_t capacity, size_t *written);
#ifdef __cplusplus
}
#endif
#endif
