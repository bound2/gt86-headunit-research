/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_COMMAND_H
#define GT86_PROJECTION_COMMAND_H
#include "projection_info.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_COMMAND_LIMIT 32768u
enum projection_command_kind { PROJECTION_COMMAND_HID=1,PROJECTION_COMMAND_NIGHT,
    PROJECTION_COMMAND_SIRI,PROJECTION_COMMAND_IAP,PROJECTION_COMMAND_KEYFRAME };
typedef struct projection_command { enum projection_command_kind kind; rtsp_slice uuid,data; uint32_t value; } projection_command;
/* Pure fixed-schema bplist command encoder. No default identity, automatic
 * press/release, device I/O, availability attestation or semantic HID parser.
 * Explicit validated /info profile and runtime feature bits (same0..15 as
 * session) required; caller must attest actual backend capability separately.
 * HID uuid must exactly match an advertised HID; opaque report1..4096 bytes.
 * KEYFRAME uuid must match a display (alt also requires feature8).
 * IAP requires feature2, data1..16384. NIGHT value0/1 encodes BOOL; SIRI value2/3
 * encodes button-down/up INTEGER. Other/unused fields reject. Payload type,
 * uuid/hidReport and params names follow the pinned reference. This does not
 * implement touch descriptors, input capture, iAP transport or video decoding.
 * Full validate/measure before any output; all errors leave output unchanged,
 * written0. outNULL/capacity0 measures. Immutable/disjoint arguments, no heap. */
int projection_command_encode(const projection_info_profile *,uint8_t enabled_features,const projection_command *,uint8_t *,size_t,size_t *written);
#ifdef __cplusplus
}
#endif
#endif
