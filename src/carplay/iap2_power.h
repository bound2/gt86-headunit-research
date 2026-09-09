/* SPDX-License-Identifier: GPL-3.0-or-later
 * Pinned LIVI power.rs fields; see third_party/README.md.
 */
#ifndef GT86_IAP2_POWER_H
#define GT86_IAP2_POWER_H
#include "iap2_control.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct iap2_power_source {
    uint8_t has_available_current;
    uint16_t available_current_ma;
    uint8_t has_should_charge, should_charge;
} iap2_power_source;

/* 0xae03: optional field 0 u16 current, field 1 bool charge intent.
 * Exactly one CSM, at most 1024 input bytes. Duplicate/malformed fields are
 * INVALID, unknown fields UNSUPPORTED. Flags/booleans exactly 0/1; absent
 * scalars zero. Empty notification and explicit zero values are codec-valid.
 * Decode failures leave destination unchanged. Encode preflights all fields,
 * leaves output unchanged and written=0 on failure; maximum output 17 bytes.
 * No overlapping arguments, allocation, I/O or assumed hardware rating.
 */
int iap2_power_source_decode(const uint8_t *, size_t, iap2_power_source *);
int iap2_power_source_encode(const iap2_power_source *, uint8_t *, size_t, size_t *written);

/* Explicit post-identification/authentication notification; both states must
 * be ACCEPTED. Requires both fields present, but zero current is valid and
 * does not imply power is physically available. Caller must supply truthful
 * policy/current from an owned power path and declare 0xae03 in identification.
 * Never copies the fixture's current rating, changes hardware charging, reads
 * a chip, opens USB, or sends automatically. Delegates to control_notify, so
 * held input is preserved and the existing TX/hold deadlines still apply.
 */
int iap2_power_source_notify(iap2_control *, const iap2_power_source *, uint64_t now_ms);
#ifdef __cplusplus
}
#endif
#endif
