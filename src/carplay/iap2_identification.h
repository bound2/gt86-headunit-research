/* SPDX-License-Identifier: GPL-3.0-or-later
 * Field reference: LIVI, Copyright (C) 2025 Lasse Heitgres.
 * Minimal local research profile, NOT a complete CarPlay identification.
 */
#ifndef GT86_IAP2_IDENTIFICATION_H
#define GT86_IAP2_IDENTIFICATION_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif

#define IAP2_IDENTIFICATION_LIMIT 1024u
#define IAP2_IDENTIFICATION_LANGUAGES 4u
#define IAP2_IDENTIFICATION_FAILED (-8)
enum iap2_identification_state { IAP2_IDENTIFICATION_DISABLED,
    IAP2_IDENTIFICATION_IDLE, IAP2_IDENTIFICATION_WAIT_RESULT,
    IAP2_IDENTIFICATION_ACCEPTED, IAP2_IDENTIFICATION_REJECTED };

/* Explicit byte spans, no NUL included. This deliberately narrow encoder
 * accepts printable ASCII only: 1..127 bytes for identity, 1..16 for languages.
 * No default identity, USB interface, MAC, vehicle or CarPlay capability.
 * All fields must come from the caller; library cannot verify their truth.
 */
typedef struct iap2_identification_text { const char *data; size_t size; } iap2_identification_text;
typedef struct iap2_identification_metadata {
    iap2_identification_text name, model, manufacturer, serial, firmware, hardware;
    iap2_identification_text current_language;
    iap2_identification_text languages[IAP2_IDENTIFICATION_LANGUAGES];
    size_t language_count; /* Unique, nonempty list containing current_language. */
    uint8_t power_capability; /* Explicit 0 (none) or 2 (advanced); 1 reserved. */
    uint16_t maximum_current_ma;
} iap2_identification_metadata;

/* Explicit assertion of a wired receiver's USB-host component. No defaults:
 * name is printable ASCII 1..127 bytes, ID is u16 and interface number u8
 * (zero is a valid explicit value). The library cannot verify device wiring,
 * descriptors, power supply or a working receiver; caller must establish them.
 */
typedef struct iap2_identification_wired {
    uint16_t component_id;
    iap2_identification_text component_name;
    uint8_t carplay_interface_number;
} iap2_identification_wired;

/* Encodes fields 0..9,12,13 only. Fixed message lists advertise only this
 * library's auth/identification IDs, not application protocols. No transport
 * components or CarPlay flags emitted. Not a claim a phone accepts this subset.
 * Supported languages share ONE field 13, with concatenated NUL-terminated
 * strings; current language remains field 12. Maximum encoded size: 930 bytes.
 * Preflight errors leave output untouched and written=0. No overlapping
 * metadata/output/storage, mutable concurrent input, heap allocation or I/O.
 */
int iap2_identification_encode(const iap2_identification_metadata *, uint8_t *, size_t, size_t *written);
/* Opt-in wired subset: same base identity plus USB-host field 16 and additional
 * sent IDs 4301/ae03, received IDs 4300/4e0d/4e0e. Requires explicit advanced
 * power capability (2); no guessed current rating. Emits pinned iAP2 flags
 * 2/5, interface 3 and CarPlay flag 4 in the USB group. No other transport,
 * subscription, vehicle or media capability is implied. Maximum 1024 bytes;
 * large combinations are rejected transactionally, not truncated. Caller must
 * implement/enable handling of the declared application messages.
 */
int iap2_identification_encode_wired(const iap2_identification_metadata *, const iap2_identification_wired *,
                                   uint8_t *, size_t, size_t *written);
typedef struct iap2_identification {
    enum iap2_identification_state state;
    uint32_t rejected_fields; /* Peer rejection flag IDs 0..31, no text parsing. */
    uint8_t wired_carplay; /* Read-only: encoded profile declares wired CarPlay/power. Reset retains metadata. */
    size_t information_size;
    uint8_t information[IAP2_IDENTIFICATION_LIMIT];
} iap2_identification;

/* Copies encoded metadata into owned storage; source spans can be released
 * after success. Invalid metadata leaves the existing sequencer unchanged.
 * Treat fields as read-only. Reset retains metadata but clears result state.
 */
int iap2_identification_init(iap2_identification *, const iap2_identification_metadata *);
int iap2_identification_init_wired(iap2_identification *, const iap2_identification_metadata *,
                                 const iap2_identification_wired *);
void iap2_identification_reset(iap2_identification *);
/* Exactly one full CSM in, at most one reply out. Start (1D00) only in IDLE;
 * Information (1D01) is outbound; Accepted/Rejected only in WAIT_RESULT.
 * Unknown IDs are UNSUPPORTED without mutation. Strict empty Start/Accepted,
 * unique empty rejection flags; no retry/reconfiguration after rejection.
 * NO_SPACE on Start leaves state intact for retry. Other handled failures
 * reject the sequence. Caller must enforce its selected startup order, wait
 * for reply ACK before processing the next message, supply a deadline and
 * reset on disconnect. The control endpoint supports either explicit order.
 */
int iap2_identification_handle(iap2_identification *, const uint8_t *, size_t,
                              uint8_t *, size_t, size_t *written);

#ifdef __cplusplus
}
#endif
#endif
