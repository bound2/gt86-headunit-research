/* SPDX-License-Identifier: GPL-3.0-or-later
 * Fields/fixtures: pinned LIVI iap2-csm/messages/car_play.rs; see third_party.
 * Strict bounded subset, not an Apple specification or a working media session.
 */
#ifndef GT86_IAP2_CARPLAY_H
#define GT86_IAP2_CARPLAY_H
#include "iap2_control.h"
#ifdef __cplusplus
extern "C" {
#endif

#define IAP2_CARPLAY_MESSAGE_LIMIT 1024u
#define IAP2_CARPLAY_TEXT_LIMIT 127u
#define IAP2_CARPLAY_ADDRESS_LIMIT 63u
#define IAP2_CARPLAY_ADDRESSES 4u

typedef struct iap2_carplay_text { const char *data; size_t size; } iap2_carplay_text;
typedef struct iap2_carplay_transport_ids {
    iap2_carplay_text bluetooth, usb;
} iap2_carplay_transport_ids;
typedef struct iap2_carplay_available_transport {
    uint8_t present, has_available, available;
    iap2_carplay_text identifier; /* Optional; NULL/0 means absent. */
} iap2_carplay_available_transport;
typedef struct iap2_carplay_availability {
    iap2_carplay_available_transport wired, wireless;
} iap2_carplay_availability;
typedef struct iap2_carplay_wired_start {
    /* Wired group is always present; zero addresses encodes an empty group. */
    size_t address_count;
    iap2_carplay_text addresses[IAP2_CARPLAY_ADDRESSES];
    uint8_t has_port;
    uint32_t port; /* Preserve observed u32 wire width; operational helper bounds it. */
    iap2_carplay_text device_identifier, public_key, source_version; /* Optional. */
} iap2_carplay_wired_start;

/* Exactly one complete CSM, <=1024 bytes. Decode returns borrowed views into
 * input; keep that input alive/unmodified until the views are no longer used.
 * Unknown fields (also nested) are UNSUPPORTED, duplicates/malformed fields
 * INVALID. Missing required fields are INVALID. Capacity limits are NO_SPACE.
 * Strict local policy: printable ASCII, nonempty, exactly NUL-terminated text;
 * optional text is NULL/0 when absent. Strings are not validated as IPs, MACs,
 * cryptographic keys, URLs or trusted identities. Never auto-connect to them.
 * Address lists are ONE parameter containing multiple NUL-terminated strings,
 * not repeated parameters or a single string containing embedded NULs.
 *
 * Decode failures leave the destination unchanged. Encoders preflight into
 * bounded local storage, set written=0 on failure, and leave output untouched.
 * No overlapping arguments/input/output/storage. Presence/boolean values are
 * exactly 0/1; nonpresent scalars are zero. No heap, I/O or implicit defaults.
 */
int iap2_carplay_transport_ids_decode(const uint8_t *, size_t, iap2_carplay_transport_ids *);
int iap2_carplay_transport_ids_encode(const iap2_carplay_transport_ids *, uint8_t *, size_t, size_t *);
int iap2_carplay_wireless_update_decode(const uint8_t *, size_t, uint8_t *available);
int iap2_carplay_wireless_update_encode(uint8_t available, uint8_t *, size_t, size_t *);
int iap2_carplay_availability_decode(const uint8_t *, size_t, iap2_carplay_availability *);
int iap2_carplay_availability_encode(const iap2_carplay_availability *, uint8_t *, size_t, size_t *);
/* A wireless or mixed StartSession is UNSUPPORTED, never silently downgraded. */
int iap2_carplay_wired_start_decode(const uint8_t *, size_t, iap2_carplay_wired_start *);
int iap2_carplay_wired_start_encode(const iap2_carplay_wired_start *, uint8_t *, size_t, size_t *);

/* Explicit application action, not called automatically by control/transport.
 * Reply to a held, valid 0x4300 only when its wired.available is explicitly true
 * and the endpoint has accepted authentication AND enabled identification.
 * Requires 1..4 addresses, port 1..65535 and all three identity strings. Caller
 * MUST supply actual receiver/network/key metadata and ensure the receiver is
 * listening on an owned, usable path; this function cannot verify that.
 *
 * No guessed metadata, USB changes, key generation, sockets or session-active
 * state. Bytes are copied through iap2_control_reply; OK means queued, not sent,
 * acknowledged, accepted by an iPhone, paired, or streaming. Keep pumping.
 * A held message view expires on success or terminal endpoint closure. Invalid
 * input leaves the request/reply unchanged; timed control-reply rules apply
 * when delegated. Call between pump polls with the same monotonic clock.
 * Current auth-before-identification policy is UNCHANGED; the pinned runtime's
 * identification-first sequence is a separate interoperability task.
 */
int iap2_carplay_reply_wired_start(iap2_control *, const iap2_carplay_wired_start *, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif
