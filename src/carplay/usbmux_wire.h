/* SPDX-License-Identifier: GPL-3.0-only
 * Independent USBmux packet implementation; pinned references in third_party.
 * This is USB framing, NOT the usbmuxd host-socket plist protocol or iAP2.
 */
#ifndef GT86_USBMUX_WIRE_H
#define GT86_USBMUX_WIRE_H
#include "iap2_wire.h" /* Shared integer/result types only. */
#ifdef __cplusplus
extern "C" {
#endif

#define USBMUX_FRAME_LIMIT 65536u
#define USBMUX_HOST_MAGIC UINT32_C(0xfeedface)
#define USBMUX_VERSION 0u
#define USBMUX_CONTROL 1u
#define USBMUX_SETUP 2u
#define USBMUX_TCP 6u
#define USBMUX_TCP_HEADER 20u
#define USBMUX_TCP_PAYLOAD_LIMIT (USBMUX_FRAME_LIMIT - 16u - USBMUX_TCP_HEADER)

typedef struct usbmux_frame {
    uint32_t protocol, magic;
    uint16_t tx_sequence, rx_sequence;
    const uint8_t *payload;
    size_t payload_size;
} usbmux_frame;
typedef struct usbmux_version { uint32_t major, minor, padding; } usbmux_version;
typedef struct usbmux_tcp {
    uint16_t source_port, destination_port;
    uint32_t sequence, acknowledgement;
    uint8_t flags;
    uint16_t window, checksum, urgent;
    const uint8_t *payload;
    size_t payload_size;
} usbmux_tcp;

/* Initial VERSION uses an 8-byte header + exactly 12-byte version payload.
 * Other supported protocols use a 16-byte header: setup has one byte, TCP at
 * least 20 bytes, control is opaque. No implicit negotiation or sequence change.
 * Encoders require zero absent extended-header fields for initial VERSION.
 * Outgoing host convention is HOST_MAGIC. Incoming magic and BOTH sequence
 * slots are preserved, not assumed to have host-direction semantics. No scan
 * or authentication uses magic. Unknown protocols are UNSUPPORTED.
 * Decoders borrow input views and consume ONE frame, retaining coalesced tails
 * with the caller. MORE/error leaves destination unchanged and consumed=0.
 * All encoders preflight, preserving output and written=0 on failure.
 * No overlapping arguments/storage, mutable concurrent input, allocation or I/O.
 */
int usbmux_frame_decode(const uint8_t *, size_t, usbmux_frame *, size_t *consumed);
int usbmux_frame_encode(const usbmux_frame *, uint8_t *, size_t, size_t *written);
/* Version payload only. Preserve all three u32 fields; handshake selects the
 * supported version separately, rather than accepting any decoded version. */
int usbmux_version_decode(const uint8_t *, size_t, usbmux_version *);
int usbmux_version_encode(const usbmux_version *, uint8_t *, size_t, size_t *written);
/* Fixed 20-byte minimal TCP header. Longer options headers are UNSUPPORTED;
 * short/invalid header offsets are INVALID. Flags, checksum and urgent fields
 * are opaque here. No IP pseudo-header checksum, routing or TCP state machine.
 * The mux-specific window scale is eight bits in both pinned references;
 * decoded/encoded window is the u16 WIRE value, not a byte count.
 */
int usbmux_tcp_decode(const uint8_t *, size_t, usbmux_tcp *);
int usbmux_tcp_encode(const usbmux_tcp *, uint8_t *, size_t, size_t *written);

typedef struct usbmux_stream {
    uint8_t *buffer;
    size_t capacity, used, expected;
    int error;
    uint8_t ready;
} usbmux_stream;
/* Caller storage 36..65536 bytes, read-only struct fields. Invalid init leaves
 * existing state unchanged. push handles one complete packet per call and
 * reports bytes accepted, including a prefix that reveals an error. Length,
 * protocol and capacity errors latch until reset/init: there is no resync scan.
 * Returned view lasts until next push/reset/init; never feed that storage back
 * as input. Zero-byte input is no progress, NOT EOF. Caller must reset on EOF,
 * timeout or generation change; this layer has no hidden clock or backend.
 * Reset discards state, not secure-erases storage. Partial/coalesced chunks need
 * no alignment and do not imply USB transfer completion or device ownership.
 */
int usbmux_stream_init(usbmux_stream *, uint8_t *, size_t);
void usbmux_stream_reset(usbmux_stream *);
int usbmux_stream_push(usbmux_stream *, const uint8_t *, size_t, size_t *consumed, usbmux_frame *);
#ifdef __cplusplus
}
#endif
#endif
