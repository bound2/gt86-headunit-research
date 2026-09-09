/* SPDX-License-Identifier: GPL-3.0-only
 * Independent bounded plist-service framing; pinned references in third_party.
 * No plist decoder, TLS, phone trust operation or I/O.
 */
#ifndef GT86_LOCKDOWN_WIRE_H
#define GT86_LOCKDOWN_WIRE_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define LOCKDOWN_BODY_LIMIT 65536u
#define LOCKDOWN_FRAME_LIMIT (LOCKDOWN_BODY_LIMIT + 4u)
typedef struct lockdown_body { const uint8_t *data; size_t size; } lockdown_body;
/* Four-byte big-endian BODY length, excluding the prefix. Local policy requires
 * 1..65536 body bytes. frame_size only examines the prefix; decode consumes one
 * complete frame and leaves any coalesced tail with its caller. Bodies are opaque
 * XML/binary plists here, NOT parsed or accepted as successful service replies.
 * MORE/error preserves destination and zeroes consumed/written/total. Encoders fully
 * preflight output bounds. No allocation/I/O; arguments/storage cannot overlap.
 */
int lockdown_frame_size(const uint8_t *, size_t available, size_t *total);
int lockdown_frame_decode(const uint8_t *, size_t, lockdown_body *, size_t *consumed);
int lockdown_frame_encode(const uint8_t *body, size_t, uint8_t *, size_t capacity, size_t *written);
/* Explicit read-only GetValue XML body builder (no framing). Label 1..64, key
 * 1..128 printable ASCII bytes; optional domain 0..128. NULL domain omits it.
 * XML metacharacters are escaped. These are local subset limits, not an Apple
 * specification. No all-values query, state mutation, pair record or default
 * host identity is supplied. Output is transactional, written=0 on failure.
 */
int lockdown_get_value_encode(const lockdown_body *label, const lockdown_body *key,
                               const lockdown_body *domain, uint8_t *, size_t capacity, size_t *written);
/* Explicit request bodies only; neither API sends bytes or changes phone state.
 * StartSession: label 1..64, HostID/SystemBUID 1..128 printable ASCII bytes.
 * Values must come from the caller's selected pairing identity; no generated
 * identity, record lookup or fallback pairing. UUID syntax is not inferred.
 * StartService: explicit service name 1..128 printable ASCII bytes; Request and
 * Service only (no automatic Label/EscrowBag). The caller must establish the
 * required secure Lockdown session before using this body on a stream.
 * All XML metacharacters escaped; bounds preflighted, written=0 on failure.
 */
int lockdown_start_session_encode(const lockdown_body *label, const lockdown_body *host_id,
                                   const lockdown_body *system_buid, uint8_t *, size_t, size_t *written);
int lockdown_start_service_encode(const lockdown_body *service, uint8_t *, size_t, size_t *written);
#ifdef __cplusplus
}
#endif
#endif
