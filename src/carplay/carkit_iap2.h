/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_CARKIT_IAP2_H
#define GT86_CARKIT_IAP2_H
#include "carkit.h"
#include "iap2_transport.h"
#ifdef __cplusplus
extern "C" {
#endif
enum carkit_iap2_state { CARKIT_IAP2_IDLE, CARKIT_IAP2_ACTIVE, CARKIT_IAP2_DEAD };
enum carkit_iap2_reason { CARKIT_IAP2_REASON_NONE, CARKIT_IAP2_REASON_LOCAL,
    CARKIT_IAP2_REASON_STALE, CARKIT_IAP2_REASON_CARKIT, CARKIT_IAP2_REASON_PUMP,
    CARKIT_IAP2_REASON_RESULT };
/* One-shot, caller-owned/noncopyable. Initialize once, all fields read-only;
 * no overlap, concurrent calls or reentry. Owns carkit and the pump/endpoint.
 * Configure the endpoint/provider/optional wired identification before init.
 * An unused OPEN carkit service is required; already buffered incoming bytes
 * are preserved, but prior application read/write use cannot be rebound.
 * No automatic identification, pairing, signing, CarPlay or media activation.
 */
typedef struct carkit_iap2 {
    carkit *channel; iap2_transport pump;
    usbmux_handle handle, lockdown_handle; uint64_t generation, now;
    size_t pending_size, submitted;
    uint8_t pending[IAP2_LINK_PACKET_LIMIT];
    uint8_t complete, again;
    enum carkit_iap2_state state; enum carkit_iap2_reason reason; int last_error;
} carkit_iap2;
int carkit_iap2_init(carkit_iap2 *, carkit *, iap2_control *, const iap2_transport_config *);
/* Start once, with a caller-supplied nonzero generation for this pump lifetime.
 * No backend I/O. Saved physical/service/control handles are checked first.
 */
int carkit_iap2_start(carkit_iap2 *, uint64_t generation, uint64_t now_ms);
/* Preflight iAP2/carkit deadlines before lower-layer I/O; one carkit poll, one
 * pending-write advancement and one iAP2 pump poll. At most two physical backend
 * reads/writes. Callbacks use this poll's explicit clock, never an implicit one.
 * Owns <=1024 bytes of pending output, retaining no pump buffer pointers.
 * Reports completion only after the whole prefix is drained/TCP-ACKed, without
 * claiming an iAP2 ACK. Partial progress does not renew the pump's deadline.
 * MESSAGE: service endpoint application APIs between polls, using the shared
 * clock. CONTROL is independently handled on the underlying dispatcher.
 */
int carkit_iap2_poll(carkit_iap2 *, uint64_t now_ms);
void carkit_iap2_close(carkit_iap2 *);
uint32_t carkit_iap2_next_delay(const carkit_iap2 *);
#ifdef __cplusplus
}
#endif
#endif
