/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_IAP_SERVICES_H
#define GT86_PROJECTION_IAP_SERVICES_H
#include "projection_services.h"
#include "projection_iap.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_IAP_SERVICES_CLOSED (-7)
typedef struct projection_iap_services projection_iap_services;
typedef struct projection_iap_services_status {
    size_t network_bytes,cipher_bytes,plain_bytes,package_bytes,body_bytes;
    uint8_t connected,held,started;
} projection_iap_services_status;
typedef struct projection_iap_relay {
    void *context;
    /* Bounded synchronous serial callbacks, no reentry/exceptions or retained
     * argument pointers. open must bind/validate a REAL existing application
     * route, not start/reset USB/link/authentication. Any nonzero child on ANY
     * return transfers close responsibility. No default relay or fake success. */
    int (*open)(void *,uint64_t,const projection_session_resource *,uint64_t *child);
    /* Can occur BEFORE provider start/RECORD: these are received control bytes,
     * not media playback or unsolicited input. Same token across partial bodies.
     * OK: accept/copy a prefix, 1..body.size (exactly0 for empty body).
     * MORE: accepted0, nothing retained. Other results terminate all resources.
     * Views last ONLY during the call. Do not assume one package==one iAP message;
     * other header fields have no interpreted semantics. accepted is not an
     * upstream ACK. A binding retaining bytes must own/bound/retire its copy. */
    int (*receive)(void *,uint64_t,uint64_t,const projection_iap_view *,projection_iap_key,size_t *accepted);
    int (*poll)(void *,uint64_t,uint64_t,uint64_t now_ns); /* OK/MORE, also before RECORD. */
    void (*close)(void *,uint64_t,uint64_t); /* Quiesce this binding/retire its bytes; cannot fail. */
} projection_iap_relay;
typedef struct projection_iap_services_config {
    projection_ip local,peer; /* Exact authenticated control-connection addresses. */
    uint64_t (*clock_ns)(void *); void *clock_context;
    projection_iap_config input;
    projection_iap_relay relay;
    uint32_t stream_id,accept_ms,poll_ms; /* Explicit nonzero ID; budgets1..60000/1..1000. */
    uint8_t enabled_features; /* Must include PROJECTION_SESSION_IAP; no default advertisement. */
    /* Other audio/screen providers, e.g. video -> audio. Leases remapped;
     * playback/FLUSH passed ONLY for live audio. Same monotonic ns domain.
     * Other's clock is not used; the enclosing root supplies timing. */
    projection_session_provider other;
} projection_iap_services_config;
/* Windows Winsock type130 service, NOT QNX or a native iAP application backend.
 * Heap-owning serial noncopyable context. Create does no I/O/clock callback.
 * Install returned provider as root media (or as another media delegate) before
 * root init. Bindings/contexts live until destroy. Caller supplies freshly
 * derived read keys, generation and session seed reuse ledger; no reconnect
 * under an old key. No direct calls into child owners/delegate while bound.
 *
 * One matching-IP connection, exclusive ephemeral port, no wildcard, DNS,
 * SO_REUSEADDR or inherited handles. Listener closes on acceptance. Wrong peers
 * cannot renew accept budget. IP equality is not authentication; AEAD still
 * gates every delivered byte. No socket writes: reverse iAPSendMessage uses the
 * separate event owner/command encoder and its start/response/drain contracts.
 *
 * Relay delivery/poll can run before RECORD after explicit successful open.
 * Provider start still validates/records the session lifecycle and starts all
 * delegated media only when the outer reply drains. It cannot reset iAP state.
 * Each poll performs <=1 relay poll, <=1 prefix delivery, <=1 accept/read/feed,
 * plus <=1 delegate poll. Held input and network tails keep absolute budgets.
 * Clock checked after callbacks/processing; no hard wall-time bound on callbacks.
 * Observed EOF/error closes all own/delegated leases; no reconnect. Input may
 * be delivered before recv observes EOF already pending in the kernel.
 * Terminal result requires immediate enclosing receiver close/poll too.
 */
int projection_iap_services_create(const projection_iap_services_config *,uint64_t,projection_iap_services **);
projection_session_provider projection_iap_services_provider(projection_iap_services *);
int projection_iap_services_poll(projection_iap_services *,uint64_t);
uint32_t projection_iap_services_next_delay(const projection_iap_services *,uint64_t);
int projection_iap_services_error(const projection_iap_services *);
/* Copy-only diagnostics for a currently owned type130 lease. No payload/key
 * exposure, clock callback, I/O, deadline renewal or readiness attestation. */
int projection_iap_services_get_status(const projection_iap_services *,uint64_t,uint64_t lease,projection_iap_services_status *);
void projection_iap_services_close(projection_iap_services *);
void projection_iap_services_destroy(projection_iap_services *);
#ifdef __cplusplus
}
#endif
#endif
