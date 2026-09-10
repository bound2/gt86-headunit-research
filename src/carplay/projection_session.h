/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_SESSION_H
#define GT86_PROJECTION_SESSION_H
#include "projection_info.h"
#include "pair_crypto.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_SESSION_STREAMS 6u
#define PROJECTION_SESSION_IDS 128u
#define PROJECTION_SESSION_REPLY 2048u
enum projection_session_feature {
    PROJECTION_SESSION_VIEW_AREAS=1, PROJECTION_SESSION_IAP=2,
    PROJECTION_SESSION_HEVC=4, PROJECTION_SESSION_ALT_SCREEN=8
};
/* Type 0 = session timing/event/optional low-power endpoints. Stream types
 * 100/101/102 = audio, 110/111 = screen, 130 = iAP. Integers never coerced from
 * bool/real/text. Peer ports are routed ONLY to the independently authenticated
 * control peer by the backend, never a hostname/URI supplied in the plist. */
typedef struct projection_session_resource {
    uint64_t connection_id; /* Stream connection ID, or iAP seed. Full uint64. */
    uint32_t type,audio_format,frames_per_packet,audio_latency_ms;
    uint16_t peer_timing_port,peer_data_port;
    uint8_t audio_type,keep_alive_low_power;
} projection_session_resource;
typedef struct projection_session_keys {
    /* Type 0: event transport keys only, not timing/low-power encryption. */
    uint8_t read[32],write[32],has_write;
} projection_session_keys;
typedef struct projection_session_endpoint {
    uint64_t lease; /* Nonzero, unique across ALL live resources of this owner. */
    uint32_t stream_id; /* Explicit nonzero iAP response ID; otherwise zero. */
    uint16_t timing_port,event_port,keep_alive_port,data_port,control_port;
} projection_session_endpoint;

typedef struct projection_playback_position {
    uint64_t raw_ns;
    uint32_t sample_time,sample_rate;
    uint8_t has_position;
} projection_playback_position;
typedef struct projection_clock_snapshot {
    uint64_t raw_ns,ntp;
    uint8_t synchronized;
} projection_clock_snapshot;
typedef struct projection_audio_flush_request {
    uint32_t sample_time; /* First permitted RTP timestamp; discard strictly before. */
    uint16_t sequence; /* Control metadata only; UDP sequence is not authenticated. */
} projection_audio_flush_request;
typedef struct projection_session_provider {
    void *context;
    /* Synchronous, bounded, no reentry/pointer retention or exceptions across
     * the C boundary. open must validate
     * actual format/resource support, reserve all endpoints for this resource,
     * install/copy the directional keys and return real bound ports. Listening,
     * required timing sync and event transport can run immediately; media playback
     * and unsolicited input forwarding wait for start. Pin the control peer and
     * reject unrelated/duplicate transport owners; never reset framing counters
     * on reconnect under reused keys. No default backend.
     * On ANY result, a nonzero lease transfers cleanup to this owner; if zero,
     * provider must have cleaned all partial allocations. Do not reuse leases.
     * Keys are transient; copy only into the allocated resource, wipe on close.
     * enabled_features is an explicit backend contract, not inferred support. */
    int (*open)(void *,uint64_t,const projection_session_resource *,uint8_t enabled_features,
                const projection_session_keys *,projection_session_endpoint *);
    /* start enables exactly the listed prepared leases. On failure, owner
     * closes ALL session leases, including partially started resources. */
    int (*start)(void *,uint64_t,const uint64_t *,size_t);
    /* Must synchronously cancel/close/wipe one lease, without failure/reentry.
     * Called once per transferred unique lease, including invalid open output. */
    void (*close)(void *,uint64_t,uint64_t);
    /* Optional paired callbacks for real nonblocking endpoint work. poll is
     * called only by explicit receiver_poll after control deadline checks.
     * OK/MORE are nonfatal; other results close the owning receiver/resources.
     * next_delay is read-only milliseconds, UINT32_MAX if no scheduled work.
     * Both callbacks or neither; no hidden worker, socket I/O in next_delay. */
    int (*poll)(void *,uint64_t,uint64_t now_ms);
    uint32_t (*next_delay)(const void *,uint64_t);
    /* Optional /feedback observations. Same bounded/serial contract as open.
     * playback receives ONLY a currently owned audio lease. Always report its
     * actual negotiated sample counter rate (1..384000); open must have checked
     * format support. has_position=1 means sample_time (modulo 2^32) was actually
     * played at raw_ns, NOT received, decoded, queued, or successfully sent.
     * No position yet: has_position=0, raw_ns=sample_time=0. No extrapolation.
     * raw_ns uses EXACTLY clock's monotonic ns domain; observations must belong
     * to this lease/generation, not a retired stream. Copy results, retain no
     * pointers. Only OK succeeds; failures terminate the owning session.
     * clock is sampled after all playback observations; ntp is the matching
     * NTP64 value at raw_ns, modulo 2^64. synchronized=0 suppresses all anchors,
     * not a wall-clock fallback. A delegate may provide playback alone when its
     * enclosing provider owns the timing clock. No default media observation. */
    int (*playback)(void *,uint64_t,uint64_t lease,projection_playback_position *);
    int (*clock)(void *,uint64_t,projection_clock_snapshot *);
    /* Optional two-phase audio FLUSH. Non-NULL: synchronously stop/clear media,
     * reset codec/output history and arm the timestamp fence, retaining keys,
     * nonce replay history, peer pinning and lease. NULL: resume ONLY after the
     * encrypted FLUSH reply drains. No automatic RECORD or device Start. Only
     * OK succeeds; failures retire the whole session. No pointer retention. */
    int (*flush)(void *,uint64_t,uint64_t,const projection_audio_flush_request *);
} projection_session_provider;
typedef struct projection_session_config {
    projection_session_provider provider;
    uint8_t enabled_features; /* Explicit 0..15, no defaults. */
    uint32_t feedback_max_age_ms; /* 0 disables /feedback; 1..60000 requires both observers. */
} projection_session_config;
typedef struct projection_session_slot {
    projection_session_resource request;
    projection_session_endpoint endpoint;
} projection_session_slot;
enum projection_session_state { PROJECTION_SESSION_EMPTY,PROJECTION_SESSION_READY,
    PROJECTION_SESSION_HELD,PROJECTION_SESSION_DEAD };
typedef struct projection_session {
    const projection_info_profile *profile;
    int (*available)(void *,uint64_t,const projection_info_profile *); void *available_context;
    projection_session_config config;
    projection_session_slot slots[PROJECTION_SESSION_STREAMS+1]; size_t count;
    uint64_t used_ids[PROJECTION_SESSION_IDS]; size_t used_count;
    uint64_t generation;
    uint8_t target[256]; size_t target_size;
    uint8_t reply[PROJECTION_SESSION_REPLY]; size_t reply_size;
    size_t pending_first;
    enum projection_session_state state;
    uint8_t enabled,recording,pending; /* pending: initial, streams, record, partial/full teardown, feedback, flush. */
} projection_session;
/* Internal child of projection_receiver: no caller attach, raw-key bind,
 * concurrent access or child calls on a live receiver. Fresh init validates
 * without I/O or modifying destination. Profile/data/provider bindings stay
 * immutable and contexts live until close. init requires the SAME profile and
 * availability check used for /info. New capability/endpoint code is hosted,
 * not part of either ARM portability claim. No clock here: enclosing receiver
 * enforces receive/held/output/drain deadlines and refreshes time after callbacks.
 *
 * Only receiver-owned, verified encrypted requests AFTER MFi reply drain reach
 * request. shared_secret must come from that owner's actual pairing exchange;
 * never user-supplied session keys. No authentication success is set by this API.
 * Exact methods SETUP/RECORD/TEARDOWN and optional FLUSH. First SETUP binds its target
 * (1..256 bytes); all subsequent session commands must match. Target is never
 * resolved or used for network I/O. Initial NTP timingPort is mandatory.
 * Nonempty bodies must be binary dicts; stream arrays nonempty, no malformed-full-teardown
 * fallback. Bounded unknown metadata is ignored, not granted as functionality.
 * Explicit eiv/ekey/et negotiation and non-NTP timing are unsupported.
 *
 * All requested streams preflight before any resource allocation. Single live
 * stream per type, every selected audio bit must be advertised, mic requires
 * advertised input support, screen/iAP require enabled capabilities. Stream IDs
 * and seeds share a 128-entry lifetime ledger, including retired streams, to
 * prevent key/counter reuse. Any failure closes all leases; no partial success.
 *
 * Replies are owned until actual outer drain. RECORD activates only then;
 * streams added while recording also start only on their SETUP reply drain.
 * Valid TEARDOWN closes selected leases before replying; full teardown terminates
 * this connection after reply drain, never resets event/stream nonces in place.
 * Optional provider.flush enables exact bodyless FLUSH on the bound target,
 * after RECORD drain and with exactly one owned audio stream. RTP-Info requires
 * one seq=uint16 and rtptime=uint32 (either order, OWS, no other parameters).
 * This is the classic AirPlay form, not verified CarPlay handset behavior;
 * ambiguous multi-audio FLUSH and FLUSHBUFFERED are unsupported. Timestamp
 * boundaries are trusted only on this authenticated encrypted control route.
 *
 * Explicit feedback_max_age_ms enables exact POST /feedback after initial
 * session SETUP drain (not bound to the opaque session target). Empty or bounded
 * binary dictionary request; unknown metadata has no effect. Enumerates current
 * owned audio streams only; no audio gives an empty 200. Descriptors are supplied
 * by playback even before RECORD. Only after RECORD drain, with synchronized
 * clock and nonfuture observations aged <= max_age, are connection ID, NTP64
 * timestamp, timestampRawNs and sampleTime included. Timestamp maps the ACTUAL
 * observed raw_ns using this snapshot, without extrapolating playback. Missing,
 * unsynchronized or stale positions omit anchors. Invalid/failing observations
 * close all leases, never publish a partial reply. Feedback has normal held/drain
 * ownership but never starts a resource or renews a timing synchronization budget.
 */
int projection_session_init(projection_session *,const projection_info_profile *,
    int (*available)(void *,uint64_t,const projection_info_profile *),void *,
    const projection_session_config *,uint64_t);
int projection_session_request(projection_session *,const rtsp_message *,const uint8_t shared_secret[32],uint8_t *scratch,size_t);
int projection_session_release(projection_session *); /* OK or END (full teardown); errors terminal. */
void projection_session_close(projection_session *);
#ifdef __cplusplus
}
#endif
#endif
