/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_EVENTS_H
#define GT86_PROJECTION_EVENTS_H
#include "rtsp_channel.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_EVENTS_SLOTS 4u
#define PROJECTION_EVENTS_REQUEST 24
#define PROJECTION_EVENTS_RESPONSE 25
#define PROJECTION_EVENTS_OUTPUT 26
#define PROJECTION_EVENTS_DRAIN 27
#define PROJECTION_EVENTS_CLOSED (-7)
typedef struct projection_events_config { uint32_t receive_ms,hold_ms,output_ms,response_ms,first_cseq; } projection_events_config;
typedef struct projection_events_storage {
    uint8_t *rx,*reply,*commands;
    size_t rx_size,reply_size,command_size,commands_size,slots; /* command_size per slot */
} projection_events_storage;
enum projection_events_phase { PROJECTION_EVENT_EMPTY,PROJECTION_EVENT_QUEUED,PROJECTION_EVENT_SENDING,
    PROJECTION_EVENT_DRAINING,PROJECTION_EVENT_WAITING,PROJECTION_EVENT_RESULT };
typedef struct projection_events_slot {
    uint64_t token,at; size_t size,offset; uint32_t cseq; uint8_t phase;
} projection_events_slot;
typedef struct projection_events {
    projection_events_config config; projection_events_storage storage; rtsp_stream input;
    projection_events_slot slots[PROJECTION_EVENTS_SLOTS],reply;
    uint64_t generation,next_token,now,rx_at,held_token;
    uint32_t next_cseq;
    uint8_t ready,dead,started,held,held_slot,active; /* held1=request,2=response; active0=none,1=reply,2..5=command */
    int last_error;
} projection_events;
/* Pure reverse-RTSP/HTTP message owner over an ALREADY authenticated event
 * byte stream. No socket, cipher, pairing, default success or semantic handler.
 * Fresh serial/noncopyable context, immutable bindings and disjoint caller
 * storage/arguments, except response body may borrow the held request input.
 * Buffers/config live until close; internals read-only.
 * All sizes64..RTSP_MAX_MESSAGE_SIZE; 1..4 command slots, explicit total capacity.
 * No unbounded queue. Config budgets1..60000ms; first CSeq explicit nonzero.
 * No idle deadline here (outer control/timing owns lifetime). Exact phase
 * deadlines; wrong generation/token/count and backward time are transactional.
 */
void projection_events_default_config(projection_events_config *);
int projection_events_init(projection_events *,const projection_events_config *,const projection_events_storage *,uint64_t,uint64_t now_ms);
int projection_events_check(projection_events *,uint64_t,uint64_t now_ms);
/* Called only by owning service after RECORD reply drains. No default start. */
int projection_events_start(projection_events *,uint64_t,uint64_t now_ms);
/* Atomic batch of1..4 already-encoded command bodies. Fixed POST /command,
 * RTSP/1.0 + plist content-type. Bodies must be prepared/validated by an explicit
 * command frontend (see projection_command); no inferred intent/automatic input.
 * On failure no command/CSeq/token is accepted. Accepted bodies copied; input
 * may then be released. Consecutive press/release commands may be one batch.
 * Sent commands may await replies concurrently; responses correlate by CSeq,
 * including out-of-order final replies. CSeq/token never wrap/reuse. */
int projection_events_queue(projection_events *,uint64_t,const rtsp_slice *,size_t,rtsp_channel_key *,uint64_t now_ms);
/* At most ONE complete incoming message, retains tail with caller. One held
 * request/response view; REQUEST requires explicit respond, RESPONSE explicit
 * release. HTTP requests may omit CSeq, but responses MUST match a fully
 * drained command CSeq. Accept final200..599 only; 1xx, unsolicited, duplicate,
 * unknown or premature replies close. Non-200 final status is exposed, not
 * silently successful or retried. Inbound request CSeq is a separate namespace. */
int projection_events_feed(projection_events *,uint64_t,const uint8_t *,size_t,size_t *,uint64_t now_ms);
int projection_events_message(const projection_events *,uint64_t,rtsp_message *,rtsp_channel_key *);
int projection_events_respond(projection_events *,rtsp_channel_key,const rtsp_response *,uint64_t now_ms);
int projection_events_release(projection_events *,rtsp_channel_key,uint64_t now_ms);
/* Single output owner: complete any active message before switching; queued
 * incoming-request reply has priority over new commands. Retire only plaintext
 * copied by downstream cipher. DRAIN means plaintext empty, not socket sent.
 * Explicit drain after final ciphertext accepted by exclusive socket owner
 * starts command response budget or retires reply. Must drain before feeding
 * a response that arrived for that command. No TCP/phone/playback ACK claim. */
int projection_events_output(projection_events *,uint64_t,rtsp_slice *,rtsp_channel_key *,int *command,uint64_t now_ms);
int projection_events_consume(projection_events *,rtsp_channel_key,size_t,uint64_t now_ms);
int projection_events_drain(projection_events *,rtsp_channel_key,uint64_t now_ms);
uint32_t projection_events_next_delay(const projection_events *);
void projection_events_close(projection_events *);
#ifdef __cplusplus
}
#endif
#endif
