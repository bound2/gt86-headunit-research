/* SPDX-License-Identifier: GPL-3.0-only
 * Bounded TCP-style stream over an ordered, reliable USBmux packet transport.
 * Not an IP TCP stack, USB backend, trust-pairing implementation or TLS layer.
 */
#ifndef GT86_USBMUX_CONNECTION_H
#define GT86_USBMUX_CONNECTION_H
#include "usbmux_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define USBMUX_CONNECTION_FLIGHTS 8u
#define USBMUX_CONNECTION_BUSY 3
#define USBMUX_CONNECTION_UNROUTED 5
#define USBMUX_CONNECTION_CLOSED (-7)
enum usbmux_connection_state { USBMUX_CONNECTION_IDLE, USBMUX_CONNECTION_SYN_TX,
    USBMUX_CONNECTION_SYN_WAIT, USBMUX_CONNECTION_OPEN_ACK, USBMUX_CONNECTION_OPEN,
    USBMUX_CONNECTION_CLOSING, USBMUX_CONNECTION_DRAINED, USBMUX_CONNECTION_DEAD };
enum usbmux_connection_reason { USBMUX_CONNECTION_REASON_NONE, USBMUX_CONNECTION_REASON_LOCAL,
    USBMUX_CONNECTION_REASON_STALE, USBMUX_CONNECTION_REASON_DEADLINE, USBMUX_CONNECTION_REASON_RESULT,
    USBMUX_CONNECTION_REASON_PROTOCOL, USBMUX_CONNECTION_REASON_ACK, USBMUX_CONNECTION_REASON_WINDOW,
    USBMUX_CONNECTION_REASON_RESET };
typedef struct usbmux_connection_config {
    uint32_t send_limit; /* 1..65500, <= TX capacity - 20. Default 16384. */
    uint32_t open_ms, write_ms, ack_ms, read_ms, close_ms; /* All 1..60000. */
} usbmux_connection_config;
typedef struct usbmux_connection_flight { uint32_t end; uint64_t sent_at; } usbmux_connection_flight;
/* All fields read-only. Caller owns separate RX (256..65536) and TX
 * (21..65520) buffers. RX is a ring; TX holds one encoded TCP packet. No heap,
 * callbacks, I/O, global mutable state, reentry, concurrency or argument overlap.
 * Initialized objects are noncopyable. Initialize once, not to bypass lifetime
 * rules. Time is monotonic/nonwrapping and generations strictly increase.
 */
typedef struct usbmux_connection {
    usbmux_connection_config config;
    uint8_t *rx, *tx;
    size_t rx_capacity, rx_head, rx_used, tx_capacity, tx_size, tx_offset, tx_payload;
    uint64_t generation, now, started_at, tx_at, ack_at, read_at, close_at;
    uint32_t initial_sequence, peer_initial, tx_next, tx_una, rx_next, rx_limit;
    uint32_t peer_window, window_sequence, window_ack, output_ack;
    uint16_t local_port, remote_port, initial_window, output_window;
    usbmux_connection_flight flights[USBMUX_CONNECTION_FLIGHTS];
    unsigned flight_head, flight_count;
    enum usbmux_connection_state state;
    enum usbmux_connection_reason reason;
    int last_error;
    uint8_t output_kind, ack_pending, fin_requested, fin_sent, fin_acked, peer_fin;
} usbmux_connection;

/* Defaults: 16384-byte segments; 5000 ms open/ACK/read/close, 250 ms write. */
void usbmux_connection_default_config(usbmux_connection_config *);
int usbmux_connection_init(usbmux_connection *, const usbmux_connection_config *,
                           uint8_t *rx, size_t rx_capacity, uint8_t *tx, size_t tx_capacity);
/* Queue SYN with explicit nonzero ports and caller initial sequence (zero is
 * valid). Require IDLE/DEAD/DRAINED with drained RX, newer generation, and a
 * fresh port tuple or freshly reset physical mux session. Generations are not
 * on the wire: the dispatcher must not route old tuple traffic to a new stream.
 * Quiesce outstanding backend work before abort/restart; no cancellation here.
 */
int usbmux_connection_start(usbmux_connection *, uint16_t local_port, uint16_t remote_port,
                            uint32_t initial_sequence, uint64_t generation, uint64_t now_ms);
/* Immediate local abort, no RST transmission; discard both queues. Idempotent.
 * Signal backend EOF/failure this way. Not secure erasure of caller storage. */
void usbmux_connection_close(usbmux_connection *);
/* Graceful send-half shutdown: drain acknowledged data, send FIN, wait for peer
 * ACK/FIN and finish its ACK. Incoming bytes remain readable. No further writes.
 * Peer FIN alone signals read EOF after buffered bytes; writes remain allowed.
 */
int usbmux_connection_finish(usbmux_connection *, uint64_t generation, uint64_t now_ms);

/* Feed ONE encoded minimal TCP header+payload from a held USBmux TCP frame.
 * Match BOTH ports; UNROUTED means try another connection. BUSY means retain
 * packet until pending SYN/data/FIN/opening-ACK physically completes. Otherwise
 * the packet is processed/discarded, with copied RX payload (never retained).
 * Exact SYN|ACK/no payload and ACK=ISS+1 required for open; arbitrary peer ISS.
 * Established ACK, PSH|ACK, FIN|ACK and routed RST are supported. Fully/partially
 * duplicate data is not redelivered; forward gaps are dropped with current ACK.
 * Future ACKs, unsupported flags and receive-credit violations close the stream.
 * Incoming checksum stays opaque; this transport has no IP pseudo-header.
 */
int usbmux_connection_feed(usbmux_connection *, const uint8_t *, size_t,
                           uint64_t generation, uint64_t now_ms);
/* write accepts a bounded prefix, limited by peer credit, TX capacity and eight
 * unacknowledged flight records. Copy success is NOT physical completion or
 * peer ACK. BUSY/accepted=0 preserves existing output; zero input is MORE.
 * Up to eight data packets may be physically sent before their cumulative ACK.
 * No TCP retransmission/congestion control/options: delivery depends on the
 * ordered reliable mux transport. Missing ACKs terminate at a bounded deadline.
 */
int usbmux_connection_write(usbmux_connection *, const uint8_t *, size_t, size_t *accepted,
                            uint64_t generation, uint64_t now_ms);
/* poll checks deadlines and queues required ACK/FIN if output is free. OK means
 * output pending, MORE means wait/events, END means graceful protocol closure.
 * All timed calls reject stale generations before accepting time/bytes and
 * enforce hard deadlines before progress. Inspect reason/last_error on CLOSED.
 * Positive application reads renew ONLY the read-progress timer; incoming
 * traffic, partial writes/ACKs and repeated views do not renew other budgets.
 */
int usbmux_connection_poll(usbmux_connection *, uint64_t generation, uint64_t now_ms);
/* Untimed output view, stable until advance/closure/restart. Call poll before
 * backend work. Wrap this TCP packet with usbmux_host_send_tcp, complete the
 * entire physical mux packet, THEN report these TCP bytes through advance.
 * Do not advance merely because the host copied them. Serialize completions;
 * async backends require their own storage and stale-operation validation.
 */
int usbmux_connection_output(const usbmux_connection *, const uint8_t **, size_t *);
int usbmux_connection_advance(usbmux_connection *, size_t completed, uint64_t generation, uint64_t now_ms);
/* Untimed contiguous RX view; MORE when empty, END when drained after peer FIN,
 * CLOSED after abort. consume may accept at most the current contiguous view.
 * Views expire on consume/closure/restart. RX append does not overwrite unread
 * bytes. All pointer/count outputs are null/zero on errors or no data.
 */
int usbmux_connection_input(const usbmux_connection *, const uint8_t **, size_t *);
int usbmux_connection_consume(usbmux_connection *, size_t, uint64_t generation, uint64_t now_ms);
/* Hard deadlines only, not backend readiness. UINT32_MAX means none. */
uint32_t usbmux_connection_next_delay(const usbmux_connection *);
#ifdef __cplusplus
}
#endif
#endif
