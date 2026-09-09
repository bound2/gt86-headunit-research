// SPDX-License-Identifier: GPL-3.0-only
// Independent synthetic TCP peers and explicit physical-completion events.
#include "usbmux_connection.h"
#include "usbmux_host.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using Bytes = std::vector<uint8_t>;
static void check(bool ok, const char *why) { if (!ok) throw std::runtime_error(why); }
template<class T> static auto snapshot(const T& value) {
    std::array<uint8_t, sizeof value> out{}; std::memcpy(out.data(), &value, sizeof value); return out;
}
static Bytes hex(const std::string& text) {
    Bytes out; for (size_t i = 0; i < text.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16))); return out;
}
static usbmux_connection_config config(uint32_t limit = 256) {
    usbmux_connection_config c{}; usbmux_connection_default_config(&c); c.send_limit = limit; return c;
}
static Bytes tcp(uint32_t seq, uint32_t ack, uint8_t flags = 16, const Bytes& data = {}, uint16_t window = 8,
                 uint16_t source = 62078, uint16_t destination = 1) {
    usbmux_tcp p{source, destination, seq, ack, flags, window, 0, 0, data.data(), data.size()}; Bytes out(data.size() + 20); size_t n;
    check(usbmux_tcp_encode(&p, out.data(), out.size(), &n) == 0 && n == out.size(), "encode peer TCP"); return out;
}
static usbmux_tcp decode(const Bytes& bytes) {
    usbmux_tcp p{}; check(usbmux_tcp_decode(bytes.data(), bytes.size(), &p) == 0, "decode output TCP"); return p;
}
struct Conn {
    usbmux_connection c{}; Bytes rx, tx;
    explicit Conn(size_t capacity = 512, usbmux_connection_config cfg = config()) : rx(capacity + 2, 0xa5), tx(cfg.send_limit + 22, 0xa5) {
        check(usbmux_connection_init(&c, &cfg, rx.data() + 1, capacity, tx.data() + 1, tx.size() - 2) == 0, "connection init");
    }
    Conn(const Conn&) = delete; Conn& operator=(const Conn&) = delete;
    int feed(const Bytes& bytes, uint64_t now = 0) { return usbmux_connection_feed(&c, bytes.data(), bytes.size(), c.generation, now); }
    Bytes output() const {
        const uint8_t *data = nullptr; size_t n;
        const int status = usbmux_connection_output(&c, &data, &n);
        check(status == 0 || status == IAP2_MORE || status == USBMUX_CONNECTION_CLOSED, "output status");
        if (status) { check(!data && !n, "no output view"); return {}; } return Bytes(data, data + n);
    }
    Bytes input() const {
        const uint8_t *data = nullptr; size_t n;
        const int status = usbmux_connection_input(&c, &data, &n);
        check(status == 0 || status == IAP2_MORE || status == IAP2_END || status == USBMUX_CONNECTION_CLOSED, "input status");
        if (status) { check(!data && !n, "no input view"); return {}; } return Bytes(data, data + n);
    }
    void complete(uint64_t now = 0) {
        const auto out = output(); check(!out.empty() && usbmux_connection_advance(&c, out.size(), c.generation, now) == 0, "physical packet complete");
    }
    Bytes flush(uint64_t now = 0) {
        const int status = usbmux_connection_poll(&c, c.generation, now);
        check(status == 0 || status == IAP2_MORE || status == IAP2_END, "poll alive");
        const auto out = output(); if (!out.empty()) complete(now); return out;
    }
    void start(uint32_t initial = 0, uint64_t now = 0, uint64_t generation = 1) {
        check(usbmux_connection_start(&c, 1, 62078, initial, generation, now) == 0, "start explicit tuple");
    }
    void open(uint32_t initial = 0, uint32_t peer = 100, uint16_t window = 8, uint64_t now = 0) {
        start(initial, now); complete(now); check(feed(tcp(peer, initial + 1u, 18, {}, window), now) == 0, "SYNACK accepted"); complete(now);
        check(c.state == USBMUX_CONNECTION_OPEN, "open only after third-leg write");
    }
    size_t write(const Bytes& bytes, uint64_t now = 0) {
        size_t n = 999; const int status = usbmux_connection_write(&c, bytes.data(), bytes.size(), &n, c.generation, now);
        check(status == 0 || status == USBMUX_CONNECTION_BUSY || status == IAP2_MORE, "write alive");
        if (status) check(!n, "busy/empty accepts zero"); return n;
    }
    void canaries() const { check(rx.front() == 0xa5 && rx.back() == 0xa5 && tx.front() == 0xa5 && tx.back() == 0xa5, "buffer canaries"); }
};
static void initialization_and_golden_handshake() {
    Conn c; c.start(); const auto syn = hex("0001f27e00000000000000005002000200000000");
    check(c.output() == syn && c.c.tx_next == 0 && !c.c.flight_count, "independent SYN with actual 512-byte RX window");
    const auto response = tcp(UINT32_MAX, 1, 18);
    check(c.feed(response) == USBMUX_CONNECTION_BUSY && !c.c.peer_window, "response cannot precede SYN completion");
    for (size_t i = 0; i < syn.size(); ++i) {
        check(c.output() == Bytes(syn.begin() + i, syn.end()), "stable SYN tail");
        check(usbmux_connection_advance(&c.c, 1, 1, i) == (i == 19 ? 0 : IAP2_MORE), "partial SYN completion");
    }
    check(c.c.tx_next == 1 && c.c.state == USBMUX_CONNECTION_SYN_WAIT, "SYN consumes one sequence number after write");
    check(c.feed(response, 20) == 0 && c.c.rx_next == 0 && c.c.tx_una == 1, "arbitrary wrapping peer initial sequence");
    const auto ack = hex("0001f27e00000001000000005010000200000000"); check(c.output() == ack, "independent final handshake ACK");
    check(c.feed(tcp(0, 1, 16, {7}), 21) == USBMUX_CONNECTION_BUSY, "opening ACK write barrier"); c.complete(22);
    check(c.c.state == USBMUX_CONNECTION_OPEN && usbmux_connection_next_delay(&c.c) == UINT32_MAX, "handshake deadline removed"); c.canaries();
    Conn bounds; const auto before = snapshot(bounds.c); const auto good = config(); auto bad = good; bad.send_limit = 257;
    check(usbmux_connection_init(&bounds.c, &bad, bounds.rx.data() + 1, 512, bounds.tx.data() + 1, 276) == IAP2_ARGUMENT && snapshot(bounds.c) == before, "init preflight transaction");
    for (const auto capacity : {size_t(255), size_t(65537)}) check(usbmux_connection_init(&bounds.c, &good, bounds.rx.data(), capacity,
        bounds.tx.data(), 276) == IAP2_ARGUMENT && snapshot(bounds.c) == before, "RX init bounds");
}
static void handshake_rejections_and_routing() {
    const std::vector<Bytes> invalid{tcp(100, 2, 18), tcp(100, 0, 18), tcp(100, 1, 16), tcp(100, 1, 18, {1})};
    for (const auto& bytes : invalid) { Conn c; c.start(); c.complete(); check(c.feed(bytes) == USBMUX_CONNECTION_CLOSED && c.output().empty(), "invalid SYNACK closes"); }
    Conn routed; routed.start(); routed.complete(); const auto before = snapshot(routed.c);
    check(routed.feed(tcp(100, 1, 18, {}, 8, 62079, 1)) == USBMUX_CONNECTION_UNROUTED && snapshot(routed.c) == before, "source port must match");
    check(routed.feed(tcp(100, 1, 18, {}, 8, 62078, 2)) == USBMUX_CONNECTION_UNROUTED && snapshot(routed.c) == before, "destination port must match");
    check(routed.feed(tcp(0, 1, 4)) == USBMUX_CONNECTION_CLOSED && routed.c.reason == USBMUX_CONNECTION_REASON_RESET, "routed refusal ends open");
}
static void owned_output_and_physical_ack_distinction() {
    Conn c; c.open(); Bytes request{1,2,3,4}; check(c.write(request) == 4, "queue bytes"); const auto out = c.output();
    std::fill(request.begin(), request.end(), 0); check(c.output() == out && c.c.tx_next == 1 && c.c.tx_una == 1 && !c.c.flight_count, "copied bytes not yet sent/ACKed");
    check(c.feed(tcp(101, 5)) == USBMUX_CONNECTION_BUSY && c.c.tx_una == 1, "early completion notification race retains ACK");
    check(usbmux_connection_advance(&c.c, 23, 1, 1) == IAP2_MORE && c.c.tx_next == 1, "partial physical output does not consume sequence");
    c.complete(2); check(c.c.tx_next == 5 && c.c.tx_una == 1 && c.c.flight_count == 1, "physical completion is not peer acknowledgement");
    check(c.feed(tcp(101, 3), 3) == 0 && c.c.tx_una == 3 && c.c.flight_count == 1, "partial ACK retains flight");
    check(c.feed(tcp(101, 5), 4) == 0 && !c.c.flight_count && c.c.tx_una == 5, "full cumulative ACK releases flight"); c.canaries();
}
static void peer_window_and_flight_bounds() {
    Conn c(512, config(300)); c.open(0, 100, 1); const Bytes payload(300, 7);
    check(c.write(payload) == 256, "wire window scales by eight bits"); c.complete();
    check(!c.write(payload), "outstanding bytes exhaust peer credit");
    check(c.feed(tcp(101, 129, 16, {}, 1)) == 0 && c.write(payload) == 128, "partial ACK opens only corresponding credit"); c.complete();
    check(c.feed(tcp(101, 385, 16, {}, 0)) == 0 && !c.write(payload), "zero peer window backpressures after full ACK");
    check(c.feed(tcp(101, 385, 16, {}, 1)) == 0 && c.write(payload) == 256, "explicit window update reopens send");
    Conn slots(512, config(1)); slots.open(0, 100, 65535);
    for (unsigned i = 0; i < USBMUX_CONNECTION_FLIGHTS; ++i) { check(slots.write({9}) == 1, "bounded pipelined flight"); slots.complete(); }
    check(slots.c.flight_count == 8 && !slots.write({9}), "flight record cap independent of large peer window");
    check(slots.feed(tcp(101, 5)) == 0 && slots.c.flight_count == 4, "cumulative ACK drains multiple flights");
    for (unsigned i = 0; i < 4; ++i) { check(slots.write({8}) == 1, "reuse wrapped flight slots"); slots.complete(); }
    check(slots.feed(tcp(101, 13)) == 0 && !slots.c.flight_count, "wrapped ring drains exactly"); slots.canaries();
}
static void ack_range_and_wrap() {
    Conn c; c.open(UINT32_MAX - 2, UINT32_MAX - 1); check(c.write({1,2,3,4}) == 4, "wrap payload queued"); c.complete();
    check(c.c.tx_next == 2 && c.c.tx_una == UINT32_MAX - 1, "sender sequence wraps modulo 32 bits");
    check(c.feed(tcp(UINT32_MAX, 0)) == 0 && c.c.tx_una == 0 && c.c.flight_count == 1, "partial ACK across wrap");
    check(c.feed(tcp(UINT32_MAX, UINT32_MAX, 16, {}, 0)) == 0 && c.c.tx_una == 0 && c.c.peer_window == 2048, "old ACK neither regresses nor shrinks window");
    check(c.feed(tcp(UINT32_MAX, 2)) == 0 && !c.c.flight_count, "full wrapped ACK");
    check(c.feed(tcp(UINT32_MAX, 3)) == USBMUX_CONNECTION_CLOSED && c.c.reason == USBMUX_CONNECTION_REASON_ACK, "future ACK cannot acknowledge unsent bytes");
    Conn ambiguous; ambiguous.open();
    check(ambiguous.feed(tcp(101, UINT32_C(0x80000001))) == USBMUX_CONNECTION_CLOSED && ambiguous.c.reason == USBMUX_CONNECTION_REASON_ACK,
        "exact half-range ACK is ambiguous, not silently old");
    Conn zero; zero.open(UINT32_MAX, UINT32_MAX);
    check(zero.c.tx_next == 0 && zero.c.tx_una == 0 && zero.c.rx_next == 0 && zero.write({1}) == 1, "both SYN sequence counters wrap through zero");
    zero.complete(); check(zero.feed(tcp(0, 1)) == 0 && !zero.c.flight_count, "first data after zero acknowledged");
}
static void duplicate_overlap_gap_and_receive_wrap() {
    Conn c; c.open(0, UINT32_MAX - 2); auto first = tcp(UINT32_MAX - 1, 1, 24, {'a','b','c'});
    check(c.feed(first) == 0 && c.c.rx_next == 1 && c.input() == Bytes({'a','b','c'}), "receive sequence wraps");
    std::fill(first.begin(), first.end(), 0); check(c.input() == Bytes({'a','b','c'}), "input payload copied");
    check(c.feed(tcp(UINT32_MAX - 1, 1, 16, {'a','b','c'})) == 0 && c.c.rx_used == 3, "duplicate not delivered twice");
    check(c.feed(tcp(0, 1, 16, {'c','d','e'})) == 0 && c.c.rx_next == 3 && c.input() == Bytes({'a','b','c','d','e'}), "overlap delivers only new suffix");
    check(c.feed(tcp(5, 1, 16, {'x'})) == 0 && c.c.rx_next == 3 && c.c.rx_used == 5, "forward gap not silently appended");
    const auto ack = c.flush(); check(decode(ack).acknowledgement == 3, "duplicate/gap ACK stays at contiguous frontier");
    check(c.feed(tcp(3, 1, 16, {'f','g'})) == 0 && c.c.rx_next == 5, "missing segment accepted later");
    check(c.feed(tcp(UINT32_MAX - 2, 1, 18)) == 0 && c.c.rx_next == 5, "duplicate SYNACK never resets established receive sequence"); c.canaries();
}
static void receive_credit_and_reopen() {
    Conn c(256); c.open(); const Bytes one(1, 'a'), rest(255, 'b');
    check(c.feed(tcp(101, 1, 16, one)) == 0, "first receive byte");
    const auto small = c.flush(); check(!decode(small).window && c.c.rx_limit == 357, "rounded-down window does not revoke prior credit");
    check(c.feed(tcp(102, 1, 16, rest)) == 0 && c.c.rx_used == 256, "remaining previously advertised credit accepted");
    const auto zero = c.flush(); check(!decode(zero).window, "full ring advertises zero");
    check(c.feed(tcp(356, 1, 16, {'b'})) == 0 && c.c.rx_used == 256, "zero-window duplicate probe only ACKed"); c.flush();
    check(usbmux_connection_consume(&c.c, 256, 1, 1) == 0 && c.c.ack_pending, "application drain schedules window reopen");
    check(c.c.rx_limit == 357, "queued update is not yet advertised"); const auto reopened = c.flush(1);
    check(decode(reopened).window == 1 && c.c.rx_limit == 613, "physical window update grants new credit");
    check(c.feed(tcp(357, 1, 16, Bytes(256, 4)), 1) == 0, "reopened credit accepted");
    check(c.feed(tcp(613, 1, 16, {5}), 1) == USBMUX_CONNECTION_CLOSED && c.c.reason == USBMUX_CONNECTION_REASON_WINDOW && !c.c.rx_used,
        "peer cannot overrun actual credit/storage"); c.canaries();
}
static void ring_views_and_pending_ack_ownership() {
    Conn c(512); c.open(); check(c.feed(tcp(101, 1, 16, Bytes(400, 1))) == 0, "initial ring data");
    check(usbmux_connection_consume(&c.c, 300, 1, 1) == 0 && c.input().size() == 100, "partial app consumption"); c.flush(1);
    check(c.feed(tcp(501, 1, 16, Bytes(200, 2)), 2) == 0 && c.c.rx_used == 300 && c.input().size() == 212, "append wraps ring within advertised credit");
    check(usbmux_connection_poll(&c.c, 1, 2) == 0, "queue snapshot ACK"); const auto pending = c.output();
    check(usbmux_connection_consume(&c.c, 212, 1, 3) == 0 && c.input() == Bytes(88, 2) && c.output() == pending, "consume preserves pending TCP packet");
    check(c.feed(tcp(701, 1, 16, {3}), 3) == 0 && c.output() == pending, "RX continues while pure ACK pending");
    c.complete(3); const auto next = c.flush(3); check(decode(next).acknowledgement == 702, "new ACK snapshot follows old physical completion");
    const auto before = c.input(); check(usbmux_connection_consume(&c.c, before.size() + 1, 1, 3) == IAP2_ARGUMENT && c.input() == before, "cannot over-consume view"); c.canaries();
}
static void graceful_close_and_half_close() {
    Conn c; c.open(); check(c.write({1,2,3}) == 3, "data before graceful close");
    check(usbmux_connection_finish(&c.c, 1, 1) == 0 && !c.write({4}, 1), "finish stops new application writes");
    c.complete(1); check(c.flush(1).empty(), "FIN waits for data peer ACK");
    check(c.feed(tcp(101, 4), 2) == 0, "peer acknowledges data"); const auto fin = c.flush(2);
    check(decode(fin).flags == 17 && decode(fin).sequence == 4 && c.c.tx_next == 5, "FIN consumes sequence after physical write");
    check(c.feed(tcp(101, 5, 17, {'o','k'}), 3) == 0 && c.c.fin_acked && c.c.peer_fin && c.input() == Bytes({'o','k'}), "simultaneous close retains last payload");
    const auto ack = c.flush(3); check(decode(ack).acknowledgement == 104 && c.c.state == USBMUX_CONNECTION_DRAINED, "final ACK completes protocol close");
    const uint8_t *data = nullptr; size_t size;
    check(usbmux_connection_input(&c.c, &data, &size) == 0 && size == 2, "graceful closed stream can drain unread data");
    check(usbmux_connection_start(&c.c, 2, 62078, 0, 2, 4) == IAP2_ARGUMENT, "restart cannot discard graceful unread data");
    check(usbmux_connection_consume(&c.c, 2, 1, 4) == 0 && usbmux_connection_input(&c.c, &data, &size) == IAP2_END && !data && !size, "read EOF only after bytes consumed");
    check(usbmux_connection_start(&c.c, 2, 62078, 0, 2, 5) == 0, "new tuple/generation after graceful drain");
    Conn half; half.open(); check(half.feed(tcp(101, 1, 17)) == 0 && half.c.peer_fin, "peer send-half closes"); half.flush();
    check(half.write({9}) == 1, "local writes still allowed after peer FIN"); half.complete();
    check(half.feed(tcp(102, 2)) == 0 && usbmux_connection_finish(&half.c, 1, 0) == 0, "ack local response then finish"); half.flush();
    check(half.feed(tcp(102, 3)) == 0 && half.c.state == USBMUX_CONNECTION_DRAINED, "passive close completes on own FIN ACK");
}
static void reset_malformed_and_post_fin() {
    Conn c; c.open(); check(c.feed(tcp(100, 1, 4)) == 0 && c.c.state == USBMUX_CONNECTION_OPEN && c.c.ack_pending, "out-of-sequence reset challenged");
    c.flush(); check(c.feed(tcp(101, 1, 4, {'e'})) == USBMUX_CONNECTION_CLOSED && c.c.reason == USBMUX_CONNECTION_REASON_RESET, "in-sequence reset aborts");
    usbmux_connection_close(&c.c); check(c.c.reason == USBMUX_CONNECTION_REASON_RESET, "first close reason retained");
    for (uint8_t flags : {uint8_t(0), uint8_t(2), uint8_t(32), uint8_t(48)}) {
        Conn bad; bad.open(); check(bad.feed(tcp(101, 1, flags)) == USBMUX_CONNECTION_CLOSED, "unsupported established flags rejected");
    }
    Conn malformed; malformed.open(); auto bytes = tcp(101, 1); bytes[12] = 0x60;
    check(malformed.feed(bytes) == USBMUX_CONNECTION_CLOSED && malformed.c.last_error == IAP2_UNSUPPORTED, "TCP options refused");
    Conn ended; ended.open(); check(ended.feed(tcp(101, 1, 17, {1})) == 0, "peer FIN with data"); ended.flush();
    check(ended.feed(tcp(101, 1, 17, {1})) == 0 && ended.c.rx_used == 1 && ended.c.rx_next == 103, "duplicate FIN/data not redelivered");
    check(ended.feed(tcp(103, 1, 16, {2})) == USBMUX_CONNECTION_CLOSED, "new data after FIN rejected");
}
static void hard_deadlines() {
    auto cfg = config(); cfg.open_ms = 10; cfg.write_ms = 50;
    for (unsigned phase = 0; phase < 3; ++phase) {
        Conn c(512, cfg); c.start(); if (phase) c.complete(1);
        if (phase == 2) check(c.feed(tcp(100, 1, 18), 9) == 0, "late SYNACK within total budget");
        check(usbmux_connection_poll(&c.c, 1, 10) == USBMUX_CONNECTION_CLOSED && c.c.reason == USBMUX_CONNECTION_REASON_DEADLINE, "total open budget covers all phases");
    }
    cfg = config(); cfg.write_ms = 10; Conn write(512, cfg); write.open(); check(write.write({1}, 1) == 1, "write timer queued");
    check(usbmux_connection_advance(&write.c, 20, 1, 10) == IAP2_MORE && usbmux_connection_advance(&write.c, 1, 1, 11) == USBMUX_CONNECTION_CLOSED,
        "partial output cannot renew packet deadline");
    cfg = config(); cfg.ack_ms = 10; Conn ack(512, cfg); ack.open(); check(ack.write({1,2,3,4}, 1) == 4, "ACK timed payload"); ack.complete(2);
    check(ack.feed(tcp(101, 3), 11) == 0 && usbmux_connection_next_delay(&ack.c) == 1, "partial ACK retains oldest packet deadline");
    check(ack.feed(tcp(101, 5), 12) == USBMUX_CONNECTION_CLOSED, "late full ACK cannot rescue expired flight");
    Conn later(512, cfg); later.open(); check(later.write({1}, 1) == 1, "first timed flight"); later.complete(1);
    check(later.write({2}, 2) == 1, "second timed flight"); later.complete(2);
    check(later.feed(tcp(101, 2), 10) == 0 && usbmux_connection_next_delay(&later.c) == 2, "new oldest flight retains its own original deadline");
    cfg = config(); cfg.close_ms = 10; Conn closing(512, cfg); closing.open(); check(usbmux_connection_finish(&closing.c, 1, 1) == 0, "start close budget"); closing.flush(1);
    check(usbmux_connection_finish(&closing.c, 1, 10) == 0 && usbmux_connection_poll(&closing.c, 1, 11) == USBMUX_CONNECTION_CLOSED, "repeated finish does not renew close budget");
}
static void read_progress_and_ack_scheduling_deadlines() {
    auto cfg = config(); cfg.read_ms = 10; Conn c(512, cfg); c.open(); check(c.feed(tcp(101, 1, 16, {1,2}), 1) == 0, "unread timer begins"); c.flush(1);
    check(c.feed(tcp(103, 1, 16, {3}), 9) == 0 && usbmux_connection_next_delay(&c.c) == 2, "new network traffic does not renew unread timer"); c.flush(9);
    check(usbmux_connection_consume(&c.c, 1, 1, 10) == 0 && usbmux_connection_next_delay(&c.c) == 10, "positive app progress renews read timer");
    check(usbmux_connection_consume(&c.c, 0, 1, 19) == IAP2_MORE && usbmux_connection_consume(&c.c, 1, 1, 20) == USBMUX_CONNECTION_CLOSED,
        "zero reads and late consume do not rescue unread buffer");
    cfg = config(); cfg.ack_ms = 10; Conn queued(512, cfg); queued.open(); check(queued.feed(tcp(101, 1, 16, {1}), 1) == 0, "ACK intent starts scheduler deadline");
    check(queued.feed(tcp(102, 1, 16, {2}), 10) == 0 && usbmux_connection_poll(&queued.c, 1, 11) == USBMUX_CONNECTION_CLOSED, "repeated data cannot indefinitely postpone ACK production");
}
static void generations_counts_and_arguments() {
    for (unsigned operation = 0; operation < 7; ++operation) {
        Conn c; c.open(); usbmux_connection_close(&c.c); c.start(0, 2, 2); const auto packet = tcp(100, 1, 18); size_t accepted = 9; int result = 0;
        switch (operation) {
        case 0: result = usbmux_connection_poll(&c.c, 1, 999); break;
        case 1: result = usbmux_connection_feed(&c.c, packet.data(), packet.size(), 1, 999); break;
        case 2: result = usbmux_connection_advance(&c.c, 1, 1, 999); break;
        case 3: result = usbmux_connection_write(&c.c, packet.data(), 1, &accepted, 1, 999); break;
        case 4: result = usbmux_connection_consume(&c.c, 0, 1, 999); break;
        case 5: result = usbmux_connection_finish(&c.c, 1, 999); break;
        case 6: result = usbmux_connection_feed(&c.c, packet.data(), packet.size(), 1, 0); break;
        }
        check(result == USBMUX_CONNECTION_CLOSED && c.c.reason == USBMUX_CONNECTION_REASON_STALE && c.c.now == 2 &&
            c.output().empty() && (operation != 3 || !accepted), "every timed API rejects stale generation before time/bytes");
    }
    Conn c; c.start(); check(usbmux_connection_advance(&c.c, 19, 1, 1) == IAP2_MORE &&
        usbmux_connection_advance(&c.c, 2, 1, 2) == USBMUX_CONNECTION_CLOSED && c.c.reason == USBMUX_CONNECTION_REASON_RESULT, "completion bounded by tail");
    const auto before = snapshot(c.c); check(usbmux_connection_start(&c.c, 1, 62078, 0, 1, 2) == IAP2_ARGUMENT && snapshot(c.c) == before, "no generation reuse");
    usbmux_connection empty{}; const uint8_t *view = nullptr; size_t n;
    check(usbmux_connection_output(&empty, &view, &n) == IAP2_ARGUMENT && !view && !n, "uninitialized output rejected");
    usbmux_connection_close(nullptr); usbmux_connection_default_config(nullptr);
    Conn clock; clock.open(0, 100, 8, UINT64_MAX - 10); check(clock.write({1}, UINT64_MAX - 5) == 1, "near max clock write");
    check(usbmux_connection_poll(&clock.c, 1, UINT64_MAX) == 0 && usbmux_connection_next_delay(&clock.c) == 245, "deadline arithmetic does not overflow");
    const auto snap = snapshot(clock.c); check(usbmux_connection_poll(&clock.c, 1, 0) == IAP2_ARGUMENT && snapshot(clock.c) == snap, "clock cannot wrap");
}
static void maximum_buffers_and_short_acceptance() {
    Conn c(65536, config(65500)); c.open(0, 100, 65535); Bytes payload(65500);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    Bytes larger = payload; larger.push_back(7); check(c.write(larger) == 65500 && c.output().size() == 65520, "bounded write prefix at maximum size");
    const auto out = c.output(); const auto p = decode(out); check(Bytes(p.payload, p.payload + p.payload_size) == payload, "maximum owned TX exact"); c.complete();
    check(c.feed(tcp(101, 65501, 16, payload)) == 0 && c.input() == payload && c.c.rx_used == 65500, "maximum receive and matching ACK");
    check(usbmux_connection_consume(&c.c, payload.size(), 1, 1) == 0, "maximum receive drained"); c.flush(1); c.canaries();
}
static Bytes mux(uint32_t protocol, const Bytes& payload) {
    usbmux_frame f{protocol, protocol ? USBMUX_HOST_MAGIC : 0, 0, 0, payload.data(), payload.size()}; Bytes bytes(payload.size() + (protocol ? 16 : 8)); size_t n;
    check(usbmux_frame_encode(&f, bytes.data(), bytes.size(), &n) == 0, "encode fake physical mux input"); return bytes;
}
static void layered_mux_exchange() {
    usbmux_host host{}; auto hc = usbmux_host_config{}; usbmux_host_default_config(&hc); uint8_t rx[512], tx[512];
    check(usbmux_host_init(&host, &hc, rx, sizeof rx, tx, sizeof tx) == 0 && usbmux_host_start(&host, 1, 0) == 0, "start physical packet host");
    check(usbmux_host_advance(&host, 20, 1, 0) == 0, "version physical completion");
    const auto ver = hex("0000000000000014000000020000000000000000"); size_t used;
    check(usbmux_host_feed(&host, ver.data(), ver.size(), &used, 1, 0) == 0 && usbmux_host_advance(&host, 17, 1, 0) == 0, "mux ready");
    Conn c; c.start();
    const auto transfer_out = [&]() {
        const auto packet = c.output(); check(!packet.empty(), "connection packet pending");
        const auto old_next = c.c.tx_next;
        check(usbmux_host_send_tcp(&host, packet.data(), packet.size(), 1, 0) == 0 && c.c.tx_next == old_next, "host copy not connection completion");
        Bytes physical;
        while (host.tx_size) {
            const uint8_t *data; size_t size;
            check(usbmux_host_output(&host, &data, &size) == 0, "physical output view"); const size_t n = std::min(size_t(5), size);
            physical.insert(physical.end(), data, data + n); const auto result = usbmux_host_advance(&host, n, 1, 0);
            check(result == 0 || result == IAP2_MORE, "partial five-byte mux write");
            check(c.c.tx_next == old_next, "TCP sequence waits for full mux completion accounting");
        }
        check(usbmux_connection_advance(&c.c, packet.size(), 1, 0) == 0, "TCP completion after entire physical mux packet");
        usbmux_frame f{}; size_t n;
        check(usbmux_frame_decode(physical.data(), physical.size(), &f, &n) == 0 && f.protocol == USBMUX_TCP &&
            Bytes(f.payload, f.payload + f.payload_size) == packet, "layered output exact"); return packet;
    };
    const auto transfer_in = [&](const Bytes& packet) {
        const auto physical = mux(USBMUX_TCP, packet); size_t offset = 0;
        while (offset < physical.size()) {
            const size_t n = std::min(size_t(3), physical.size() - offset);
            const int result = usbmux_host_feed(&host, physical.data() + offset, n, &used, 1, 0);
            check(used == n && (result == IAP2_MORE || result == USBMUX_HOST_PACKET), "three-byte mux input assembly"); offset += used;
        }
        const usbmux_frame *held = nullptr; check(usbmux_host_packet(&host, &held) == USBMUX_HOST_PACKET, "held mux frame");
        check(usbmux_connection_feed(&c.c, held->payload, held->payload_size, 1, 0) == 0, "route held TCP into stream");
        check(usbmux_host_release(&host, 1, 0) == 0, "release mux only after connection processes packet");
    };
    check(decode(transfer_out()).flags == 2, "SYN travels through mux host"); transfer_in(tcp(100, 1, 18));
    check(decode(transfer_out()).flags == 16 && c.c.state == USBMUX_CONNECTION_OPEN, "complete layered TCP opening");
    const Bytes request{0,0,0,3,'a','b','c'}; check(c.write(request) == request.size(), "synthetic length-prefixed service bytes queued"); transfer_out();
    transfer_in(tcp(101, 8, 16, {0,0,0,2,'o','k'}));
    check(c.input() == Bytes({0,0,0,2,'o','k'}) && !c.c.flight_count, "layered response delivered and request acknowledged");
    check(usbmux_connection_poll(&c.c, 1, 0) == 0, "response ACK queued"); transfer_out();
    check(usbmux_connection_consume(&c.c, 6, 1, 0) == 0, "application drains service response"); c.canaries();
}
int main() {
    try {
        initialization_and_golden_handshake(); handshake_rejections_and_routing(); owned_output_and_physical_ack_distinction();
        peer_window_and_flight_bounds(); ack_range_and_wrap(); duplicate_overlap_gap_and_receive_wrap(); receive_credit_and_reopen();
        ring_views_and_pending_ack_ownership(); graceful_close_and_half_close(); reset_malformed_and_post_fin(); hard_deadlines();
        read_progress_and_ack_scheduling_deadlines(); generations_counts_and_arguments(); maximum_buffers_and_short_acceptance(); layered_mux_exchange();
        std::cout << "PASS: 15 bounded USBmux connection groups; simulated mux/TCP only. State bytes=" << sizeof(usbmux_connection) << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
