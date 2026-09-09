// SPDX-License-Identifier: GPL-3.0-only
#include "support/usbmux_fixture.h"
static void init_start_and_capacity_contracts() {
    Runtime r; const auto before = snapshot(r.d); auto backend = r.peer.backend(); auto cfg = usbmux_dispatcher_config{5};
    for (unsigned count : {0u, 5u}) check(usbmux_dispatcher_init(&r.d, &r.host, r.pointers.data(), count, &backend, &cfg) == IAP2_ARGUMENT && snapshot(r.d) == before, "slot count transaction");
    for (uint32_t retry : {0u, 1001u}) { cfg.retry_ms = retry; check(usbmux_dispatcher_init(&r.d, &r.host, r.pointers.data(), 2, &backend, &cfg) == IAP2_ARGUMENT && snapshot(r.d) == before, "retry bound transaction"); }
    cfg.retry_ms = 5; auto duplicate = r.pointers; duplicate[1] = duplicate[0];
    check(usbmux_dispatcher_init(&r.d, &r.host, duplicate.data(), 2, &backend, &cfg) == IAP2_ARGUMENT && snapshot(r.d) == before, "duplicate connection object refused");
    backend.cancel = nullptr; check(usbmux_dispatcher_init(&r.d, &r.host, r.pointers.data(), 2, &backend, &cfg) == IAP2_ARGUMENT, "cancel required"); backend = r.peer.backend();
    uint8_t rx[36], tx[36]; usbmux_host small{}; usbmux_host_config hc{}; usbmux_host_default_config(&hc);
    check(usbmux_host_init(&small, &hc, rx, sizeof rx, tx, sizeof tx) == 0 &&
        usbmux_dispatcher_init(&r.d, &small, r.pointers.data(), 2, &backend, &cfg) == IAP2_ARGUMENT && snapshot(r.d) == before, "advertised connection capacity must fit raw host");
    check(usbmux_dispatcher_start(&r.d, 0, 0) == IAP2_ARGUMENT && snapshot(r.d) == before, "zero physical generation refused");
    r.start(); check(!r.peer.reads && !r.peer.writes && r.peer.cancelled.empty(), "start queues but performs no device callback");
    usbmux_handle h{99,99,99}; const auto original = snapshot(h);
    check(usbmux_dispatcher_open(&r.d, 62078, 0, &h, 0) == USBMUX_DISPATCHER_BUSY && snapshot(h) == original, "no TCP before mux READY");
    check(usbmux_dispatcher_start(&r.d, 2, 0) == IAP2_ARGUMENT, "active session cannot be restarted"); r.canaries();
}
static void fragmented_handshake_and_four_streams() {
    Runtime r(4); r.ready(); std::array<usbmux_handle,4> handles;
    for (unsigned i = 0; i < 4; ++i) handles[i] = r.open(static_cast<uint16_t>(62078 + i));
    r.until([&] { return std::all_of(r.conns.begin(), r.conns.end(), [](const auto& c) { return c.state == USBMUX_CONNECTION_OPEN; }); });
    check(r.peer.streams.size() == 4, "four real dispatcher routes opened");
    std::vector<uint16_t> syn_order;
    for (const auto& bytes : r.peer.sent) { usbmux_frame f{}; size_t used; check(usbmux_frame_decode(bytes.data(), bytes.size(), &f, &used) == 0, "recorded mux packet");
        if (f.protocol == USBMUX_TCP) { usbmux_tcp p{}; check(usbmux_tcp_decode(f.payload, f.payload_size, &p) == 0, "recorded TCP"); if (p.flags == 2) syn_order.push_back(p.source_port); } }
    check(syn_order == std::vector<uint16_t>({1,2,3,4}), "round-robin opening packets stay fair and noninterleaved");
    for (unsigned i = 0; i < 4; ++i) { Bytes data(50 + i, static_cast<uint8_t>(i + 1)); check(r.write(handles[i], data) == data.size(), "concurrent bounded application writes"); std::fill(data.begin(), data.end(), 0); }
    r.until([&] { for (unsigned i = 0; i < 4; ++i) if (r.conns[i].rx_used != 50 + i || r.conns[i].flight_count) return false; return true; });
    for (unsigned i = 0; i < 4; ++i) check(r.read_all(handles[i]) == Bytes(50 + i, static_cast<uint8_t>(i + 1)) &&
        r.peer.streams.at(static_cast<uint16_t>(i + 1)).received == Bytes(50 + i, static_cast<uint8_t>(i + 1)), "isolated byte streams preserve copied caller data");
    r.canaries();
}
static void physical_completion_and_early_peer_response() {
    Runtime r(1); r.ready(); r.peer.respond = false; r.peer.read_limit = 1024;
    const auto h = r.open(); r.peer.inject(tcp(62078, 1, 1001, 1, 18));
    check(r.step() == 0 && r.host.held && r.d.owner && r.conns[0].state == USBMUX_CONNECTION_SYN_TX && r.conns[0].tx_next == 0,
        "early SYNACK is held while first physical tail is pending");
    check(r.host.tx_offset == 5 && !r.conns[0].tx_offset, "physical write progress does not advance TCP packet early");
    r.until([&] { return r.conns[0].state == USBMUX_CONNECTION_SYN_WAIT; });
    check(!r.d.owner && r.host.held && r.conns[0].tx_next == 1, "full mux completion credited before retained reply dispatch");
    r.established(h); check(!r.host.held && !r.d.owner, "retained reply and final ACK complete");
    check(r.write(h, {1,2,3,4}) == 4, "queue data"); r.step(); check(r.conns[0].tx_next == 1 && !r.conns[0].flight_count, "copy into host not peer ACK or TCP completion");
    r.until([&] { return r.conns[0].flight_count == 1; }); check(r.conns[0].tx_next == 5 && r.conns[0].tx_una == 1, "physical completion still awaits peer ACK"); r.canaries();
}
static void held_control_tokens_and_coalesced_tails() {
    Runtime r(1); r.ready(); const auto h = r.open(); r.established(h); r.peer.read_limit = 1024;
    r.peer.inject(packet(USBMUX_CONTROL, {5,'o','n','e'})); r.peer.inject(tcp(62079, 99, 1, 1)); r.peer.inject(packet(USBMUX_CONTROL, {7,'t','w','o'}));
    r.until([&] { return r.d.control_pending != 0; });
    const usbmux_frame *view = nullptr; uint64_t first;
    check(usbmux_dispatcher_control(&r.d, &view, &first) == USBMUX_DISPATCHER_CONTROL && view->payload_size == 4 && view->payload[1] == 'o', "opaque held control");
    const auto before = snapshot(r.d);
    check(usbmux_dispatcher_release_control(&r.d, 1, first + 1, r.now + 100) == USBMUX_DISPATCHER_STALE && snapshot(r.d) == before, "wrong token does not consume event or clock");
    check(r.write(h, {'x','y'}) == 2, "TX remains usable with held control");
    r.until([&] { return r.peer.streams.at(1).received.size() == 2 && !r.d.owner; });
    check(view->payload[1] == 'o' && r.d.rx_size > r.d.rx_offset && r.d.ignored_packets == 0, "held view and coalesced tail survive TX");
    r.step(); r.step(); check(usbmux_dispatcher_next_delay(&r.d) > 0, "unhandled control does not busy-spin");
    check(usbmux_dispatcher_release_control(&r.d, 1, first, r.now) == 0, "release exact control");
    r.until([&] { return r.d.control_pending != 0; }); uint64_t second;
    check(usbmux_dispatcher_control(&r.d, &view, &second) == USBMUX_DISPATCHER_CONTROL && second != first && view->payload[1] == 't' && r.d.ignored_packets == 1,
        "coalesced unknown TCP discarded before next control with new token");
    check(usbmux_dispatcher_release_control(&r.d, 1, first, r.now) == USBMUX_DISPATCHER_STALE && r.d.control_pending, "old release cannot consume newer event");
    check(usbmux_dispatcher_release_control(&r.d, 1, second, r.now) == 0, "second event released");
    r.until([&] { return r.conns[0].rx_used == 2; }); check(r.read_all(h) == Bytes({'x','y'}), "TCP response behind control delivered after release"); r.canaries();
}
static void graceful_reuse_and_stale_handles() {
    Runtime r(1); r.ready(); const auto first = r.open(); r.established(first); check(r.write(first, {4,5,6}) == 3, "old connection payload");
    r.until([&] { return r.conns[0].rx_used == 3; }); check(usbmux_dispatcher_finish(&r.d, &first, r.now) == 0, "graceful finish");
    r.until([&] { return r.conns[0].state == USBMUX_CONNECTION_DRAINED; }); usbmux_handle blocked{99,99,99}; const auto old = snapshot(blocked);
    check(usbmux_dispatcher_open(&r.d, 62079, 0, &blocked, r.now) == USBMUX_DISPATCHER_BUSY && snapshot(blocked) == old, "unread graceful bytes prevent slot reuse");
    check(r.read_all(first) == Bytes({4,5,6}), "drain final bytes before EOF"); const auto second = r.open(62079); check(second.slot == first.slot && second.connection > first.connection && r.conns[0].local_port == 2, "slot reused with fresh token and local port");
    const auto before = snapshot(r.d); size_t n = 99; uint8_t byte = 1; enum usbmux_connection_state state = USBMUX_CONNECTION_IDLE;
    check(usbmux_dispatcher_write(&r.d, &first, &byte, 1, &n, r.now + 999) == USBMUX_DISPATCHER_STALE && !n && snapshot(r.d) == before, "old write handle cannot affect new slot/time");
    check(usbmux_dispatcher_read(&r.d, &first, &byte, 1, &n, r.now + 999) == USBMUX_DISPATCHER_STALE && !n && snapshot(r.d) == before, "old read handle rejected");
    check(usbmux_dispatcher_finish(&r.d, &first, r.now + 999) == USBMUX_DISPATCHER_STALE &&
        usbmux_dispatcher_state(&r.d, &first, &state) == USBMUX_DISPATCHER_STALE && snapshot(r.d) == before, "old finish/state handle rejected");
    r.peer.inject(tcp(62078, 1, 1002, 4)); r.established(second);
    r.until([&] { return r.d.ignored_packets == 1; }); check(r.d.active && r.conns[0].local_port == 2, "retired tuple cannot alias new stream"); r.canaries();
}
static void cancel_and_fresh_physical_generation() {
    Runtime r; r.ready(); const auto first = r.open(); r.established(first); check(r.write(first, {1,2}) == 2, "pending old output"); r.step();
    usbmux_dispatcher_close(&r.d); usbmux_dispatcher_close(&r.d);
    check(r.peer.cancelled == std::vector<uint64_t>({1}) && !r.d.owner && !r.d.rx_size && r.host.state == USBMUX_HOST_DEAD &&
        r.conns[0].state == USBMUX_CONNECTION_DEAD && r.peer.partial.empty(), "cancel exactly once and clear both owned layers");
    const auto before = snapshot(r.d); check(usbmux_dispatcher_start(&r.d, 1, r.now) == IAP2_ARGUMENT && snapshot(r.d) == before, "physical generation cannot repeat");
    check(usbmux_dispatcher_start(&r.d, 2, r.d.now - 1) == IAP2_ARGUMENT && snapshot(r.d) == before, "restart time cannot decrease");
    r.start(2); r.until([&] { return r.host.state == USBMUX_HOST_READY; }); const auto second = r.open(); r.established(second);
    check(second.physical == 2 && second.connection > first.connection && r.conns[0].local_port == 1, "fresh physical stream permits local-port reset, not token reuse");
    size_t n; uint8_t byte = 7; check(usbmux_dispatcher_write(&r.d, &first, &byte, 1, &n, r.now + 999) == USBMUX_DISPATCHER_STALE && r.d.active, "old physical handle rejected without cancelling new session");
    usbmux_dispatcher_close(&r.d); check(r.peer.cancelled == std::vector<uint64_t>({1,2}), "each physical lifetime cancelled once");
}
static void blocked_write_backoff_and_exact_deadline() {
    Runtime r(1); r.ready(); const auto h = r.open(); (void)h; r.peer.block_write = true;
    const uint64_t started = r.now; check(r.at(started) == 0 && r.d.owner, "pending SYN is submitted but write blocked");
    const auto writes = r.peer.writes; check(r.at(started + 1) == IAP2_MORE && r.peer.writes == writes && usbmux_dispatcher_next_delay(&r.d) == 4, "backoff avoids repeated blocked write");
    check(r.at(started + 5) == IAP2_MORE && r.peer.writes == writes + 1, "write retried once at deadline");
    const auto attempts = r.peer.writes;
    check(r.at(started + 250) == USBMUX_DISPATCHER_CLOSED && r.peer.writes == attempts && r.peer.cancelled.size() == 1 && !r.conns[0].tx_next,
        "exact write timeout closes before late I/O without crediting unsent SYN");
    check(usbmux_dispatcher_next_delay(&r.d) == UINT32_MAX, "inactive delay");
}
static void shared_connection_deadline_precedes_io() {
    Runtime r(2, 256, 128, 10); r.ready(); const auto a = r.open(), b = r.open(62079); r.established(a); r.established(b); r.peer.respond = false;
    check(r.write(a, {1}) == 1, "unacknowledged stream A payload"); r.until([&] { return r.conns[0].flight_count == 1; });
    check(r.write(b, {2}) == 1, "other stream has pending output"); r.peer.block_write = true; r.step();
    const auto reads = r.peer.reads, writes = r.peer.writes;
    const auto deadline = r.conns[0].flights[r.conns[0].flight_head].sent_at + r.conns[0].config.ack_ms;
    check(r.at(deadline) == USBMUX_DISPATCHER_CLOSED && r.peer.reads == reads && r.peer.writes == writes && r.peer.cancelled.size() == 1,
        "shared hard deadline checked before any backend work");
    check(!r.d.active && r.d.reason == USBMUX_DISPATCHER_REASON_CONNECTION && r.d.failed_slot == 0 &&
        r.conns[0].reason == USBMUX_CONNECTION_REASON_DEADLINE && r.conns[0].state == USBMUX_CONNECTION_DEAD && r.conns[1].state == USBMUX_CONNECTION_DEAD,
        "expired peer ACK on one stream cancels both while another write is pending");
}
static void malformed_peer_and_control_timeout() {
    Runtime partial(1); partial.ready(); partial.peer.read_limit = 1024; partial.peer.inject({0,0,0,1,0,0,0});
    partial.until([&] { return partial.host.rx.used == 7; }); const auto reads = partial.peer.reads;
    check(partial.at(partial.host.rx_at + partial.host.config.receive_ms) == USBMUX_DISPATCHER_CLOSED && partial.peer.reads == reads &&
        partial.d.reason == USBMUX_DISPATCHER_REASON_HOST, "partial physical frame timeout checked before read");
    Runtime held(1); held.ready(); held.peer.inject(packet(USBMUX_CONTROL, {5,'x'})); held.until([&] { return held.d.control_pending != 0; });
    const usbmux_frame *frame; uint64_t token; check(usbmux_dispatcher_control(&held.d, &frame, &token) == USBMUX_DISPATCHER_CONTROL, "held event view");
    check(usbmux_dispatcher_release_control(&held.d, 1, token, held.host.rx_at + held.host.config.receive_ms) == USBMUX_DISPATCHER_CLOSED && !held.d.control_pending,
        "late control release cannot rescue deadline");
    Runtime malformed(1); malformed.ready(); malformed.peer.read_limit = 1024; malformed.peer.inject({0,0,0,99,0,0,0,8});
    const auto end = malformed.now + 5;
    check(malformed.at(end) == USBMUX_DISPATCHER_CLOSED && malformed.d.reason == USBMUX_DISPATCHER_REASON_HOST && malformed.peer.cancelled.size() == 1,
        "malformed physical prefix closes shared transport");
}
static void backend_result_validation() {
    for (const bool write : {false, true}) for (const auto fault : {Fault::Stale, Fault::Overcount, Fault::NonprogressCount, Fault::Disconnect, Fault::Fatal, Fault::Unknown}) {
        Runtime r(2); r.ready(); const auto a = r.open(), b = r.open(62079); r.established(a); r.established(b);
        if (write) { check(r.write(a, {1}) == 1, "faulting output queued"); r.peer.write_fault = fault; }
        else r.peer.read_fault = fault;
        const auto result = r.at(r.now + 5);
        check(result == USBMUX_DISPATCHER_CLOSED && r.peer.cancelled == std::vector<uint64_t>({1}) && !r.d.owner && !r.d.rx_size, "bad backend result closes/cancels once");
        const auto expected = fault == Fault::Stale ? USBMUX_DISPATCHER_REASON_STALE : fault == Fault::Disconnect ? USBMUX_DISPATCHER_REASON_DISCONNECTED :
            fault == Fault::Fatal ? USBMUX_DISPATCHER_REASON_IO : USBMUX_DISPATCHER_REASON_RESULT;
        check(r.d.reason == expected && r.conns[0].tx_next == 1 && r.conns[1].tx_next == 1, "failed/stale callback never credits connection data");
        usbmux_dispatcher_close(&r.d); check(r.d.reason == expected && r.peer.cancelled.size() == 1, "diagnostic retained across repeated closure");
    }
}
static void zero_progress_and_clock_contracts() {
    Runtime r(1); r.ready(); const auto h = r.open(); r.established(h); const auto before = snapshot(r.d); size_t n = 7;
    check(usbmux_dispatcher_write(&r.d, &h, nullptr, 1, &n, r.now + 999) == IAP2_ARGUMENT && !n && snapshot(r.d) == before, "bad write pointer is transactional");
    check(usbmux_dispatcher_read(&r.d, &h, nullptr, 1, &n, r.now + 999) == IAP2_ARGUMENT && !n && snapshot(r.d) == before, "bad read pointer is transactional");
    check(r.at(r.d.now - 1) == IAP2_ARGUMENT && snapshot(r.d) == before, "decreasing clock changes no dispatcher state");
    check(usbmux_dispatcher_write(&r.d, &h, nullptr, 0, &n, r.now) == IAP2_MORE && !n &&
        usbmux_dispatcher_read(&r.d, &h, nullptr, 0, &n, r.now) == IAP2_MORE && !n, "zero-byte operations are no progress, not EOF");
    r.peer.read_fault = Fault::Zero; check(r.at(r.now + 5) == IAP2_MORE && r.d.read_paused && usbmux_dispatcher_next_delay(&r.d) == 5, "zero read result gets retry backoff");
    r.now += 6; check(r.write(h, {1}) == 1, "zero physical write fixture"); r.peer.write_fault = Fault::Zero; r.at(r.now);
    const auto writes = r.peer.writes; r.at(r.now + 1); check(r.peer.writes == writes && r.conns[0].tx_next == 1, "zero write result neither busy-spins nor advances TCP");
    usbmux_dispatcher null{}; const usbmux_frame *frame = nullptr; uint64_t token;
    check(usbmux_dispatcher_poll(nullptr, 0) == IAP2_ARGUMENT && usbmux_dispatcher_control(&null, &frame, &token) == IAP2_ARGUMENT && !frame && !token,
        "null/uninitialized API contracts"); usbmux_dispatcher_close(nullptr); usbmux_dispatcher_default_config(nullptr);
    Runtime near(1); near.peer.read_limit = near.peer.write_limit = 65536; near.now = UINT64_MAX - 20;
    near.start(UINT64_MAX); near.until([&] { return near.host.state == USBMUX_HOST_READY; }); const auto last = near.open(); near.established(last);
    const auto status = near.at(UINT64_MAX); check(status == 0 || status == IAP2_MORE, "near-maximum caller clock remains valid");
    const auto last_state = snapshot(near.d); check(near.at(0) == IAP2_ARGUMENT && snapshot(near.d) == last_state, "dispatcher clock cannot wrap");
    usbmux_dispatcher_close(&near.d); check(usbmux_dispatcher_start(&near.d, 1, UINT64_MAX) == IAP2_ARGUMENT, "physical generation exhaustion cannot wrap");
}
static void zero_window_does_not_starve_other_streams() {
    Runtime r(2); r.peer.zero_first_window = true; r.ready(); const auto a = r.open(), b = r.open(62079); r.established(a); r.established(b);
    check(!r.write(a, {1,2,3}) && r.write(b, {7,8}) == 2, "one zero-window stream does not block others");
    r.until([&] { return r.conns[1].rx_used == 2; }); check(r.read_all(b) == Bytes({7,8}), "other stream response routed correctly");
    r.peer.inject(tcp(62078, 1, 1002, 1, 16, {}, 8)); r.until([&] { return r.conns[0].peer_window == 2048; });
    check(r.write(a, {1,2,3}) == 3, "window update reopens original stream"); r.until([&] { return r.conns[0].rx_used == 3; });
    check(r.read_all(a) == Bytes({1,2,3}), "reopened stream preserves independent bytes");
}
static void maximum_packet_through_bounded_backend_reads() {
    Runtime r(1, 65536, 65500); r.peer.read_limit = 65536; r.peer.write_limit = 65536; r.peer.window = 65535;
    r.ready(); const auto h = r.open(); r.established(h); Bytes payload(65500);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    check(r.write(h, payload) == payload.size(), "maximum application segment accepted");
    const auto reads = r.peer.reads; r.until([&] { return r.conns[0].rx_used == payload.size(); });
    check(r.peer.reads - reads >= 64 && r.read_all(h) == payload, "65536-byte physical packet reassembled using 1024-byte backend chunks");
    check(!r.conns[0].flight_count && r.peer.streams.at(1).received == payload, "maximum payload independently acknowledged and echoed"); r.canaries();
}
int main() {
    try {
        init_start_and_capacity_contracts(); fragmented_handshake_and_four_streams(); physical_completion_and_early_peer_response();
        held_control_tokens_and_coalesced_tails(); graceful_reuse_and_stale_handles(); cancel_and_fresh_physical_generation();
        blocked_write_backoff_and_exact_deadline(); shared_connection_deadline_precedes_io(); malformed_peer_and_control_timeout();
        backend_result_validation(); zero_progress_and_clock_contracts(); zero_window_does_not_starve_other_streams(); maximum_packet_through_bounded_backend_reads();
        std::cout << "PASS: 13 USBmux dispatcher groups; fake physical backend only. Dispatcher bytes=" << sizeof(usbmux_dispatcher) << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
