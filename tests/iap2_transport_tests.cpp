// SPDX-License-Identifier: GPL-3.0-or-later
// Fake nonblocking byte streams and synthetic credentials only. No USB calls.
#include "iap2_transport.h"
#include <algorithm>
#include <array>
#include <deque>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>
using Bytes = std::vector<uint8_t>;
static void check(bool ok, const char *why) { if (!ok) throw std::runtime_error(why); }
static Bytes csm(uint16_t id, const Bytes *body = nullptr) {
    iap2_param param{0, body ? body->data() : nullptr, body ? body->size() : 0};
    Bytes out(4096); size_t n;
    check(iap2_message_encode(id, body ? &param : nullptr, body ? 1 : 0, out.data(), out.size(), &n) == 0, "CSM encode");
    out.resize(n); return out;
}
static Bytes frame(uint8_t flags, uint8_t seq, uint8_t ack, const Bytes *body = nullptr, uint8_t session = 10) {
    iap2_frame f{flags, seq, ack, static_cast<uint8_t>(body ? session : 0), body != nullptr,
                 body ? body->data() : nullptr, body ? body->size() : 0};
    Bytes out(1024); size_t n;
    check(iap2_frame_encode(&f, out.data(), out.size(), &n) == 0, "frame encode"); out.resize(n); return out;
}
static void append(Bytes& out, const Bytes& in) { out.insert(out.end(), in.begin(), in.end()); }
struct Action { int status; size_t count; uint64_t generation = 0; };
struct Backend {
    Bytes input, output;
    std::vector<Bytes> writes;
    std::deque<Action> reads_script, writes_script;
    std::vector<uint64_t> cancelled;
    size_t read_limit = 1024, write_limit = 1024;
    unsigned reads = 0, write_calls = 0;
    bool read_block = false, write_block = false;
    static void read(void *ctx, uint64_t generation, uint8_t *out, size_t cap, iap2_transport_result *r) {
        auto& b = *static_cast<Backend *>(ctx); ++b.reads;
        Action action{IAP2_TRANSPORT_PROGRESS, std::min({cap, b.read_limit, b.input.size()})};
        if (b.read_block || b.input.empty()) action = {IAP2_TRANSPORT_WOULD_BLOCK, 0};
        if (!b.reads_script.empty()) { action = b.reads_script.front(); b.reads_script.pop_front(); }
        *r = {action.status, action.count, action.generation ? action.generation : generation};
        if (r->status == IAP2_TRANSPORT_PROGRESS && r->count <= cap && r->count <= b.input.size()) {
            std::copy_n(b.input.begin(), r->count, out);
            b.input.erase(b.input.begin(), b.input.begin() + r->count);
        }
    }
    static void write(void *ctx, uint64_t generation, const uint8_t *in, size_t n, iap2_transport_result *r) {
        auto& b = *static_cast<Backend *>(ctx); ++b.write_calls;
        b.writes.emplace_back(in, in + n);
        Action action{IAP2_TRANSPORT_PROGRESS, std::min(n, b.write_limit)};
        if (b.write_block) action = {IAP2_TRANSPORT_WOULD_BLOCK, 0};
        if (!b.writes_script.empty()) { action = b.writes_script.front(); b.writes_script.pop_front(); }
        *r = {action.status, action.count, action.generation ? action.generation : generation};
        if (r->status == IAP2_TRANSPORT_PROGRESS && r->count <= n && r->generation == generation)
            b.output.insert(b.output.end(), in, in + r->count);
    }
    static void cancel(void *ctx, uint64_t generation) {
        auto& b = *static_cast<Backend *>(ctx); b.cancelled.push_back(generation);
        b.input.clear(); b.reads_script.clear(); b.writes_script.clear();
    }
};
struct Fixture {
    iap2_control endpoint{};
    iap2_transport pump{};
    iap2_control_config control_config{};
    iap2_transport_config pump_config{};
    std::array<uint8_t, 4098> rx{}, reply{}, scratch{};
    Backend backend;
    iap2_transport_backend io{&backend, Backend::read, Backend::write, Backend::cancel};
    iap2_auth_provider provider{this, certificate, sign};
    unsigned certificates = 0, signatures = 0;
    Bytes signed_challenge;
    uint8_t sequence = 42;
    uint64_t now = 0;
    static int certificate(void *ctx, uint8_t *out, size_t cap, size_t *n) {
        ++static_cast<Fixture *>(ctx)->certificates;
        if (cap < 257) return IAP2_NO_SPACE;
        std::fill_n(out, 257, uint8_t{0x37}); *n = 257; return 0;
    }
    static int sign(void *ctx, const uint8_t *in, size_t size, uint8_t *out, size_t cap, size_t *n) {
        auto& f = *static_cast<Fixture *>(ctx); ++f.signatures;
        f.signed_challenge.assign(in, in + size);
        if (cap < 32) return IAP2_NO_SPACE;
        std::fill_n(out, 32, uint8_t{0x52}); *n = 32; return 0;
    }
    Fixture() {
        rx.fill(0xa5); reply.fill(0xa5); scratch.fill(0xa5);
        iap2_control_default_config(&control_config);
        iap2_transport_default_config(&pump_config);
        reinit(); init_pump();
    }
    Fixture(const Fixture&) = delete; Fixture& operator=(const Fixture&) = delete;
    void reinit() {
        iap2_control_buffers buffers{rx.data() + 1, reply.data() + 1, scratch.data() + 1, 4096, 4096, 4086};
        check(iap2_control_init(&endpoint, &control_config, &provider, &buffers) == 0, "control init");
    }
    void init_pump() { check(iap2_transport_init(&pump, &endpoint, &io, &pump_config) == 0, "pump init"); }
    void start(uint64_t generation = 1) { check(iap2_transport_start(&pump, generation, now) == 0, "pump start"); }
    int poll(uint64_t advance = 1) {
        now += advance;
        const auto reads = backend.reads, writes = backend.write_calls;
        int status = iap2_transport_poll(&pump, now);
        check(backend.reads - reads <= 1 && backend.write_calls - writes <= 1, "I/O call budget");
        canaries(); return status;
    }
    int run(unsigned count = 1) {
        int status = 0;
        for (unsigned i = 0; i < count; ++i) { status = poll(); check(status >= 0, "live bounded poll"); }
        return status;
    }
    void canaries() const {
        check(rx.front() == 0xa5 && rx.back() == 0xa5 && reply.front() == 0xa5 && reply.back() == 0xa5 &&
              scratch.front() == 0xa5 && scratch[4087] == 0xa5, "endpoint external buffer canaries");
    }
    void handshake(uint16_t packet = 1024, uint16_t retransmit = 1000) {
        start(); run();
        while (pump.tx_size) run();
        check(backend.output == Bytes(iap2_detect_marker, iap2_detect_marker + 6), "initial marker");
        backend.output.clear(); append(backend.input, Bytes(iap2_detect_marker, iap2_detect_marker + 6));
        for (unsigned i = 0; i < 1000 && (endpoint.link.state != IAP2_LINK_SYNCHRONIZE || !endpoint.link.syn_sent || pump.tx_size); ++i) run();
        check(endpoint.link.syn_sent && !pump.tx_size, "SYN sent");
        auto offer = control_config.link.offer; offer.packet_size = packet; offer.retransmit_ms = retransmit;
        offer.ack_ms = std::min<uint16_t>(offer.ack_ms, static_cast<uint16_t>(retransmit - 1));
        Bytes payload(32); size_t n;
        check(iap2_lsp_encode(&offer, payload.data(), payload.size(), &n) == 0, "LSP encode"); payload.resize(n);
        append(backend.input, frame(0xc0, sequence, control_config.link.initial_sequence, &payload, 0));
        for (unsigned i = 0; i < 1000 && (endpoint.link.state != IAP2_LINK_NORMAL || pump.tx_size); ++i) run();
        check(endpoint.link.state == IAP2_LINK_NORMAL && !pump.tx_size, "normal link"); backend.output.clear();
    }
    void queue(const Bytes& bytes) { append(backend.input, frame(0x40, ++sequence, endpoint.link.tx_acked, &bytes)); }
    Bytes held() const {
        const uint8_t *data; size_t n;
        check(iap2_control_message(&endpoint, &data, &n) == 0, "held message"); return Bytes(data, data + n);
    }
    void until_message() {
        for (unsigned i = 0; i < 1000; ++i) if (run() == IAP2_CONTROL_MESSAGE) return;
        throw std::runtime_error("no application message");
    }
};

static void configuration_and_clock() {
    Fixture f;
    const auto saved = Bytes(reinterpret_cast<const uint8_t *>(&f.pump), reinterpret_cast<const uint8_t *>(&f.pump) + sizeof f.pump);
    for (unsigned i = 0; i < 8; ++i) {
        auto config = f.pump_config; auto io = f.io;
        if (i == 0) config.pending_ms = 0;
        if (i == 1) config.pending_ms = 60001;
        if (i == 2) config.retry_ms = 0;
        if (i == 3) config.retry_ms = 1001;
        if (i == 4) config.retry_ms = config.pending_ms + 1;
        if (i == 5) io.read = nullptr;
        if (i == 6) io.cancel = nullptr;
        if (i == 7) io.write = nullptr;
        check(iap2_transport_init(&f.pump, &f.endpoint, &io, &config) == IAP2_ARGUMENT, "invalid config");
        check(saved == Bytes(reinterpret_cast<const uint8_t *>(&f.pump), reinterpret_cast<const uint8_t *>(&f.pump) + sizeof f.pump), "transactional init");
    }
    check(iap2_transport_start(&f.pump, 0, 0) == IAP2_ARGUMENT, "zero generation");
    check(iap2_transport_next_delay(&f.pump) == UINT32_MAX, "inactive delay");
    f.now = 10; f.start();
    check(iap2_transport_start(&f.pump, 2, 10) == IAP2_ARGUMENT, "active start rejected");
    check(iap2_transport_poll(&f.pump, 9) == IAP2_ARGUMENT && f.pump.now == 10 && f.backend.reads == 0, "backward clock is transactional");
    check(iap2_transport_poll(nullptr, 0) == IAP2_ARGUMENT && iap2_transport_next_delay(nullptr) == UINT32_MAX, "null handling");
    iap2_transport_close(nullptr); iap2_transport_default_config(nullptr);
}
static void partial_output_and_budget() {
    Fixture f; f.backend.write_limit = 2; f.start();
    f.run(3);
    check(f.backend.output == Bytes(iap2_detect_marker, iap2_detect_marker + 6), "partial marker exactly once");
    check(f.backend.writes.size() == 3 && f.backend.writes[0].size() == 6 && f.backend.writes[1].size() == 4 && f.backend.writes[2].size() == 2, "write only unsent tails");
    check(!f.pump.tx_size && std::all_of(std::begin(f.pump.tx), std::end(f.pump.tx), [](auto v) { return !v; }), "completed tail cleared");
}
static void no_progress_backoff() {
    for (int status : {IAP2_TRANSPORT_WOULD_BLOCK, IAP2_TRANSPORT_PROGRESS}) {
        Fixture f; f.backend.writes_script.push_back({status, 0}); f.start();
        check(f.run() == IAP2_MORE, "zero write waits");
        check(iap2_transport_next_delay(&f.pump) == 5, "no busy spin for retained output");
        const auto reads = f.backend.reads, writes = f.backend.write_calls;
        for (unsigned i = 0; i < 20; ++i) check(f.poll(0) == IAP2_MORE, "same-clock backoff");
        check(f.backend.reads == reads && f.backend.write_calls == writes, "blocked callbacks not repeated");
        f.poll(5);
        check(!f.pump.tx_size && f.backend.output.size() == 6, "retry completes marker");
    }
    Fixture f; f.backend.reads_script.push_back({IAP2_TRANSPORT_PROGRESS, 0}); f.start(); f.run();
    check(f.pump.active && f.pump.read_paused && f.backend.cancelled.empty(), "zero read is not EOF");
}
static void invalid_backend_results() {
    for (bool read : {false, true}) for (Action action : {Action{IAP2_TRANSPORT_PROGRESS, 1025},
            Action{IAP2_TRANSPORT_WOULD_BLOCK, 1}, Action{99, 0}}) {
        Fixture f; (read ? f.backend.reads_script : f.backend.writes_script).push_back(action); f.start();
        check(f.poll() == IAP2_LINK_CLOSED && f.pump.reason == IAP2_TRANSPORT_REASON_RESULT, "invalid completion rejected");
        check(f.backend.cancelled == std::vector<uint64_t>{1} && f.endpoint.link.state == IAP2_LINK_DEAD, "bad backend cancelled");
    }
}
static void disconnect_stall_and_cleanup() {
    for (bool read : {false, true}) for (int status : {IAP2_TRANSPORT_DISCONNECTED, IAP2_TRANSPORT_FATAL}) {
        Fixture f; f.backend.write_limit = 2; f.start(); f.run();
        check(f.pump.tx_offset == 2, "partial before failure");
        (read ? f.backend.reads_script : f.backend.writes_script).push_back({status, 0});
        check(f.poll(5) == IAP2_LINK_CLOSED, "terminal callback closes");
        check(f.backend.output.size() == 2 && !f.pump.tx_size && !f.pump.rx_size, "failed tail never sent");
        const auto reason = f.pump.reason;
        check(reason == (status == IAP2_TRANSPORT_FATAL ? IAP2_TRANSPORT_REASON_IO : IAP2_TRANSPORT_REASON_DISCONNECTED), "failure reason");
        iap2_transport_close(&f.pump); check(f.poll() == IAP2_LINK_CLOSED && f.backend.cancelled.size() == 1 && f.pump.reason == reason, "idempotent cancellation");
        check(f.endpoint.auth.state == IAP2_AUTH_IDLE && !f.endpoint.receive_used && !f.endpoint.reply_size, "endpoint state discarded");
    }
}
static void reconnect_and_stale_results() {
    for (bool read : {false, true}) {
        Fixture f; f.backend.write_limit = 2; f.start(); f.run(); iap2_transport_close(&f.pump);
        check(iap2_transport_start(&f.pump, 2, f.now) == IAP2_ARGUMENT, "closed endpoint needs reinit");
        f.reinit();
        check(iap2_transport_start(&f.pump, 1, f.now) == IAP2_ARGUMENT, "generation reuse rejected");
        f.backend.output.clear(); f.backend.write_limit = 1024;
        (read ? f.backend.reads_script : f.backend.writes_script).push_back({IAP2_TRANSPORT_PROGRESS, 1, 1});
        if (read) f.backend.input.push_back(iap2_detect_marker[0]);
        f.start(2); check(f.poll() == IAP2_LINK_CLOSED && f.pump.reason == IAP2_TRANSPORT_REASON_STALE, "stale result closed");
        check(f.backend.output.empty() && f.backend.cancelled == std::vector<uint64_t>({1, 2}), "old tail not reused on new connection");
        f.reinit(); f.start(3); f.run();
        check(f.backend.output == Bytes(iap2_detect_marker, iap2_detect_marker + 6), "fresh generation starts from marker");
        check(f.endpoint.identification.state == IAP2_IDENTIFICATION_DISABLED, "reinit disables identification");
    }
    Fixture f; f.start(UINT64_MAX); iap2_transport_close(&f.pump); f.reinit();
    check(iap2_transport_start(&f.pump, 1, f.now) == IAP2_ARGUMENT, "generation never wraps");
}
static void output_and_handshake_deadlines() {
    Fixture f; f.pump_config.pending_ms = 12; f.init_pump(); f.backend.write_limit = 1; f.start(); f.run();
    f.run(); f.backend.write_block = true; f.run();
    check(f.pump.tx_at == 1, "partial progress does not reset total budget");
    check(f.poll(10) == IAP2_LINK_CLOSED && f.pump.reason == IAP2_TRANSPORT_REASON_DEADLINE && f.backend.output.size() == 2, "exact tail deadline closes before I/O");
    Fixture h; h.control_config.link.handshake_ms = 9; h.reinit(); h.init_pump(); h.backend.write_block = true; h.start(); h.run();
    h.poll(5); check(iap2_transport_next_delay(&h.pump) == 3, "handshake deadline visible under backpressure");
    check(h.poll(3) == IAP2_LINK_CLOSED && h.pump.reason == IAP2_TRANSPORT_REASON_ENDPOINT, "handshake timeout preserved");
}
static void input_fragmentation_and_coalescing() {
    Fixture f; f.backend.read_limit = 1; f.backend.write_limit = 3; f.handshake();
    const auto a = csm(0x6800), b = csm(0x6801);
    Bytes joined = a; append(joined, b); f.queue(joined); f.until_message();
    check(f.held() == a, "fragmented first CSM");
    check(iap2_control_release_message(&f.endpoint) == 0, "release first CSM"); f.until_message();
    check(f.held() == b, "coalesced second CSM retained");
    f.run(10); check(iap2_transport_next_delay(&f.pump) > 0, "held message alone not an immediate timer");
}
static void recoverable_frame_tail() {
    for (bool unsupported : {false, true}) {
    Fixture f; f.handshake();
    const auto message = csm(0x6802);
    auto bad = frame(unsupported ? 0x60 : 0x40, 43, f.endpoint.link.tx_acked, &message);
    if (!unsupported) bad.back() ^= 1;
    const auto good = frame(0x40, 43, f.endpoint.link.tx_acked, &message);
    append(bad, good); append(f.backend.input, bad);
    f.poll(5);
    check(f.pump.last_feed_error == (unsupported ? IAP2_UNSUPPORTED : IAP2_INVALID) &&
          f.pump.rx_size > f.pump.rx_offset, "bad frame consumed but next frame retained");
    const auto reads = f.backend.reads; f.until_message();
    check(f.held() == message && f.backend.reads == reads, "retained tail fed without replacement read");
    }
}
static void receive_queue_pressure() {
    Fixture f; f.handshake(); f.queue(csm(0x6805)); f.until_message();
    for (unsigned i = 0; i < 10; ++i) f.queue(csm(0x6806));
    f.poll(5);
    check(f.pump.last_feed_error == IAP2_LINK_BUSY && f.pump.rx_size > f.pump.rx_offset &&
          f.endpoint.link.rx_acked == 51, "full RX consumes rejected packet but retains following tail");
    const auto reads = f.backend.reads;
    f.run();
    check(!f.pump.rx_size && f.backend.reads == reads && f.endpoint.link.rx_acked == 51,
          "pending tail processed before another backend read; rejected packets not ACKed");
    f.run(2);
    check(iap2_transport_next_delay(&f.pump) > 0 && f.held() == csm(0x6805), "queue pressure does not busy-spin or lose held request");
}
static void receiving_while_output_blocked() {
    Fixture f; f.handshake();
    f.backend.write_block = true;
    f.queue(csm(0x6803)); f.until_message();
    // Force a cumulative ACK while leaving the application message held.
    f.queue(csm(0x6804)); f.run(10);
    check(f.pump.tx_size && f.pump.write_paused, "ACK retained under blocked output");
    const auto before = f.backend.reads;
    append(f.backend.input, frame(0x40, f.sequence, f.endpoint.link.tx_acked)); f.poll(5);
    check(f.backend.reads > before && f.pump.active && f.held() == csm(0x6803), "RX and app state serviced under TX pressure");
}
static void endpoint_timeouts_and_peer_reset() {
    Fixture f; f.control_config.authentication_ms = 17; f.reinit(); f.init_pump(); f.handshake();
    const auto deadline = f.endpoint.authentication_at + 17;
    f.backend.write_block = true; f.queue(csm(0xaa00));
    while (f.now + 1 < deadline) f.run();
    check(f.pump.tx_size && iap2_transport_next_delay(&f.pump) <= 1, "auth deadline not hidden by pending reply");
    check(f.poll() == IAP2_LINK_CLOSED && f.endpoint.reason == IAP2_CONTROL_REASON_TIMEOUT, "auth timeout closes blocked transport");
    Fixture reset; reset.handshake(); append(reset.backend.input, frame(0x10, reset.sequence, reset.endpoint.link.tx_acked));
    check(reset.poll(5) == IAP2_LINK_CLOSED && reset.endpoint.link.reason == IAP2_LINK_REASON_RESET && reset.backend.cancelled.size() == 1, "peer reset cancels backend");
}
static void retransmission_blocked_by_tail() {
    Fixture f; f.handshake(64, 30); f.backend.write_limit = 2; f.queue(csm(0xaa00));
    for (unsigned i = 0; i < 100 && !f.endpoint.link.tx_sent; ++i) f.run();
    check(f.endpoint.link.tx_sent && f.pump.tx_size, "certificate data tail retained");
    const auto sent = f.endpoint.link.tx[f.endpoint.link.tx_head].sent_at;
    f.backend.write_block = true;
    check(f.poll(sent + 30 - f.now) == IAP2_LINK_CLOSED && f.pump.reason == IAP2_TRANSPORT_REASON_DEADLINE, "negotiated retry deadline closes partial tail");
    check(f.now == sent + 30, "did not wait default tail budget");
}
static void retry_exhaustion_without_tail() {
    Fixture f; f.handshake(64, 10); f.queue(csm(0xaa00));
    for (unsigned i = 0; i < 200 && f.pump.active; ++i) f.poll();
    check(!f.pump.active && f.pump.reason == IAP2_TRANSPORT_REASON_ENDPOINT &&
          f.endpoint.link.reason == IAP2_LINK_REASON_TIMEOUT, "link retry exhaustion still serviced");
    size_t offset = 0; unsigned first_transmissions = 0;
    while (offset < f.backend.output.size()) {
        iap2_frame decoded{}; size_t n;
        check(iap2_frame_decode(f.backend.output.data() + offset, f.backend.output.size() - offset, &decoded, &n) == 0,
              "all emitted retries are complete frames");
        if (decoded.has_payload && decoded.sequence == 100) ++first_transmissions;
        offset += n;
    }
    check(first_transmissions == 4 && f.backend.cancelled.size() == 1, "initial send plus three retries, then cancel");
}

static void full_authentication_exchange() {
    Fixture f; f.control_config.link.offer.packet_size = 64; f.reinit(); f.init_pump();
    f.backend.read_limit = 3; f.backend.write_limit = 5;
    iap2_link peer{}; auto peer_config = f.control_config.link; peer_config.initial_sequence = 42;
    check(iap2_link_init(&peer, &peer_config) == 0 && iap2_link_start(&peer, 0) == 0, "peer start");
    f.start(); Bytes received; unsigned stage = 0;
    bool requested = false, accepted = false, app_queued = false, replied = false;
    const Bytes cert(257, 0x37), signature(32, 0x52), challenge(16, 0x71);
    const Bytes app_body(90, 0x24), app_request = csm(0x6807), app_reply = csm(0x6808, &app_body);
    for (unsigned iteration = 0; iteration < 5000; ++iteration) {
        const int pump_status = f.poll(); check(pump_status >= 0, "pump exchange alive");
        if (pump_status == IAP2_CONTROL_MESSAGE) {
            check(app_queued && !replied && f.held() == app_request, "application request held by pump");
            ++f.now; // Application can advance the shared clock between pump calls.
            check(iap2_control_reply(&f.endpoint, app_reply.data(), app_reply.size(), f.now) == 0, "application reply accepted");
            check(iap2_transport_next_delay(&f.pump) == 0 &&
                  iap2_transport_poll(&f.pump, f.now - 1) == IAP2_ARGUMENT, "application clock advance requires fresh poll time");
            replied = true;
        }
        if (!f.backend.output.empty()) {
            size_t used;
            check(iap2_link_feed(&peer, f.backend.output.data(), f.backend.output.size(), &used, f.now) == 0 && used == f.backend.output.size(), "peer consumes partial transport writes");
            f.backend.output.clear();
        }
        if (peer.state == IAP2_LINK_NORMAL && !requested) {
            const auto request = csm(0xaa00);
            check(iap2_link_send(&peer, 10, request.data(), request.size(), f.now) == 0, "peer requests certificate"); requested = true;
        }
        uint8_t bytes[1024], session; size_t n;
        while (iap2_link_receive(&peer, &session, bytes, sizeof bytes, &n) == 0) {
            check(session == 10, "peer control session"); received.insert(received.end(), bytes, bytes + n);
        }
        if (received.size() >= 6 && received.size() == (static_cast<size_t>(received[2]) << 8 | received[3])) {
            check(received == (stage == 0 ? csm(0xaa01, &cert) : stage == 1 ? csm(0xaa03, &signature) : app_reply), "peer sees complete synthetic reply");
            if (stage < 2) {
                const auto next = stage == 0 ? csm(0xaa02, &challenge) : csm(0xaa05);
                check(iap2_link_send(&peer, 10, next.data(), next.size(), f.now) == 0, "peer queues next auth step");
            }
            check(++stage <= 3, "no duplicate replies"); received.clear();
        }
        if (stage == 2 && f.endpoint.auth.state == IAP2_AUTH_ACCEPTED && !app_queued) {
            check(iap2_link_send(&peer, 10, app_request.data(), app_request.size(), f.now) == 0, "peer application request");
            app_queued = true;
        }
        const int status = iap2_link_output(&peer, bytes, sizeof bytes, &n, f.now);
        check(status == IAP2_OK || status == IAP2_MORE, "peer output live");
        if (n) f.backend.input.insert(f.backend.input.end(), bytes, bytes + n);
        if (stage == 3 && f.endpoint.auth.state == IAP2_AUTH_ACCEPTED && !peer.tx_count && !f.pump.tx_size &&
            !f.endpoint.reply_size && !f.endpoint.link.tx_count) { accepted = true; break; }
    }
    check(accepted && replied && f.certificates == 1 && f.signatures == 1 && f.signed_challenge == challenge,
          "full auth/application exchange over pump, exact challenge, provider exactly once");
    check(f.endpoint.identification.state == IAP2_IDENTIFICATION_DISABLED, "auth is not implicit identification or CarPlay");
    iap2_transport_close(&f.pump);
    check(f.endpoint.auth.state == IAP2_AUTH_IDLE && f.backend.cancelled.size() == 1, "accepted auth cleared on transport close");
}
int main() {
    try {
        configuration_and_clock(); partial_output_and_budget(); no_progress_backoff(); invalid_backend_results();
        disconnect_stall_and_cleanup(); reconnect_and_stale_results(); output_and_handshake_deadlines();
        input_fragmentation_and_coalescing(); recoverable_frame_tail(); receive_queue_pressure(); receiving_while_output_blocked();
        endpoint_timeouts_and_peer_reset(); retransmission_blocked_by_tail(); retry_exhaustion_without_tail(); full_authentication_exchange();
        std::cout << "PASS: 15 bounded transport test groups (fake byte streams only).\n";
        std::cout << "Host transport storage: " << sizeof(iap2_transport) << " bytes plus control endpoint/buffers.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
