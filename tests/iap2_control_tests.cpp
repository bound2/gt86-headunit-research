// SPDX-License-Identifier: GPL-3.0-or-later
// Synthetic transport/provider integration, NOT an iPhone/auth-chip test.
#include "iap2_control.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
using Bytes = std::vector<uint8_t>;
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static Bytes pattern(size_t size, uint8_t base) {
    Bytes b(size); for (size_t i = 0; i < size; ++i) b[i] = static_cast<uint8_t>(base + i % 31); return b;
}
static Bytes csm(uint16_t id, const Bytes *body = nullptr) {
    iap2_param p{0, body ? body->data() : nullptr, body ? body->size() : 0};
    Bytes b(65535); size_t n;
    check(iap2_message_encode(id, body ? &p : nullptr, body ? 1 : 0, b.data(), b.size(), &n) == IAP2_OK, "encode CSM");
    b.resize(n); return b;
}
static Bytes frame(uint8_t flags, uint8_t seq, uint8_t ack, const Bytes *body = nullptr, uint8_t session = 10) {
    iap2_frame f{flags, seq, ack, static_cast<uint8_t>(body ? session : 0), body != nullptr,
        body ? body->data() : nullptr, body ? body->size() : 0};
    Bytes b(1024); size_t n;
    check(iap2_frame_encode(&f, b.data(), b.size(), &n) == IAP2_OK, "encode frame"); b.resize(n); return b;
}
struct Provider {
    unsigned certificates = 0, signatures = 0;
    size_t certificate_size = 2048, signature_size = 128;
    int error = IAP2_OK;
    bool overreport = false;
    Bytes challenge;
    static int certificate(void *ctx, uint8_t *out, size_t cap, size_t *n) {
        auto& p = *static_cast<Provider *>(ctx); ++p.certificates;
        if (p.error) return p.error;
        if (p.overreport) { *n = cap + 1; return IAP2_OK; }
        if (cap < p.certificate_size) return IAP2_NO_SPACE;
        const auto data = pattern(p.certificate_size, 0x90);
        std::copy(data.begin(), data.end(), out); *n = data.size(); return IAP2_OK;
    }
    static int sign(void *ctx, const uint8_t *in, size_t size, uint8_t *out, size_t cap, size_t *n) {
        auto& p = *static_cast<Provider *>(ctx); ++p.signatures;
        p.challenge.assign(in, in + size);
        if (p.error) return p.error;
        if (cap < p.signature_size) return IAP2_NO_SPACE;
        const auto data = pattern(p.signature_size, 0x30);
        std::copy(data.begin(), data.end(), out); *n = data.size(); return IAP2_OK;
    }
};
struct Endpoint {
    Provider provider;
    iap2_control_config config{};
    iap2_auth_provider callbacks{&provider, Provider::certificate, Provider::sign};
    Bytes rx, tx, scratch;
    iap2_control_buffers buffers{};
    iap2_control engine{};
    uint8_t peer_sequence = 42;
    explicit Endpoint(size_t capacity = 8192, uint16_t packet = 1024)
        : rx(capacity + 2, 0xa5), tx(capacity + 2, 0xa5), scratch(capacity - 10 + 2, 0xa5) {
        iap2_control_default_config(&config); config.link.offer.packet_size = packet;
        buffers = {rx.data() + 1, tx.data() + 1, scratch.data() + 1, capacity, capacity, capacity - 10};
        init();
    }
    Endpoint(const Endpoint&) = delete; Endpoint& operator=(const Endpoint&) = delete;
    void init() { check(iap2_control_init(&engine, &config, &callbacks, &buffers) == IAP2_OK, "control init"); }
    void canaries() const {
        check(rx.front() == 0xa5 && rx.back() == 0xa5 && tx.front() == 0xa5 && tx.back() == 0xa5 &&
            scratch.front() == 0xa5 && scratch.back() == 0xa5, "external buffer canaries");
    }
    void feed(const Bytes& b, uint64_t now = 0, int expected = IAP2_OK, size_t chunk = 0) {
        if (!chunk) chunk = std::max<size_t>(1, b.size());
        size_t offset = 0;
        do {
            size_t n = 999, count = std::min(chunk, b.size() - offset);
            int status = iap2_control_feed(&engine, b.data() + offset, count, &n, now);
            if (status != expected) throw std::runtime_error("feed " + std::to_string(status) + " expected " + std::to_string(expected));
            check(n == count, "test feed consumed count"); offset += count;
        } while (offset < b.size());
    }
    Bytes output(uint64_t now = 0) {
        Bytes b(1024); size_t n = 999;
        int status = iap2_control_output(&engine, b.data(), b.size(), &n, now);
        check(status == IAP2_OK || status == IAP2_MORE, "control output"); b.resize(n); return b;
    }
    int poll(uint64_t now = 0) {
        int status; unsigned count = 0;
        do { status = iap2_control_poll(&engine, now); check(++count <= 10000, "bounded poll loop"); }
        while (status == IAP2_OK);
        return status;
    }
    void handshake(uint64_t now = 0, uint16_t selected_packet = 0) {
        check(iap2_control_start(&engine, now) == IAP2_OK, "control start");
        check(output(now) == Bytes(iap2_detect_marker, iap2_detect_marker + 6), "control marker");
        feed(Bytes(iap2_detect_marker, iap2_detect_marker + 6), now, IAP2_OK, 1);
        check(!output(now).empty(), "control SYN");
        auto selected = config.link.offer;
        if (selected_packet) selected.packet_size = selected_packet;
        Bytes proposal(19); size_t n;
        check(iap2_lsp_encode(&selected, proposal.data(), proposal.size(), &n) == IAP2_OK, "selected LSP");
        proposal.resize(n); peer_sequence = 42;
        feed(frame(0xc0, peer_sequence, config.link.initial_sequence, &proposal, 0), now);
        check(!output(now).empty() && engine.link.state == IAP2_LINK_NORMAL, "control established");
        check(engine.authentication_timer && engine.authentication_at == now, "auth total deadline armed");
    }
    void payload(const Bytes& b, uint64_t now = 0, size_t transport_chunk = 0) {
        feed(frame(0x40, ++peer_sequence, engine.link.tx_acked, &b, config.link.offer.sessions[0].id), now, IAP2_OK, transport_chunk);
    }
    Bytes held() const {
        const uint8_t *data = nullptr; size_t size = 999;
        check(iap2_control_message(&engine, &data, &size) == IAP2_OK, "held CSM view"); return Bytes(data, data + size);
    }
    Bytes drain_reply(uint64_t now = 0) {
        Bytes joined;
        for (unsigned tries = 0; tries < 10000; ++tries) {
            int status = poll(now);
            check(status == IAP2_LINK_BUSY || status == IAP2_MORE || status == IAP2_CONTROL_MESSAGE, "drain poll");
            auto bytes = output(now);
            if (!bytes.empty()) {
                iap2_frame f{}; size_t n;
                check(iap2_frame_decode(bytes.data(), bytes.size(), &f, &n) == IAP2_OK, "drain decode");
                if (f.has_payload) {
                    check(f.session == config.link.offer.sessions[0].id && bytes.size() <= engine.link.negotiated.packet_size,
                        "reply negotiated session/MTU");
                    joined.insert(joined.end(), f.payload, f.payload + f.payload_size);
                    feed(frame(0x40, peer_sequence, f.sequence), now);
                }
            }
            if (!engine.reply_size && !engine.link.tx_count) return joined;
        }
        throw std::runtime_error("reply did not drain");
    }
    void certificate(uint64_t now = 0) {
        payload(csm(0xaa00), now); check(poll(now) == IAP2_LINK_BUSY, "certificate reply pending");
        const auto data = pattern(provider.certificate_size, 0x90);
        check(drain_reply(now) == csm(0xaa01, &data), "complete certificate response");
    }
    void authenticate(uint64_t now = 0) {
        certificate(now);
        const auto challenge = pattern(64, 0x10); payload(csm(0xaa02, &challenge), now);
        const auto signature = pattern(provider.signature_size, 0x30);
        check(drain_reply(now) == csm(0xaa03, &signature), "complete signature response");
        payload(csm(0xaa05), now); check(poll(now) == IAP2_MORE && engine.auth.state == IAP2_AUTH_ACCEPTED,
            "synthetic success notification");
    }
};

static void configuration() {
    Endpoint e;
    const auto before = Bytes(reinterpret_cast<uint8_t *>(&e.engine), reinterpret_cast<uint8_t *>(&e.engine) + sizeof e.engine);
    for (unsigned choice = 0; choice < 10; ++choice) {
        auto config = e.config; auto buffers = e.buffers;
        switch (choice) {
        case 0: buffers.receive_capacity = 5; break;
        case 1: buffers.reply_capacity = 10; break;
        case 2: buffers.scratch_capacity = 0; break;
        case 3: buffers.scratch_capacity = buffers.reply_capacity - 9; break;
        case 4: buffers.receive_capacity = 65536; break;
        case 5: config.message_ms = 0; break;
        case 6: config.authentication_ms = 0; break;
        case 7: config.link.offer.session_count = 2; break;
        case 8: config.link.offer.sessions[0].kind = 1; break;
        case 9: config.link.offer.packet_size = 28; break;
        }
        check(iap2_control_init(&e.engine, &config, &e.callbacks, &buffers) == IAP2_ARGUMENT, "invalid control config");
        check(std::memcmp(&e.engine, before.data(), before.size()) == 0, "failed init transaction");
    }
    size_t n = 777; const uint8_t *p = reinterpret_cast<const uint8_t *>(1);
    check(iap2_control_message(&e.engine, &p, &n) == IAP2_MORE && p == nullptr && n == 0, "no stale message outputs");
    check(iap2_control_poll(&e.engine, 0) == IAP2_ARGUMENT && iap2_control_next_delay(&e.engine) == UINT32_MAX, "poll requires start");
    check(iap2_control_poll(nullptr, 0) == IAP2_ARGUMENT, "null poll");
    check(iap2_control_feed(nullptr, nullptr, 0, &n, 0) == IAP2_ARGUMENT && n == 0, "null feed");
    check(iap2_control_output(nullptr, e.rx.data(), 1, &n, 0) == IAP2_ARGUMENT && n == 0, "null output");
    check(iap2_control_release_message(&e.engine) == IAP2_MORE, "nothing to release");
    e.canaries();
    Endpoint session; session.config.link.offer.sessions[0].id = 23; session.init(); session.handshake();
    session.authenticate(); session.canaries();
}
static void header_splits() {
    const auto request = csm(0xaa00);
    for (size_t cut = 0; cut <= request.size(); ++cut) {
        Endpoint e; e.handshake();
        e.payload(Bytes(request.begin(), request.begin() + cut), 0, 1);
        const int first = e.poll();
        check(first == (cut == request.size() ? IAP2_LINK_BUSY : IAP2_MORE), "CSM header split first half");
        e.payload(Bytes(request.begin() + cut, request.end()), 0, 1);
        check(e.poll() == IAP2_LINK_BUSY && e.provider.certificates == 1, "split certificate request exactly once");
        const auto data = pattern(2048, 0x90);
        check(e.drain_reply() == csm(0xaa01, &data), "fragmented certificate bytes"); e.canaries();
    }
}
static void large_receive() {
    const auto body = pattern(5990, 0x50), message = csm(0x1234, &body);
    for (size_t chunk : {size_t(1), size_t(5), size_t(17), size_t(1014)}) {
        Endpoint e; e.handshake();
        for (size_t offset = 0; offset < message.size(); offset += chunk) {
            const auto end = std::min(message.size(), offset + chunk);
            e.payload(Bytes(message.begin() + offset, message.begin() + end));
            check(e.poll() == (end == message.size() ? IAP2_CONTROL_MESSAGE : IAP2_MORE), "large RX split");
        }
        check(e.held() == message && e.provider.certificates == 0, "unknown CSM preserved");
        check(e.poll() == IAP2_CONTROL_MESSAGE && e.held() == message, "held view stable"); e.canaries();
    }
    Endpoint maximum(65535); maximum.handshake();
    const auto maximum_body = pattern(65525, 0x20), maximum_message = csm(0x1234, &maximum_body);
    for (size_t offset = 0; offset < maximum_message.size(); offset += 1014) {
        const auto end = std::min(maximum_message.size(), offset + 1014);
        maximum.payload(Bytes(maximum_message.begin() + offset, maximum_message.begin() + end));
        check(maximum.poll() == (end == maximum_message.size() ? IAP2_CONTROL_MESSAGE : IAP2_MORE), "maximum RX chunks");
    }
    check(maximum.held() == maximum_message, "maximum legal RX length"); maximum.canaries();
}
static void coalesced_and_hold() {
    Endpoint e; e.handshake();
    const auto a = csm(0x1234), b = csm(0x5678), request = csm(0xaa00);
    auto joined = a; joined.insert(joined.end(), b.begin(), b.end()); joined.insert(joined.end(), request.begin(), request.end());
    e.payload(joined); check(e.poll() == IAP2_CONTROL_MESSAGE && e.held() == a, "first coalesced CSM");
    for (unsigned i = 0; i < 5; ++i) check(e.poll() == IAP2_CONTROL_MESSAGE, "held CSM pressure");
    check(e.provider.certificates == 0, "no callback through app hold");
    check(iap2_control_release_message(&e.engine) == IAP2_OK && iap2_control_next_delay(&e.engine) == 0, "release schedules work");
    check(e.poll() == IAP2_CONTROL_MESSAGE && e.held() == b, "second coalesced CSM");
    check(iap2_control_release_message(&e.engine) == IAP2_OK, "release second");
    check(e.poll() == IAP2_LINK_BUSY && e.provider.certificates == 1, "coalesced auth after release");
    e.drain_reply(); e.canaries();
}
static void malformed_and_capacity() {
    const std::vector<Bytes> bad{{0x41,0x40,0,6,0xaa,0}, {0x40,0x40,0,5,0xaa,0},
        {0x40,0x40,0,7,0xaa,0,0}, {0x40,0x40,0,10,0xaa,2,0,3,0,0},
        {0x40,0x40,0,10,0xaa,2,0,5,0,0}, {0x40,0x40,0xff,0xff,0xaa,0}};
    for (size_t i = 0; i < bad.size(); ++i) {
        Endpoint e; e.handshake(); e.payload(bad[i]);
        check(e.poll() == (i == bad.size() - 1 ? IAP2_NO_SPACE : IAP2_INVALID), "malformed CSM rejected");
        check(e.engine.reason == IAP2_CONTROL_REASON_MESSAGE && e.engine.link.state == IAP2_LINK_DEAD &&
            e.engine.auth.state == IAP2_AUTH_IDLE && !e.engine.receive_used, "message failure teardown");
        const int original = e.engine.last_error;
        check(e.poll() == IAP2_LINK_CLOSED && e.engine.last_error == original && e.provider.certificates == 0, "sticky error"); e.canaries();
    }
    Endpoint exact(64); exact.handshake();
    const auto body = pattern(54, 3); const auto message = csm(0x4321, &body);
    exact.payload(message); check(exact.poll() == IAP2_CONTROL_MESSAGE && exact.held() == message, "exact RX capacity");
    exact.canaries();
}
static void negotiated_fragmentation_and_pressure() {
    Endpoint e; e.handshake(0, 29); e.payload(csm(0xaa00));
    check(iap2_control_poll(&e.engine, 0) == IAP2_OK && e.engine.work_pending &&
        iap2_control_next_delay(&e.engine) == 0 && e.engine.reply_offset < 8 * 19,
        "bounded poll yields with immediate continuation");
    check(e.poll() == IAP2_LINK_BUSY && e.engine.link.tx_count == 8 && e.engine.reply_offset == 8 * 19,
        "small negotiated MTU saturates queue");
    const auto offset = e.engine.reply_offset;
    for (unsigned i = 0; i < 10; ++i) check(e.poll() == IAP2_LINK_BUSY, "reply backpressure");
    check(e.provider.certificates == 1 && e.engine.reply_offset == offset, "no duplicate callback/progress under pressure");
    uint8_t tiny[8]{}; size_t n = 77;
    check(iap2_control_output(&e.engine, tiny, sizeof tiny, &n, 0) == IAP2_NO_SPACE && n == 0 && !e.engine.link.tx_sent,
        "small physical output preserves queued reply");
    const auto certificate = pattern(2048, 0x90);
    check(e.drain_reply() == csm(0xaa01, &certificate) && e.provider.certificates == 1, "reply resumes exact bytes");
    e.canaries();
    Endpoint final_ack; final_ack.handshake(); final_ack.payload(csm(0xaa00)); final_ack.poll();
    while (!final_ack.output().empty()) {}
    check(final_ack.poll() == IAP2_LINK_BUSY && iap2_control_next_delay(&final_ack.engine) > 0, "ACK wait does not spin");
    final_ack.feed(frame(0x40, final_ack.peer_sequence, final_ack.engine.link.tx_sequence));
    check(iap2_control_next_delay(&final_ack.engine) == 0 && final_ack.poll() == IAP2_MORE, "final ACK schedules reply release");
}
static void authentication_serialization() {
    Endpoint e; e.handshake();
    const auto challenge = pattern(64, 0x10);
    auto pipeline = csm(0xaa00), request = csm(0xaa02, &challenge), success = csm(0xaa05);
    pipeline.insert(pipeline.end(), request.begin(), request.end()); pipeline.insert(pipeline.end(), success.begin(), success.end());
    e.payload(pipeline); check(e.poll() == IAP2_LINK_BUSY, "pipelined auth starts");
    check(e.provider.certificates == 1 && e.provider.signatures == 0 && e.engine.auth.state == IAP2_AUTH_WAIT_CHALLENGE,
        "no signing before certificate ACK");
    // Hand off the entire certificate without ACKing it. Queued later CSMs stay blocked.
    while (!e.output().empty()) {}
    check(e.poll() == IAP2_LINK_BUSY && !e.provider.signatures, "sent is not acknowledged");
    e.feed(frame(0x40, e.peer_sequence, e.engine.link.tx_sequence));
    check(e.poll() == IAP2_LINK_BUSY && e.provider.signatures == 1 && e.provider.challenge == challenge, "ACK allows challenge");
    check(e.engine.auth.state == IAP2_AUTH_WAIT_RESULT, "success still blocked behind signature ACK");
    const auto signature = pattern(128, 0x30);
    check(e.drain_reply() == csm(0xaa03, &signature) && e.engine.auth.state == IAP2_AUTH_ACCEPTED &&
        !e.engine.authentication_timer, "ACK allows success notification only");
    e.canaries();
}
static void provider_failures() {
    for (unsigned mode = 0; mode < 4; ++mode) {
        Endpoint e;
        if (mode == 0) e.provider.error = IAP2_INVALID;
        if (mode == 1) e.callbacks.certificate = nullptr;
        if (mode == 2) e.provider.certificate_size = 0;
        if (mode == 3) e.provider.overreport = true;
        e.init(); e.handshake(); e.payload(csm(0xaa00));
        check(e.poll() == IAP2_PROVIDER_FAILED && e.engine.reason == IAP2_CONTROL_REASON_AUTH &&
            e.engine.auth.state == IAP2_AUTH_IDLE && !e.engine.link.tx_count, "certificate failure closes"); e.canaries();
    }
    Endpoint e; e.handshake(); e.certificate(); e.provider.error = IAP2_INVALID;
    const auto challenge = pattern(64, 0x10); e.payload(csm(0xaa02, &challenge));
    check(e.poll() == IAP2_PROVIDER_FAILED && e.provider.signatures == 1 && !e.engine.reply_size, "sign failure closes"); e.canaries();
}
static void auth_protocol_failures() {
    const auto challenge = pattern(64, 1);
    for (const auto& message : {csm(0xaa02, &challenge), csm(0xaa05), csm(0xaa04), csm(0xaa00, &challenge)}) {
        Endpoint e; e.handshake(); e.payload(message);
        const auto status = e.poll();
        check((status == IAP2_INVALID || status == IAP2_AUTH_FAILED) && e.engine.reason == IAP2_CONTROL_REASON_AUTH &&
            !e.provider.certificates && !e.provider.signatures, "out-of-sequence auth failed");
    }
    Endpoint e; e.handshake(); e.certificate(); e.payload(csm(0xaa00));
    check(e.poll() == IAP2_INVALID && e.provider.certificates == 1, "duplicate certificate request not repeated");
}
static void disconnect_and_reinit() {
    for (unsigned phase = 0; phase < 4; ++phase) {
        Endpoint e; e.handshake();
        if (phase == 0) { e.payload(Bytes{0x40,0x40,0}); check(e.poll() == IAP2_MORE, "partial before close"); }
        if (phase == 1) { e.payload(csm(0xaa00)); check(e.poll() == IAP2_LINK_BUSY, "reply before close"); }
        if (phase == 2) e.authenticate();
        if (phase == 3) { e.payload(csm(0x1234)); check(e.poll() == IAP2_CONTROL_MESSAGE, "held before close"); }
        iap2_control_close(&e.engine);
        check(e.engine.reason == IAP2_CONTROL_REASON_LOCAL && e.engine.auth.state == IAP2_AUTH_IDLE &&
            !e.engine.reply_size && !e.engine.receive_used && !e.engine.fragment_size, "local close discards upper layers");
        for (const auto *buffer : {&e.rx, &e.tx, &e.scratch})
            check(std::all_of(buffer->begin() + 1, buffer->end() - 1, [](auto b){return b == 0;}), "close clears external buffers");
        check(e.poll() == IAP2_LINK_CLOSED && iap2_control_next_delay(&e.engine) == UINT32_MAX, "closed endpoint not runnable");
        e.init(); e.handshake(); e.authenticate(); e.canaries();
    }
    Endpoint direct; direct.handshake(); direct.authenticate();
    direct.init(); check(direct.engine.auth.state == IAP2_AUTH_IDLE && direct.engine.link.state == IAP2_LINK_IDLE, "direct reinit clears acceptance");
    direct.handshake(); direct.payload(csm(0xaa05)); check(direct.poll() == IAP2_INVALID, "stale success not accepted after reinit");
}
static void remote_close_and_retry_timeout() {
    Endpoint e; e.handshake(); e.payload(csm(0xaa00)); check(e.poll() == IAP2_LINK_BUSY, "pending before RST");
    e.feed(frame(0x10, 0, 0), 0, IAP2_LINK_CLOSED);
    check(e.engine.reason == IAP2_CONTROL_REASON_LINK && e.engine.link.reason == IAP2_LINK_REASON_RESET &&
        e.engine.auth.state == IAP2_AUTH_IDLE && !e.engine.reply_size, "RST immediate auth reset without poll");
    Endpoint timeout; timeout.handshake(); timeout.payload(csm(0xaa00)); timeout.poll();
    for (unsigned i = 0; i < 4; ++i) while (!timeout.output(i * 1000).empty()) {}
    uint8_t b[1024]; size_t n = 77;
    check(iap2_control_output(&timeout.engine, b, sizeof b, &n, 4000) == IAP2_LINK_CLOSED && n == 0 &&
        timeout.engine.reason == IAP2_CONTROL_REASON_LINK && timeout.engine.link.reason == IAP2_LINK_REASON_TIMEOUT &&
        timeout.engine.auth.state == IAP2_AUTH_IDLE, "retry exhaustion resets adapter");
    Endpoint handshake; check(iap2_control_start(&handshake.engine, 0) == IAP2_OK, "timeout start");
    check(handshake.poll(10000) == IAP2_LINK_CLOSED && handshake.engine.reason == IAP2_CONTROL_REASON_LINK, "handshake timeout through poll");
    Endpoint recoverable; recoverable.handshake();
    // Bad body checksum must not discard an otherwise live auth session.
    const auto request = csm(0xaa00);
    auto damaged = frame(0x40, 43, 99, &request); damaged.back() ^= 1;
    recoverable.feed(damaged, 0, IAP2_INVALID);
    check(recoverable.engine.reason == IAP2_CONTROL_REASON_NONE && recoverable.engine.link.state == IAP2_LINK_NORMAL,
        "recoverable wire error retains endpoint");
    recoverable.payload(request); check(recoverable.poll() == IAP2_LINK_BUSY, "valid retransmit after damaged body");
    Endpoint restart; restart.handshake(); restart.authenticate();
    Bytes proposal(19); size_t size;
    check(iap2_lsp_encode(&restart.config.link.offer, proposal.data(), proposal.size(), &size) == IAP2_OK, "restart LSP");
    proposal.resize(size); restart.feed(frame(0x80, 90, 0, &proposal, 0), 0, IAP2_LINK_CLOSED);
    check(restart.engine.link.reason == IAP2_LINK_REASON_RESTART && restart.engine.auth.state == IAP2_AUTH_IDLE,
        "peer restart clears previously accepted auth");
}
static void adapter_timers() {
    Endpoint e; e.config.message_ms = 50; e.config.authentication_ms = 200; e.init(); e.handshake();
    e.payload(Bytes{0x40}, 10); check(e.poll(10) == IAP2_MORE && iap2_control_next_delay(&e.engine) == 50, "partial CSM deadline");
    e.payload(Bytes{0x40}, 49); check(e.poll(49) == IAP2_MORE && e.engine.message_at == 10, "drip does not extend deadline");
    e.output(49); // Drain immediate ACK so next_delay measures the adapter timer.
    check(iap2_control_next_delay(&e.engine) == 11 && e.poll(60) == IAP2_LINK_CLOSED &&
        e.engine.reason == IAP2_CONTROL_REASON_TIMEOUT, "partial total timeout");
    Endpoint held; held.config.message_ms = 50; held.init(); held.handshake(); held.payload(csm(0x1234));
    check(held.poll() == IAP2_CONTROL_MESSAGE && iap2_control_next_delay(&held.engine) == 50, "held message deadline without spin");
    check(held.poll(50) == IAP2_LINK_CLOSED, "application hold bounded");
    Endpoint auth; auth.config.authentication_ms = 200; auth.init(); auth.handshake();
    check(iap2_control_next_delay(&auth.engine) == 200 && auth.poll(199) == IAP2_MORE, "auth total budget");
    size_t n = 777;
    check(iap2_control_feed(&auth.engine, nullptr, 0, &n, 200) == IAP2_LINK_CLOSED && n == 0 &&
        auth.engine.reason == IAP2_CONTROL_REASON_TIMEOUT, "auth deadline checked on feed");
    Endpoint blocked; blocked.config.authentication_ms = 200; blocked.init(); blocked.handshake(); blocked.payload(csm(0xaa00)); blocked.poll();
    uint8_t out[1024];
    check(iap2_control_output(&blocked.engine, out, sizeof out, &n, 200) == IAP2_LINK_CLOSED && !n, "TX stall bounded by auth budget");
    Endpoint accepted; accepted.handshake(); accepted.authenticate(); accepted.output(100);
    check(accepted.poll(40000) == IAP2_MORE && accepted.engine.auth.state == IAP2_AUTH_ACCEPTED &&
        iap2_control_next_delay(&accepted.engine) == UINT32_MAX, "accepted auth cancels total timer");
    check(accepted.poll(39999) == IAP2_ARGUMENT && accepted.engine.auth.state == IAP2_AUTH_ACCEPTED, "backward time transaction");
    Endpoint high; const auto start = UINT64_MAX - 1000; high.config.authentication_ms = 200; high.init(); high.handshake(start);
    check(high.poll(start + 199) == IAP2_MORE && iap2_control_next_delay(&high.engine) == 1 &&
        high.poll(start + 200) == IAP2_LINK_CLOSED, "deadline arithmetic near UINT64_MAX");
}
static void work_budget_and_queue_pressure() {
    Endpoint e; e.handshake();
    const auto empty = csm(0xaa00); // Unknowns are used below to exercise explicit application flow.
    for (unsigned i = 0; i < 8; ++i) e.payload(Bytes{});
    check(e.poll() == IAP2_MORE, "empty payloads consumed without loop");
    e.payload(csm(0x1234)); check(e.poll() == IAP2_CONTROL_MESSAGE, "hold before RX saturation");
    for (unsigned i = 0; i < 8; ++i) e.payload(csm(0x2000 + i));
    const auto dropped = frame(0x40, ++e.peer_sequence, e.engine.link.tx_acked, &empty);
    e.feed(dropped, 0, IAP2_LINK_BUSY);
    check(e.provider.certificates == 0 && e.held() == csm(0x1234), "RX pressure preserves held CSM");
    for (unsigned i = 0; i < 8; ++i) {
        check(iap2_control_release_message(&e.engine) == IAP2_OK && e.poll() == IAP2_CONTROL_MESSAGE &&
            e.held() == csm(0x2000 + i), "queued unknown messages preserve order");
    }
    check(iap2_control_release_message(&e.engine) == IAP2_OK && e.poll() == IAP2_MORE, "RX queue drained");
    e.feed(dropped); check(e.poll() == IAP2_LINK_BUSY && e.provider.certificates == 1, "peer retry after RX pressure");
    Endpoint budget(65535, 29); budget.provider.certificate_size = 65525; budget.handshake();
    budget.payload(csm(0xaa00)); check(budget.poll() == IAP2_LINK_BUSY, "maximum certificate bounded queue");
    const auto data = pattern(65525, 0x90);
    check(budget.drain_reply() == csm(0xaa01, &data), "maximum legal CSM reply"); budget.canaries();
}

// Both real library endpoints, byte-fragmented synthetic transport, one lost
// certificate frame. The peer checks complete bytes before issuing each next
// auth message. Test data is a deterministic pattern, never a credential.
static void two_endpoint_exchange() {
    Endpoint a(8192, 128); a.config.link.offer.retransmit_ms = 250; a.init();
    iap2_link peer{}; auto config = a.config.link; config.initial_sequence = 42;
    check(iap2_link_init(&peer, &config) == IAP2_OK && iap2_link_start(&peer, 0) == IAP2_OK &&
        iap2_control_start(&a.engine, 0) == IAP2_OK, "two endpoint start");
    const auto challenge = pattern(64, 0x10), certificate = pattern(2048, 0x90), signature = pattern(128, 0x30);
    Bytes incoming;
    bool requested = false, lost = false;
    unsigned responses = 0;
    for (uint64_t now = 0; now < 10000; now += 5) {
        auto bytes = a.output(now);
        if (!bytes.empty()) {
            bool drop = false;
            if (bytes.size() >= 10 && bytes[7] == 10 && !lost) { lost = true; drop = true; }
            if (!drop) for (size_t offset = 0; offset < bytes.size();) {
                size_t n = 777, amount = std::min<size_t>(3, bytes.size() - offset);
                check(iap2_link_feed(&peer, bytes.data() + offset, amount, &n, now) == IAP2_OK && n == amount, "peer fragmented feed");
                offset += n;
            }
        }
        if (peer.state == IAP2_LINK_NORMAL && !requested) {
            const auto request = csm(0xaa00);
            check(iap2_link_send(&peer, 10, request.data(), request.size(), now) == IAP2_OK, "peer requests certificate"); requested = true;
        }
        for (;;) {
            uint8_t out[1014], session; size_t n;
            const auto status = iap2_link_receive(&peer, &session, out, sizeof out, &n);
            if (status == IAP2_MORE) break;
            check(status == IAP2_OK && session == 10, "peer receive session");
            incoming.insert(incoming.end(), out, out + n);
            iap2_message message{}; size_t used;
            const auto decoded = iap2_message_decode(incoming.data(), incoming.size(), &message, &used);
            if (decoded == IAP2_MORE) continue;
            check(decoded == IAP2_OK && used == incoming.size(), "peer complete CSM decode");
            check(incoming == (responses == 0 ? csm(0xaa01, &certificate) : csm(0xaa03, &signature)), "peer verifies full reply bytes");
            const auto next = responses == 0 ? csm(0xaa02, &challenge) : csm(0xaa05);
            check(++responses <= 2 && iap2_link_send(&peer, 10, next.data(), next.size(), now) == IAP2_OK, "peer next auth request");
            incoming.clear();
        }
        uint8_t out[1024]; size_t n;
        const auto status = iap2_link_output(&peer, out, sizeof out, &n, now);
        check(status == IAP2_OK || status == IAP2_MORE, "peer output");
        if (n) a.feed(Bytes(out, out + n), now, IAP2_OK, 2);
        const auto control = a.poll(now);
        check(control == IAP2_MORE || control == IAP2_LINK_BUSY, "two endpoint control poll");
        if (a.engine.auth.state == IAP2_AUTH_ACCEPTED && !peer.tx_count) {
            check(lost && responses == 2 && a.provider.certificates == 1 && a.provider.signatures == 1 &&
                a.provider.challenge == challenge, "full exchange despite loss, callbacks exactly once");
            a.canaries(); return;
        }
    }
    throw std::runtime_error("two-endpoint exchange did not finish");
}
int main() {
    try {
        configuration(); header_splits(); large_receive(); coalesced_and_hold(); malformed_and_capacity();
        negotiated_fragmentation_and_pressure(); authentication_serialization(); provider_failures(); auth_protocol_failures();
        disconnect_and_reinit(); remote_close_and_retry_timeout(); adapter_timers(); work_budget_and_queue_pressure(); two_endpoint_exchange();
        std::cout << "PASS: 14 control adapter test groups (synthetic providers/transport only).\n";
        std::cout << "Host control-state storage: " << sizeof(iap2_control) << " bytes, plus caller buffers.\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
