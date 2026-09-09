// SPDX-License-Identifier: GPL-3.0-only
// Synthetic packet/completion events only: no USB backend or phone connection.
#include "usbmux_host.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using Bytes = std::vector<uint8_t>;
static void check(bool value, const char *why) { if (!value) throw std::runtime_error(why); }
static usbmux_host_config defaults() { usbmux_host_config c{}; usbmux_host_default_config(&c); return c; }
template<class T> static auto snapshot(const T& value) {
    std::array<uint8_t, sizeof value> bytes{}; std::memcpy(bytes.data(), &value, sizeof value); return bytes;
}
static Bytes hex(const std::string& text) {
    Bytes bytes;
    for (size_t i = 0; i < text.size(); i += 2) bytes.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return bytes;
}
static Bytes version(uint32_t major = 2, uint32_t minor = 0, uint32_t padding = 0) {
    usbmux_version v{major, minor, padding}; uint8_t payload[12]; size_t n;
    check(usbmux_version_encode(&v, payload, sizeof payload, &n) == 0, "encode version payload");
    usbmux_frame f{USBMUX_VERSION, 0, 0, 0, payload, n}; Bytes result(20);
    check(usbmux_frame_encode(&f, result.data(), result.size(), &n) == 0, "encode version frame"); return result;
}
static Bytes frame(uint32_t protocol, const Bytes& payload, uint16_t tx = 17, uint16_t rx = 34) {
    usbmux_frame f{protocol, 0xdeadbeef, tx, rx, payload.data(), payload.size()}; Bytes bytes(payload.size() + 16); size_t n;
    check(usbmux_frame_encode(&f, bytes.data(), bytes.size(), &n) == 0 && n == bytes.size(), "encode peer frame"); return bytes;
}
static Bytes tcp(const Bytes& payload = {}) {
    usbmux_tcp t{1, 62078, 0, 0, 2, 512, 0, 0, payload.data(), payload.size()}; Bytes bytes(payload.size() + 20); size_t n;
    check(usbmux_tcp_encode(&t, bytes.data(), bytes.size(), &n) == 0, "encode synthetic TCP"); return bytes;
}
static usbmux_frame decode(const Bytes& bytes) {
    usbmux_frame f{}; size_t used;
    check(usbmux_frame_decode(bytes.data(), bytes.size(), &f, &used) == 0 && used == bytes.size(), "one output packet"); return f;
}
struct Host {
    usbmux_host p{}; Bytes rx, tx;
    explicit Host(size_t rc = 256, size_t tc = 256, usbmux_host_config c = defaults()) : rx(rc + 2, 0xa5), tx(tc + 2, 0xa5) {
        check(usbmux_host_init(&p, &c, rx.data() + 1, rc, tx.data() + 1, tc) == 0, "host init");
    }
    Host(const Host&) = delete; Host& operator=(const Host&) = delete;
    void start(uint64_t now = 0, uint64_t generation = 1) {
        check(usbmux_host_start(&p, generation, now) == 0, "host start");
    }
    int feed(const Bytes& bytes, uint64_t now, size_t& used) {
        return usbmux_host_feed(&p, bytes.data(), bytes.size(), &used, p.generation, now);
    }
    Bytes output() const {
        const uint8_t *data = nullptr; size_t size;
        const int status = usbmux_host_output(&p, &data, &size);
        check(status == 0 || status == IAP2_MORE || status == USBMUX_HOST_CLOSED, "output status");
        if (status) { check(!data && !size, "empty output view"); return {}; }
        return Bytes(data, data + size);
    }
    void complete(uint64_t now) {
        const auto out = output(); check(!out.empty(), "pending packet to complete");
        check(usbmux_host_advance(&p, out.size(), p.generation, now) == 0, "complete packet");
    }
    void ready(uint64_t now = 0) {
        start(now); complete(now); size_t used;
        check(feed(version(), now, used) == 0 && used == 20, "accept version"); complete(now);
        check(p.state == USBMUX_HOST_READY && p.tx_sequence == 1, "setup completion gates ready");
    }
    void canaries() const { check(rx.front() == 0xa5 && rx.back() == 0xa5 && tx.front() == 0xa5 && tx.back() == 0xa5, "storage canaries"); }
};
static void config_transactions() {
    auto good = defaults(); check(good.sequence == USBMUX_HOST_USBMUXD && good.handshake_ms == 2000 &&
        good.write_ms == 250 && good.receive_ms == 5000, "documented defaults");
    Host h; const auto before = snapshot(h.p); const auto rx = h.rx, tx = h.tx;
    for (unsigned field = 0; field < 3; ++field) for (uint32_t value : {0u, 60001u, UINT32_MAX}) {
        auto c = good;
        if (field == 0) c.handshake_ms = value;
        if (field == 1) c.write_ms = value;
        if (field == 2) c.receive_ms = value;
        check(usbmux_host_init(&h.p, &c, h.rx.data() + 1, 256, h.tx.data() + 1, 256) == IAP2_ARGUMENT &&
            snapshot(h.p) == before && h.rx == rx && h.tx == tx, "invalid config unchanged");
    }
    auto bad = good; bad.sequence = static_cast<usbmux_host_sequence>(2);
    check(usbmux_host_init(&h.p, &bad, h.rx.data() + 1, 256, h.tx.data() + 1, 256) == IAP2_ARGUMENT, "unknown convention");
    for (size_t capacity : {size_t(0), size_t(35), size_t(65537)}) {
        check(usbmux_host_init(&h.p, &good, h.rx.data() + 1, capacity, h.tx.data() + 1, 256) == IAP2_ARGUMENT, "RX bounds");
        check(usbmux_host_init(&h.p, &good, h.rx.data() + 1, 256, h.tx.data() + 1, capacity) == IAP2_ARGUMENT, "TX bounds");
    }
    check(usbmux_host_init(&h.p, &good, h.rx.data(), 36, h.rx.data(), 36) == IAP2_ARGUMENT && snapshot(h.p) == before, "same storage rejected");
    good.handshake_ms = good.write_ms = good.receive_ms = 1; Host minimal(36, 36, good); minimal.ready(); minimal.canaries();
}
static void handshake_profiles() {
    for (const auto policy : {USBMUX_HOST_USBMUXD, USBMUX_HOST_LIVI}) {
        auto c = defaults(); c.sequence = policy; Host h(36, 36, c); h.start(100);
        const auto offer = hex("0000000000000014000000020000000000000000");
        check(h.output() == offer && h.p.state == USBMUX_HOST_VERSION_TX, "independent initial bytes"); size_t used = 99;
        check(h.feed(version(), 100, used) == USBMUX_HOST_BUSY && !used, "no version input before physical offer completion");
        for (size_t i = 0; i < offer.size(); ++i) {
            check(h.output() == Bytes(offer.begin() + i, offer.end()), "stable version tail");
            check(usbmux_host_advance(&h.p, 1, 1, 101 + i) == (i + 1 == offer.size() ? IAP2_OK : IAP2_MORE), "one-byte physical completion");
            check(h.p.tx_sequence == 0, "initial header has no sequence slot");
        }
        check(h.p.state == USBMUX_HOST_VERSION_RX && h.output().empty(), "wait for peer version");
        check(h.feed(version(), 122, used) == 0 && used == 20, "valid version response");
        const auto setup = hex(policy == USBMUX_HOST_USBMUXD ? "0000000200000011feedface0000ffff07" : "0000000200000011feedface0000000007");
        check(h.output() == setup && h.p.state == USBMUX_HOST_SETUP_TX, "independent setup profile bytes");
        check(h.feed(frame(USBMUX_CONTROL, {5}), 122, used) == USBMUX_HOST_BUSY && !used, "setup physical barrier retains input");
        for (size_t i = 0; i < setup.size(); ++i) {
            check(h.output() == Bytes(setup.begin() + i, setup.end()), "stable setup tail");
            check(usbmux_host_advance(&h.p, 1, 1, 123 + i) == (i + 1 == setup.size() ? IAP2_OK : IAP2_MORE), "partial setup writes");
            if (i + 1 < setup.size()) check(h.p.state == USBMUX_HOST_SETUP_TX && !h.p.tx_sequence, "not ready on copied/partial setup");
        }
        check(h.p.state == USBMUX_HOST_READY && h.p.tx_sequence == 1 && usbmux_host_next_delay(&h.p) == UINT32_MAX, "ready has no idle deadline");
        const auto syn = tcp();
        check(usbmux_host_send_tcp(&h.p, syn.data(), syn.size(), 1, 140) == 0, "explicit first TCP packet");
        const auto expected = hex(policy == USBMUX_HOST_USBMUXD ?
            "0000000600000024feedface0001ffff0001f27e00000000000000005002020000000000" :
            "0000000600000024feedface000100000001f27e00000000000000005002020000000000");
        check(h.output() == expected, "independent first SYN bytes retain setup convention"); h.complete(141);
        h.canaries();
    }
}
static void version_splits_and_tails() {
    const auto peer = version(2, UINT32_MAX, 1234), control = frame(USBMUX_CONTROL, {5, 'o', 'k'});
    for (size_t split = 0; split <= peer.size(); ++split) {
        Host h; h.start(); h.complete(1); size_t used;
        const Bytes prefix(peer.begin(), peer.begin() + split);
        check(h.feed(prefix, 2, used) == (split == peer.size() ? IAP2_OK : IAP2_MORE) && used == split, "every version split prefix");
        if (split != peer.size()) {
            Bytes tail(peer.begin() + split, peer.end()); tail.insert(tail.end(), control.begin(), control.end());
            check(h.feed(tail, 3, used) == 0 && used == peer.size() - split, "coalesced tail not consumed after version");
        }
        check(h.p.peer_version.major == 2 && h.p.peer_version.minor == UINT32_MAX && h.p.peer_version.padding == 1234, "nonzero minor/padding preserved");
        check(!h.p.rx_timer && !h.p.rx.used, "version assembly discarded on setup");
        h.complete(4); check(h.feed(control, 5, used) == USBMUX_HOST_PACKET && used == control.size(), "retained tail accepted after setup"); h.canaries();
    }
}
static void rejected_versions() {
    for (uint32_t major : {0u, 1u, 3u, UINT32_MAX}) {
        Host h; h.start(); h.complete(1); size_t used;
        check(h.feed(version(major), 2, used) == USBMUX_HOST_CLOSED && used == 20 && h.p.reason == USBMUX_HOST_REASON_VERSION &&
            h.p.last_error == IAP2_UNSUPPORTED && h.p.peer_version.major == major && h.output().empty(), "unsupported version has no setup/fallback");
        usbmux_host_close(&h.p); check(h.p.reason == USBMUX_HOST_REASON_VERSION, "first terminal diagnostic retained");
    }
    for (const auto& input : {frame(USBMUX_SETUP, {7}), frame(USBMUX_CONTROL, {}), frame(USBMUX_TCP, tcp())}) {
        Host h; h.start(); h.complete(1); size_t used;
        check(h.feed(input, 2, used) == USBMUX_HOST_CLOSED && h.p.reason == USBMUX_HOST_REASON_PROTOCOL, "non-version packet during version wait closes");
    }
}
static void packet_ownership_and_sequences() {
    for (const auto policy : {USBMUX_HOST_USBMUXD, USBMUX_HOST_LIVI}) {
        auto c = defaults(); c.sequence = policy; Host h(256, 256, c); h.ready(); size_t used;
        const auto first = frame(USBMUX_TCP, tcp({'a','b','c'}), 65535, 0x1234), second = frame(USBMUX_CONTROL, {5});
        auto joined = first; joined.insert(joined.end(), second.begin(), second.end());
        check(h.feed(joined, 1, used) == USBMUX_HOST_PACKET && used == first.size(), "exact consumed count for coalesced packets");
        std::fill(joined.begin(), joined.end(), 0); const usbmux_frame *held = nullptr;
        check(usbmux_host_packet(&h.p, &held) == USBMUX_HOST_PACKET && held && held->magic == 0xdeadbeef &&
            held->tx_sequence == 65535 && held->rx_sequence == 0x1234, "held fields owned despite caller mutation");
        const Bytes held_payload(held->payload, held->payload + held->payload_size);
        check(h.feed(second, 2, used) == USBMUX_HOST_BUSY && !used && h.p.rx_at == 1, "held receive blocks overwrite, retains deadline");
        check(usbmux_host_send_tcp(&h.p, held->payload, held->payload_size, 1, 2) == 0, "send may copy borrowed RX payload");
        const auto outgoing = h.output(); const auto header = decode(outgoing);
        check(header.magic == USBMUX_HOST_MAGIC && header.tx_sequence == 1 && header.rx_sequence == (policy == USBMUX_HOST_USBMUXD ? 0x1234 : 0) &&
            Bytes(header.payload, header.payload + header.payload_size) == held_payload, "explicit outgoing convention and copied payload");
        check(usbmux_host_release(&h.p, 1, 3) == 0 && h.output() == outgoing, "release RX does not alter pending TX");
        check(h.feed(second, 4, used) == USBMUX_HOST_PACKET && h.output() == outgoing, "RX continues while TX retained without rewriting header");
        h.complete(5); check(usbmux_host_packet(&h.p, &held) == USBMUX_HOST_PACKET && held->protocol == USBMUX_CONTROL && h.p.tx_sequence == 2,
            "physical completion does not release held RX");
        check(usbmux_host_release(&h.p, 1, 6) == 0 && h.feed(frame(USBMUX_CONTROL, {}, 0, 65535), 7, used) == USBMUX_HOST_PACKET &&
            usbmux_host_packet(&h.p, &held) == USBMUX_HOST_PACKET && !held->payload_size, "empty control remains an explicit held packet");
        h.canaries();
    }
}
static void invalid_ready_input() {
    auto bad_offset = frame(USBMUX_TCP, tcp()); bad_offset[28] = 0x40;
    auto options = bad_offset; options[28] = 0x60;
    auto reserved = bad_offset; reserved[28] = 0x51;
    const std::vector<Bytes> bad{version(), frame(USBMUX_SETUP, {7}), bad_offset, options, reserved,
        hex("0000009900000010"), hex("0000000600000023"), hex("0000000100010001")};
    for (const auto& input : bad) {
        Host h; h.ready(); size_t used;
        check(h.feed(input, 1, used) == USBMUX_HOST_CLOSED && h.p.reason == USBMUX_HOST_REASON_PROTOCOL && used > 0 &&
            !h.p.held && !h.p.rx.used && h.output().empty(), "bad ready packet closes and discards"); h.canaries();
    }
    Host h(36, 36); h.ready(); size_t used;
    check(h.feed(frame(USBMUX_TCP, tcp({1})), 1, used) == USBMUX_HOST_CLOSED && used == 8 && h.p.last_error == IAP2_NO_SPACE, "oversized prefix consumes only eight bytes");
}
static void local_send_backpressure() {
    Host h(36, 36); h.start(); auto syn = tcp();
    check(usbmux_host_send_tcp(&h.p, syn.data(), syn.size(), 1, 0) == USBMUX_HOST_BUSY, "no TCP before handshake");
    h.complete(0); size_t used; check(h.feed(version(), 0, used) == 0, "version accepted"); h.complete(0);
    for (const auto& bytes : {Bytes{0}, tcp({1})}) {
        const auto output = h.tx;
        check(usbmux_host_send_tcp(&h.p, bytes.data(), bytes.size(), 1, 1) == (bytes.size() == 1 ? IAP2_INVALID : IAP2_NO_SPACE) &&
            h.p.state == USBMUX_HOST_READY && h.p.tx_sequence == 1 && h.output().empty() && h.tx == output, "local malformed/capacity failure preserves queue and sequence");
    }
    auto options = syn; options[12] = 0x60;
    check(usbmux_host_send_tcp(&h.p, options.data(), options.size(), 1, 1) == IAP2_UNSUPPORTED, "local TCP options rejected without closure");
    check(usbmux_host_send_tcp(&h.p, syn.data(), syn.size(), 1, 2) == 0, "exact-capacity send");
    const auto output = h.output(); std::fill(syn.begin(), syn.end(), 0);
    check(h.output() == output && h.p.tx_sequence == 1, "queue owns caller input but sequence waits for completion");
    check(usbmux_host_send_tcp(&h.p, syn.data(), syn.size(), 1, 3) == USBMUX_HOST_BUSY && h.output() == output, "pending packet never overwritten");
    check(usbmux_host_advance(&h.p, 1, 1, 4) == IAP2_MORE && h.p.tx_sequence == 1, "partial completion preserves slot");
    h.complete(5); check(h.p.tx_sequence == 2, "full completion advances exactly once"); h.canaries();
}
static void bad_completion_results() {
    for (unsigned phase = 0; phase < 4; ++phase) {
        Host h;
        if (phase < 2) { h.start(); if (phase == 1) { h.complete(0); size_t used; check(h.feed(version(), 0, used) == 0, "setup phase"); } }
        else { h.ready(); if (phase == 2) { const auto bytes = tcp(); check(usbmux_host_send_tcp(&h.p, bytes.data(), bytes.size(), 1, 0) == 0, "TCP phase"); } }
        const auto bytes = h.output();
        check(usbmux_host_advance(&h.p, 0, 1, 1) == IAP2_MORE && h.output() == bytes, "zero completion makes no progress");
        check(usbmux_host_advance(&h.p, bytes.size() + 1, 1, 2) == USBMUX_HOST_CLOSED && h.p.reason == USBMUX_HOST_REASON_RESULT &&
            !h.p.tx_size && !h.p.tx_offset, "overcount or unsolicited completion closes");
    }
    Host partial; partial.start(); check(usbmux_host_advance(&partial.p, 19, 1, 1) == IAP2_MORE, "retain one byte");
    check(usbmux_host_advance(&partial.p, 2, 1, 2) == USBMUX_HOST_CLOSED, "count checked against tail not original packet");
}
static void handshake_deadlines() {
    auto c = defaults(); c.handshake_ms = 10; c.write_ms = 50;
    for (unsigned phase = 0; phase < 3; ++phase) {
        Host h(36, 36, c); h.start(100); size_t used;
        if (phase) h.complete(101);
        if (phase == 2) check(h.feed(version(), 108, used) == 0, "late valid version still within total budget");
        check(usbmux_host_poll(&h.p, 1, 109) == 0 && usbmux_host_next_delay(&h.p) == 1, "handshake keeps original total budget");
        if (phase == 1) check(h.feed(version(), 110, used) == USBMUX_HOST_CLOSED && !used, "version at exact deadline not consumed");
        else check(usbmux_host_advance(&h.p, h.output().size(), 1, 110) == USBMUX_HOST_CLOSED, "completion at exact deadline cannot revive handshake");
        check(h.p.reason == USBMUX_HOST_REASON_DEADLINE && h.output().empty(), "handshake timeout discards pending state");
    }
    c.handshake_ms = 100; c.write_ms = 10; Host stalled(36, 36, c); stalled.start();
    check(usbmux_host_advance(&stalled.p, 19, 1, 9) == IAP2_MORE && usbmux_host_next_delay(&stalled.p) == 1, "progress does not renew write deadline");
    check(usbmux_host_advance(&stalled.p, 1, 1, 10) == USBMUX_HOST_CLOSED, "offer write timeout");
    Host setup(36, 36, c); setup.start(); setup.complete(1); size_t used;
    check(setup.feed(version(), 5, used) == 0 && usbmux_host_next_delay(&setup.p) == 10, "new setup write gets its own packet budget");
    check(usbmux_host_advance(&setup.p, 16, 1, 14) == IAP2_MORE && usbmux_host_poll(&setup.p, 1, 15) == USBMUX_HOST_CLOSED, "setup stall closes");
}
static void receive_and_hold_deadlines() {
    auto c = defaults(); c.receive_ms = 10;
    for (bool complete : {false, true}) {
        Host h(256, 256, c); h.ready(); const auto packet = frame(USBMUX_CONTROL, {5, 6}); size_t used;
        check(usbmux_host_feed(&h.p, nullptr, 0, &used, 1, 100) == IAP2_MORE && !used && !h.p.rx_timer &&
            usbmux_host_next_delay(&h.p) == UINT32_MAX, "zero receive is not EOF, progress or timer start");
        check(usbmux_host_feed(&h.p, packet.data(), 1, &used, 1, 101) == IAP2_MORE && used == 1, "first byte starts total RX budget");
        if (complete) check(usbmux_host_feed(&h.p, packet.data() + 1, packet.size() - 1, &used, 1, 109) == USBMUX_HOST_PACKET, "late assembly enters hold");
        else check(usbmux_host_feed(&h.p, packet.data() + 1, 1, &used, 1, 109) == IAP2_MORE, "fragment cannot reset deadline");
        check(usbmux_host_release(&h.p, 1, 110) == (complete ? IAP2_OK : IAP2_MORE), "release complete only");
        if (complete) {
            check(!h.p.rx_timer && usbmux_host_next_delay(&h.p) == UINT32_MAX, "release removes RX deadline");
            check(h.feed(packet, 111, used) == USBMUX_HOST_PACKET, "new packet starts new deadline");
            const auto bytes = tcp(); check(usbmux_host_send_tcp(&h.p, bytes.data(), bytes.size(), 1, 120) == 0, "sending allowed while held");
            check(usbmux_host_release(&h.p, 1, 121) == USBMUX_HOST_CLOSED, "late release cannot rescue hold");
        } else check(usbmux_host_feed(&h.p, nullptr, 0, &used, 1, 111) == USBMUX_HOST_CLOSED && !used, "empty feed enforces partial timeout");
        check(h.p.reason == USBMUX_HOST_REASON_DEADLINE && !h.p.rx_timer && !h.p.held && !h.p.tx_size, "receive failure discards both directions");
    }
}
static void ready_write_deadlines() {
    auto c = defaults(); c.write_ms = 10; c.receive_ms = 100; Host h(256, 256, c); h.ready(); const auto bytes = tcp(); size_t used;
    check(usbmux_host_send_tcp(&h.p, bytes.data(), bytes.size(), 1, 1) == 0, "queue starts write timer");
    check(h.feed(frame(USBMUX_CONTROL, {5}), 5, used) == USBMUX_HOST_PACKET, "receive remains live with pending write");
    check(usbmux_host_advance(&h.p, 1, 1, 10) == IAP2_MORE && usbmux_host_next_delay(&h.p) == 1, "shortest deadline is write");
    check(h.feed(frame(USBMUX_CONTROL, {6}), 11, used) == USBMUX_HOST_CLOSED && !used && h.p.reason == USBMUX_HOST_REASON_DEADLINE,
        "held-input backpressure cannot mask write timeout");
}
static void generations_and_reconnect() {
    for (unsigned operation = 0; operation < 5; ++operation) {
        Host h; h.ready(10); size_t used;
        const auto input = frame(USBMUX_CONTROL, {5});
        check(usbmux_host_feed(&h.p, input.data(), 7, &used, 1, 11) == IAP2_MORE, "old generation partial input");
        usbmux_host_close(&h.p); check(h.p.reason == USBMUX_HOST_REASON_LOCAL && !h.p.rx.used && !h.p.tx_size, "close discards old tails");
        const auto before = snapshot(h.p);
        for (uint64_t generation : {uint64_t(0), uint64_t(1)})
            check(usbmux_host_start(&h.p, generation, 12) == IAP2_ARGUMENT && snapshot(h.p) == before, "generation cannot be reused");
        check(usbmux_host_start(&h.p, 2, 9) == IAP2_ARGUMENT && snapshot(h.p) == before, "reconnect clock cannot decrease");
        h.start(12, 2); check(!h.p.peer_version.major && !h.p.rx.used && !h.p.tx_sequence && h.p.reason == USBMUX_HOST_REASON_NONE, "new generation resets session metadata");
        const auto bytes = tcp(); int result = 0; used = 999;
        switch (operation) {
        case 0: result = usbmux_host_poll(&h.p, 1, 9999); break;
        case 1: result = usbmux_host_advance(&h.p, 1, 1, 9999); break;
        case 2: result = usbmux_host_feed(&h.p, input.data(), input.size(), &used, 1, 9999); break;
        case 3: result = usbmux_host_release(&h.p, 1, 9999); break;
        case 4: result = usbmux_host_send_tcp(&h.p, bytes.data(), bytes.size(), 1, 9999); break;
        }
        check(result == USBMUX_HOST_CLOSED && h.p.reason == USBMUX_HOST_REASON_STALE && h.p.now == 12 && !h.p.tx_size && !h.p.rx.used &&
            (operation != 2 || !used), "all timed APIs reject stale events before time or progress");
        usbmux_host_close(&h.p); check(h.p.reason == USBMUX_HOST_REASON_STALE, "stale reason survives close");
    }
    Host h; h.start(5, UINT64_MAX); usbmux_host_close(&h.p); const auto before = snapshot(h.p);
    check(usbmux_host_start(&h.p, 1, 6) == IAP2_ARGUMENT && snapshot(h.p) == before, "generation exhaustion does not wrap");
}
static void sequence_wrap() {
    Host h(36, 36); h.ready(); const auto bytes = tcp();
    for (uint32_t i = 1; i <= 65536; ++i) {
        check(usbmux_host_send_tcp(&h.p, bytes.data(), bytes.size(), 1, 0) == 0, "queue every mux sequence slot");
        const auto output = h.output(); check(decode(output).tx_sequence == static_cast<uint16_t>(i), "all u16 sequence values including wrap");
        h.complete(0);
    }
    check(h.p.tx_sequence == 1, "sequence advances modulo 65536 only after completion"); h.canaries();
}
static void clock_and_argument_contracts() {
    usbmux_host empty{}; const uint8_t *data = nullptr; size_t size = 99; const usbmux_frame *held = nullptr;
    check(usbmux_host_start(&empty, 1, 0) == IAP2_ARGUMENT && usbmux_host_poll(nullptr, 1, 0) == IAP2_ARGUMENT &&
        usbmux_host_output(&empty, &data, &size) == IAP2_ARGUMENT && !data && !size &&
        usbmux_host_packet(nullptr, &held) == IAP2_ARGUMENT && !held, "uninitialized/null contracts");
    usbmux_host_close(nullptr); usbmux_host_default_config(nullptr);
    auto c = defaults(); c.write_ms = 25; c.handshake_ms = 40; Host h(36, 36, c); h.ready(UINT64_MAX - 20);
    const auto bytes = tcp(); check(usbmux_host_send_tcp(&h.p, bytes.data(), bytes.size(), 1, UINT64_MAX - 16) == 0, "queue near max clock");
    check(usbmux_host_poll(&h.p, 1, UINT64_MAX) == 0 && usbmux_host_next_delay(&h.p) == 9, "subtraction-based deadline avoids overflow");
    const auto before = snapshot(h.p); size_t used = 99;
    check(usbmux_host_poll(&h.p, 1, 0) == IAP2_ARGUMENT && snapshot(h.p) == before, "clock cannot wrap");
    check(usbmux_host_feed(&h.p, nullptr, 1, &used, 1, UINT64_MAX) == IAP2_ARGUMENT && !used && snapshot(h.p) == before, "bad feed pointer transaction");
    check(usbmux_host_feed(&h.p, bytes.data(), bytes.size(), nullptr, 1, UINT64_MAX) == IAP2_ARGUMENT && snapshot(h.p) == before, "missing feed count");
    check(usbmux_host_send_tcp(&h.p, nullptr, 0, 1, UINT64_MAX) == IAP2_ARGUMENT && snapshot(h.p) == before, "missing TCP pointer transaction");
    check(usbmux_host_packet(&h.p, nullptr) == IAP2_ARGUMENT && usbmux_host_output(&h.p, nullptr, &size) == IAP2_ARGUMENT && !size, "missing view arguments");
    usbmux_host_close(&h.p); check(usbmux_host_output(&h.p, &data, &size) == USBMUX_HOST_CLOSED && !data && !size &&
        usbmux_host_packet(&h.p, &held) == USBMUX_HOST_CLOSED && !held && usbmux_host_next_delay(&h.p) == UINT32_MAX, "closed views invalidated");
}
static void maximum_owned_packets() {
    Host h(USBMUX_FRAME_LIMIT, USBMUX_FRAME_LIMIT); h.ready(); Bytes payload(USBMUX_TCP_PAYLOAD_LIMIT);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    auto input = frame(USBMUX_TCP, tcp(payload)); size_t offset = 0, used;
    while (offset < input.size()) {
        const size_t amount = std::min(size_t(137), input.size() - offset);
        const int result = usbmux_host_feed(&h.p, input.data() + offset, amount, &used, 1, 1);
        check(used == amount && result == (offset + amount == input.size() ? USBMUX_HOST_PACKET : IAP2_MORE), "maximum RX bounded chunks"); offset += used;
    }
    const usbmux_frame *held = nullptr; check(usbmux_host_packet(&h.p, &held) == USBMUX_HOST_PACKET, "maximum held view");
    check(usbmux_host_send_tcp(&h.p, held->payload, held->payload_size, 1, 2) == 0, "maximum RX to owned TX copy");
    const auto out = h.output(); const auto header = decode(out); usbmux_tcp t{};
    check(out.size() == USBMUX_FRAME_LIMIT && usbmux_tcp_decode(header.payload, header.payload_size, &t) == 0 &&
        Bytes(t.payload, t.payload + t.payload_size) == payload, "maximum payload intact");
    check(usbmux_host_release(&h.p, 1, 3) == 0, "release maximum RX");
    std::fill(input.begin(), input.end(), 0); std::fill(h.rx.begin() + 1, h.rx.end() - 1, 0);
    check(h.output() == out, "maximum TX independent of released input backing");
    check(usbmux_host_advance(&h.p, 32768, 1, 4) == IAP2_MORE && h.output() == Bytes(out.begin() + 32768, out.end()), "maximum partial write tail");
    h.complete(5); h.canaries();
}
int main() {
    try {
        config_transactions(); handshake_profiles(); version_splits_and_tails(); rejected_versions();
        packet_ownership_and_sequences(); invalid_ready_input(); local_send_backpressure(); bad_completion_results();
        handshake_deadlines(); receive_and_hold_deadlines(); ready_write_deadlines(); generations_and_reconnect();
        sequence_wrap(); clock_and_argument_contracts(); maximum_owned_packets();
        std::cout << "PASS: 15 bounded USBmux host test groups; no USB or phone access. Host state bytes=" << sizeof(usbmux_host) << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
