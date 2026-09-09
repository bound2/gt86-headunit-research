// SPDX-License-Identifier: GPL-3.0-only
// Simulated raw backend only. No native USB, phone trust record or service.
#pragma once
#include "usbmux_dispatcher.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <iostream>
#include <functional>
#include <map>
#include <stdexcept>
#include <vector>
using Bytes = std::vector<uint8_t>;
static void check(bool ok, const char *why) { if (!ok) throw std::runtime_error(why); }
template<class T> static auto snapshot(const T& value) {
    std::array<uint8_t, sizeof value> result{}; std::memcpy(result.data(), &value, sizeof value); return result;
}
static Bytes packet(uint32_t protocol, const Bytes& payload) {
    usbmux_frame frame{protocol, protocol ? USBMUX_HOST_MAGIC : 0, 17, 34, payload.data(), payload.size()}; size_t n;
    if (!protocol) frame.tx_sequence = frame.rx_sequence = 0;
    Bytes out(payload.size() + (protocol ? 16 : 8));
    check(usbmux_frame_encode(&frame, out.data(), out.size(), &n) == 0, "peer mux packet encode"); return out;
}
static Bytes tcp(uint16_t source, uint16_t destination, uint32_t seq, uint32_t ack, uint8_t flags = 16, const Bytes& payload = {}, uint16_t window = 8) {
    usbmux_tcp value{source, destination, seq, ack, flags, window, 0, 0, payload.data(), payload.size()}; size_t n; Bytes bytes(20 + payload.size());
    check(usbmux_tcp_encode(&value, bytes.data(), bytes.size(), &n) == 0, "peer TCP encode"); return packet(USBMUX_TCP, bytes);
}
enum class Fault { None, Stale, Overcount, NonprogressCount, Disconnect, Fatal, Unknown, Zero };
struct Peer {
    struct Stream { uint16_t remote; uint32_t next, host_next; Bytes received; };
    std::deque<uint8_t> incoming; Bytes partial;
    std::vector<Bytes> sent; std::map<uint16_t, Stream> streams;
    std::vector<uint64_t> cancelled;
    size_t reads = 0, writes = 0, read_limit = 3, write_limit = 5;
    bool block_read = false, block_write = false, respond = true, zero_first_window = false;
    uint16_t window = 8;
    Fault read_fault = Fault::None, write_fault = Fault::None;
    std::function<void(Peer&, uint16_t, const Bytes&)> on_data;
    void inject(const Bytes& bytes) { incoming.insert(incoming.end(), bytes.begin(), bytes.end()); }
    bool fault(Fault& which, uint64_t generation, size_t maximum, usbmux_io_result *result) {
        const auto f = which; which = Fault::None; if (f == Fault::None) return false;
        result->generation = f == Fault::Stale ? generation - 1 : generation; result->count = 0; result->status = USBMUX_IO_PROGRESS;
        if (f == Fault::Stale) result->count = 1; // Old operation reports progress; none belongs to this stream.
        if (f == Fault::Overcount) result->count = maximum + 1;
        if (f == Fault::NonprogressCount) { result->status = USBMUX_IO_WOULD_BLOCK; result->count = 1; }
        if (f == Fault::Disconnect) result->status = USBMUX_IO_DISCONNECTED;
        if (f == Fault::Fatal) result->status = USBMUX_IO_FATAL;
        if (f == Fault::Unknown) result->status = 99;
        return true;
    }
    void received_packet(const Bytes& bytes) {
        usbmux_frame frame{}; size_t used;
        check(usbmux_frame_decode(bytes.data(), bytes.size(), &frame, &used) == 0 && used == bytes.size(), "complete noninterleaved physical mux packet");
        sent.push_back(bytes);
        if (frame.protocol == USBMUX_VERSION) {
            inject(packet(USBMUX_VERSION, {0,0,0,2,0,0,0,0,0,0,0,0})); return;
        }
        if (frame.protocol == USBMUX_SETUP) { check(frame.payload_size == 1 && frame.payload[0] == 7, "setup value"); return; }
        check(frame.protocol == USBMUX_TCP, "only supported host protocols"); usbmux_tcp p{};
        check(usbmux_tcp_decode(frame.payload, frame.payload_size, &p) == 0, "host TCP header");
        if (p.flags == 2) {
            check(!streams.contains(p.source_port), "local port never reused in physical generation");
            auto& s = streams[p.source_port]; s.remote = p.destination_port; s.next = 1000u + p.source_port; s.host_next = p.sequence + 1u;
            if (respond) inject(tcp(s.remote, p.source_port, s.next, s.host_next, 18, {}, zero_first_window && p.source_port == 1 ? 0 : window));
            s.next++; return;
        }
        auto& s = streams.at(p.source_port); check(s.remote == p.destination_port, "outgoing peer port unchanged");
        if (p.payload_size) {
            check(p.sequence == s.host_next, "data follows exact sent sequence");
            const Bytes payload(p.payload, p.payload + p.payload_size); s.received.insert(s.received.end(), payload.begin(), payload.end());
            s.host_next += static_cast<uint32_t>(payload.size());
            if (on_data) on_data(*this, p.source_port, payload);
            else if (respond) { inject(tcp(s.remote, p.source_port, s.next, s.host_next, 16, payload, window)); s.next += static_cast<uint32_t>(payload.size()); }
        }
        if (p.flags & 1) {
            check(p.sequence == s.host_next, "FIN follows all sent data"); s.host_next++;
            if (respond) { inject(tcp(s.remote, p.source_port, s.next, s.host_next, 17, {}, window)); s.next++; }
        }
    }
    static void read(void *context, uint64_t generation, uint8_t *out, size_t maximum, usbmux_io_result *result) {
        auto& p = *static_cast<Peer *>(context); p.reads++;
        if (p.fault(p.read_fault, generation, maximum, result)) return;
        result->generation = generation; result->count = 0; result->status = USBMUX_IO_WOULD_BLOCK;
        if (p.block_read || p.incoming.empty()) return;
        result->count = std::min({maximum, p.read_limit, p.incoming.size()}); result->status = USBMUX_IO_PROGRESS;
        for (size_t i = 0; i < result->count; ++i) { out[i] = p.incoming.front(); p.incoming.pop_front(); }
    }
    static void write(void *context, uint64_t generation, const uint8_t *data, size_t maximum, usbmux_io_result *result) {
        auto& p = *static_cast<Peer *>(context); p.writes++;
        if (p.fault(p.write_fault, generation, maximum, result)) return;
        result->generation = generation; result->count = 0; result->status = USBMUX_IO_WOULD_BLOCK;
        if (p.block_write) return;
        result->count = std::min(maximum, p.write_limit); result->status = USBMUX_IO_PROGRESS;
        p.partial.insert(p.partial.end(), data, data + result->count);
        usbmux_frame frame{}; size_t used;
        const int status = usbmux_frame_decode(p.partial.data(), p.partial.size(), &frame, &used);
        check(status == IAP2_MORE || status == IAP2_OK, "partial physical output remains valid");
        if (!status) { check(used == p.partial.size(), "at most one physical packet per write call"); p.received_packet(p.partial); p.partial.clear(); }
    }
    static void cancel(void *context, uint64_t generation) {
        auto& p = *static_cast<Peer *>(context); p.cancelled.push_back(generation);
        p.incoming.clear(); p.partial.clear(); p.streams.clear();
    }
    usbmux_backend backend() { return {this, read, write, cancel}; }
};
struct Runtime {
    Peer peer; usbmux_host host{}; usbmux_dispatcher d{};
    std::array<usbmux_connection, USBMUX_DISPATCHER_SLOTS> conns{};
    std::array<usbmux_connection *, USBMUX_DISPATCHER_SLOTS> pointers{};
    Bytes host_rx, host_tx; std::array<Bytes, USBMUX_DISPATCHER_SLOTS> rx, tx;
    uint64_t now = 0;
    explicit Runtime(unsigned count = 2, size_t rx_capacity = 256, uint32_t send_limit = 128, uint32_t ack_ms = 5000) :
        host_rx(std::min(rx_capacity + 36, size_t(65536)) + 2, 0xa5), host_tx(send_limit + 38, 0xa5) {
        usbmux_host_config hc{}; usbmux_host_default_config(&hc);
        check(usbmux_host_init(&host, &hc, host_rx.data() + 1, host_rx.size() - 2, host_tx.data() + 1, host_tx.size() - 2) == 0, "host init");
        for (unsigned i = 0; i < count; ++i) {
            usbmux_connection_config cfg{}; usbmux_connection_default_config(&cfg); cfg.send_limit = send_limit; cfg.ack_ms = ack_ms;
            rx[i] = Bytes(rx_capacity + 2, 0xa5); tx[i] = Bytes(send_limit + 22, 0xa5);
            check(usbmux_connection_init(&conns[i], &cfg, rx[i].data() + 1, rx_capacity, tx[i].data() + 1, send_limit + 20) == 0, "connection init"); pointers[i] = &conns[i];
        }
        const auto backend = peer.backend(); usbmux_dispatcher_config cfg{}; usbmux_dispatcher_default_config(&cfg);
        check(usbmux_dispatcher_init(&d, &host, pointers.data(), count, &backend, &cfg) == 0, "dispatcher init");
    }
    Runtime(const Runtime&) = delete; Runtime& operator=(const Runtime&) = delete;
    void start(uint64_t generation = 1) { check(usbmux_dispatcher_start(&d, generation, now) == 0, "fresh physical start"); }
    int at(uint64_t time) {
        const auto reads = peer.reads, writes = peer.writes; const int result = usbmux_dispatcher_poll(&d, time);
        check(peer.reads - reads <= 1 && peer.writes - writes <= 1, "one read and write maximum per poll"); return result;
    }
    int step() { return at(now++); }
    template<class Predicate> void until(Predicate predicate, unsigned limit = 10000) {
        for (unsigned i = 0; i < limit && !predicate(); ++i) {
            const int result = step(); check(result == 0 || result == IAP2_MORE || result == USBMUX_DISPATCHER_CONTROL, "dispatcher stays active during simulation");
        }
        check(predicate(), "bounded event loop reaches expected state");
    }
    void ready() { start(); until([&] { return host.state == USBMUX_HOST_READY; }); }
    usbmux_handle open(uint16_t remote = 62078, uint32_t initial = 0) {
        usbmux_handle h{}; check(usbmux_dispatcher_open(&d, remote, initial, &h, now) == 0, "open stream handle"); return h;
    }
    void established(const usbmux_handle& h) { until([&] { return conns[h.slot].state == USBMUX_CONNECTION_OPEN; }); }
    size_t write(const usbmux_handle& h, const Bytes& bytes) {
        size_t n = 999; const int status = usbmux_dispatcher_write(&d, &h, bytes.data(), bytes.size(), &n, now);
        check(status == 0 || status == USBMUX_DISPATCHER_BUSY || status == IAP2_MORE, "byte write alive"); if (status) check(!n, "blocked write accepts zero"); return n;
    }
    Bytes read_all(const usbmux_handle& h) {
        Bytes all; std::array<uint8_t, 37> bytes{};
        for (unsigned i = 0; i < 10000; ++i) {
            size_t n; const int status = usbmux_dispatcher_read(&d, &h, bytes.data(), bytes.size(), &n, now);
            if (status == IAP2_MORE || status == IAP2_END) { check(!n, "empty/EOF read count"); return all; }
            check(status == 0 && n && n <= bytes.size(), "bounded positive read"); all.insert(all.end(), bytes.begin(), bytes.begin() + n);
        }
        throw std::runtime_error("read loop bounded");
    }
    void canaries() const {
        check(host_rx.front() == 0xa5 && host_rx.back() == 0xa5 && host_tx.front() == 0xa5 && host_tx.back() == 0xa5, "host storage canaries");
        for (unsigned i = 0; i < d.count; ++i) check(rx[i].front() == 0xa5 && rx[i].back() == 0xa5 && tx[i].front() == 0xa5 && tx[i].back() == 0xa5, "connection storage canaries");
    }
};
