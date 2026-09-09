// SPDX-License-Identifier: GPL-3.0-only
// Synthetic service peer only; no phone, trust records, TLS or native USB.
#pragma once
#include "lockdown_channel.h"
#include "lockdown_reply.h"
#include "usbmux_fixture.h"
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
inline std::filesystem::path fixtures;
inline Bytes fixture(const char *name) {
    std::ifstream in(fixtures / name, std::ios::binary);
    check(bool(in), "open independent XML fixture");
    return Bytes(std::istreambuf_iterator<char>(in), {});
}
inline Bytes binary_fixture(const char *wanted) {
    std::ifstream in(fixtures / "plist-binary-vectors.txt"); check(bool(in),"open binary plist fixtures"); std::string line;
    while(std::getline(in,line)) {
        std::istringstream row(line); std::string name,hex; row>>name>>hex;
        if(name!=wanted) continue;
        Bytes out; check(hex.size()%2==0,"binary hex pairs");
        for(size_t i=0;i<hex.size();i+=2) out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i,2),nullptr,16)));
        return out;
    }
    throw std::runtime_error("named binary plist fixture missing");
}
inline Bytes binary_product_fixture() { return binary_fixture("product"); }
inline lockdown_body view(const Bytes& v) { return {v.data(), v.size()}; }
inline Bytes bytes(const char *s) { return Bytes(s, s + std::strlen(s)); }
// Expected prefix is specified without calling the implementation under test.
inline Bytes framed(const Bytes& body) {
    const auto n = static_cast<uint32_t>(body.size());
    Bytes out{static_cast<uint8_t>(n >> 24), static_cast<uint8_t>(n >> 16),
              static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n)};
    out.insert(out.end(), body.begin(), body.end()); return out;
}
inline Bytes get_value() {
    const auto l = bytes("gt86-research"), k = bytes("ProductType");
    const auto label = view(l), key = view(k); Bytes out(1024); size_t n;
    check(lockdown_get_value_encode(&label, &key, nullptr, out.data(), out.size(), &n) == 0, "explicit GetValue encode");
    out.resize(n); check(out == fixture("get-product-type.xml"), "exact independent GetValue XML"); return out;
}
inline void send(Peer& peer, uint16_t port, const Bytes& data, uint32_t ack, bool fin = false) {
    auto& s = peer.streams.at(port);
    peer.inject(tcp(s.remote, port, s.next, ack, fin ? 17 : 16, data, peer.window));
    s.next += static_cast<uint32_t>(data.size()) + (fin ? 1u : 0u);
}
inline void reply_with(Runtime& r, const Bytes& request, const Bytes& response, size_t cut = 0) {
    const auto expected = framed(request);
    r.peer.on_data = [expected, response, cut, offset = size_t(0)](Peer& peer, uint16_t port, const Bytes& data) mutable {
        check(offset + data.size() <= expected.size() &&
              std::equal(data.begin(), data.end(), expected.begin() + offset), "peer independently verifies copied request and prefix");
        offset += data.size();
        if (offset == expected.size()) {
            offset = 0;
            if (cut) {
                check(cut < response.size(), "valid synthetic response split");
                send(peer, port, Bytes(response.begin(), response.begin() + cut), peer.streams.at(port).host_next);
                send(peer, port, Bytes(response.begin() + cut, response.end()), peer.streams.at(port).host_next);
            } else send(peer, port, response, peer.streams.at(port).host_next);
        } else send(peer, port, {}, peer.streams.at(port).host_next);
    };
}
struct Service {
    Runtime& r; usbmux_handle handle; lockdown_channel c{}; Bytes rx, tx;
    explicit Service(Runtime& runtime, usbmux_handle h, size_t rcap = 1024, size_t tcap = 1024,
                     lockdown_channel_config cfg = {5000,5000})
        : r(runtime), handle(h), rx(rcap + 2, 0xa5), tx(tcap + 2, 0xa5) {
        check(lockdown_channel_init(&c, &r.d, &handle, &cfg, rx.data() + 1, rcap, tx.data() + 1, tcap, r.now) == 0, "bind service stream");
    }
    void request(const Bytes& data) { check(lockdown_channel_request(&c, data.data(), data.size(), r.now) == 0, "queue explicit framed request"); }
    int at(uint64_t time) {
        const auto reads = r.peer.reads, writes = r.peer.writes;
        const int status = lockdown_channel_poll(&c, time);
        check(r.peer.reads - reads <= 1 && r.peer.writes - writes <= 1, "bounded raw callbacks per channel poll"); return status;
    }
    int step() { return at(r.now++); }
    template<class Predicate> void until(Predicate predicate, unsigned limit = 15000) {
        for (unsigned i = 0; i < limit && !predicate(); ++i) {
            const int status = step();
            check(status == 0 || status == IAP2_MORE || status == USBMUX_DISPATCHER_CONTROL ||
                  status == LOCKDOWN_CHANNEL_RESPONSE || (status == LOCKDOWN_CHANNEL_CLOSED && predicate()), "service simulation remains in expected state");
        }
        check(predicate(), "bounded service loop reaches expected state");
    }
    Bytes response(uint64_t& token) {
        lockdown_body body{};
        check(lockdown_channel_response(&c, &body, &token) == LOCKDOWN_CHANNEL_RESPONSE && token, "borrow current response");
        return Bytes(body.data, body.data + body.size);
    }
    void held() { until([&] { return c.state == LOCKDOWN_CHANNEL_HELD; }); }
    void canaries() {
        check(rx.front() == 0xa5 && rx.back() == 0xa5 && tx.front() == 0xa5 && tx.back() == 0xa5, "service storage canaries"); r.canaries();
    }
};
