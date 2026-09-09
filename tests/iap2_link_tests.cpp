// SPDX-License-Identifier: GPL-3.0-or-later
// Pinned LIVI framing/LSP vectors plus independent bounded-state regressions.
// No real transport, certificate, phone or head unit is used.
#include "iap2_link.h"
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
static Bytes hex(const std::string& s) {
    Bytes b; for (size_t i = 0; i < s.size(); i += 2) b.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return b;
}
static Bytes frame(uint8_t flags, uint8_t seq, uint8_t ack, uint8_t session, const Bytes *payload = nullptr) {
    iap2_frame f{flags, seq, ack, session, payload != nullptr, payload ? payload->data() : nullptr, payload ? payload->size() : 0};
    Bytes b(65535); size_t n;
    check(iap2_frame_encode(&f, b.data(), b.size(), &n) == IAP2_OK, "test frame encode"); b.resize(n); return b;
}
static Bytes lsp(const iap2_lsp& p) {
    Bytes b(IAP2_LINK_LSP_LIMIT); size_t n;
    check(iap2_lsp_encode(&p, b.data(), b.size(), &n) == IAP2_OK, "test LSP encode"); b.resize(n); return b;
}
struct Link {
    iap2_link_config config{};
    iap2_link engine{};
    Link(uint8_t seq = 99, uint8_t window = 4) {
        iap2_link_default_config(&config); config.initial_sequence = seq; config.offer.window = window;
        config.offer.max_ack = std::min<uint8_t>(window, 2);
        check(iap2_link_init(&engine, &config) == IAP2_OK, "link init");
    }
    Link(const Link&) = delete; Link& operator=(const Link&) = delete;
    int feed(const Bytes& bytes, uint64_t now = 0, int expected = IAP2_OK) {
        size_t n = 777;
        const int result = iap2_link_feed(&engine, bytes.data(), bytes.size(), &n, now);
        if (result != expected) throw std::runtime_error("feed result " + std::to_string(result) +
            " expected " + std::to_string(expected) + " state " + std::to_string(engine.state) +
            " bytes " + std::to_string(bytes.size()));
        check(n == bytes.size(), "feed consumed all test bytes"); return result;
    }
    Bytes output(uint64_t now = 0) {
        Bytes b(IAP2_LINK_PACKET_LIMIT); size_t n = 777;
        int status = iap2_link_output(&engine, b.data(), b.size(), &n, now);
        check(status == IAP2_OK || status == IAP2_MORE, "output result");
        if (status == IAP2_MORE) check(n == 0, "empty output length");
        b.resize(n); return b;
    }
    void start(uint64_t now = 0) {
        check(iap2_link_start(&engine, now) == IAP2_OK, "start");
        check(output(now) == Bytes(iap2_detect_marker, iap2_detect_marker + 6), "initial marker");
    }
    void handshake(uint8_t peer_seq = 42, uint64_t now = 0) {
        start(now); feed(Bytes(iap2_detect_marker, iap2_detect_marker + 6), now);
        auto proposal = lsp(config.offer);
        check(output(now) == frame(0x80, config.initial_sequence, 0, 0, &proposal), "local SYN bytes");
        feed(frame(0x80, peer_seq, 0, 0, &proposal), now);
        check(engine.state == IAP2_LINK_SYNCHRONIZE, "not established without peer ACK");
        check(output(now) == frame(0x40, config.initial_sequence, peer_seq, 0), "ACK peer SYN");
        feed(frame(0x40, 0, config.initial_sequence, 0), now);
        check(engine.state == IAP2_LINK_NORMAL, "negotiated state");
        check(output(now).empty(), "no ACK loop after handshake");
    }
    void send(const Bytes& b, uint64_t now = 0, int expected = IAP2_OK, uint8_t session = 10) {
        check(iap2_link_send(&engine, session, b.data(), b.size(), now) == expected, "send result");
    }
    Bytes receive(uint8_t expected_session = 10) {
        Bytes b(IAP2_LINK_PAYLOAD_LIMIT); size_t n = 777; uint8_t session = 0;
        check(iap2_link_receive(&engine, &session, b.data(), b.size(), &n) == IAP2_OK, "receive result");
        check(session == expected_session, "receive session"); b.resize(n); return b;
    }
    void empty() {
        uint8_t b = 0, session = 77; size_t n = 777;
        check(iap2_link_receive(&engine, &session, &b, 1, &n) == IAP2_MORE && n == 0 && session == 77,
              "no duplicate/early delivery");
    }
};

static void lsp_codec() {
    const auto golden = hex("011effff0fa001f404030a00010b02010c0102");
    iap2_lsp p{};
    check(iap2_lsp_decode(golden.data(), golden.size(), &p) == IAP2_OK && lsp(p) == golden, "upstream LSP roundtrip");
    check(p.window == 30 && p.packet_size == 65535 && p.session_count == 3, "LSP fields");
    for (size_t n : {size_t(0),size_t(9),size_t(10),size_t(11),size_t(12),size_t(14),size_t(18)})
        check(iap2_lsp_decode(golden.data(), n, &p) == IAP2_INVALID, "malformed/trailing LSP bytes");
    for (const auto& mutation : std::vector<std::pair<size_t,uint8_t>>{{0,2},{1,0},{1,128},{8,0},{9,0},{9,31},{10,0},{13,10},{12,0}}) {
        auto bad = golden; bad[mutation.first] = mutation.second;
        auto before = p;
        check(iap2_lsp_decode(bad.data(), bad.size(), &p) == IAP2_INVALID, "invalid LSP accepted");
        check(std::memcmp(&p, &before, sizeof p) == 0, "failed LSP decode modified output");
    }
    Bytes b(4, 0xa5); size_t n = 77;
    check(iap2_lsp_encode(&p, b.data(), b.size(), &n) == IAP2_NO_SPACE && n == 0 && b == Bytes(4,0xa5), "LSP capacity transaction");
}
static void detection() {
    Link a; a.start();
    check(a.output(999).empty() && a.output(1000) == Bytes(iap2_detect_marker, iap2_detect_marker+6), "marker retry timer");
    for (unsigned i = 0; i < 6; ++i) a.feed(Bytes{iap2_detect_marker[i]}, 1000);
    auto syn = a.output(1000); check(!syn.empty() && syn[4] == 0x80, "fragmented marker negotiation");
    check(a.output(1499).empty() && a.output(1500) == syn, "SYN retry timer");
    Link b; b.start(); b.feed(Bytes{0}, 0, IAP2_LINK_CLOSED);
    check(b.engine.reason == IAP2_LINK_REASON_MARKER, "bad marker reason");
    Link c; c.start(); uint8_t out[1024]; size_t n;
    check(iap2_link_output(&c.engine,out,sizeof out,&n,10000) == IAP2_LINK_CLOSED && n == 0, "handshake bounded timeout");
}
static void handshake_validation() {
    Link a; a.start(); a.feed(Bytes(iap2_detect_marker,iap2_detect_marker+6)); a.output();
    a.feed(frame(0x40,0,99,0),0,IAP2_INVALID);
    check(a.engine.state == IAP2_LINK_SYNCHRONIZE, "ACK alone cannot establish");
    auto p = a.config.offer; p.window = 8;
    auto body = lsp(p); a.feed(frame(0x80,42,0,0,&body),0,IAP2_UNSUPPORTED);
    check(!a.engine.peer_syn, "unsupported proposal mutated state");
    p = a.config.offer; p.sessions[0].id = 11; body = lsp(p);
    a.feed(frame(0x80,42,0,0,&body),0,IAP2_UNSUPPORTED);
    body = lsp(a.config.offer); a.feed(frame(0xc0,42,98,0,&body)); a.output();
    a.feed(frame(0x40,0,100,0),0,IAP2_INVALID);
    check(a.engine.state == IAP2_LINK_SYNCHRONIZE, "wrong handshake ACK rejected");
    a.feed(frame(0x40,0,99,0)); check(a.engine.state == IAP2_LINK_NORMAL, "valid completion");
    a.feed(frame(0xc0,42,99,0,&body));
    check(a.output() == frame(0x40,99,42,0), "duplicate SYN re-ACKed");
    a.feed(frame(0x80,43,0,0,&body),0,IAP2_LINK_CLOSED);
    check(a.engine.reason == IAP2_LINK_REASON_RESTART, "changed SYN terminates old session");
    Link b; b.start(); b.feed(Bytes(iap2_detect_marker,iap2_detect_marker+6)); b.output();
    b.feed(frame(0xc0,42,99,0,&body));
    check(b.engine.state == IAP2_LINK_SYNCHRONIZE, "final ACK not yet handed to transport");
    b.output(); check(b.engine.state == IAP2_LINK_NORMAL, "combined SYN ACK completion");
}
static void window_and_ack() {
    Link a; a.handshake();
    for (uint8_t i = 0; i < 8; ++i) a.send(Bytes{i});
    a.send(Bytes{8},0,IAP2_LINK_BUSY);
    for (uint8_t i = 0; i < 4; ++i) { auto data = Bytes{i}; check(a.output() == frame(0x40,100+i,42,10,&data), "window packet"); }
    check(a.output().empty() && a.engine.tx_sent == 4, "no window plus one");
    a.feed(frame(0x40,0,104,0),10,IAP2_INVALID);
    check(a.engine.tx_sent == 4 && a.engine.tx_count == 8, "future ACK kept data");
    a.feed(frame(0x40,0,98,0),10);
    check(a.engine.tx_count == 8, "stale ACK kept data");
    a.feed(frame(0x40,0,101,0),10);
    check(a.engine.tx_sent == 2 && a.engine.tx_count == 6, "cumulative ACK clears exact prefix");
    check(!a.output(10).empty() && !a.output(10).empty() && a.output(10).empty(), "window resumes");
    a.feed(frame(0x40,0,105,0),20); a.output(20); a.output(20);
    a.feed(frame(0x40,0,107,0),30);
    check(a.engine.tx_count == 0 && iap2_link_next_delay(&a.engine) == UINT32_MAX, "queue fully acknowledged");
}
static void retransmission() {
    Link a; a.handshake(); const Bytes data{1,2,3}; a.send(data);
    auto first = a.output(); check(a.output(999).empty(), "no early retry");
    for (unsigned i = 1; i <= 3; ++i) check(a.output(i*1000) == first, "same sequence/payload retransmission");
    uint8_t out[1024]; size_t n;
    check(iap2_link_output(&a.engine,out,sizeof out,&n,4000) == IAP2_LINK_CLOSED && n == 0, "retry exhaustion");
    check(a.engine.reason == IAP2_LINK_REASON_TIMEOUT && a.engine.tx_count == 0, "timeout flushes state");
    Link b; b.handshake(); b.send(data,0); auto f = b.output(500);
    check(b.output(1499).empty() && b.output(1500) == f, "timer starts at output not enqueue");
    b.feed(frame(0x40,0,100,0),1501);
    check(b.output(10000).empty() && b.engine.state == IAP2_LINK_NORMAL, "ACK cancels timer");
}
static void oldest_timer_and_backpressure() {
    Link a; a.handshake(); a.send(Bytes{1}); auto first = a.output();
    a.send(Bytes{2},900); a.output(900);
    check(iap2_link_next_delay(&a.engine) == 100, "new send does not postpone oldest timeout");
    check(a.output(1000) == first, "oldest retransmitted");
    Link b; b.handshake(); b.send(Bytes{1}); auto original = b.output();
    uint8_t tiny[8]; std::fill(std::begin(tiny),std::end(tiny),0xa5); size_t n = 77;
    check(iap2_link_output(&b.engine,tiny,sizeof tiny,&n,1000) == IAP2_NO_SPACE && n == 0, "retry output capacity");
    check(b.engine.tx[0].attempts == 0 && b.output(1000) == original && b.engine.tx[0].attempts == 1, "failed output retains retry budget");
    check(std::all_of(std::begin(tiny),std::end(tiny),[](auto x){return x==0xa5;}), "output canary");
}
static void receive_and_ack_timers() {
    Link a; a.handshake(); const Bytes one{1},two{2};
    a.feed(frame(0x40,43,99,10,&one),0); check(a.receive() == one, "payload delivery");
    check(a.output(99).empty(), "delayed ACK not early");
    check(a.output(100) == frame(0x40,99,43,0), "delayed ACK");
    check(a.output(200).empty(), "ACK deadline cleared");
    a.feed(frame(0x40,43,99,10,&one),200); a.empty();
    check(a.output(200) == frame(0x40,99,43,0), "duplicate ACK without redelivery");
    a.feed(frame(0x40,44,99,10,&one),300); a.feed(frame(0x40,45,99,10,&two),350);
    check(a.output(350) == frame(0x40,99,45,0), "cumulative ACK threshold");
    check(a.output(450).empty(), "no duplicate delayed ACK after cumulative ACK");
    Link b; b.handshake(); b.feed(frame(0x40,43,99,10,&one),0); b.send(two,50);
    check(b.output(50) == frame(0x40,100,43,10,&two), "piggyback ACK");
    check(b.output(100).empty(), "piggyback cancels ACK timer");
    for (unsigned i=0;i<10;++i) b.feed(frame(0x40,0,100,0),100);
    check(b.output(200).empty(), "pure ACKs do not create ACK traffic");
}
static void reordered_and_full_receive() {
    Link a; a.handshake(); Bytes one{1},two{2};
    a.feed(frame(0x40,44,99,10,&two)); a.empty();
    a.feed(frame(0x40,44,99,10,&two)); a.empty();
    a.feed(frame(0x40,43,99,10,&one));
    check(a.receive() == one && a.receive() == two, "out-of-order single delivery"); a.empty();
    for (uint8_t i=0;i<8;++i) { Bytes body{i}; a.feed(frame(0x40,45+i,99,10,&body)); a.output(); }
    a.feed(frame(0x40,53,99,10,&one),0,IAP2_LINK_BUSY);
    check(a.engine.rx_acked == 52, "full RX does not acknowledge lost payload");
    for (uint8_t i=0;i<8;++i) check(a.receive() == Bytes{i}, "full queue remains intact");
    a.feed(frame(0x40,53,99,10,&one)); check(a.receive() == one, "retry after RX drain");
    Link b; b.handshake(); b.feed(frame(0x40,50,99,10,&one)); b.empty();
    check(b.engine.rx_acked == 42, "outside receive window not accepted");
}
static void wrapping_sequences() {
    Link a(254); a.handshake(254);
    for (unsigned i=0;i<300;++i) {
        const auto seq=static_cast<uint8_t>(255+i); Bytes body{static_cast<uint8_t>(i)};
        a.send(body,i); check(a.output(i)[5] == seq, "TX wraps at 255");
        a.feed(frame(0x40,seq,seq,10,&body),i);
        check(a.receive() == body && a.engine.tx_count == 0, "RX and cumulative ACK wrap");
        a.output(i);
    }
}
static void damaged_and_unsupported() {
    Link a; a.handshake(); Bytes payload{1,2,3};
    auto bad=frame(0x40,43,99,10,&payload); bad.back()^=1;
    a.feed(bad,0,IAP2_INVALID); a.empty();
    auto valid=frame(0x40,43,99,10,&payload); Bytes noise{0x13,0xff,0x01,0x5a}; noise.insert(noise.end(),valid.begin(),valid.end());
    for(auto byte:noise) a.feed(Bytes{byte});
    check(a.receive()==payload,"resynchronization and fragmented frame");
    a.send(payload); a.output();
    Bytes missing{100}; a.feed(frame(0x60,0,100,0,&missing),0,IAP2_UNSUPPORTED);
    check(a.engine.tx_count==1,"unsupported EAK does not ACK data");
    a.feed(frame(0x40,44,100,11,&payload),0,IAP2_UNSUPPORTED);
    check(a.engine.tx_count==1,"unnegotiated session does not mutate ACK state");
    a.feed(frame(0xd0,44,100,10,&payload),0,IAP2_LINK_CLOSED);
    check(a.engine.reason==IAP2_LINK_REASON_RESET && a.engine.tx_count==0,"RST is terminal before SYN/ACK/data");
}
static void capacity_time_disconnect() {
    Link a; a.handshake(); a.send(Bytes(1015,1),0,IAP2_NO_SPACE);
    Bytes full(1014,0x55); a.send(full); check(a.output().size()==1024,"maximum frame size");
    a.feed(frame(0x40,43,100,10,&full));
    uint8_t small[4]; size_t n=9; uint8_t session=77;
    check(iap2_link_receive(&a.engine,&session,small,sizeof small,&n)==IAP2_NO_SPACE && n==0 && session==77,"RX capacity leaves queue");
    check(a.receive()==full,"RX retry after capacity failure");
    check(iap2_link_output(&a.engine,small,sizeof small,&n,10)==IAP2_MORE,"advance clock");
    check(iap2_link_send(&a.engine,10,small,1,9)==IAP2_ARGUMENT,"backward clock rejected");
    iap2_link_close(&a.engine); a.send(Bytes{1},10,IAP2_LINK_CLOSED);
    check(iap2_link_next_delay(&a.engine)==UINT32_MAX,"closed has no timers");
    check(iap2_link_start(&a.engine,10)==IAP2_ARGUMENT,"closed requires reinitialization");
    check(iap2_link_init(&a.engine,&a.config)==IAP2_OK,"explicit reconnect init"); a.handshake(42,20);
    Link b; b.handshake(); Bytes large(1015,1); auto oversized=frame(0x40,43,99,10,&large);
    size_t consumed=0;
    check(iap2_link_feed(&b.engine,oversized.data(),oversized.size(),&consumed,0)==IAP2_LINK_CLOSED && consumed==9,
          "oversized header stops before body");
    check(b.engine.reason==IAP2_LINK_REASON_OVERSIZE,"oversize reason");
}
static void near_clock_limit_and_empty_payload() {
    Link a; const uint64_t at=UINT64_MAX-1100; a.handshake(42,at);
    a.send({},at); auto packet=a.output(at);
    check(packet.size()==10,"empty checksummed payload is data");
    check(a.output(at+999).empty() && a.output(at+1000)==packet,"timer near uint64 limit without deadline overflow");
    Bytes empty; a.feed(frame(0x40,43,100,10,&empty),UINT64_MAX);
    check(a.receive().empty(),"empty payload delivered exactly once"); a.empty();
}
static void partial_error_consumption() {
    Link a; a.handshake(); Bytes body{1};
    auto bad=frame(0x40,43,99,10,&body); bad.back()^=1;
    const auto good=frame(0x40,43,99,10,&body); auto both=bad; both.insert(both.end(),good.begin(),good.end());
    size_t used=0;
    check(iap2_link_feed(&a.engine,both.data(),both.size(),&used,0)==IAP2_INVALID && used==bad.size(),"bad body leaves caller's remaining input");
    a.feed(Bytes(both.begin()+used,both.end())); check(a.receive()==body,"resume after rejected frame");
    auto rst=frame(0x10,0,0,0); both=rst; both.insert(both.end(),good.begin(),good.end());
    check(iap2_link_feed(&a.engine,both.data(),both.size(),&used,0)==IAP2_LINK_CLOSED && used==rst.size(),"RST stops coalesced input");
}
static void negotiated_subset_and_limits() {
    Link a;
    a.config.offer.session_count=3;
    a.config.offer.sessions[1]={11,2,1}; a.config.offer.sessions[2]={12,1,2};
    check(iap2_link_init(&a.engine,&a.config)==IAP2_OK,"custom session offer");
    a.start(); a.feed(Bytes(iap2_detect_marker,iap2_detect_marker+6)); a.output();
    auto p=a.config.offer; p.session_count=2; p.window=2; p.packet_size=64;
    auto payload=lsp(p); a.feed(frame(0xc0,42,99,0,&payload)); a.output();
    check(a.engine.state==IAP2_LINK_NORMAL,"accepted bounded subset");
    a.send(Bytes{1},0,IAP2_OK,11); a.send(Bytes{1},0,IAP2_UNSUPPORTED,12);
    a.send(Bytes(55,1),0,IAP2_NO_SPACE);
    check(a.output()[7]==11,"negotiated optional session routed raw");
    Bytes data{0,7,0x33}; a.feed(frame(0x40,43,100,11,&data)); check(a.receive(11)==data,"raw session payload preserved");
    Link b; auto config=b.config; config.offer.window=9;
    check(iap2_link_init(&b.engine,&config)==IAP2_ARGUMENT,"oversized local window");
    config=b.config; config.offer.packet_size=1025;
    check(iap2_link_init(&b.engine,&config)==IAP2_ARGUMENT,"oversized local packet buffer");
    config=b.config; config.offer.ack_ms=config.offer.retransmit_ms;
    check(iap2_link_init(&b.engine,&config)==IAP2_ARGUMENT,"invalid timer profile");
}
static void simulated_loss() {
    Link sender(99), receiver(42);
    sender.start(); receiver.start(); const Bytes marker(iap2_detect_marker,iap2_detect_marker+6);
    sender.feed(marker); receiver.feed(marker);
    auto s=sender.output(), r=receiver.output(); sender.feed(r); receiver.feed(s);
    s=sender.output(); r=receiver.output(); sender.feed(r); receiver.feed(s);
    check(sender.engine.state==IAP2_LINK_NORMAL && receiver.engine.state==IAP2_LINK_NORMAL,"two-engine handshake");
    for (uint8_t i=0;i<8;++i) sender.send(Bytes{i});
    bool lost_data=false,lost_ack=false; Bytes delivered;
    for (uint64_t t=0;t<=5000;t+=50) {
        for(unsigned guard=0;guard<32;++guard) {
            auto packet=sender.output(t); if(packet.empty()) break;
            if(!lost_data && packet.size()>9 && packet[5]==100) { lost_data=true; continue; }
            // Feed real encoded frames one byte at a time across a synthetic transport.
            for(auto byte:packet) receiver.feed(Bytes{byte},t);
            check(guard<31,"bounded sender drain");
        }
        while(receiver.engine.rx_delivered!=receiver.engine.rx_acked) {
            auto payload=receiver.receive(); check(payload.size()==1,"simulated payload"); delivered.push_back(payload[0]);
        }
        for(unsigned guard=0;guard<32;++guard) {
            auto packet=receiver.output(t); if(packet.empty()) break;
            if(!lost_ack && packet[4]==0x40 && packet[6]==103) { lost_ack=true; continue; }
            sender.feed(packet,t); check(guard<31,"bounded receiver drain");
        }
        if(!sender.engine.tx_count && delivered.size()==8) break;
    }
    check(lost_data && lost_ack && delivered==Bytes({0,1,2,3,4,5,6,7}),"loss recovery preserves exactly-once order");
    check(!sender.engine.tx_count && sender.engine.state==IAP2_LINK_NORMAL,"all simulated data acknowledged");
}
static void exhaustive_ack_ranges_and_output_transactions() {
    for (unsigned delta=0;delta<256;++delta) {
        Link a(254); a.handshake();
        for(unsigned i=0;i<4;++i) { a.send(Bytes{1}); a.output(); }
        const bool future=delta>4 && delta<=127;
        a.feed(frame(0x40,0,static_cast<uint8_t>(254+delta),0),0,future ? IAP2_INVALID : IAP2_OK);
        check(a.engine.tx_count == (delta<=4 ? 4-delta : 4),"all 256 ACK distances preserve correct queue prefix");
    }
    Link b;
    check(iap2_link_start(&b.engine,0)==IAP2_OK,"transaction setup");
    uint8_t out[1024]; size_t n=77;
    check(iap2_link_output(&b.engine,out,5,&n,0)==IAP2_NO_SPACE && n==0 && !b.engine.marker_sent,"marker short-buffer transaction");
    b.output(); b.feed(Bytes(iap2_detect_marker,iap2_detect_marker+6));
    check(iap2_link_output(&b.engine,out,22,&n,0)==IAP2_NO_SPACE && n==0 && !b.engine.syn_sent,"SYN short-buffer transaction");
    b.output(); auto payload=lsp(b.config.offer); b.feed(frame(0xc0,42,99,0,&payload));
    check(iap2_link_output(&b.engine,out,8,&n,0)==IAP2_NO_SPACE && n==0 && b.engine.state==IAP2_LINK_SYNCHRONIZE,
          "failed final ACK does not establish link");
    b.output(); b.send(Bytes{1});
    check(iap2_link_output(&b.engine,out,10,&n,0)==IAP2_NO_SPACE && n==0 && b.engine.tx_sent==0 && b.engine.tx_sequence==99,
          "failed first output does not consume sequence or send slot");
    check(b.output()[5]==100,"first accepted output consumes sequence once");
}
int main() {
    try {
        const std::pair<const char*,void(*)()> groups[] = {
            {"lsp_codec",lsp_codec},{"detection",detection},{"handshake_validation",handshake_validation},
            {"window_and_ack",window_and_ack},{"retransmission",retransmission},
            {"oldest_timer_and_backpressure",oldest_timer_and_backpressure},{"receive_and_ack_timers",receive_and_ack_timers},
            {"reordered_and_full_receive",reordered_and_full_receive},{"wrapping_sequences",wrapping_sequences},
            {"damaged_and_unsupported",damaged_and_unsupported},{"capacity_time_disconnect",capacity_time_disconnect},
            {"near_clock_limit_and_empty_payload",near_clock_limit_and_empty_payload},{"partial_error_consumption",partial_error_consumption},
            {"negotiated_subset_and_limits",negotiated_subset_and_limits},{"simulated_loss",simulated_loss},
            {"exhaustive_ack_ranges_and_output_transactions",exhaustive_ack_ranges_and_output_transactions}};
        for(const auto& group:groups) {
            try { group.second(); } catch(const std::exception& e) { throw std::runtime_error(std::string(group.first)+": "+e.what()); }
        }
        std::cout << "PASS: 16 bounded iAP2 link test groups; simulated transport only.\n";
        std::cout << "Host link-state storage: " << sizeof(iap2_link) << " bytes.\n";
        return 0;
    } catch(const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
