// SPDX-License-Identifier: GPL-3.0-only
#include "support/lockdown_fixture.h"
static void wire_lengths_and_truncations() {
    for (const auto name : {"get-product-type.xml", "product-type.xml", "error.xml", "escaped.xml"}) {
        const auto body = fixture(name), input = framed(body);
        for (size_t n = 0; n < input.size(); ++n) {
            lockdown_body out{input.data(), 999}; const auto before = snapshot(out); size_t consumed = 99, total = 99;
            check(lockdown_frame_decode(input.data(), n, &out, &consumed) == IAP2_MORE && !consumed && snapshot(out) == before, "all frame truncations preserve view");
            check(lockdown_frame_size(input.data(), n, &total) == (n < 4 ? IAP2_MORE : IAP2_OK) &&
                  total == (n < 4 ? 0 : input.size()), "prefix determines body-only length");
        }
        auto coalesced = input; coalesced.insert(coalesced.end(), input.begin(), input.end()); lockdown_body out{}; size_t consumed;
        check(lockdown_frame_decode(coalesced.data(), coalesced.size(), &out, &consumed) == 0 && consumed == input.size() &&
              out.data == coalesced.data() + 4 && Bytes(out.data, out.data + out.size) == body, "borrow one frame and preserve coalesced tail");
    }
    for (const auto& input : {Bytes{0,0,0,0}, Bytes{0,1,0,1}, Bytes{255,255,255,255}}) {
        lockdown_body out{input.data(), 77}; const auto before = snapshot(out); size_t n = 99;
        check(lockdown_frame_decode(input.data(), input.size(), &out, &n) == (input[1] || input[0] ? IAP2_NO_SPACE : IAP2_INVALID) &&
              !n && snapshot(out) == before, "zero and over-limit prefixes fail closed");
    }
}
static void wire_encoding_boundaries() {
    for (size_t length : {size_t(1), size_t(256), size_t(65536)}) {
        Bytes body(length, 0xbd), out(length + 6, 0xa5); size_t n;
        check(lockdown_frame_encode(body.data(), body.size(), out.data() + 1, out.size() - 2, &n) == 0 &&
              Bytes(out.begin() + 1, out.end() - 1) == framed(body) && n == length + 4 &&
              out.front() == 0xa5 && out.back() == 0xa5, "minimum, endian boundary and maximum body frames");
        lockdown_body decoded{};
        check(lockdown_frame_decode(out.data() + 1, n, &decoded, &n) == 0 && decoded.size == length, "maximum exact decode");
    }
    const auto body = fixture("product-type.xml"); Bytes out(body.size() + 8, 0xa5); const auto before = out;
    for (size_t capacity = 0; capacity < body.size() + 4; ++capacity) {
        size_t n = 99; check(lockdown_frame_encode(body.data(), body.size(), out.data() + 1, capacity, &n) == IAP2_NO_SPACE &&
                             !n && out == before, "every insufficient framing capacity transactional");
    }
    size_t n = 99; const uint8_t byte = 1;
    check(lockdown_frame_encode(&byte, 65537, out.data(), out.size(), &n) == IAP2_NO_SPACE && !n && out == before, "oversize rejected before reading input");
    check(lockdown_frame_encode(nullptr, 0, out.data(), out.size(), &n) == IAP2_INVALID && !n && out == before, "empty body refused");
}
static void xml_golden_and_escape() {
    (void)get_value(); const auto l = bytes("&<>\"'"), k = bytes("K&<>\"'"), d = bytes("D&<>\"'");
    const auto label = view(l), key = view(k), domain = view(d); const auto expected = fixture("escaped.xml");
    Bytes out(expected.size() + 2, 0xa5); size_t n;
    for (size_t cap = 0; cap < expected.size(); ++cap) {
        check(lockdown_get_value_encode(&label, &key, &domain, out.data() + 1, cap, &n) == IAP2_NO_SPACE && !n &&
              std::all_of(out.begin(), out.end(), [](uint8_t b) { return b == 0xa5; }), "XML capacity checked before any output");
    }
    check(lockdown_get_value_encode(&label, &key, &domain, out.data() + 1, expected.size(), &n) == 0 &&
          n == expected.size() && Bytes(out.begin() + 1, out.end() - 1) == expected && out.front() == 0xa5 && out.back() == 0xa5, "all XML entities exact");
    const lockdown_body empty{nullptr, 0}; out.resize(4096);
    check(lockdown_get_value_encode(&label, &key, &empty, out.data(), out.size(), &n) == 0 &&
          std::string(out.begin(), out.begin() + n).find("<key>Domain</key><string></string>") != std::string::npos, "empty domain differs from omitted domain");
}
static void xml_limits_and_arguments() {
    Bytes valid_label(64, 'L'), valid_key(128, 'K'), valid_domain(128, 'D'), out(4096, 0xa5);
    auto l = view(valid_label), k = view(valid_key), d = view(valid_domain); size_t n;
    check(lockdown_get_value_encode(&l, &k, &d, out.data(), out.size(), &n) == 0, "maximum permitted metadata");
    for (unsigned field = 0; field < 3; ++field) for (const unsigned byte : {0u, 9u, 31u, 127u, 128u, 255u}) {
        auto bad_l = valid_label, bad_k = valid_key, bad_d = valid_domain;
        (field == 0 ? bad_l : field == 1 ? bad_k : bad_d)[0] = static_cast<uint8_t>(byte);
        const auto lv = view(bad_l), kv = view(bad_k), dv = view(bad_d); const auto before = out;
        check(lockdown_get_value_encode(&lv, &kv, &dv, out.data(), out.size(), &n) == IAP2_ARGUMENT && !n && out == before, "reject control and non-ASCII metadata");
    }
    for (unsigned field = 0; field < 3; ++field) {
        auto a = l, b = k, c = d; ++(field == 0 ? a : field == 1 ? b : c).size;
        check(lockdown_get_value_encode(&a, &b, &c, out.data(), out.size(), &n) == IAP2_ARGUMENT && !n, "over-limit text rejected before reading");
    }
    l.size = 0; check(lockdown_get_value_encode(&l, &k, nullptr, out.data(), out.size(), &n) == IAP2_ARGUMENT, "no default label");
    l = view(valid_label); k.size = 0;
    check(lockdown_get_value_encode(&l, &k, nullptr, out.data(), out.size(), &n) == IAP2_ARGUMENT, "all-values query not supplied");
    lockdown_body decoded{};
    check(lockdown_frame_size(nullptr, 0, &n) == IAP2_MORE && !n &&
          lockdown_frame_size(nullptr, 4, &n) == IAP2_ARGUMENT &&
          lockdown_frame_decode(nullptr, 0, &decoded, nullptr) == IAP2_ARGUMENT &&
          lockdown_frame_encode(nullptr, 1, out.data(), out.size(), &n) == IAP2_ARGUMENT &&
          lockdown_get_value_encode(nullptr, &k, nullptr, out.data(), out.size(), &n) == IAP2_ARGUMENT, "null argument contracts");
}
static void channel_init_and_queue_contracts() {
    Runtime r(1,1024,64); r.ready(); auto h = r.open(); r.established(h);
    lockdown_channel c{}; lockdown_channel_config cfg{}; lockdown_channel_default_config(&cfg); uint8_t rx[128], tx[256];
    check(cfg.exchange_ms == 5000 && cfg.hold_ms == 5000, "bounded local defaults");
    const auto before = snapshot(c); const auto reads = r.peer.reads, writes = r.peer.writes;
    for (size_t capacity : {size_t(0),size_t(4),size_t(65541)}) {
        check(lockdown_channel_init(&c, &r.d, &h, &cfg, rx, capacity, tx, sizeof tx, r.now) == IAP2_ARGUMENT &&
              snapshot(c) == before, "invalid RX capacity leaves channel unchanged");
        check(lockdown_channel_init(&c, &r.d, &h, &cfg, rx, sizeof rx, tx, capacity, r.now) == IAP2_ARGUMENT &&
              snapshot(c) == before, "invalid TX capacity leaves channel unchanged");
    }
    for (uint32_t value : {0u,60001u}) {
        auto invalid = cfg; invalid.exchange_ms = value;
        check(lockdown_channel_init(&c, &r.d, &h, &invalid, rx, sizeof rx, tx, sizeof tx, r.now) == IAP2_ARGUMENT && snapshot(c) == before, "exchange budget bound");
        invalid = cfg; invalid.hold_ms = value;
        check(lockdown_channel_init(&c, &r.d, &h, &invalid, rx, sizeof rx, tx, sizeof tx, r.now) == IAP2_ARGUMENT && snapshot(c) == before, "hold budget bound");
    }
    auto stale = h; ++stale.connection;
    check(lockdown_channel_init(&c, &r.d, &stale, &cfg, rx, sizeof rx, tx, sizeof tx, r.now) == USBMUX_DISPATCHER_STALE && snapshot(c) == before, "stale bind transactional");
    check(lockdown_channel_init(&c, &r.d, &h, &cfg, rx, sizeof rx, rx, sizeof rx, r.now) == IAP2_ARGUMENT && snapshot(c) == before, "shared buffer refused");
    check(r.peer.reads == reads && r.peer.writes == writes && r.peer.cancelled.empty(), "init validation never performs I/O");
    Service s(r,h); const auto idle = snapshot(s.c);
    check(lockdown_channel_request(&s.c, nullptr, 0, r.now + 999) == IAP2_ARGUMENT && snapshot(s.c) == idle, "bad request cannot advance clock");
    Bytes large(1021); const auto tx_before = s.tx;
    check(lockdown_channel_request(&s.c, large.data(), large.size(), r.now) == IAP2_NO_SPACE && s.tx == tx_before &&
          s.c.state == LOCKDOWN_CHANNEL_IDLE, "oversize request does not become pending");
    s.request(get_value());
    check(r.peer.reads == reads && r.peer.writes == writes && s.c.tx_offset == 0, "request copies only, with no I/O");
    check(lockdown_channel_request(&s.c, large.data(), 1, r.now) == LOCKDOWN_CHANNEL_BUSY &&
          lockdown_channel_detach(&s.c, &h, r.now) == LOCKDOWN_CHANNEL_BUSY, "one exchange, no detach while pending"); s.canaries();
}
static void fragmented_service_every_split() {
    const auto request = get_value(), response = fixture("product-type.xml"), wire = framed(response);
    for (size_t cut = 1; cut < wire.size(); ++cut) {
        Runtime r(1,1024,64); r.ready(); const auto h = r.open(); r.established(h);
        reply_with(r,request,wire,cut); Service s(r,h); auto temporary = request; s.request(temporary); std::fill(temporary.begin(), temporary.end(), 0);
        s.held(); uint64_t token; check(s.response(token) == response && !r.conns[0].flight_count &&
                                      r.peer.streams.at(1).received == framed(request), "all service-prefix/body splits through fragmented raw backend");
        check(s.c.rx_used == wire.size() && s.c.tx_offset == request.size() + 4, "exact independent framing lengths"); s.canaries();
    }
}
static void coalesced_tail_and_detach() {
    Runtime r(1,1024,64); r.ready(); const auto h = r.open(); r.established(h);
    const auto request = get_value(), response = fixture("product-type.xml");
    const Bytes tail{0x16,0x03,0x03,0x00,0x04,0xde,0xad,0xbe,0xef}; // TLS-looking bytes, NOT a TLS session.
    auto coalesced = framed(response); coalesced.insert(coalesced.end(), tail.begin(), tail.end());
    reply_with(r,request,coalesced); Service s(r,h); s.request(request); s.held(); uint64_t token;
    check(s.response(token) == response && r.conns[0].rx_used == tail.size(), "channel never consumes post-frame handoff bytes");
    const auto before = snapshot(s.c); const auto transport = snapshot(r.d);
    check(lockdown_channel_release(&s.c, token + 1, r.now + 999) == USBMUX_DISPATCHER_STALE && snapshot(s.c) == before && snapshot(r.d) == transport, "wrong release cannot advance time or consume view");
    check(lockdown_channel_release(&s.c, token, r.now) == 0, "release current frame");
    const auto reads = r.peer.reads, writes = r.peer.writes; usbmux_handle detached{};
    check(lockdown_channel_detach(&s.c, &detached, r.now) == 0 && detached.physical == h.physical && detached.connection == h.connection &&
          r.peer.reads == reads && r.peer.writes == writes, "detach returns owned stream without I/O or TLS");
    lockdown_channel_close(&s.c);
    check(r.d.active && r.peer.cancelled.empty() && r.read_all(detached) == tail &&
          lockdown_channel_next_delay(&s.c) == UINT32_MAX, "detached close no-op and raw tail preserved"); s.canaries();
}
static void serial_tokens_and_opaque_error() {
    Runtime r(1,1024,64); r.ready(); const auto h = r.open(); r.established(h);
    const auto request = get_value(), error = fixture("error.xml"); reply_with(r,request,framed(error));
    Service s(r,h); s.request(request); s.held(); uint64_t first, second;
    check(s.response(first) == error, "Error body is opaque data, never semantic success");
    const auto received = r.peer.streams.at(1).received.size();
    for (unsigned i = 0; i < 10; ++i) check(s.step() == LOCKDOWN_CHANNEL_RESPONSE, "held body remains stable without retries");
    check(r.peer.streams.at(1).received.size() == received && lockdown_channel_next_delay(&s.c) > 0, "held response does not resend or busy-spin");
    check(lockdown_channel_release(&s.c, first, r.now) == 0, "release first"); s.request(request); s.held();
    check(s.response(second) == error && second > first &&
          lockdown_channel_release(&s.c, first, r.now + 999) == USBMUX_DISPATCHER_STALE && s.c.token == second, "old token cannot release later RPC"); s.canaries();
}
static void response_waits_for_request_ack() {
    Runtime r(1,1024,64); r.ready(); const auto h = r.open(); r.established(h);
    const Bytes request{'q'}, response{'o','k'};
    r.peer.on_data = [&](Peer& peer, uint16_t port, const Bytes&) { send(peer,port,framed(response),1); };
    Service s(r,h); s.request(request); s.until([&] { return s.c.complete != 0; });
    lockdown_body body{}; uint64_t token;
    check(s.c.state == LOCKDOWN_CHANNEL_EXCHANGE && r.conns[0].flight_count == 1 &&
          lockdown_channel_response(&s.c, &body, &token) == IAP2_MORE && !body.data && !body.size && !token, "complete response cannot hide unacknowledged request");
    send(r.peer,1,{},r.peer.streams.at(1).host_next); s.held();
    check(s.response(token) == response && r.conns[0].flight_count == 0, "request acknowledged before publishing body"); s.canaries();
}
static void bad_prefixes_close_shared_transport() {
    for (const auto& prefix : {Bytes{0,0,0,0},Bytes{0,1,0,1},Bytes{255,255,255,255},Bytes{0,0,4,0}}) {
        Runtime r(2,1024,64); r.ready(); const auto h = r.open(), other = r.open(62079); r.established(h); r.established(other);
        reply_with(r,{'q'},prefix); Service s(r,h); s.request({'q'});
        s.until([&] { return s.c.state == LOCKDOWN_CHANNEL_DEAD; });
        check(s.c.reason == LOCKDOWN_CHANNEL_REASON_LENGTH && r.peer.cancelled == std::vector<uint64_t>({1}) &&
              r.conns[1].state == USBMUX_CONNECTION_DEAD && !s.c.rx_used, "bad or locally oversized service prefix cancels shared transport without a body allocation");
        lockdown_channel_close(&s.c); check(r.peer.cancelled.size() == 1, "idempotent failure"); s.canaries();
    }
}
static void partial_eof() {
    const Bytes wire{0,0,0,4,'b','o','d','y'};
    for (size_t n = 0; n < wire.size(); ++n) {
        Runtime r(1,1024,64); r.ready(); const auto h = r.open(); r.established(h);
        r.peer.on_data = [&](Peer& peer, uint16_t port, const Bytes&) {
            send(peer,port,Bytes(wire.begin(),wire.begin()+n),peer.streams.at(port).host_next,true);
        };
        Service s(r,h); s.request({'q'}); s.until([&] { return s.c.state == LOCKDOWN_CHANNEL_DEAD; });
        check(s.c.reason == LOCKDOWN_CHANNEL_REASON_EOF && r.peer.cancelled.size() == 1, "EOF at every incomplete prefix/body position fails closed"); s.canaries();
    }
}
static void exchange_and_hold_deadlines() {
    for (bool trickle : {false,true}) {
        Runtime r(1,1024,64); r.ready(); const auto h = r.open(); r.established(h);
        reply_with(r,{'q'},trickle ? Bytes{0} : Bytes{}); Service s(r,h,1024,1024,{1000,500}); s.request({'q'});
        s.until([&] { return s.c.tx_offset == s.c.tx_size && !r.conns[0].tx_size && !r.conns[0].flight_count && (!trickle || s.c.rx_used == 1); });
        const auto deadline = s.c.started_at + 1000;
        check(s.at(deadline - 1) == IAP2_MORE && lockdown_channel_next_delay(&s.c) == 1, "total exchange budget not renewed by partial response");
        const auto reads = r.peer.reads, writes = r.peer.writes;
        check(s.at(deadline) == LOCKDOWN_CHANNEL_CLOSED && s.c.reason == LOCKDOWN_CHANNEL_REASON_DEADLINE &&
              r.peer.reads == reads && r.peer.writes == writes && r.peer.cancelled.size() == 1, "exchange expires before exact-deadline I/O"); s.canaries();
    }
    Runtime r(1,1024,64); r.ready(); const auto h = r.open(); r.established(h); reply_with(r,{'q'},framed({'r'}));
    Service s(r,h,1024,1024,{1000,100}); s.request({'q'}); s.held(); uint64_t token; (void)s.response(token);
    const auto deadline = s.c.held_at + 100, reads = r.peer.reads;
    check(lockdown_channel_release(&s.c, token, deadline) == LOCKDOWN_CHANNEL_CLOSED &&
          s.c.reason == LOCKDOWN_CHANNEL_REASON_DEADLINE && r.peer.reads == reads, "late release cannot rescue hold deadline"); s.canaries();
}
static void zero_window_and_clock() {
    Runtime r(1,1024,64); r.peer.zero_first_window = true; r.ready(); const auto h = r.open(); r.established(h);
    Service s(r,h,1024,1024,{100,100}); s.request({'q'});
    for (unsigned i=0; i<10; ++i) s.step();
    check(s.c.tx_offset == 0 && lockdown_channel_next_delay(&s.c) > 0, "zero window waits without false write progress or spin");
    const auto before = snapshot(s.c); const auto transport = snapshot(r.d);
    check(s.at(s.c.now - 1) == IAP2_ARGUMENT && snapshot(s.c) == before && snapshot(r.d) == transport, "backward clock rejected transactionally");
    const auto writes = r.peer.writes;
    check(s.at(s.c.started_at + 100) == LOCKDOWN_CHANNEL_CLOSED && r.peer.writes == writes, "zero window does not renew operation budget");
    Runtime near(1,1024,64); near.ready(); const auto nh = near.open(); near.established(nh);
    Service ns(near,nh,1024,1024,{10,10});
    check(lockdown_channel_request(&ns.c, reinterpret_cast<const uint8_t *>("q"), 1, UINT64_MAX-10) == 0 &&
          ns.at(UINT64_MAX) == LOCKDOWN_CHANNEL_CLOSED && ns.c.reason == LOCKDOWN_CHANNEL_REASON_DEADLINE, "budget subtraction does not overflow near maximum clock");
}
static void stale_channel_never_cancels_new_session() {
    Runtime r(1,1024,64); r.ready(); const auto h = r.open(); r.established(h); Service s(r,h);
    usbmux_dispatcher_close(&r.d); r.start(2); r.until([&] { return r.host.state == USBMUX_HOST_READY; }); const auto fresh = r.open(); r.established(fresh);
    const auto before = snapshot(r.d);
    check(s.at(r.now + 999) == LOCKDOWN_CHANNEL_CLOSED && s.c.reason == LOCKDOWN_CHANNEL_REASON_STALE &&
          snapshot(r.d) == before && r.peer.cancelled == std::vector<uint64_t>({1}), "stale channel checks lifetime before time/cancel");
    lockdown_channel_close(&s.c); check(r.d.active && r.peer.cancelled.size() == 1, "old channel closure cannot cancel new generation");
    Service current(r,fresh); lockdown_channel_close(&current.c); lockdown_channel_close(&current.c);
    check(r.peer.cancelled == std::vector<uint64_t>({1,2}) && current.c.reason == LOCKDOWN_CHANNEL_REASON_LOCAL, "current abort cancels once");
    lockdown_channel zero{}; lockdown_body body{reinterpret_cast<const uint8_t *>("x"),1}; uint64_t token=5;
    check(lockdown_channel_poll(nullptr,0) == IAP2_ARGUMENT && lockdown_channel_response(&zero,&body,&token) == IAP2_ARGUMENT &&
          !body.data && !body.size && !token && lockdown_channel_next_delay(&zero) == UINT32_MAX, "uninitialized service contracts");
    lockdown_channel_close(nullptr); lockdown_channel_default_config(nullptr);
}
static void other_stream_and_control_keep_progressing() {
    Runtime r(2,1024,64); r.ready(); const auto h = r.open(), other = r.open(62079); r.established(h); r.established(other);
    const auto request=get_value(), response=fixture("product-type.xml"); reply_with(r,request,framed(response));
    const auto service_reply = r.peer.on_data;
    r.peer.on_data = [service_reply](Peer& peer,uint16_t port,const Bytes& data) {
        if (port == 1) service_reply(peer,port,data); else send(peer,port,data,peer.streams.at(port).host_next);
    };
    Service s(r,h); s.request(request); check(r.write(other,{'x','y'}) == 2, "second raw stream remains available");
    r.peer.inject(packet(USBMUX_CONTROL,{5,'c'}));
    s.until([&] { return r.d.control_pending != 0; });
    check(s.step() == USBMUX_DISPATCHER_CONTROL, "control event remains visible while waiting for service reply");
    const usbmux_frame *control; uint64_t token;
    check(usbmux_dispatcher_control(&r.d,&control,&token) == USBMUX_DISPATCHER_CONTROL && control->payload[1] == 'c' &&
          usbmux_dispatcher_release_control(&r.d,1,token,r.now) == 0, "explicit control release");
    s.held(); s.until([&] { return r.conns[1].rx_used == 2; });
    check(s.response(token) == response && r.read_all(other) == Bytes({'x','y'}), "independent stream and service bytes preserved"); s.canaries();
}
static void maximum_body_with_bounded_read_credit() {
    Runtime r(1,65536,64); r.peer.read_limit = r.peer.write_limit = 65536; r.ready(); const auto h = r.open(); r.established(h);
    reply_with(r,{'q'},{}); Service s(r,h,65540,5); s.request({'q'});
    s.until([&] { return s.c.tx_offset == 5 && !r.conns[0].tx_size && !r.conns[0].flight_count; });
    Bytes body(65536); for (size_t i=0;i<body.size();++i) body[i]=static_cast<uint8_t>(i);
    const auto wire=framed(body); size_t sent=0;
    for (unsigned i=0;i<15000 && s.c.state != LOCKDOWN_CHANNEL_HELD;++i) {
        auto& stream=r.peer.streams.at(1); const size_t credit=r.conns[0].rx_limit-stream.next;
        if (sent<wire.size() && credit && r.peer.incoming.empty()) {
            const auto n=std::min({size_t(32768),credit,wire.size()-sent});
            send(r.peer,1,Bytes(wire.begin()+sent,wire.begin()+sent+n),stream.host_next); sent+=n;
        }
        const auto previous=s.c.rx_used; const int status=s.step();
        check((status==0 || status==IAP2_MORE || status==LOCKDOWN_CHANNEL_RESPONSE) && s.c.rx_used-previous<=512, "at most 512 service bytes consumed per poll");
    }
    uint64_t token;
    check(sent==wire.size() && s.response(token)==body && s.c.rx_used==65540, "maximum body spans mux packets and honors advertised credit"); s.canaries();
}
static void transport_failure_and_counter_exhaustion() {
    Runtime r(1,1024,64); r.ready(); const auto h=r.open(); r.established(h); Service s(r,h);
    // White-box boundary seeding; applications may not mutate channel fields.
    s.c.next_token=UINT64_MAX; const auto before=s.tx;
    check(lockdown_channel_request(&s.c,reinterpret_cast<const uint8_t *>("q"),1,r.now)==IAP2_NO_SPACE && s.tx==before &&
          s.c.state==LOCKDOWN_CHANNEL_IDLE, "response token never wraps");
    r.peer.read_fault=Fault::Disconnect;
    check(s.at(r.now+5)==LOCKDOWN_CHANNEL_CLOSED && s.c.reason==LOCKDOWN_CHANNEL_REASON_TRANSPORT &&
          r.peer.cancelled.size()==1 && lockdown_channel_next_delay(&s.c)==UINT32_MAX, "backend closure invalidates idle service"); s.canaries();
}
static void typed_validation_of_held_channel_responses() {
    for(const char *name:{"product-type.xml","error.xml","product-binary"}) {
        Runtime r(1,1024,64); r.ready(); const auto h=r.open(); r.established(h);
        const auto request=get_value(), response=std::string(name)=="product-binary"?binary_product_fixture():fixture(name);
        reply_with(r,request,framed(response)); Service s(r,h);
        service_plist_node nodes[32]; uint8_t arena[1024]; const service_plist_storage storage{nodes,32,arena,sizeof arena};
        service_plist_document doc{}; lockdown_reply result{}; uint64_t token=99;
        check(lockdown_reply_read(&s.c,&storage,LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,&doc,&result,&token)==IAP2_MORE &&
              !doc.nodes && !result.value && !token,"no typed response before actual held frame");
        s.request(request); s.held(); const auto before=snapshot(s.c); const auto reads=r.peer.reads,writes=r.peer.writes;
        const auto status=lockdown_reply_read(&s.c,&storage,LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,&doc,&result,&token);
        check(status==(std::string(name)=="error.xml"?LOCKDOWN_REPLY_REMOTE_ERROR:IAP2_OK) &&
              token==s.c.token && doc.count && snapshot(s.c)==before && r.peer.reads==reads && r.peer.writes==writes,"explicit typed bridge does not release or perform I/O");
        const auto *value=result.value?result.value:result.error;
        const Bytes copy(value->data,value->data+value->size);
        check(lockdown_channel_release(&s.c,token,r.now)==0,"validated reply explicitly released");
        std::fill(s.rx.begin()+1,s.rx.end()-1,0);
        check(Bytes(value->data,value->data+value->size)==copy,"typed data outlives raw channel view through owned parser arena"); s.canaries();
    }
    Runtime r(1,1024,64); r.ready(); const auto h=r.open(); r.established(h); const auto request=get_value();
    reply_with(r,request,framed(Bytes{'n','o','t',' ','p','l','i','s','t'})); Service s(r,h); s.request(request); s.held();
    service_plist_node nodes[32]; uint8_t arena[1024]; const service_plist_storage storage{nodes,32,arena,sizeof arena};
    service_plist_document doc{}; lockdown_reply result{}; uint64_t token=99; const auto before=snapshot(s.c);
    check(lockdown_reply_read(&s.c,&storage,LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,&doc,&result,&token)<0 &&
          !doc.nodes && !result.value && !token && snapshot(s.c)==before,"malformed body cannot yield a usable release token or silently continue");
    lockdown_channel_close(&s.c); check(r.peer.cancelled.size()==1,"application explicitly aborts invalid response");
}
int main(int argc,char **argv) {
    try {
        check(argc==2,"fixture directory required"); fixtures=argv[1];
        wire_lengths_and_truncations(); wire_encoding_boundaries(); xml_golden_and_escape(); xml_limits_and_arguments();
        channel_init_and_queue_contracts(); fragmented_service_every_split(); coalesced_tail_and_detach(); serial_tokens_and_opaque_error();
        response_waits_for_request_ack(); bad_prefixes_close_shared_transport(); partial_eof(); exchange_and_hold_deadlines();
        zero_window_and_clock(); stale_channel_never_cancels_new_session(); other_stream_and_control_keep_progressing();
        maximum_body_with_bounded_read_credit(); transport_failure_and_counter_exhaustion();
        typed_validation_of_held_channel_responses();
        std::cout<<"PASS: 18 Lockdown framing/channel groups; synthetic service only. Channel bytes="<<sizeof(lockdown_channel)<<'\n'; return 0;
    } catch (const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
