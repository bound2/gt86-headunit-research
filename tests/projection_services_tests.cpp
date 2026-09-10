/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_socket_fixture.h"
#include "projection_command.h"
struct Service {
    projection_services s{}; projection_services_config cfg{}; projection_session_keys keys{};
    std::array<uint8_t,274> rx{},tx{}; std::array<uint8_t,256> plain{}; std::array<uint8_t,512> network{};
    Bytes message_rx=Bytes(4096),message_reply=Bytes(4096),message_commands=Bytes(4*4096);
    uint64_t now=ms; unsigned clock_calls=0;
    explicit Service(bool v6=false,SessionBackend* media=nullptr) {
        projection_services_default_config(&cfg); cfg.local=cfg.peer=loopback(v6); cfg.clock_ns=clock; cfg.clock_context=this;
        cfg.ntp_origin=UINT64_C(0x1234567800000000); cfg.event.payload_limit=256;
        if(media) { cfg.media=media->config().provider; cfg.enabled_features=15; }
        for(unsigned i=0;i<32;++i) { keys.read[i]=static_cast<uint8_t>(i); keys.write[i]=static_cast<uint8_t>(i+32); } keys.has_write=1;
    }
    ~Service() { projection_services_close(&s); }
    static uint64_t clock(void* p) { auto& f=*static_cast<Service*>(p); ++f.clock_calls; return f.now; }
    projection_services_storage storage() { return {rx.data(),plain.data(),tx.data(),network.data(),rx.size(),plain.size(),tx.size(),network.size()}; }
    void init() { auto b=storage(); CHECK(projection_services_init(&s,&cfg,&b,91)==IAP2_OK&&clock_calls==0); }
    void enable_messages() {
        projection_events_config c{}; projection_events_default_config(&c);
        projection_events_storage b{message_rx.data(),message_reply.data(),message_commands.data(),message_rx.size(),message_reply.size(),4096,message_commands.size(),4};
        auto old=snapshot(s); CHECK(projection_services_enable_events(&s,90,&c,&b)==IAP2_INVALID&&snapshot(s)==old);
        auto bad=b; bad.commands_size=0; CHECK(projection_services_enable_events(&s,91,&c,&bad)==IAP2_ARGUMENT&&snapshot(s)==old);
        CHECK(projection_services_enable_events(&s,91,&c,&b)==IAP2_OK); old=snapshot(s);
        CHECK(projection_services_enable_events(&s,91,&c,&b)==RTSP_BUSY&&snapshot(s)==old);
    }
    projection_session_endpoint open(uint16_t peer_port,bool keep=true) {
        auto p=projection_services_provider(&s); projection_session_resource q{}; q.peer_timing_port=peer_port; q.keep_alive_low_power=keep?1:0; projection_session_endpoint out{};
        CHECK(p.open(p.context,91,&q,cfg.enabled_features,&keys,&out)==IAP2_OK&&out.lease&&out.timing_port&&out.event_port&&bool(out.keep_alive_port)==keep); return out;
    }
    void poll() { CHECK(projection_services_poll(&s,91)==IAP2_OK); }
    template<class F> void until(F condition) {
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(!condition()) { CHECK(std::chrono::steady_clock::now()<deadline); poll(); if(!condition()) Sleep(1); }
    }
    void closed() {
        CHECK(s.failed&&!s.connected&&s.timing_socket==static_cast<uintptr_t>(INVALID_SOCKET)&&s.listener==static_cast<uintptr_t>(INVALID_SOCKET));
        CHECK(zeroed(rx.data(),rx.size())&&zeroed(tx.data(),tx.size())&&zeroed(plain.data(),plain.size())&&zeroed(network.data(),network.size()));
        CHECK(zeroed(s.event.read_key,32)&&zeroed(s.event.write_key,32));
        if(s.events_enabled) CHECK(s.events.dead&&zeroed(message_rx.data(),message_rx.size())&&zeroed(message_reply.data(),message_reply.size())&&zeroed(message_commands.data(),message_commands.size()));
    }
};
static Bytes frame(const uint8_t* key,uint64_t counter,const Bytes& plain) {
    Bytes b(plain.size()+18); b[0]=static_cast<uint8_t>(plain.size()); b[1]=static_cast<uint8_t>(plain.size()>>8); auto n=nonce(counter); size_t used=0;
    CHECK(pair_aead_seal(key,n.data(),b.data(),2,plain.data(),plain.size(),b.data()+2,b.size()-2,&used)==IAP2_OK&&used==b.size()-2); return b;
}
static void decrypt(const Bytes& b,const uint8_t* key,uint64_t counter,const Bytes& expected) {
    auto n=nonce(counter); Bytes out(256); size_t used=0;
    CHECK(pair_aead_open(key,n.data(),b.data(),2,b.data()+2,b.size()-2,out.data(),out.size(),&used)==IAP2_OK);
    out.resize(used); CHECK(out==expected);
}
static void configuration() {
    for(unsigned mode=0;mode<19;++mode) {
        Service f; auto b=f.storage(); auto saved=snapshot(f.s);
        if(mode==0) f.cfg.local={}; if(mode==1) f.cfg.peer.bytes[0]=224; if(mode==2) f.cfg.peer.bytes[4]=1;
        if(mode==3) f.cfg.peer.scope=1; if(mode==4) f.cfg.peer=loopback(true); if(mode==5) f.cfg.clock_ns=nullptr;
        if(mode==6) f.cfg.poll_ms=0; if(mode==7) f.cfg.poll_ms=1001; if(mode==8) f.cfg.accept_ms=60001;
        if(mode==9) f.cfg.enabled_features=1; if(mode==10) b.network_size=0; if(mode==11) b.cipher_tx_size=273;
        if(mode==12) f.cfg.media.open=SessionBackend::open; if(mode==13) f.cfg.event.payload_limit=0;
        if(mode==18) f.cfg.media.playback=SessionBackend::playback;
        if(mode>=14&&mode<=17) { f.cfg.local=f.cfg.peer=loopback(true); auto& p=f.cfg.peer;
            if(mode==14) p.bytes[15]=0; if(mode==15) p.bytes[0]=255;
            if(mode==16) { p.bytes[10]=255; p.bytes[11]=255; } if(mode==17) { p.bytes[0]=0xfe; p.bytes[1]=0x80; } }
        CHECK(projection_services_init(&f.s,&f.cfg,&b,91)==IAP2_ARGUMENT&&snapshot(f.s)==saved&&f.clock_calls==0);
    }
    Service f; f.init(); auto provider=projection_services_provider(&f.s); CHECK(!provider.playback&&provider.clock);
    projection_clock_snapshot clock{1,1,1}; auto old=snapshot(f.s);
    CHECK(provider.clock(provider.context,90,&clock)==IAP2_INVALID&&zeroed(&clock,sizeof(clock))&&snapshot(f.s)==old&&f.clock_calls==0);
    CHECK(provider.clock(provider.context,91,&clock)==IAP2_UNSUPPORTED&&snapshot(f.s)==old&&f.clock_calls==0);
    CHECK(projection_services_poll(&f.s,90)==IAP2_INVALID&&snapshot(f.s)==old&&f.clock_calls==0);
    CHECK(projection_services_poll(&f.s,91)==IAP2_MORE&&projection_services_next_delay(&f.s,91)==UINT32_MAX);
    projection_services_close(&f.s); f.network.fill(0xaa); projection_services_close(&f.s); CHECK(f.network[0]==0xaa); // Final close never revisits released storage.
}
static void sockets_and_timing(bool v6) {
    Socket phone(SOCK_DGRAM,v6),other(SOCK_DGRAM,v6); Service f(v6); f.init(); auto e=f.open(phone.port);
    for(auto handle:{f.s.timing_socket,f.s.keep_socket,f.s.listener}) { DWORD flags=0; CHECK(GetHandleInformation(reinterpret_cast<HANDLE>(handle),&flags)&&!(flags&HANDLE_FLAG_INHERIT)); }
    SOCKET collision=socket(v6?AF_INET6:AF_INET,SOCK_DGRAM,0); CHECK(collision!=INVALID_SOCKET); int n=0; auto a=address(loopback(v6),e.timing_port,n);
    int r=bind(collision,reinterpret_cast<SOCKADDR*>(&a),n); int error=WSAGetLastError(); closesocket(collision); CHECK(r==SOCKET_ERROR&&(error==WSAEACCES||error==WSAEADDRINUSE));
    CHECK(projection_services_next_delay(&f.s,91)==0); f.poll(); auto probe=phone.receive_datagram(e.timing_port);
    CHECK(probe.size()==32&&probe[0]==0x80&&probe[1]==210&&probe[3]==7&&f.s.timing.pending);
    auto response=probe; response[1]=211; std::copy(probe.begin()+24,probe.end(),response.begin()+8);
    std::copy(probe.begin()+24,probe.end(),response.begin()+16);
    other.datagram(response,e.timing_port); f.poll(); CHECK(f.s.timing.pending&&!f.s.timing.synced);
    auto huge=response; huge.resize(33); phone.datagram(huge,e.timing_port); phone.datagram({},e.timing_port); f.poll(); CHECK(f.s.timing.pending);
    f.now+=sec/8; phone.datagram(response,e.timing_port); f.until([&]{return !f.s.timing.pending;}); CHECK(f.s.timing.picks==1);
    f.now=ms+sec; f.poll(); probe=phone.receive_datagram(e.timing_port); response=probe; response[1]=211;
    std::copy(probe.begin()+24,probe.end(),response.begin()+8); std::copy(probe.begin()+24,probe.end(),response.begin()+16);
    f.now+=sec/8; phone.datagram(response,e.timing_port); f.until([&]{return f.s.timing.synced!=0;}); CHECK(f.s.timing.samples==1);
    probe[1]=210; phone.datagram(probe,e.timing_port); f.poll(); response=phone.receive_datagram(e.timing_port);
    CHECK(response[1]==211&&std::equal(probe.begin()+24,probe.end(),response.begin()+8));
    phone.datagram(bytes("ping"),e.keep_alive_port); f.until([&]{return f.s.keep_received==1;}); CHECK(!phone.ready(false,1000));
    auto p=projection_services_provider(&f.s); p.close(p.context,91,e.lease); f.closed(); CHECK(!f.s.wsa);
    // Released UDP port can be bound again; no TIME_WAIT ambiguity.
    collision=socket(v6?AF_INET6:AF_INET,SOCK_DGRAM,0); CHECK(collision!=INVALID_SOCKET); r=bind(collision,reinterpret_cast<SOCKADDR*>(&a),n); closesocket(collision); CHECK(r==0);
}
static void encrypted_events(bool v6,size_t network_limit) {
    Socket timing(SOCK_DGRAM,v6),phone(SOCK_STREAM,v6); Service f(v6); auto b=f.storage(); b.network_size=network_limit;
    CHECK(projection_services_init(&f.s,&f.cfg,&b,91)==IAP2_OK); auto e=f.open(timing.port); phone.connect_to(e.event_port); f.until([&]{return f.s.connected!=0;});
    CHECK(f.s.listener==static_cast<uintptr_t>(INVALID_SOCKET)); DWORD flags=0; CHECK(GetHandleInformation(reinterpret_cast<HANDLE>(f.s.event_socket),&flags)&&!(flags&HANDLE_FLAG_INHERIT));
    auto message=bytes("POST /feedback RTSP/1.0\r\nCSeq: 8\r\n\r\n"); auto wire=frame(f.keys.read,0,message);
    for(auto byte:wire) { phone.send_bytes(Bytes{byte}); f.poll(); } f.until([&]{return f.s.event.held!=0;});
    rtsp_slice out{}; control_cipher_key key{}; CHECK(projection_services_event_peek(&f.s,91,&out,&key)==CONTROL_CIPHER_FRAME&&Bytes(out.data,out.data+out.size)==message&&key.counter==0);
    auto saved=snapshot(f.s); auto wrong=key; ++wrong.counter;
    CHECK(projection_services_event_consume(&f.s,wrong,1,UINT64_MAX)==IAP2_INVALID&&snapshot(f.s)==saved);
    CHECK(projection_services_event_consume(&f.s,key,out.size+1,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(f.s)==saved);
    CHECK(projection_services_event_consume(&f.s,key,1,f.now)==CONTROL_CIPHER_FRAME&&f.plain[0]==0);
    auto next=frame(f.keys.read,1,{}),third=frame(f.keys.read,2,bytes("next")); next.insert(next.end(),third.begin(),third.end()); phone.send_bytes(next);
    f.poll(); CHECK(f.s.event.read_counter==1); // Held first frame prevents further reads/decrypts.
    CHECK(projection_services_event_consume(&f.s,key,message.size()-1,f.now)==IAP2_OK);
    f.until([&]{return f.s.event.held!=0;}); CHECK(projection_services_event_peek(&f.s,91,&out,&key)==CONTROL_CIPHER_FRAME&&out.size==0&&key.counter==1);
    CHECK(projection_services_event_consume(&f.s,key,0,f.now)==IAP2_OK); f.until([&]{return f.s.event.held!=0;});
    CHECK(projection_services_event_peek(&f.s,91,&out,&key)==CONTROL_CIPHER_FRAME&&out.size==4&&key.counter==2);
    CHECK(projection_services_event_consume(&f.s,key,4,f.now)==IAP2_OK);
    CHECK(projection_services_event_queue(&f.s,91,message.data(),message.size(),1,f.now)==CONTROL_CIPHER_BUSY);
    CHECK(projection_services_event_queue(&f.s,91,message.data(),message.size(),0,f.now)==CONTROL_CIPHER_OUTPUT);
    f.poll(); decrypt(phone.receive_bytes(message.size()+18),f.keys.write,0,message);
    auto p=projection_services_provider(&f.s); CHECK(p.start(p.context,91,&e.lease,1)==IAP2_OK&&f.s.started);
    CHECK(projection_services_event_queue(&f.s,91,nullptr,0,1,f.now)==CONTROL_CIPHER_OUTPUT); f.poll(); decrypt(phone.receive_bytes(18),f.keys.write,1,{});
    phone.close(); auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(!f.s.failed) { CHECK(std::chrono::steady_clock::now()<deadline); int r=projection_services_poll(&f.s,91); CHECK(r==IAP2_OK||r==PROJECTION_SERVICES_CLOSED); Sleep(1); } f.closed();
}
static void peers_and_failure_budgets() {
    { Socket timing,wrong(SOCK_STREAM,false,2),phone(SOCK_STREAM),wrong_udp(SOCK_DGRAM,false,2,timing.port); Service f; f.init(); auto e=f.open(timing.port);
      wrong.connect_to(e.event_port); f.poll(); CHECK(!f.s.connected&&f.s.opened_ns==ms);
      auto probe=timing.receive_datagram(e.timing_port); wrong_udp.datagram(probe,e.timing_port); f.poll(); CHECK(!timing.ready(false,1000)&&f.s.timing.pending);
      wrong_udp.datagram(bytes("ping"),e.keep_alive_port); f.poll(); CHECK(f.s.keep_received==0);
      phone.connect_to(e.event_port); f.until([&]{return f.s.connected!=0;}); }
    for(unsigned mode=0;mode<8;++mode) {
        Socket timing,phone(SOCK_STREAM); Service f; f.cfg.accept_ms=10; f.cfg.timing.sync_ms=100;
        f.cfg.event.receive_ms=f.cfg.event.hold_ms=f.cfg.event.output_ms=10; f.init(); auto e=f.open(timing.port);
        if(mode!=0) { phone.connect_to(e.event_port); f.until([&]{return f.s.connected!=0;}); }
        if(mode==0) f.now+=10*ms; // Exact accept deadline.
        if(mode==1) f.now+=100*ms; // No valid timing samples.
        if(mode==2) { phone.send_bytes({1}); f.until([&]{return f.s.event.rx_used!=0;}); f.now+=10*ms; }
        if(mode==3) { phone.send_bytes(frame(f.keys.read,0,bytes("held"))); f.until([&]{return f.s.event.held!=0;}); f.now+=10*ms; }
        if(mode==4) { CHECK(projection_services_event_queue(&f.s,91,nullptr,0,0,f.now)==CONTROL_CIPHER_OUTPUT); f.now+=10*ms; }
        if(mode==5) --f.now; // Backend clock regression is terminal.
        if(mode==6) { auto bad=frame(f.keys.read,0,bytes("bad")); bad.back()^=1; phone.send_bytes(bad); }
        if(mode==7) { auto replay=frame(f.keys.read,0,bytes("old")); phone.send_bytes(replay); f.until([&]{return f.s.event.held!=0;});
            rtsp_slice out{}; control_cipher_key key{}; CHECK(projection_services_event_peek(&f.s,91,&out,&key)==CONTROL_CIPHER_FRAME);
            CHECK(projection_services_event_consume(&f.s,key,out.size,f.now)==IAP2_OK); phone.send_bytes(replay); }
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(!f.s.failed) { CHECK(std::chrono::steady_clock::now()<deadline); int r=projection_services_poll(&f.s,91); CHECK(r==IAP2_OK||r==PROJECTION_SERVICES_CLOSED); if(!f.s.failed) Sleep(1); }
        f.closed(); CHECK(projection_services_poll(&f.s,91)==PROJECTION_SERVICES_CLOSED&&projection_services_next_delay(&f.s,91)==UINT32_MAX);
    }
}
static void delegated_resources() {
    for(unsigned mode=0;mode<4;++mode) {
        Socket timing; SessionBackend media; Service f(false,&media); f.init(); auto root=f.open(timing.port); auto p=projection_services_provider(&f.s);
        projection_session_resource q{}; q.type=110; projection_session_endpoint e{};
        if(mode==1) media.fail_open=1;
        int r=p.open(p.context,91,&q,15,&f.keys,&e); CHECK(r==(mode==1?-55:IAP2_OK)&&e.lease==2&&media.live==std::vector<uint64_t>{1});
        if(mode==2) { media.bad_output=6; projection_session_endpoint duplicate{}; CHECK(p.open(p.context,91,&q,15,&f.keys,&duplicate)==PROJECTION_SERVICES_CLOSED&&!duplicate.lease); }
        if(mode==3) { media.start_error=-77; uint64_t leases[]={root.lease,e.lease}; CHECK(p.start(p.context,91,leases,2)==PROJECTION_SERVICES_CLOSED); }
        p.close(p.context,91,e.lease); p.close(p.context,91,root.lease); CHECK(media.live.empty()&&media.closed==std::vector<uint64_t>{1}&&!f.s.wsa); f.closed();
    }
    Socket timing; Service f; f.init(); auto root=f.open(timing.port,false); auto p=projection_services_provider(&f.s); projection_session_resource q{}; q.type=110; projection_session_endpoint e{};
    CHECK(p.open(p.context,91,&q,0,&f.keys,&e)==IAP2_UNSUPPORTED&&!e.lease); p.close(p.context,91,root.lease);
}
static int request(Harness& h,const Bytes& body,const char* method="SETUP",const char* target="rtsp://127.0.0.1/123") {
    auto wire=outer(body,12,target,method,"application/x-apple-binary-plist"); int r=IAP2_MORE;
    for(size_t at=0;at<wire.size();) { auto end=std::min(at+256,wire.size()); r=h.feed(h.frame(Bytes(wire.begin()+at,wire.begin()+end))); at=end; if(at<wire.size()) CHECK(r==IAP2_MORE); } return r;
}
static int available(void*,uint64_t gen,const projection_info_profile*) { CHECK(gen==91); return IAP2_OK; } // Test media attestation only.
static Bytes event_response(uint32_t seq,unsigned status=200) { return bytes("RTSP/1.0 "+std::to_string(status)+" Test\r\nCSeq: "+std::to_string(seq)+"\r\nContent-Length: 0\r\n\r\n"); }
static void send_message(Socket& phone,const uint8_t* key,uint64_t& counter,const Bytes& message) {
    Bytes wire; for(size_t at=0;at<message.size();) { auto end=std::min(at+size_t(31),message.size()); auto record=frame(key,counter++,Bytes(message.begin()+at,message.begin()+end)); wire.insert(wire.end(),record.begin(),record.end()); at=end; }
    phone.send_bytes(wire);
}
static Bytes read_message(Socket& phone,const uint8_t* key,uint64_t& counter) {
    Bytes message; rtsp_message parsed{}; size_t used=0;
    while(rtsp_message_decode(message.data(),message.size(),&parsed,&used)==IAP2_MORE) {
        auto head=phone.receive_bytes(2); size_t size=head[0]+256u*head[1]; CHECK(size<=256);
        auto encrypted=phone.receive_bytes(size+16); auto n=nonce(counter++); Bytes plain(size); size_t decoded=0;
        CHECK(pair_aead_open(key,n.data(),head.data(),2,encrypted.data(),encrypted.size(),plain.data(),plain.size(),&decoded)==IAP2_OK&&decoded==size);
        message.insert(message.end(),plain.begin(),plain.end());
    }
    CHECK(rtsp_message_decode(message.data(),message.size(),&parsed,&used)==IAP2_OK&&used==message.size()); return message;
}
template<class F> static void receiver_until(Harness& h,F condition) {
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(!condition()) { CHECK(std::chrono::steady_clock::now()<deadline); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK); if(!condition()) Sleep(1); }
}
static void event_commands(Harness& h,Service& f,Socket& phone,const projection_info_profile& profile,const uint8_t* read_key,const uint8_t* write_key,uint64_t& incoming,uint64_t& outgoing,unsigned mode) {
    Bytes down(256),up(256); size_t a=0,b=0; projection_command d{PROJECTION_COMMAND_SIRI,{},{},2},u{PROJECTION_COMMAND_SIRI,{},{},3};
    CHECK(projection_command_encode(&profile,15,&d,down.data(),down.size(),&a)==IAP2_OK); down.resize(a);
    CHECK(projection_command_encode(&profile,15,&u,up.data(),up.size(),&b)==IAP2_OK); up.resize(b);
    rtsp_slice bodies[]={{down.data(),down.size()},{up.data(),up.size()}}; rtsp_channel_key keys[2]{};
    auto old=snapshot(f.s); CHECK(projection_services_commands(&f.s,90,bodies,2,keys,UINT64_MAX)==IAP2_INVALID&&snapshot(f.s)==old);
    CHECK(projection_services_commands(&f.s,91,bodies,2,keys,f.now)==PROJECTION_EVENTS_OUTPUT);
    receiver_until(h,[&]{return f.s.events.slots[1].phase==PROJECTION_EVENT_WAITING;});
    for(unsigned i=0;i<2;++i) { auto wire=read_message(phone,write_key,outgoing); rtsp_message m{}; size_t n=0;
        CHECK(rtsp_message_decode(wire.data(),wire.size(),&m,&n)==IAP2_OK&&m.cseq==i+1&&m.kind==RTSP_REQUEST&&m.target.size==8);
        CHECK(Bytes(m.body.data,m.body.data+m.body.size)==(i?up:down)); }
    if(mode==5) { f.now+=5000*ms; CHECK(projection_receiver_poll(&h.s,91,1)==PROJECTION_RECEIVER_CLOSED); return; }
    if(mode==6) { send_message(phone,read_key,incoming,event_response(999));
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(!f.s.failed) { CHECK(std::chrono::steady_clock::now()<deadline); int r=projection_receiver_poll(&h.s,91,1); CHECK(r==IAP2_OK||r==PROJECTION_RECEIVER_CLOSED); } return; }
    auto peer_request=bytes("POST /unknown HTTP/1.1\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n");
    if(mode==7) {
        for(unsigned seq=1;seq<=2;++seq) { send_message(phone,read_key,incoming,event_response(seq)); receiver_until(h,[&]{return f.s.events.held==2;});
            rtsp_message m{}; rtsp_channel_key k{}; CHECK(projection_services_message(&f.s,91,&m,&k)==PROJECTION_EVENTS_RESPONSE); CHECK(projection_services_release(&f.s,k,f.now)==IAP2_OK); }
        send_message(phone,read_key,incoming,peer_request); receiver_until(h,[&]{return f.s.events.held==1;}); f.now+=5000*ms;
        CHECK(projection_receiver_poll(&h.s,91,1)==PROJECTION_RECEIVER_CLOSED); return; }
    auto combined=event_response(2,503),first=event_response(1); combined.insert(combined.end(),peer_request.begin(),peer_request.end()); combined.insert(combined.end(),first.begin(),first.end());
    send_message(phone,read_key,incoming,combined); receiver_until(h,[&]{return f.s.events.held==2;});
    rtsp_message message{}; rtsp_channel_key key{}; CHECK(projection_services_message(&f.s,91,&message,&key)==PROJECTION_EVENTS_RESPONSE&&message.status==503&&message.cseq==2&&key.token==keys[1].token);
    old=snapshot(f.s); CHECK(projection_services_release(&f.s,{91,key.token+99},UINT64_MAX)==IAP2_INVALID&&snapshot(f.s)==old);
    CHECK(projection_services_release(&f.s,key,f.now)==IAP2_OK); receiver_until(h,[&]{return f.s.events.held==1;});
    CHECK(projection_services_message(&f.s,91,&message,&key)==PROJECTION_EVENTS_REQUEST&&message.cseq==1);
    rtsp_response reply{404,{},nullptr,0,{}}; CHECK(projection_services_respond(&f.s,key,&reply,f.now)==PROJECTION_EVENTS_OUTPUT);
    receiver_until(h,[&]{return f.s.events.held==2;}); CHECK(projection_services_message(&f.s,91,&message,&key)==PROJECTION_EVENTS_RESPONSE&&key.token==keys[0].token&&message.status==200);
    CHECK(projection_services_release(&f.s,key,f.now)==IAP2_OK); receiver_until(h,[&]{return f.s.events.reply.phase==0;});
    auto wire=read_message(phone,write_key,outgoing); size_t n=0; CHECK(rtsp_message_decode(wire.data(),wire.size(),&message,&n)==IAP2_OK&&message.status==404&&message.cseq==1&&message.protocol==RTSP_HTTP_11);
}
static void receiver_integration(const Vectors& v,const Vectors& setup,const Vectors& sv) {
    for(unsigned mode=0;mode<9;++mode) {
        bool v6=mode==8; Socket timing(SOCK_DGRAM,v6),phone(SOCK_STREAM,v6); SessionBackend media; Service f(v6,&media);
        f.cfg.media.poll=SessionBackend::poll; f.cfg.media.next_delay=SessionBackend::next_delay;
        if(mode>=4) f.cfg.event.payload_limit=64; // Outgoing commands span multiple encrypted records.
        f.init(); if(mode>=4) f.enable_messages(); auto profile=session_profile(); Bytes info_scratch(PROJECTION_INFO_LIMIT);
        Harness h(v,setup); projection_receiver_info_config info{}; projection_receiver_info_default_config(&info);
        info.profile=&profile; info.available=available; info.buffer=info_scratch.data(); info.capacity=info_scratch.size();
        CHECK(projection_receiver_enable_info(&h.s,91,&info,0)==IAP2_OK);
        projection_session_config config{projection_services_provider(&f.s),15,0}; auto invalid=config; invalid.provider.next_delay=nullptr; auto old=snapshot(h.s);
        CHECK(projection_receiver_enable_session(&h.s,91,&invalid,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(h.s)==old);
        CHECK(projection_receiver_enable_session(&h.s,91,&config,0)==IAP2_OK); h.pair();
        CHECK(h.feed(h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT); h.drain(true,MFI_SAP_DRAINED);
        auto body=sv.at("session"); const Bytes encoded_port={0x11,0x69,0x79}; // Fixture's unique BE16 integer27001, not an arbitrary plist search in production.
        auto pos=std::search(body.begin(),body.end(),encoded_port.begin(),encoded_port.end()); CHECK(pos!=body.end()); pos[1]=static_cast<uint8_t>(timing.port>>8); pos[2]=static_cast<uint8_t>(timing.port);
        CHECK(request(h,body)==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK); CHECK(f.s.event_lease&&h.s.session.count==1);
        auto endpoint=h.s.session.slots[0].endpoint; phone.connect_to(endpoint.event_port);
        auto saved=snapshot(f.s); auto calls=f.clock_calls; CHECK(projection_receiver_poll(&h.s,90,UINT64_MAX)==IAP2_INVALID&&snapshot(f.s)==saved&&f.clock_calls==calls);
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(!f.s.connected) { CHECK(std::chrono::steady_clock::now()<deadline); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK); }
        CHECK(projection_receiver_next_delay(&h.s)<=5);
        uint8_t key[32]{}; auto salt=bytes("Events-Salt"),label=bytes("Events-Read-Encryption-Key");
        CHECK(pair_hkdf_sha512(v.at("pv_shared_secret").data(),32,salt.data(),salt.size(),label.data(),label.size(),key,32)==IAP2_OK);
        uint64_t incoming=0,outgoing=0; uint8_t write_key[32]{}; label=bytes("Events-Write-Encryption-Key");
        CHECK(pair_hkdf_sha512(v.at("pv_shared_secret").data(),32,salt.data(),salt.size(),label.data(),label.size(),write_key,32)==IAP2_OK);
        if(mode<4) {
            phone.send_bytes(frame(key,0,bytes("authenticated event")));
            while(!f.s.event.held) { CHECK(std::chrono::steady_clock::now()<deadline); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK); }
            rtsp_slice out{}; control_cipher_key token{}; CHECK(projection_services_event_peek(&f.s,91,&out,&token)==CONTROL_CIPHER_FRAME&&out.size==19);
            CHECK(projection_services_event_consume(&f.s,token,out.size,f.now)==IAP2_OK);
        } else {
            rtsp_slice out{}; control_cipher_key raw{}; CHECK(projection_services_event_peek(&f.s,91,&out,&raw)==IAP2_UNSUPPORTED);
            CHECK(projection_services_event_queue(&f.s,91,nullptr,0,0,f.now)==IAP2_UNSUPPORTED);
            send_message(phone,key,incoming,bytes("POST /unknown RTSP/1.0\r\nCSeq: 19\r\n\r\n")); receiver_until(h,[&]{return f.s.events.held==1;});
            rtsp_message message{}; rtsp_channel_key token{}; CHECK(projection_services_message(&f.s,91,&message,&token)==PROJECTION_EVENTS_REQUEST&&!f.s.started);
            rtsp_response reply{501,{},nullptr,0,{}}; CHECK(projection_services_respond(&f.s,token,&reply,f.now)==PROJECTION_EVENTS_OUTPUT);
            receiver_until(h,[&]{return f.s.events.reply.phase==0;}); auto wire=read_message(phone,write_key,outgoing); size_t n=0;
            CHECK(rtsp_message_decode(wire.data(),wire.size(),&message,&n)==IAP2_OK&&message.status==501&&message.cseq==19);
        }
        CHECK(request(h,sv.at("streams"))==RTSP_CHANNEL_OUTPUT&&media.opens==6); h.drain(true,IAP2_OK);
        CHECK(projection_receiver_next_delay(&h.s)==2&&projection_receiver_poll(&h.s,91,1)==IAP2_OK&&media.polls==1);
        CHECK(request(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT&&!f.s.started&&media.starts==0);
        if(mode<4) CHECK(projection_services_event_queue(&f.s,91,nullptr,0,1,f.now)==CONTROL_CIPHER_BUSY);
        else { const auto dummy=bytes("bplist00"); rtsp_slice b{dummy.data(),dummy.size()}; rtsp_channel_key token{};
            CHECK(projection_services_commands(&f.s,91,&b,1,&token,f.now)==RTSP_BUSY); }
        h.drain(true,IAP2_OK); CHECK(f.s.started&&media.starts==1);
        if(mode>=4) { CHECK(f.s.events.started); event_commands(h,f,phone,profile,key,write_key,incoming,outgoing,mode);
            if(mode==4||mode==8) { CHECK(request(h,{},"TEARDOWN")==RTSP_CHANNEL_OUTPUT); h.drain(true,PROJECTION_RECEIVER_CLOSED); } }
        if(mode==0) { CHECK(request(h,sv.at("teardown_audio"),"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&media.closed.size()==1); h.drain(true,IAP2_OK);
            CHECK(request(h,{},"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&media.live.empty()); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_MORE); h.drain(true,PROJECTION_RECEIVER_CLOSED); }
        if(mode==1) { f.now+=30000*ms; CHECK(projection_receiver_poll(&h.s,91,1)==PROJECTION_RECEIVER_CLOSED); }
        if(mode==2) { calls=f.clock_calls; CHECK(projection_receiver_poll(&h.s,91,30001)==PROJECTION_RECEIVER_CLOSED&&f.clock_calls==calls); }
        if(mode==3) { media.poll_error=-55; CHECK(projection_receiver_poll(&h.s,91,1)==PROJECTION_RECEIVER_CLOSED&&media.polls==2); }
        CHECK(media.live.empty()&&media.closed.size()==6); f.closed(); h.cleared();
    }
}
static void feedback_integration(const Vectors& v,const Vectors& setup,const Vectors& sv) {
    for(unsigned mode=0;mode<8;++mode) {
        bool v6=mode==1; Socket timing(SOCK_DGRAM,v6),phone(SOCK_STREAM,v6); SessionBackend media; Service f(v6,&media);
        f.cfg.media.playback=SessionBackend::playback; f.cfg.media.clock=SessionBackend::clock; f.init();
        auto profile=session_profile(); Bytes scratch(PROJECTION_INFO_LIMIT); Harness h(v,setup);
        projection_receiver_info_config info{}; projection_receiver_info_default_config(&info);
        info.profile=&profile; info.available=available; info.buffer=scratch.data(); info.capacity=scratch.size();
        CHECK(projection_receiver_enable_info(&h.s,91,&info,0)==IAP2_OK);
        projection_session_config config{projection_services_provider(&f.s),15,1000};
        CHECK(config.provider.playback&&config.provider.clock&&projection_receiver_enable_session(&h.s,91,&config,0)==IAP2_OK);
        h.pair(); CHECK(h.feed(h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT); h.drain(true,MFI_SAP_DRAINED);
        auto body=sv.at("session"); const Bytes encoded_port={0x11,0x69,0x79}; auto pos=std::search(body.begin(),body.end(),encoded_port.begin(),encoded_port.end());
        CHECK(pos!=body.end()); pos[1]=static_cast<uint8_t>(timing.port>>8); pos[2]=static_cast<uint8_t>(timing.port);
        CHECK(request(h,body)==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        CHECK(request(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT&&feedback_response(h.drain(true,IAP2_OK),12).empty()&&media.playback_calls==0);
        auto endpoint=h.s.session.slots[0].endpoint; phone.connect_to(endpoint.event_port); receiver_until(h,[&]{return f.s.connected!=0;});
        CHECK(request(h,sv.at("streams"))==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        auto p=projection_services_provider(&f.s); projection_playback_position observed{}; auto saved=snapshot(f.s); auto calls=f.clock_calls;
        CHECK(p.playback(p.context,90,4,&observed)==IAP2_INVALID&&snapshot(f.s)==saved&&f.clock_calls==calls);
        for(uint64_t invalid:{UINT64_C(0),endpoint.lease,UINT64_C(2),UINT64_C(999)})
            CHECK(p.playback(p.context,91,invalid,&observed)==IAP2_INVALID&&snapshot(f.s)==saved&&f.clock_calls==calls);
        CHECK(request(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); auto values=feedback_response(h.drain(true,IAP2_OK),12);
        for(const auto& entry:values) CHECK(entry.size()==2); CHECK(media.observed_leases==std::vector<uint64_t>({3,4,5})&&media.clock_calls==0);
        CHECK(request(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        CHECK(request(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); values=feedback_response(h.drain(true,IAP2_OK),12);
        for(const auto& entry:values) CHECK(entry.size()==2); CHECK(!f.s.timing.synced); // RECORD/socket sends do not create a clock or position.
        for(unsigned i=0;i<2;++i) {
            if(i) { f.now=ms+sec; CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK); }
            auto probe=timing.receive_datagram(endpoint.timing_port),response=probe; CHECK(probe[1]==210); response[1]=211;
            std::copy(probe.begin()+24,probe.end(),response.begin()+8); std::copy(probe.begin()+24,probe.end(),response.begin()+16);
            f.now+=sec/8; timing.datagram(response,endpoint.timing_port); receiver_until(h,[&]{return !f.s.timing.pending;});
        }
        CHECK(f.s.timing.synced&&f.s.timing.samples==1); media.position.raw_ns=f.now-sec/8;
        auto expected=projection_timing_now(&f.s.timing,f.now)-UINT64_C(0x20000000);
        CHECK(request(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); values=feedback_response(h.drain(true,IAP2_OK),12);
        for(const auto& entry:values) CHECK(entry.size()==6&&entry.at("timestamp")==expected&&entry.at("timestampRawNs")==media.position.raw_ns&&entry.at("sampleTime")==UINT32_MAX);
        CHECK(media.clock_calls==0); // Root uses real timing samples, never the delegate's synthetic clock.
        if(mode>=2&&mode<=6) {
            if(mode==2) media.playback_error=-55; if(mode==3) media.position.raw_ns=f.now+1;
            if(mode==4) media.position.raw_ns=0; if(mode==5) f.now+=30000*ms; if(mode==6) --f.now;
            CHECK(request(h,{},"POST","/feedback")==PROJECTION_RECEIVER_CLOSED&&media.live.empty()); f.closed(); h.cleared(); continue;
        }
        CHECK(request(h,sv.at("teardown_audio"),"TEARDOWN")==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        CHECK(request(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); values=feedback_response(h.drain(true,IAP2_OK),12);
        CHECK(values.size()==2&&values[0].at("type")==101);
        auto before=media.playback_calls; CHECK(p.playback(p.context,91,4,&observed)==IAP2_INVALID&&media.playback_calls==before);
        CHECK(request(h,sv.at("audio_new"))==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        if(mode==7) { // An otherwise fresh observation predates this replacement lease.
            CHECK(request(h,{},"POST","/feedback")==PROJECTION_RECEIVER_CLOSED&&media.live.empty()); f.closed(); h.cleared(); continue;
        }
        media.position.raw_ns=f.now; media.position.sample_time=0;
        CHECK(request(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); values=feedback_response(h.drain(true,IAP2_OK),12);
        CHECK(values.size()==3&&values.back().at("streamConnectionID")==UINT64_MAX&&media.observed_leases.back()==7);
        CHECK(request(h,{},"TEARDOWN")==RTSP_CHANNEL_OUTPUT); h.drain(true,PROJECTION_RECEIVER_CLOSED); CHECK(media.live.empty()); f.closed(); h.cleared();
    }
}
int main(int argc,char** argv) {
    try { CHECK(argc==4); Winsock wsa; auto v=load_vectors(argv[1],39),setup=load_vectors(argv[2],51),sv=load_vectors(argv[3],42);
        configuration(); sockets_and_timing(false); sockets_and_timing(true); encrypted_events(false,512); encrypted_events(true,7);
        peers_and_failure_budgets(); delegated_resources(); receiver_integration(v,setup,sv); feedback_integration(v,setup,sv);
        std::cout<<"PASS: 9 service groups; real IPv4/IPv6 loopback timing/events, encrypted records, lifecycle/deadlines and paired/MFi observed feedback integration\n";
        std::cout<<"Synthetic credentials/MFi/media only; no phone, target, USB or firmware operation; service bytes: "<<sizeof(projection_services)<<'\n'; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
