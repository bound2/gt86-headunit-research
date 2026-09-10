/* SPDX-License-Identifier: GPL-3.0-only; real loopback UDP, synthetic sinks only. */
#include "projection_socket_fixture.h"
#include "projection_audio_services.h"
#include "projection_audio_fixture.h"
#include "projection_sync_fixture.h"
#include "projection_pcm_output.hpp"
#include <memory>
struct Sink {
    struct Seen { uint64_t child,counter; uint32_t sample,frames; Bytes data; };
    uint64_t next=1; unsigned opens=0,starts=0,submits=0,polls=0,observations=0; int failure=0; bool busy=false;
    std::map<uint64_t,projection_audio_format> live; std::vector<uint64_t> closed; std::vector<Seen> seen;
    projection_playback_position position{};
    std::vector<projection_audio_anchor> anchors; int anchor_result=IAP2_OK;
    unsigned start_failure_at=0;
    projection_audio_sink provider() { return {this,open,start,submit,poll,playback,close}; }
    static int open(void* p,uint64_t gen,const projection_session_resource* q,const projection_audio_format* f,uint64_t* lease) {
        auto& s=*static_cast<Sink*>(p); CHECK(gen==91&&q->audio_format==f->bit); ++s.opens;
        if(s.failure==1) return -55;
        *lease=s.next++; s.live.emplace(*lease,*f); return s.failure==2?-55:IAP2_OK;
    }
    static int start(void* p,uint64_t gen,uint64_t lease) { auto& s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.contains(lease)); ++s.starts; return s.failure==3||s.starts==s.start_failure_at?-55:IAP2_OK; }
    static int submit(void* p,uint64_t gen,uint64_t lease,const projection_audio_format* f,const projection_audio_packet* packet) {
        auto& s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.contains(lease)&&s.starts); ++s.submits;
        if(s.failure==4) return -55; if(s.busy) return IAP2_MORE;
        Bytes data(packet->size);
        if(f->codec==PROJECTION_AUDIO_PCM16&&packet->size) { size_t used=0; CHECK(projection_audio_pcm16le(f,packet->data,packet->size,data.data(),data.size(),&used)==IAP2_OK&&used==data.size()); }
        else data.assign(packet->data,packet->data+packet->size); // Opaque compressed transport test, NOT a decoder.
        s.seen.push_back({lease,packet->counter,packet->sample_time,packet->frames,data}); return IAP2_OK;
    }
    static int poll(void* p,uint64_t gen,uint64_t lease,uint64_t) { auto& s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.contains(lease)); ++s.polls; return s.failure==5?-55:IAP2_OK; }
    static int playback(void* p,uint64_t gen,uint64_t lease,projection_playback_position* out) {
        auto& s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.contains(lease)); ++s.observations;
        *out=s.position; out->sample_rate=s.live.at(lease).clock_rate; if(s.failure==7) ++out->sample_rate; return s.failure==6?-55:IAP2_OK;
    }
    static void close(void* p,uint64_t gen,uint64_t lease) { auto& s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.erase(lease)==1); s.closed.push_back(lease); }
    static int anchor(void* p,uint64_t gen,uint64_t lease,const projection_audio_anchor* a) {
        auto& s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.contains(lease)); s.anchors.push_back(*a); return s.anchor_result;
    }
};
struct AudioService {
    Sink sink; projection_audio_services s{}; projection_audio_services_config cfg{};
    Bytes storage=Bytes(3*4*256+1,0xaa),network=Bytes(256+36+1,0xaa); uint64_t now=ms; unsigned clocks=0;
    explicit AudioService(bool v6=false,bool initialize=true) {
        cfg.local=cfg.peer=loopback(v6); cfg.clock_ns=clock; cfg.clock_context=this; cfg.poll_ms=2; cfg.sink=sink.provider();
        projection_audio_default_config(&cfg.audio); cfg.audio.slots=4; cfg.audio.payload_capacity=256; cfg.audio.reorder_ms=10;
        if(initialize) init();
    }
    ~AudioService() { projection_audio_services_close(&s); }
    static uint64_t clock(void* p) { auto& s=*static_cast<AudioService*>(p); ++s.clocks; return s.now; }
    void init() { CHECK(projection_audio_services_init(&s,&cfg,storage.data(),storage.size(),network.data(),network.size(),91)==IAP2_OK&&clocks==0); }
    projection_session_endpoint open(unsigned type=100,uint32_t format=16) {
        projection_session_resource q{}; q.type=type; q.audio_format=format; q.audio_type=PROJECTION_AUDIO_MEDIA;
        projection_session_keys keys{}; std::fill(keys.read,keys.read+32,9); auto p=projection_audio_services_provider(&s); projection_session_endpoint e{};
        CHECK(p.open(p.context,91,&q,0,&keys,&e)==IAP2_OK&&e.lease&&e.data_port&&e.control_port&&!e.event_port); return e;
    }
    void start(uint64_t lease) { auto p=projection_audio_services_provider(&s); CHECK(p.start(p.context,91,&lease,1)==IAP2_OK); }
    void poll() { CHECK(projection_audio_services_poll(&s,91)==IAP2_OK); }
    template<class F> void until(F condition) {
        auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(!condition()) { CHECK(std::chrono::steady_clock::now()<end); poll(); if(!condition()) Sleep(1); }
    }
    void closed() { CHECK(s.failed&&sink.live.empty()&&!s.count&&!s.wsa&&zeroed(network.data(),network.size()-1)&&network.back()==0xaa);
        for(auto& slot:s.slots) CHECK(!slot.occupied&&zeroed(slot.audio.key,32)&&slot.data_socket==static_cast<uintptr_t>(INVALID_SOCKET)); }
};
static void configuration() {
    for(unsigned mode=0;mode<18;++mode) { AudioService f(false,false); auto old=snapshot(f.s); auto memory=f.storage,network=f.network;
        if(mode==0) f.cfg.local={}; if(mode==1) f.cfg.peer.bytes[0]=224; if(mode==2) f.cfg.peer.scope=1; if(mode==3) f.cfg.peer=loopback(true);
        if(mode==4) f.cfg.clock_ns=nullptr; if(mode==5) f.cfg.poll_ms=0; if(mode==6) f.cfg.audio.slots=65;
        if(mode==7) f.cfg.audio.payload_capacity=8193; if(mode==8) f.cfg.audio.hold_ms=0; if(mode==9) f.cfg.audio.reorder_ms=1001;
        if(mode==10) f.cfg.sink.open=nullptr; if(mode==11) f.cfg.sink.submit=nullptr; if(mode==12) f.cfg.sink.start=nullptr;
        if(mode==13) f.cfg.sink.poll=nullptr; if(mode==14) f.cfg.sink.playback=nullptr; if(mode==15) f.cfg.sink.close=nullptr;
        int r=projection_audio_services_init(&f.s,&f.cfg,f.storage.data(),mode==16?1:f.storage.size(),f.network.data(),mode==17?1:f.network.size(),91);
        CHECK(r==(mode>=16?IAP2_NO_SPACE:IAP2_ARGUMENT)&&snapshot(f.s)==old&&f.storage==memory&&f.network==network&&f.clocks==0&&f.sink.opens==0);
    }
    { AudioService f; auto p=projection_audio_services_provider(&f.s); auto old=snapshot(f.s); projection_session_keys keys{}; projection_session_resource q{}; projection_session_endpoint e{};
      for(unsigned mode=0;mode<4;++mode) { q.type=mode==0?110:100; q.audio_format=mode==1?4096:16; q.peer_data_port=mode==2?123:0; keys.has_write=mode==3?1:0;
          CHECK(p.open(p.context,91,&q,0,&keys,&e)==IAP2_UNSUPPORTED&&!e.lease&&snapshot(f.s)==old&&f.sink.opens==0); }
      CHECK(projection_audio_services_poll(&f.s,90)==IAP2_INVALID&&snapshot(f.s)==old&&f.clocks==0);
      CHECK(projection_audio_services_poll(&f.s,91)==IAP2_MORE&&projection_audio_services_next_delay(&f.s,91)==UINT32_MAX);
      projection_audio_services_close(&f.s); f.storage[0]=0xab; projection_audio_services_close(&f.s); CHECK(f.storage[0]==0xab); }
}
static void datagrams(bool v6,const Vectors& v) {
    AudioService f(v6); Socket phone(SOCK_DGRAM,v6),other(SOCK_DGRAM,v6); auto e=f.open();
    for(auto handle:{f.s.slots[0].data_socket,f.s.slots[0].control_socket}) { DWORD flags=0; CHECK(GetHandleInformation(reinterpret_cast<HANDLE>(handle),&flags)&&!(flags&HANDLE_FLAG_INHERIT)); }
    auto packet=audio_packet(v.at("key").data(),0,UINT32_MAX,v.at("pcm_plain")); auto bad=packet; bad.back()^=1;
    if(!v6) { Socket foreign(SOCK_DGRAM,false,2); foreign.datagram(packet,e.data_port); f.poll(); CHECK(!f.s.slots[0].peer_port&&!f.s.slots[0].audio.count); }
    other.datagram(bad,e.data_port); f.poll(); CHECK(!f.s.slots[0].peer_port&&!f.s.slots[0].audio.count);
    auto huge=packet; huge.resize(f.network.size()+1); phone.datagram(huge,e.data_port); f.poll(); CHECK(!f.s.slots[0].peer_port&&zeroed(f.network.data(),f.network.size()-1));
    phone.datagram(packet,e.data_port); f.until([&]{return f.s.slots[0].audio.count==1;}); CHECK(f.s.slots[0].peer_port==phone.port&&f.sink.submits==0&&f.sink.polls==0);
    other.datagram(audio_packet(v.at("key").data(),1,3,v.at("pcm_plain")),e.data_port); f.poll(); CHECK(f.s.slots[0].audio.count==1);
    f.start(e.lease); f.now+=10*ms; f.until([&]{return f.sink.seen.size()==1;});
    CHECK(f.sink.seen[0].data==hex("008000000100ff7f")&&f.sink.seen[0].sample==UINT32_MAX&&f.sink.seen[0].frames==4);
    auto p=projection_audio_services_provider(&f.s); projection_playback_position position{};
    CHECK(p.playback(p.context,91,e.lease,&position)==IAP2_OK&&position.sample_rate==16000&&!position.has_position); // Packet submission never reports playback.
    f.sink.position={f.now,123,16000,1}; CHECK(p.playback(p.context,91,e.lease,&position)==IAP2_OK&&position.sample_time==123);
    auto saved=snapshot(f.s); CHECK(p.playback(p.context,92,e.lease,&position)==IAP2_INVALID&&snapshot(f.s)==saved);
    phone.datagram(bytes("unimplemented control"),e.control_port); f.until([&]{return f.s.slots[0].control_received==1;}); CHECK(!phone.ready(false,1000));
    p.close(p.context,91,e.lease); CHECK(f.sink.closed==std::vector<uint64_t>{1}&&!f.s.count&&!f.s.wsa);
    Socket reuse(SOCK_DGRAM,v6,1,e.data_port); // Actual port released, not only logical lease.
    projection_audio_services_close(&f.s); f.closed(); CHECK(zeroed(f.storage.data(),f.storage.size()-1)&&f.storage.back()==0xaa);
}
static void sender_sync(bool v6) {
    for(unsigned mode=0;mode<7;++mode) {
        AudioService f(v6,false); projection_timing timing{}; f.cfg.timing=&timing; f.cfg.sync_ms=500; f.cfg.max_sync_latency_ms=1000; f.cfg.sink.anchor=Sink::anchor;
        if(mode==0) f.cfg.sync_ms=0; if(mode==1) f.cfg.sync_ms=5001; if(mode==2) f.cfg.max_sync_latency_ms=0;
        if(mode==3) f.cfg.max_sync_latency_ms=60001; if(mode==4) f.cfg.timing=nullptr; if(mode==5) f.cfg.sink.anchor=nullptr;
        if(mode==6) { f.cfg.timing=nullptr; f.cfg.sync_ms=0; }
        auto before=snapshot(f.s); auto storage=f.storage,network=f.network;
        CHECK(projection_audio_services_init(&f.s,&f.cfg,f.storage.data(),f.storage.size(),f.network.data(),f.network.size(),91)==IAP2_ARGUMENT);
        CHECK(snapshot(f.s)==before&&storage==f.storage&&network==f.network&&!f.clocks);
    }
    AudioService f(v6,false); projection_timing timing{}; f.cfg.timing=&timing; f.cfg.sync_ms=500; f.cfg.max_sync_latency_ms=1000; f.cfg.sink.anchor=Sink::anchor; f.init();
    auto e=f.open(); Socket phone(SOCK_DGRAM,v6),other(SOCK_DGRAM,v6); auto& slot=f.s.slots[0];
    auto send=[&](Socket& peer,const Bytes& packet) { auto n=slot.control_received; peer.datagram(packet,e.control_port); f.until([&]{return slot.control_received==n+1;}); };
    send(other,audio_sync_packet(0,0,0)); CHECK(!slot.sync_port&&f.sink.anchors.empty()); // Unsynchronized root cannot anchor or pin.
    audio_sync_clock(timing,f.now);
    uint32_t sender=UINT32_MAX-10,play=sender-1600; auto ntp=projection_timing_now(&timing,f.now); auto valid=audio_sync_packet(ntp,play,sender);
    if(!v6) { Socket foreign(SOCK_DGRAM,false,2); foreign.datagram(valid,e.control_port); f.poll(); CHECK(!slot.sync_port&&f.sink.anchors.empty()); }
    auto bad=valid; bad[3]=7; send(other,bad); send(other,audio_sync_packet(ntp,0,16001));
    send(other,audio_sync_packet(ntp+(UINT64_C(1)<<32),play,sender)); CHECK(!slot.sync_port&&f.sink.anchors.empty());
    send(phone,valid); CHECK(slot.sync_port==phone.port&&slot.sync_received==1&&f.sink.anchors.size()==1);
    CHECK(f.sink.anchors.back().local_ns==f.now&&f.sink.anchors.back().received_ns==f.now&&f.sink.anchors.back().sample_time==play);
    CHECK(!slot.peer_port&&!slot.audio.received&&!f.sink.starts); // Control anchor is not authenticated media or playback authorization.
    send(phone,valid); ++f.now; ntp=projection_timing_now(&timing,f.now);
    send(phone,audio_sync_packet(ntp,play-1,sender-1)); send(other,audio_sync_packet(ntp,play+1,sender+1));
    CHECK(slot.sync_received==1&&f.sink.anchors.size()==1);
    f.sink.anchor_result=IAP2_MORE; send(phone,audio_sync_packet(ntp,play+32,sender+32)); // Modulo32 wrap; ignored child anchor isn't an error.
    CHECK(slot.sync_received==2&&f.sink.anchors.size()==2&&!f.s.failed);
    f.now=timing.last_sync_ns+uint64_t(timing.config.sync_ms)*ms;
    send(phone,audio_sync_packet(projection_timing_now(&timing,f.now),play+64,sender+64));
    CHECK(slot.sync_received==2&&timing.active); // Inverse is read-only at exact freshness expiry.
    projection_timing_close(&timing); audio_sync_clock(timing,f.now); f.sink.anchor_result=IAP2_PROVIDER_FAILED;
    // The new synthetic root epoch is older than the retained anchor: still a drop.
    send(phone,audio_sync_packet(projection_timing_now(&timing,f.now),play+64,sender+64)); CHECK(!f.s.failed);
    f.now+=ms;
    phone.datagram(audio_sync_packet(projection_timing_now(&timing,f.now),play+64,sender+64),e.control_port);
    int r=IAP2_OK; auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(r==IAP2_OK) { CHECK(std::chrono::steady_clock::now()<end); r=projection_audio_services_poll(&f.s,91); }
    CHECK(r==PROJECTION_AUDIO_CLOSED); f.closed();
}
static void backpressure_and_failure(const Vectors& v) {
    for(int failure=1;failure<=9;++failure) { AudioService f; f.sink.failure=failure;
        if(failure<=2) { auto p=projection_audio_services_provider(&f.s); projection_session_resource q{}; q.type=100; q.audio_format=16; projection_session_keys keys{}; projection_session_endpoint e{};
            CHECK(p.open(p.context,91,&q,0,&keys,&e)==PROJECTION_AUDIO_CLOSED&&!e.lease); f.closed(); CHECK(f.sink.closed.size()==(failure==2?1u:0u)); continue; }
        auto e=f.open(); auto p=projection_audio_services_provider(&f.s);
        if(failure==3) { CHECK(p.start(p.context,91,&e.lease,1)==PROJECTION_AUDIO_CLOSED); f.closed(); continue; }
        f.start(e.lease);
        if(failure==4||failure==5) { Socket phone; phone.datagram(audio_packet(v.at("key").data(),0,0,{1,2}),e.data_port);
            if(failure==4) { f.poll(); f.now+=10*ms; } CHECK(projection_audio_services_poll(&f.s,91)==PROJECTION_AUDIO_CLOSED); }
        else { if(failure==8) f.sink.position={f.now+1,0,16000,1}; if(failure==9) f.sink.position={0,0,16000,1}; projection_playback_position position{};
            CHECK(p.playback(p.context,91,e.lease,&position)==PROJECTION_AUDIO_CLOSED&&zeroed(&position,sizeof(position))); }
        f.closed(); CHECK(f.sink.closed==std::vector<uint64_t>{1});
    }
    { AudioService f; Socket phone; auto e=f.open(); f.start(e.lease); f.sink.busy=true;
      for(unsigned i=0;i<4;++i) phone.datagram(audio_packet(v.at("key").data(),i,i*4,{1,2}),e.data_port);
      f.until([&]{return f.s.slots[0].audio.count==4;}); f.now+=10*ms; f.poll(); CHECK(f.s.slots[0].audio.held&&f.sink.seen.empty());
      f.now+=999*ms; f.poll(); CHECK(f.s.slots[0].audio.count==4); f.sink.busy=false; f.poll();
      CHECK(f.sink.seen.size()==1&&f.sink.seen[0].counter==0); f.until([&]{return f.sink.seen.size()==4;}); }
    { AudioService f; Socket phone; auto e=f.open(); f.start(e.lease); f.sink.busy=true;
      phone.datagram(audio_packet(v.at("key").data(),0,0,{1,2}),e.data_port); f.until([&]{return f.s.slots[0].audio.count==1;}); f.now+=10*ms; f.poll();
      f.now+=1000*ms; CHECK(projection_audio_services_poll(&f.s,91)==PROJECTION_AUDIO_CLOSED&&f.sink.seen.empty()); f.closed(); }
    { AudioService f; auto e=f.open(); (void)e; --f.now; CHECK(projection_audio_services_poll(&f.s,91)==PROJECTION_AUDIO_CLOSED); f.closed(); }
    for(bool before:{false,true}) { AudioService f; auto e=f.open(); auto p=projection_audio_services_provider(&f.s);
        f.sink.position={f.now,1,16000,1}; if(!before) { f.now+=ms; f.start(e.lease); }
        projection_playback_position position{}; CHECK(p.playback(p.context,91,e.lease,&position)==PROJECTION_AUDIO_CLOSED); f.closed(); }
    { AudioService f; auto a=f.open(100),b=f.open(101),c=f.open(102,0x400000); uint64_t leases[]={a.lease,b.lease,c.lease}; auto p=projection_audio_services_provider(&f.s);
      f.sink.start_failure_at=2; CHECK(p.start(p.context,91,leases,3)==PROJECTION_AUDIO_CLOSED&&f.sink.starts==2&&f.sink.closed.size()==3); f.closed(); }
}
struct Root {
    projection_services s{}; std::array<uint8_t,274> rx{},tx{}; std::array<uint8_t,256> plain{}; std::array<uint8_t,512> network{};
    explicit Root(AudioService& audio) { projection_services_config cfg{}; projection_services_default_config(&cfg); cfg.local=audio.cfg.local; cfg.peer=audio.cfg.peer;
        cfg.clock_ns=audio.cfg.clock_ns; cfg.clock_context=audio.cfg.clock_context; cfg.ntp_origin=UINT64_C(0x1234567800000000); cfg.event.payload_limit=256;
        cfg.media=projection_audio_services_provider(&audio.s); projection_services_storage storage{rx.data(),plain.data(),tx.data(),network.data(),rx.size(),plain.size(),tx.size(),network.size()};
        CHECK(projection_services_init(&s,&cfg,&storage,91)==IAP2_OK); }
    ~Root() { projection_services_close(&s); }
};
static int control(Harness& h,const Bytes& body={},const char* method="SETUP",const char* target="rtsp://127.0.0.1/audio") {
    auto wire=outer(body,30,target,method,"application/x-apple-binary-plist"); int r=IAP2_MORE;
    for(size_t at=0;at<wire.size();) { size_t end=std::min(at+256,wire.size()); r=h.feed(h.frame(Bytes(wire.begin()+at,wire.begin()+end))); at=end; if(at<wire.size()) CHECK(r==IAP2_MORE); } return r;
}
static int available_audio(void*,uint64_t gen,const projection_info_profile* p) { CHECK(gen==91&&p->audio_count==3&&!p->display_count); return IAP2_OK; } // Synthetic sink support only.
template<class F> static void receiver_until(Harness& h,F condition) {
    auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(!condition()) { CHECK(std::chrono::steady_clock::now()<end); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK); if(!condition()) Sleep(1); }
}
static Bytes media_key(const Vectors& v,unsigned id) {
    auto salt=bytes("DataStream-Salt"+std::to_string(id)),label=bytes("DataStream-Output-Encryption-Key"); Bytes key(32);
    CHECK(pair_hkdf_sha512(v.at("pv_shared_secret").data(),32,salt.data(),salt.size(),label.data(),label.size(),key.data(),key.size())==IAP2_OK); return key;
}
static void receiver_integration(const Vectors& v,const Vectors& setup,const Vectors& av) {
    for(unsigned mode=0;mode<4;++mode) {
        bool v6=mode==1; AudioService f(v6); Root root(f); Socket timing(SOCK_DGRAM,v6),events(SOCK_STREAM,v6),phone0(SOCK_DGRAM,v6),phone1(SOCK_DGRAM,v6),phone2(SOCK_DGRAM,v6);
        Socket* phones[]={&phone0,&phone1,&phone2}; auto profile=info_fixture(0); profile.audio_count=3;
        profile.resource_count=1; profile.resources[0]={2,1,100,100,100,100};
        profile.audio[0]={100,0,16,PROJECTION_AUDIO_MEDIA}; profile.audio[1]={101,0,32768,PROJECTION_AUDIO_DEFAULT}; profile.audio[2]={102,0,4194304,PROJECTION_AUDIO_MEDIA};
        Bytes scratch(PROJECTION_INFO_LIMIT); Harness h(v,setup); projection_receiver_info_config info{}; projection_receiver_info_default_config(&info);
        info.profile=&profile; info.available=available_audio; info.buffer=scratch.data(); info.capacity=scratch.size();
        CHECK(projection_receiver_enable_info(&h.s,91,&info,0)==IAP2_OK); projection_session_config config{projection_services_provider(&root.s),0,1000};
        CHECK(projection_receiver_enable_session(&h.s,91,&config,0)==IAP2_OK); h.pair();
        CHECK(h.feed(h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT); h.drain(true,MFI_SAP_DRAINED);
        auto body=av.at("session"); const Bytes port={0x11,0x69,0x79}; auto found=std::search(body.begin(),body.end(),port.begin(),port.end()); CHECK(found!=body.end());
        found[1]=static_cast<uint8_t>(timing.port>>8); found[2]=static_cast<uint8_t>(timing.port); CHECK(control(h,body)==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        auto root_endpoint=h.s.session.slots[0].endpoint; events.connect_to(root_endpoint.event_port); receiver_until(h,[&]{return root.s.connected!=0;});
        CHECK(control(h,av.at("streams"))==RTSP_CHANNEL_OUTPUT&&f.sink.opens==3); h.drain(true,IAP2_OK);
        std::array<projection_session_endpoint,3> endpoints{};
        for(unsigned i=0;i<3;++i) { endpoints[i]=h.s.session.slots[i+1].endpoint; auto key=media_key(v,10+i);
            CHECK(std::equal(key.begin(),key.end(),f.s.slots[i].audio.key)); phones[i]->datagram(audio_packet(key.data(),42+i,4242,i==2?av.at("aac_plain"):av.at("pcm_plain")),endpoints[i].data_port); }
        receiver_until(h,[&]{return f.s.slots[0].audio.count&&f.s.slots[1].audio.count&&f.s.slots[2].audio.count;}); CHECK(f.sink.submits==0&&f.sink.starts==0);
        CHECK(control(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); auto values=feedback_response(h.drain(true,IAP2_OK),30); for(const auto& item:values) CHECK(item.size()==2);
        CHECK(control(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT&&f.sink.starts==0); h.drain(true,IAP2_OK); CHECK(f.sink.starts==3);
        f.now+=10*ms;
        if(mode>=2) { if(mode==2) f.sink.failure=4; else f.sink.busy=true;
            if(mode==3) { CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK); f.now+=1000*ms; }
            CHECK(projection_receiver_poll(&h.s,91,1)==PROJECTION_RECEIVER_CLOSED&&f.sink.live.empty()&&root.s.failed); f.closed(); h.cleared(); continue; }
        receiver_until(h,[&]{return f.sink.seen.size()==3;});
        CHECK(f.sink.seen[0].data==hex("008000000100ff7f")&&f.sink.seen[1].frames==2&&f.sink.seen[2].data==av.at("aac_plain"));
        CHECK(control(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); values=feedback_response(h.drain(true,IAP2_OK),30); for(const auto& item:values) CHECK(item.size()==2);
        // Real UDP timing synchronization; observed playback below is still an explicit synthetic sink report.
        for(unsigned i=0;i<2;++i) { if(i) { f.now=ms+sec; CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK); }
            auto probe=timing.receive_datagram(root_endpoint.timing_port),reply=probe; reply[1]=211;
            std::copy(probe.begin()+24,probe.end(),reply.begin()+8); std::copy(probe.begin()+24,probe.end(),reply.begin()+16);
            f.now+=sec/8; timing.datagram(reply,root_endpoint.timing_port); receiver_until(h,[&]{return !root.s.timing.pending;}); }
        CHECK(root.s.timing.synced); f.sink.position={f.now,13000,0,1};
        CHECK(control(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); values=feedback_response(h.drain(true,IAP2_OK),30);
        CHECK(values.size()==3&&values[0].at("sampleRate")==16000&&values[1].at("sampleRate")==48000&&values[2].at("sampleRate")==44100);
        for(const auto& item:values) CHECK(item.at("sampleTime")==13000&&item.at("timestampRawNs")==f.now);
        CHECK(control(h,av.at("retire"),"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&f.sink.closed==std::vector<uint64_t>{1}); h.drain(true,IAP2_OK);
        f.sink.position={}; CHECK(control(h,av.at("replacement"))==RTSP_CHANNEL_OUTPUT&&f.sink.starts==3); h.drain(true,IAP2_OK); CHECK(f.sink.starts==4);
        uint16_t newport=h.s.session.slots[h.s.session.count-1].endpoint.data_port; auto wrong=media_key(v,10),key=media_key(v,13);
        phone0.datagram(audio_packet(wrong.data(),0,0,av.at("pcm_plain")),newport); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK&&!f.s.slots[0].peer_port);
        phone0.datagram(audio_packet(key.data(),0,0,av.at("pcm_plain")),newport); receiver_until(h,[&]{return f.s.slots[0].audio.count==1;}); f.now+=10*ms;
        receiver_until(h,[&]{return f.sink.seen.size()==4;}); CHECK(f.sink.seen.back().child==4&&f.sink.seen.back().counter==0);
        CHECK(control(h,{},"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&f.sink.live.empty()&&!f.s.wsa); h.drain(true,PROJECTION_RECEIVER_CLOSED); h.cleared();
        CHECK(f.sink.closed.size()==4&&zeroed(f.storage.data(),f.storage.size()-1));
    }
}
struct PcmDeviceFixture {
    uint64_t now=ms; unsigned closed=0;
    struct Device final:projection_pcm::Device {
        PcmDeviceFixture& owner; Bytes data; uint32_t pad=0; uint64_t pos=0; unsigned starts=0; bool broken=false; int reset_error=0;
        explicit Device(PcmDeviceFixture& p):owner(p) { capacity=1600; frequency=64000; period_ns=ms; }
        ~Device() noexcept override { ++owner.closed; }
        int padding(uint32_t& n) noexcept override { n=pad; return broken?IAP2_PROVIDER_FAILED:IAP2_OK; }
        int acquire(uint32_t n,uint8_t*& p) noexcept override { data.resize(size_t(n)*2); p=data.data(); return IAP2_OK; }
        int release(uint32_t n) noexcept override { pad+=n; return IAP2_OK; }
        int start() noexcept override { ++starts; return IAP2_OK; }
        int reset() noexcept override { pos=pad=0; return reset_error; }
        int position(uint64_t& p,uint64_t& q) noexcept override { p=pos; q=owner.now; return IAP2_OK; }
    };
    Device *device=nullptr;
    projection_pcm::Output output{{this,open,clock,thread},91,100,0};
    static bool thread(void*) noexcept { return true; }
    static uint64_t clock(void* p) noexcept { return static_cast<PcmDeviceFixture*>(p)->now; }
    static int open(void* p,const projection_audio_format&,uint32_t,projection_pcm::Device*& out) noexcept {
        auto& f=*static_cast<PcmDeviceFixture*>(p); f.device=new Device(f); out=f.device; return IAP2_OK;
    }
};
struct PcmFixtureUnwind {};
static void pcm_output_integration(const Vectors& v,bool check_unwind=false) {
    auto device_owner=std::make_unique<PcmDeviceFixture>(); auto& device=*device_owner;
    AudioService f(false,false); Socket phone;
    f.cfg.sink=device.output.sink(); f.cfg.clock_ns=PcmDeviceFixture::clock; f.cfg.clock_context=&device; f.init();
    auto e=f.open(); auto p=projection_audio_services_provider(&f.s);
    phone.datagram(audio_packet(v.at("key").data(),0,UINT32_MAX,v.at("pcm_plain")),e.data_port);
    f.until([&]{return f.s.slots[0].audio.count==1;}); CHECK(device.device->starts==0);
    f.start(e.lease); device.now+=10*ms;
    f.until([&]{return device.device->starts==1;});
    CHECK(device.device->data==hex("008000000100ff7f")&&!f.s.slots[0].audio.count);
    projection_playback_position position{};
    CHECK(p.playback(p.context,91,e.lease,&position)==IAP2_OK&&!position.has_position);
    device.device->pos=4; device.now+=ms;
    CHECK(p.playback(p.context,91,e.lease,&position)==IAP2_OK&&position.has_position&&position.sample_time==0&&position.raw_ns==device.now&&position.sample_rate==16000);
    device.device->broken=true;
    CHECK(projection_audio_services_poll(&f.s,91)==PROJECTION_AUDIO_CLOSED&&device.closed==1&&!f.s.count&&!f.s.wsa);
    if(check_unwind) throw PcmFixtureUnwind{};
    CHECK(zeroed(f.storage.data(),f.s.stream_bytes)&&f.storage[f.s.stream_bytes]==0xaa);
    projection_audio_services_close(&f.s); // Final close also wipes never-opened stream extents.
    CHECK(zeroed(f.storage.data(),f.storage.size()-1)&&f.storage.back()==0xaa);
    Socket reused(SOCK_DGRAM,false,1,e.data_port);
}
static void receiver_flush(const Vectors& v,const Vectors& setup,const Vectors& av) {
    for(unsigned mode=0;mode<5;++mode) {
        auto device_owner=std::make_unique<PcmDeviceFixture>(); auto& device=*device_owner; AudioService f(false,false);
        f.cfg.sink=device.output.sink(); f.cfg.clock_ns=PcmDeviceFixture::clock; f.cfg.clock_context=&device; f.init();
        Root root(f); Socket timing,events(SOCK_STREAM),phone; auto profile=info_fixture(0); profile.audio_count=1;
        profile.audio[0]={100,0,16,PROJECTION_AUDIO_MEDIA}; profile.resource_count=1; profile.resources[0]={2,1,100,100,100,100};
        Bytes scratch(PROJECTION_INFO_LIMIT); Harness h(v,setup); projection_receiver_info_config info{}; projection_receiver_info_default_config(&info);
        info.profile=&profile; info.available=[](void*,uint64_t,const projection_info_profile*) -> int { return IAP2_OK; }; info.buffer=scratch.data(); info.capacity=scratch.size();
        CHECK(projection_receiver_enable_info(&h.s,91,&info,0)==IAP2_OK); projection_session_config cfg{projection_services_provider(&root.s),0,1000};
        CHECK(cfg.provider.flush&&projection_receiver_enable_session(&h.s,91,&cfg,0)==IAP2_OK); h.pair();
        if(mode==1) { // The wire form cannot cross the not-yet-drained MFi boundary.
            auto wire=bytes("FLUSH rtsp://127.0.0.1/audio RTSP/1.0\r\nCSeq: 31\r\nRTP-Info: seq=0;rtptime=5000\r\nContent-Length: 0\r\n\r\n");
            CHECK(h.feed(h.frame(wire))==PROJECTION_RECEIVER_CLOSED); h.cleared(); CHECK(device.closed==0); continue;
        }
        CHECK(h.feed(h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT); h.drain(true,MFI_SAP_DRAINED);
        auto body=av.at("session"); auto needle=Bytes{0x11,0x69,0x79}; auto found=std::search(body.begin(),body.end(),needle.begin(),needle.end()); CHECK(found!=body.end());
        found[1]=static_cast<uint8_t>(timing.port>>8); found[2]=static_cast<uint8_t>(timing.port);
        CHECK(control(h,body)==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK); events.connect_to(h.s.session.slots[0].endpoint.event_port);
        receiver_until(h,[&]{return root.s.connected!=0;}); CHECK(control(h,av.at("replacement"))==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        auto e=h.s.session.slots[1].endpoint; auto key=media_key(v,13); auto original=audio_packet(key.data(),42,4242,av.at("pcm_plain"));
        phone.datagram(original,e.data_port); receiver_until(h,[&]{return f.s.slots[0].audio.count==1;});
        CHECK(control(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK); device.now+=10*ms;
        receiver_until(h,[&]{return device.device->starts==1;});
        auto wire=bytes("FLUSH rtsp://127.0.0.1/audio RTSP/1.0\r\nCSeq: 31\r\nRTP-Info: seq=65535;rtptime=5000\r\nContent-Length: 0\r\n\r\n");
        if(mode==3) { device.device->reset_error=IAP2_PROVIDER_FAILED;
            CHECK(h.feed(h.frame(wire))==PROJECTION_RECEIVER_CLOSED); h.cleared(); CHECK(device.closed==1&&root.s.failed&&!f.s.count&&!f.s.wsa); continue; }
        CHECK(h.feed(h.frame(wire))==RTSP_CHANNEL_OUTPUT&&f.s.slots[0].flushing&&!device.device->pad);
        CHECK(f.s.slots[0].audio.highest==42&&Bytes(f.s.slots[0].audio.key,f.s.slots[0].audio.key+32)==key&&f.s.slots[0].peer_port==phone.port);
        if(mode==2) { projection_receiver_close(&h.s); h.cleared(); CHECK(device.closed==1&&root.s.failed&&!f.s.count&&!f.s.wsa); continue; }
        if(mode==4) { CHECK(projection_receiver_poll(&h.s,91,60001)==PROJECTION_RECEIVER_CLOSED); h.cleared(); CHECK(device.closed==1&&root.s.failed&&!f.s.count&&!f.s.wsa); continue; }
        phone.datagram(original,e.data_port); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK&&!f.s.slots[0].audio.count);
        phone.datagram(audio_packet(key.data(),43,4999,av.at("pcm_plain")),e.data_port); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK&&!f.s.slots[0].audio.count);
        auto replacement=hex("1234567801234567"); phone.datagram(audio_packet(key.data(),44,5000,replacement,0),e.data_port);
        receiver_until(h,[&]{return f.s.slots[0].audio.count==1;}); CHECK(device.device->starts==1&&!f.s.slots[0].started);
        auto reply=h.drain(true,IAP2_OK,false); rtsp_message message{}; size_t used=0;
        CHECK(rtsp_message_decode(reply.data(),reply.size(),&message,&used)==IAP2_OK&&message.status==200&&message.cseq==31&&!message.body.size);
        CHECK(f.s.slots[0].flushing&&device.device->starts==1); rtsp_slice output{}; rtsp_channel_key drain{};
        CHECK(projection_receiver_output(&h.s,91,&output,&drain,1)==RTSP_CHANNEL_OUTPUT_DONE);
        CHECK(projection_receiver_release(&h.s,drain,1)==IAP2_OK&&!f.s.slots[0].flushing&&f.s.slots[0].started);
        device.now+=10*ms; receiver_until(h,[&]{return device.device->starts==2;}); CHECK(device.device->data==hex("3412785623016745"));
        CHECK(control(h,{},"POST","/feedback")==RTSP_CHANNEL_OUTPUT); CHECK(feedback_response(h.drain(true,IAP2_OK),30)[0].size()==2); // No synchronized/observed anchor fabricated by reset.
        CHECK(control(h,{},"TEARDOWN")==RTSP_CHANNEL_OUTPUT); h.drain(true,PROJECTION_RECEIVER_CLOSED); h.cleared(); CHECK(device.closed==1&&!f.s.wsa);
        Socket reuse(SOCK_DGRAM,false,1,e.data_port);
    }
}
int main(int argc,char** argv) {
    try { CHECK(argc==4); Winsock wsa; auto v=load_vectors(argv[1],39),setup=load_vectors(argv[2],51),av=load_vectors(argv[3],13);
        configuration(); datagrams(false,av); datagrams(true,av); sender_sync(false); sender_sync(true); backpressure_and_failure(av); receiver_integration(v,setup,av); pcm_output_integration(av); receiver_flush(v,setup,av);
        bool unwound=false;
        // No named catch parameter: Clang 19 Windows ASan corrupts that binding
        // even in an independent minimal throw/catch. No sanitizer is disabled.
        try { pcm_output_integration(av,true); } catch(const PcmFixtureUnwind&) { unwound=true; }
        CHECK(unwound); // Exercise assertion/exception cleanup with the large PCM owner on the heap.
        std::cout<<"PASS: 9 audio service groups; real IPv4/IPv6 UDP, sender sync/source-port pinning, PCM output engine, errors and paired/MFi/session/timing/feedback/FLUSH integration\n";
        std::cout<<"Synthetic credentials/sinks only; no compressed decoder or physical playback claim; x64 service bytes: "<<sizeof(projection_audio_services)<<'\n'; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
