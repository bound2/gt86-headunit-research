/* SPDX-License-Identifier: GPL-3.0-only; real loopback/crypto, synthetic iAP application and MFi. */
#include "projection_socket_fixture.h"
#include "projection_iap_services.h"
#include "projection_command.h"
#include "projection_audio_services.h"
#include "projection_audio_fixture.h"
#include <iphlpapi.h>
#include <memory>
#include <cstdlib>
#include <fcntl.h>
#include <io.h>
#undef CHECK
#define CHECK(x) do { if(!(x)) { std::cerr<<"CHECK failed: " #x " at "<<__LINE__<<'\n';std::exit(1); } } while(0)
extern "C" int projection_iap_services_c_api_test(void);
static Bytes join(Bytes a,const Bytes &b) { a.insert(a.end(),b.begin(),b.end());return a; }
static Bytes package(const Bytes &body,uint32_t type=PROJECTION_IAP_COMM) {
    Bytes p(32);for(unsigned i=0;i<32;++i) p[i]=uint8_t(i*7+3);
    for(unsigned i=0;i<4;++i) { p[i]=uint8_t((body.size()+32)>>(24-8*i));p[16+i]=uint8_t(type>>(24-8*i)); }
    return join(p,body);
}
static Bytes frame(const uint8_t *key,uint64_t counter,const Bytes &body) {
    CHECK(body.size()<=16384);Bytes out(body.size()+18);out[0]=uint8_t(body.size());out[1]=uint8_t(body.size()>>8);
    auto n=nonce(counter);size_t written=0;CHECK(pair_aead_seal(key,n.data(),out.data(),2,body.data(),body.size(),out.data()+2,out.size()-2,&written)==IAP2_OK);return out;
}
struct Relay {
    uint64_t next=1,*clock=nullptr,advance=0;
    unsigned opens=0,calls=0,polls=0,empty=0;int failure=0;bool busy=false,emit=false;size_t prefix=SIZE_MAX;
    Bytes received;std::vector<uint64_t> live,closed;std::vector<projection_iap_key> tokens;
    projection_iap_relay provider() { return {this,open,receive,poll,close}; }
    static int open(void *p,uint64_t gen,const projection_session_resource *q,uint64_t *child) {
        auto &s=*static_cast<Relay*>(p);CHECK(gen==91&&q->type==130);++s.opens;
        if(s.failure==1) return IAP2_PROVIDER_FAILED;
        *child=s.next++;s.live.push_back(*child);return s.failure==2?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static int receive(void *p,uint64_t gen,uint64_t child,const projection_iap_view *v,projection_iap_key key,size_t *accepted) {
        auto &s=*static_cast<Relay*>(p);CHECK(gen==91&&key.generation==gen&&key.token&&std::find(s.live.begin(),s.live.end(),child)!=s.live.end());
        CHECK(v->header.size==32&&v->header.data[16]=='c'&&v->header.data[17]=='o'&&v->header.data[18]=='m'&&v->header.data[19]=='m');
        ++s.calls;if(s.advance) *s.clock+=s.advance;
        if(s.failure==3) return IAP2_PROVIDER_FAILED;
        if(s.failure==4) { *accepted=v->body.size+1;return IAP2_OK; }
        if(s.failure==5) { *accepted=1;return IAP2_MORE; }
        if(s.failure==6) return IAP2_OK;
        if(s.busy) return IAP2_MORE;
        if(s.emit) { CHECK(s.prefix==SIZE_MAX);std::cout.write(reinterpret_cast<const char*>(v->header.data),std::streamsize(v->header.size));
            std::cout.write(reinterpret_cast<const char*>(v->body.data),std::streamsize(v->body.size)); }
        *accepted=std::min(s.prefix,v->body.size);s.received.insert(s.received.end(),v->body.data,v->body.data+*accepted);s.tokens.push_back(key);
        if(!v->body.size) ++s.empty;return IAP2_OK;
    }
    static int poll(void *p,uint64_t gen,uint64_t child,uint64_t) {
        auto &s=*static_cast<Relay*>(p);CHECK(gen==91&&std::find(s.live.begin(),s.live.end(),child)!=s.live.end());++s.polls;
        return s.failure==7?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static void close(void *p,uint64_t gen,uint64_t child) {
        auto &s=*static_cast<Relay*>(p);CHECK(gen==91);auto at=std::find(s.live.begin(),s.live.end(),child);CHECK(at!=s.live.end());s.live.erase(at);s.closed.push_back(child);
        // received is test history, not a live relay queue.
    }
};
struct Service {
    Relay relay;projection_iap_services_config cfg{};projection_iap_services *s=nullptr;uint64_t now=ms;unsigned clocks=0;
    explicit Service(bool v6=false,bool init=true) {
        cfg.local=cfg.peer=loopback(v6);cfg.clock_ns=clock;cfg.clock_context=this;projection_iap_default_config(&cfg.input);
        cfg.input.package_limit=262144;cfg.input.records.receive_ms=1000;cfg.input.records.hold_ms=3000;cfg.input.package_ms=1500;cfg.input.hold_ms=2000;
        cfg.relay=relay.provider();cfg.stream_id=7;cfg.accept_ms=1000;cfg.poll_ms=2;cfg.enabled_features=PROJECTION_SESSION_IAP;relay.clock=&now;
        if(init) create();
    }
    ~Service() { projection_iap_services_destroy(s); }
    static uint64_t clock(void *p) { auto &s=*static_cast<Service*>(p);++s.clocks;return s.now; }
    void create() { CHECK(projection_iap_services_create(&cfg,91,&s)==IAP2_OK&&s&&!clocks); }
    projection_session_provider provider() { return projection_iap_services_provider(s); }
    projection_session_endpoint open(unsigned type=130,const uint8_t *key=nullptr) {
        projection_session_resource q{};q.type=type;q.connection_id=42;q.audio_type=type==100?PROJECTION_AUDIO_MEDIA:0;q.audio_format=type==100?16:0;
        projection_session_keys k{};if(key) std::memcpy(k.read,key,32);projection_session_endpoint e{};auto p=provider();
        CHECK(p.open(p.context,91,&q,cfg.enabled_features,&k,&e)==IAP2_OK&&e.lease&&e.data_port);return e;
    }
    void poll() { CHECK(projection_iap_services_poll(s,91)==IAP2_OK); }
    projection_iap_services_status status(uint64_t lease) const {
        projection_iap_services_status out{};CHECK(projection_iap_services_get_status(s,91,lease,&out)==IAP2_OK);return out;
    }
    template<class F> void until(F condition) { auto end=std::chrono::steady_clock::now()+std::chrono::seconds(3);
        while(!condition()) { CHECK(std::chrono::steady_clock::now()<end);poll();if(!condition()) Sleep(1); } }
    void failure(int expected) { auto end=std::chrono::steady_clock::now()+std::chrono::seconds(3);int r=IAP2_OK;
        while(r==IAP2_OK) { CHECK(std::chrono::steady_clock::now()<end);r=projection_iap_services_poll(s,91);if(!r) Sleep(1); }
        CHECK(r==PROJECTION_IAP_SERVICES_CLOSED&&projection_iap_services_error(s)==expected&&relay.live.empty()&&projection_iap_services_next_delay(s,91)==UINT32_MAX);
    }
};
static bool listening(uint16_t port,bool v6) {
    DWORD size=0;ULONG family=v6?AF_INET6:AF_INET,result=ERROR_INSUFFICIENT_BUFFER;
    CHECK(GetExtendedTcpTable(nullptr,&size,FALSE,family,TCP_TABLE_OWNER_PID_LISTENER,0)==ERROR_INSUFFICIENT_BUFFER);std::vector<uint64_t> storage;
    for(unsigned i=0;i<4&&result==ERROR_INSUFFICIENT_BUFFER;++i) { CHECK(size<=2*1024*1024);storage.resize((size+7u)/8u);result=GetExtendedTcpTable(storage.data(),&size,FALSE,family,TCP_TABLE_OWNER_PID_LISTENER,0); }
    CHECK(result==NO_ERROR);const auto *data=reinterpret_cast<const uint8_t*>(storage.data());DWORD count=0;CHECK(size>=sizeof(count));std::memcpy(&count,data,sizeof(count));
    auto search=[&](auto row,size_t offset) { CHECK(offset<=size&&count<=(size-offset)/sizeof(row));
        for(DWORD i=0;i<count;++i) { std::memcpy(&row,data+offset+size_t(i)*sizeof(row),sizeof(row));if(row.dwOwningPid==GetCurrentProcessId()&&ntohs(static_cast<u_short>(row.dwLocalPort))==port) return true; }return false; };
    return v6?search(MIB_TCP6ROW_OWNER_PID{},offsetof(MIB_TCP6TABLE_OWNER_PID,table)):search(MIB_TCPROW_OWNER_PID{},offsetof(MIB_TCPTABLE_OWNER_PID,table));
}
static void validation() {
    for(unsigned mode=0;mode<18;++mode) { Service f(false,false);
        if(mode==0) f.cfg.local={};if(mode==1) f.cfg.peer=loopback(true);if(mode==2) f.cfg.peer.bytes[0]=224;
        if(mode==3) f.cfg.stream_id=0;if(mode==4) f.cfg.enabled_features=0;if(mode==5) f.cfg.accept_ms=0;if(mode==6) f.cfg.poll_ms=1001;
        if(mode==7) f.cfg.input.package_limit=31;if(mode==8) f.cfg.input.records.payload_limit=16385;if(mode==9) f.cfg.input.package_ms=60001;
        if(mode==10) f.cfg.input.hold_ms=0;if(mode==11) f.cfg.relay.receive=nullptr;if(mode==12) f.cfg.relay.close=nullptr;
        if(mode==13) f.cfg.other.start=SessionBackend::start;if(mode==14) f.cfg.other.poll=SessionBackend::poll;
        if(mode==15) f.cfg.input.records.hold_ms=0;if(mode==16) f.cfg.clock_ns=nullptr;if(mode==17) f.cfg.enabled_features=16;
        CHECK(projection_iap_services_create(&f.cfg,91,&f.s)==IAP2_ARGUMENT&&!f.s&&!f.clocks&&!f.relay.opens);
    }
    Service f;auto p=f.provider();CHECK(projection_iap_services_poll(f.s,90)==IAP2_INVALID&&!f.clocks);
    CHECK(projection_iap_services_poll(f.s,91)==IAP2_MORE&&!f.clocks&&projection_iap_services_next_delay(f.s,91)==UINT32_MAX);
    projection_session_resource q{};q.type=130;projection_session_keys k{};projection_session_endpoint e{};
    k.has_write=1;CHECK(p.open(p.context,91,&q,2,&k,&e)==IAP2_UNSUPPORTED&&!e.lease&&!f.clocks);k.has_write=0;
    q.peer_data_port=1;CHECK(p.open(p.context,91,&q,2,&k,&e)==IAP2_UNSUPPORTED);q.peer_data_port=0;
    CHECK(p.open(p.context,91,&q,0,&k,&e)==IAP2_ARGUMENT);q.type=110;CHECK(p.open(p.context,91,&q,2,&k,&e)==IAP2_UNSUPPORTED);
    auto live=f.open();q.type=130;CHECK(p.open(p.context,91,&q,2,&k,&e)==IAP2_INVALID&&f.relay.opens==1);
    auto status_calls=f.clocks;projection_iap_services_status st{};CHECK(!f.status(live.lease).connected&&f.clocks==status_calls);
    CHECK(projection_iap_services_get_status(f.s,90,live.lease,&st)==IAP2_INVALID&&zeroed(&st,sizeof(st))&&f.clocks==status_calls);
    auto calls=f.clocks;uint64_t dup[]={live.lease,live.lease};CHECK(p.start(p.context,91,dup,2)==IAP2_INVALID&&f.clocks==calls);
    p.close(p.context,90,live.lease);CHECK(f.relay.live.size()==1);p.close(p.context,91,live.lease);p.close(p.context,91,live.lease);CHECK(f.relay.closed.size()==1);
}
static void transport(bool v6) {
    Service f(v6);uint8_t key[32]{};auto e=f.open();CHECK(e.stream_id==7&&listening(e.data_port,v6));Socket phone(SOCK_STREAM,v6);
    if(!v6) { Socket wrong(SOCK_STREAM,false,2);wrong.connect_to(e.data_port);f.poll();CHECK(listening(e.data_port,false)&&f.relay.received.empty()); }
    phone.connect_to(e.data_port);f.until([&]{return !listening(e.data_port,v6);});auto p=package(bytes("first"));auto wire=frame(key,0,p);
    phone.send_bytes(Bytes(wire.begin(),wire.begin()+1));f.poll();CHECK(f.relay.received.empty());phone.send_bytes(Bytes(wire.begin()+1,wire.end()));f.until([&]{return f.relay.received==bytes("first");});
    // Incoming control is delivered without RECORD or a new iAP authentication session.
    auto both=join(package(bytes("discard"),0),join(package({}),package(bytes("second"))));phone.send_bytes(frame(key,1,both));
    f.until([&]{return f.relay.received==bytes("firstsecond");});CHECK(f.relay.empty==1&&f.relay.tokens.back().token==3);
    Bytes big(70001);for(size_t i=0;i<big.size();++i) big[i]=uint8_t(i);p=package(big);
    uint64_t counter=2;for(size_t at=0;at<p.size();) { auto n=std::min<size_t>(16384,p.size()-at);phone.send_bytes(frame(key,counter++,Bytes(p.begin()+at,p.begin()+at+n)));at+=n;f.poll(); }
    f.until([&]{return f.relay.received.size()==11+big.size();});CHECK(Bytes(f.relay.received.begin()+11,f.relay.received.end())==big);
    auto provider=f.provider();CHECK(provider.start(provider.context,91,&e.lease,1)==IAP2_OK&&provider.start(provider.context,91,&e.lease,1)==IAP2_INVALID);
    phone.send_bytes(frame(key,counter++,package(bytes("last"))));f.until([&]{return f.relay.received.size()==15+big.size();});
    phone.send_bytes(frame(key,0,package(bytes("replay"))));f.failure(IAP2_AUTH_FAILED);CHECK(f.relay.closed==std::vector<uint64_t>{1});
}
static void budgets_and_callbacks() {
    uint8_t key[32]{};auto wire=frame(key,0,package(bytes("body")));
    { Service f;auto e=f.open();Socket wrong(SOCK_STREAM,false,2);f.now+=999*ms;wrong.connect_to(e.data_port);f.poll();CHECK(projection_iap_services_next_delay(f.s,91)==1);f.now+=ms;f.failure(IAP2_MORE); }
    { Service f;auto e=f.open();Socket phone(SOCK_STREAM);phone.connect_to(e.data_port);phone.send_bytes(Bytes{wire[0]});f.until([&]{return f.status(e.lease).cipher_bytes==1;});
      f.now+=999*ms;phone.send_bytes(Bytes{wire[1]});f.until([&]{return f.status(e.lease).cipher_bytes==2;});f.now+=ms;f.failure(IAP2_MORE); }
    { Service f;auto e=f.open();Socket phone(SOCK_STREAM);phone.connect_to(e.data_port);f.until([&]{return f.status(e.lease).connected;});phone.close();f.failure(IAP2_END); }
    for(bool partial_package:{false,true}) { Service f;auto e=f.open();Socket phone(SOCK_STREAM);phone.connect_to(e.data_port);
        phone.send_bytes(partial_package?frame(key,0,Bytes(10)):Bytes{wire[0]});
        f.until([&]{auto s=f.status(e.lease);return partial_package?s.package_bytes==10:s.cipher_bytes==1;});
        phone.close();f.failure(IAP2_INVALID);
    }
    { Service f;f.open();--f.now;f.failure(IAP2_INVALID); }
    { Service f;auto e=f.open();Socket phone(SOCK_STREAM);phone.connect_to(e.data_port);auto p=package(bytes("body"));phone.send_bytes(frame(key,0,Bytes(p.begin(),p.begin()+33)));f.until([&]{return f.status(e.lease).package_bytes==33;});
      f.now+=1499*ms;phone.send_bytes(frame(key,1,{}));f.poll();f.now+=ms;f.failure(IAP2_MORE); }
    for(unsigned mode=0;mode<4;++mode) {
        Service f;auto e=f.open();Socket phone(SOCK_STREAM);phone.connect_to(e.data_port);f.relay.busy=true;
        auto input=wire;if(mode==3) for(unsigned i=1;i<32;++i) input=join(input,frame(key,i,package(bytes("tail"))));
        phone.send_bytes(input);if(mode==3) f.until([&]{return f.status(e.lease).network_bytes!=0;});
        f.until([&]{return f.relay.calls!=0;});CHECK(f.relay.received.empty());
        f.now+=(mode==3?999:1999)*ms;f.poll();CHECK(projection_iap_services_next_delay(f.s,91)==1);
        if(mode==0) { f.relay.busy=false;f.relay.prefix=1;f.until([&]{return f.relay.received==bytes("body");});CHECK(f.relay.tokens.size()==4&&f.relay.tokens[0].token==f.relay.tokens[3].token); }
        else if(mode==2) { f.relay.advance=2*ms;f.failure(IAP2_MORE); }
        else { f.now+=ms;f.failure(IAP2_MORE); }
    }
    for(int failure=1;failure<=7;++failure) {
        Service f;f.relay.failure=failure;auto p=f.provider();projection_session_resource q{};q.type=130;projection_session_keys k{};projection_session_endpoint e{};
        int r=p.open(p.context,91,&q,2,&k,&e);
        if(failure<=2) { CHECK(r==PROJECTION_IAP_SERVICES_CLOSED&&!e.lease&&f.relay.closed.size()==size_t(failure==2));continue; }
        CHECK(r==IAP2_OK);Socket phone(SOCK_STREAM);phone.connect_to(e.data_port);phone.send_bytes(wire);f.failure(failure==3||failure==7?IAP2_PROVIDER_FAILED:IAP2_INVALID);
    }
}
struct CloseService { Service &f;~CloseService() { projection_iap_services_close(f.s); } };
static void delegation() {
    for(unsigned mode=0;mode<6;++mode) {
        Service f(false,false);SessionBackend other;CloseService cleanup{f};f.cfg.other=other.config(true).provider;
        f.cfg.other.poll=SessionBackend::poll;f.cfg.other.next_delay=SessionBackend::next_delay;f.cfg.other.flush=SessionBackend::flush;f.create();
        auto iap=f.open(),audio=f.open(100);auto p=f.provider();CHECK(audio.lease!=iap.lease&&other.live.size()==1);
        uint64_t leases[]={iap.lease,audio.lease};if(mode==0) other.start_error=IAP2_PROVIDER_FAILED;
        int r=p.start(p.context,91,leases,2);if(mode==0) { CHECK(r==PROJECTION_IAP_SERVICES_CLOSED&&other.live.empty()&&f.relay.live.empty());continue; }
        CHECK(r==IAP2_OK&&other.started==std::vector<uint64_t>{1});
        if(mode==1) { other.poll_error=IAP2_PROVIDER_FAILED;f.failure(IAP2_PROVIDER_FAILED);CHECK(other.live.empty());continue; }
        projection_playback_position position{};if(mode==2) other.playback_error=IAP2_PROVIDER_FAILED;
        r=p.playback(p.context,91,audio.lease,&position);
        if(mode==2) { CHECK(r==PROJECTION_IAP_SERVICES_CLOSED&&zeroed(&position,sizeof(position))&&other.live.empty());continue; }
        CHECK(r==IAP2_OK&&other.observed_leases.back()==1&&p.playback(p.context,91,iap.lease,&position)==IAP2_INVALID);
        projection_audio_flush_request request{12,34};if(mode==3) other.flush_error=IAP2_PROVIDER_FAILED;
        r=p.flush(p.context,91,audio.lease,&request);if(mode==3) { CHECK(r==PROJECTION_IAP_SERVICES_CLOSED&&other.live.empty());continue; }
        CHECK(r==IAP2_OK&&other.flushed_lease==1&&p.start(p.context,91,&audio.lease,1)==IAP2_INVALID);
        CHECK(p.flush(p.context,91,audio.lease,nullptr)==IAP2_OK&&other.resumes==1);
        if(mode==4) { uint8_t key[32]{};Socket phone(SOCK_STREAM);phone.connect_to(iap.data_port);auto bad=frame(key,0,package(bytes("bad")));bad.back()^=1;phone.send_bytes(bad);f.failure(IAP2_AUTH_FAILED);CHECK(other.live.empty());continue; }
        p.close(p.context,91,iap.lease);CHECK(f.relay.live.empty()&&other.live.size()==1);p.close(p.context,91,audio.lease);CHECK(other.closed==std::vector<uint64_t>{1});
    }
}
struct Audio {
    projection_audio_services s{};Bytes storage=Bytes(3*4*256),network=Bytes(292);unsigned starts=0,submits=0,closes=0;
    explicit Audio(Service &f) { projection_audio_services_config c{};c.local=f.cfg.local;c.peer=f.cfg.peer;c.clock_ns=f.cfg.clock_ns;c.clock_context=f.cfg.clock_context;c.poll_ms=2;
        projection_audio_default_config(&c.audio);c.audio.slots=4;c.audio.payload_capacity=256;c.audio.reorder_ms=0;c.sink={this,open,start,submit,poll,playback,close};
        CHECK(projection_audio_services_init(&s,&c,storage.data(),storage.size(),network.data(),network.size(),91)==IAP2_OK); }
    ~Audio() { projection_audio_services_close(&s); }
    static int open(void*,uint64_t,const projection_session_resource*,const projection_audio_format*,uint64_t *child) { *child=1;return IAP2_OK; }
    static int start(void *p,uint64_t,uint64_t) { ++static_cast<Audio*>(p)->starts;return IAP2_OK; }
    static int submit(void *p,uint64_t,uint64_t,const projection_audio_format*,const projection_audio_packet *q) { CHECK(q->size==8);++static_cast<Audio*>(p)->submits;return IAP2_OK; }
    static int poll(void*,uint64_t,uint64_t,uint64_t) { return IAP2_OK; }
    static int playback(void*,uint64_t,uint64_t,projection_playback_position *out) { *out={0,0,16000,0};return IAP2_OK; }
    static void close(void *p,uint64_t,uint64_t) { ++static_cast<Audio*>(p)->closes; }
};
static void mixed_audio() {
    Service f(false,false);Audio audio(f);CloseService cleanup{f};f.cfg.other=projection_audio_services_provider(&audio.s);f.create();
    auto iap=f.open(),a=f.open(100);auto p=f.provider();uint64_t leases[]={iap.lease,a.lease};CHECK(p.start(p.context,91,leases,2)==IAP2_OK);
    Socket phone(SOCK_STREAM),udp(SOCK_DGRAM);uint8_t key[32]{};phone.connect_to(iap.data_port);f.relay.busy=true;phone.send_bytes(frame(key,0,package(bytes("busy"))));
    f.until([&]{return f.relay.calls!=0;});udp.datagram(audio_packet(key,0,0,Bytes(8)),a.data_port);f.until([&]{return audio.submits==1;});CHECK(f.relay.received.empty());
    f.relay.busy=false;f.until([&]{return f.relay.received==bytes("busy");});phone.close();f.failure(IAP2_END);CHECK(audio.closes==1);
}
struct Root {
    projection_services s{};std::array<uint8_t,274> rx{},tx{};std::array<uint8_t,256> plain{};std::array<uint8_t,512> network{};
    Bytes messages=Bytes(4096),reply=Bytes(256),commands=Bytes(2048);
    explicit Root(Service &f) { projection_services_config c{};projection_services_default_config(&c);c.local=f.cfg.local;c.peer=f.cfg.peer;c.clock_ns=f.cfg.clock_ns;c.clock_context=f.cfg.clock_context;
        c.ntp_origin=UINT64_C(0x1234567800000000);c.event.payload_limit=256;c.enabled_features=2;c.media=f.provider();
        projection_services_storage b{rx.data(),plain.data(),tx.data(),network.data(),rx.size(),plain.size(),tx.size(),network.size()};CHECK(projection_services_init(&s,&c,&b,91)==IAP2_OK);
        projection_events_config ec{};projection_events_default_config(&ec);projection_events_storage eb{messages.data(),reply.data(),commands.data(),messages.size(),reply.size(),1024,commands.size(),2};
        CHECK(projection_services_enable_events(&s,91,&ec,&eb)==IAP2_OK);
    }
    ~Root() { projection_services_close(&s); }
};
static int control(Harness &h,const Bytes &body={},const char *method="SETUP") {
    auto wire=outer(body,30,"rtsp://127.0.0.1/iap",method,"application/x-apple-binary-plist");int r=IAP2_MORE;
    for(size_t at=0;at<wire.size();) { size_t end=std::min(at+256,wire.size());r=h.feed(h.frame(Bytes(wire.begin()+at,wire.begin()+end)));at=end;if(at<wire.size()) CHECK(r==IAP2_MORE); }return r;
}
static int available(void*,uint64_t gen,const projection_info_profile*) { CHECK(gen==91);return IAP2_OK; } // Synthetic application attestation only.
template<class F> static void receiver_until(Harness &h,F condition) { auto end=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    while(!condition()) { CHECK(std::chrono::steady_clock::now()<end);CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK);if(!condition()) Sleep(1); } }
static Bytes derived(const Vectors &v,const std::string &salt,const std::string &label) { Bytes key(32);
    CHECK(pair_hkdf_sha512(v.at("pv_shared_secret").data(),32,reinterpret_cast<const uint8_t*>(salt.data()),salt.size(),reinterpret_cast<const uint8_t*>(label.data()),label.size(),key.data(),key.size())==IAP2_OK);return key; }
static void return_path(Harness &h,Service &f,Root &root,Socket &events,const projection_info_profile &profile,const Vectors &v,bool before) {
    auto payload=bytes("explicit application output");projection_command command{PROJECTION_COMMAND_IAP,{},{payload.data(),payload.size()},0};Bytes b(256);size_t n=0;
    CHECK(projection_command_encode(&profile,2,&command,b.data(),b.size(),&n)==IAP2_OK);b.resize(n);rtsp_slice body{b.data(),b.size()};rtsp_channel_key token{};
    int r=projection_services_commands(&root.s,91,&body,1,&token,f.now);
    if(before) { CHECK(r==RTSP_BUSY);return; }CHECK(r==PROJECTION_EVENTS_OUTPUT);
    receiver_until(h,[&]{return root.s.events.slots[0].phase==PROJECTION_EVENT_WAITING;});
    Bytes message;auto key=derived(v,"Events-Salt","Events-Write-Encryption-Key");rtsp_message parsed{};size_t used=0;uint64_t counter=0;
    while(rtsp_message_decode(message.data(),message.size(),&parsed,&used)==IAP2_MORE) { auto head=events.receive_bytes(2);size_t length=head[0]+256u*head[1];CHECK(length<=256);
        auto sealed=events.receive_bytes(length+16);Bytes plain(length);auto nonce_bytes=nonce(counter++);size_t written=0;
        CHECK(pair_aead_open(key.data(),nonce_bytes.data(),head.data(),2,sealed.data(),sealed.size(),plain.data(),plain.size(),&written)==IAP2_OK);message=join(message,plain); }
    CHECK(rtsp_message_decode(message.data(),message.size(),&parsed,&used)==IAP2_OK&&used==message.size());
    CHECK(parsed.kind==RTSP_REQUEST&&Bytes(parsed.body.data,parsed.body.data+parsed.body.size)==b);
    key=derived(v,"Events-Salt","Events-Read-Encryption-Key");events.send_bytes(frame(key.data(),0,bytes("RTSP/1.0 200 OK\r\nCSeq: "+std::to_string(parsed.cseq)+"\r\nContent-Length: 0\r\n\r\n")));
    receiver_until(h,[&]{return root.s.events.held==2;});rtsp_channel_key result{};rtsp_message reply{};
    CHECK(projection_services_message(&root.s,91,&reply,&result)==PROJECTION_EVENTS_RESPONSE&&result.token==token.token&&reply.status==200);
    CHECK(projection_services_release(&root.s,result,f.now)==IAP2_OK);
}
static void receiver_integration(const Vectors &v,const Vectors &setup,const Vectors &sv,const Vectors &iv) {
    for(unsigned mode=0;mode<4;++mode) {
        bool v6=mode==1;Service f(v6);Root root(f);Socket timing(SOCK_DGRAM,v6),events(SOCK_STREAM,v6),phone(SOCK_STREAM,v6);
        auto profile=info_fixture(1);profile.audio_count=profile.latency_count=profile.hid_count=profile.extension_count=0;profile.resource_count=1;profile.keep_alive_low_power=1;
        Bytes scratch(PROJECTION_INFO_LIMIT);auto harness=std::make_unique<Harness>(v,setup);auto &h=*harness;
        projection_receiver_info_config info{};projection_receiver_info_default_config(&info);info.profile=&profile;info.available=available;info.buffer=scratch.data();info.capacity=scratch.size();
        CHECK(projection_receiver_enable_info(&h.s,91,&info,0)==IAP2_OK);projection_session_config config{projection_services_provider(&root.s),2,0};
        CHECK(projection_receiver_enable_session(&h.s,91,&config,0)==IAP2_OK);h.pair();CHECK(h.feed(h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT);h.drain(true,MFI_SAP_DRAINED);
        auto body=sv.at("session");const Bytes marker{0x11,0x69,0x79};auto at=std::search(body.begin(),body.end(),marker.begin(),marker.end());CHECK(at!=body.end());at[1]=uint8_t(timing.port>>8);at[2]=uint8_t(timing.port);
        CHECK(control(h,body)==RTSP_CHANNEL_OUTPUT);h.drain(true,IAP2_OK);events.connect_to(h.s.session.slots[0].endpoint.event_port);receiver_until(h,[&]{return root.s.connected!=0;});
        CHECK(control(h,iv.at("iap"))==RTSP_CHANNEL_OUTPUT);h.drain(true,IAP2_OK);auto endpoint=h.s.session.slots[1].endpoint;CHECK(endpoint.stream_id==7);
        auto key=derived(v,"DataStream-Salt42","DataStream-Output-Encryption-Key");phone.connect_to(endpoint.data_port);phone.send_bytes(frame(key.data(),0,package(bytes("before RECORD"))));
        receiver_until(h,[&]{return f.relay.received==bytes("before RECORD");});return_path(h,f,root,events,profile,v,true);
        CHECK(control(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT&&!root.s.started);h.drain(true,IAP2_OK);CHECK(root.s.started);return_path(h,f,root,events,profile,v,false);
        if(mode==2) { auto bad=frame(key.data(),1,package(bytes("tamper")));bad.back()^=1;phone.send_bytes(bad);int r=IAP2_OK;auto end=std::chrono::steady_clock::now()+std::chrono::seconds(3);
            while(r==IAP2_OK) { CHECK(std::chrono::steady_clock::now()<end);r=projection_receiver_poll(&h.s,91,1); }CHECK(r==PROJECTION_RECEIVER_CLOSED&&root.s.failed&&!root.s.media_count&&f.relay.live.empty());h.cleared();continue; }
        CHECK(control(h,iv.at("teardown_iap"),"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&f.relay.live.empty());h.drain(true,IAP2_OK);
        if(mode==3) { CHECK(control(h,iv.at("iap"))==PROJECTION_RECEIVER_CLOSED&&f.relay.opens==1);h.cleared();continue; }
        CHECK(control(h,iv.at("iap_new"))==RTSP_CHANNEL_OUTPUT);h.drain(true,IAP2_OK);auto replacement=h.s.session.slots[1].endpoint;CHECK(replacement.lease!=endpoint.lease);
        Socket next(SOCK_STREAM,v6);key=derived(v,"DataStream-Salt43","DataStream-Output-Encryption-Key");next.connect_to(replacement.data_port);next.send_bytes(frame(key.data(),0,package(bytes("replacement"))));
        receiver_until(h,[&]{return f.relay.received==bytes("before RECORDreplacement");});CHECK(f.relay.tokens.back().token==1&&f.relay.opens==2);
        CHECK(control(h,{},"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&f.relay.live.empty());h.drain(true,PROJECTION_RECEIVER_CLOSED);h.cleared();CHECK(f.relay.closed==std::vector<uint64_t>({1,2}));
    }
}
static int stdin_decode() {
    CHECK(_setmode(_fileno(stdin),_O_BINARY)!=-1&&_setmode(_fileno(stdout),_O_BINARY)!=-1);Winsock sockets;
    Service f(false,false);f.cfg.input.package_limit=PROJECTION_IAP_MAX_PACKAGE;f.relay.emit=true;f.create();
    uint8_t key[32];for(unsigned i=0;i<32;++i) key[i]=uint8_t(i);auto e=f.open(130,key);Socket phone(SOCK_STREAM);phone.connect_to(e.data_port);
    std::array<char,997> buffer{};size_t total=0;
    while(std::cin) {
        std::cin.read(buffer.data(),buffer.size());size_t n=size_t(std::cin.gcount()),at=0;total+=n;CHECK(total<=16*1024*1024);
        auto end=std::chrono::steady_clock::now()+std::chrono::seconds(10);
        while(at<n) {
            CHECK(std::chrono::steady_clock::now()<end);int written=send(phone.value,buffer.data()+at,static_cast<int>(n-at),0);
            if(written==SOCKET_ERROR) CHECK(WSAGetLastError()==WSAEWOULDBLOCK);else { CHECK(written>0);at+=size_t(written); }
            f.poll();
        }
        for(;;) { auto s=f.status(e.lease);if(!s.network_bytes&&!s.plain_bytes&&!s.held) break;
            CHECK(std::chrono::steady_clock::now()<end);f.poll(); }
    }
    CHECK(shutdown(phone.value,SD_SEND)==0);f.failure(IAP2_END);CHECK(std::cout.good());return 0;
}
int main(int argc,char **argv) {
    if(argc==2&&std::string(argv[1])=="--failure-test") CHECK(false);
    if(argc==2&&std::string(argv[1])=="--wire-stdin") return stdin_decode();
    CHECK(argc==5&&projection_iap_services_c_api_test());Winsock sockets;auto v=load_vectors(argv[1],39),setup=load_vectors(argv[2],51),sv=load_vectors(argv[3],42),iv=load_vectors(argv[4],3);
    validation();transport(false);transport(true);budgets_and_callbacks();delegation();mixed_audio();receiver_integration(v,setup,sv,iv);
    std::cout<<"PASS: 7 iAP-service groups: real IPv4/IPv6 TCP, relay/backpressure, deadlines, audio UDP/delegation, paired SETUP/RECORD/TEARDOWN and event return path\n";return 0;
}
