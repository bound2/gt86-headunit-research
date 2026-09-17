/* SPDX-License-Identifier: GPL-3.0-only; real loopback/AEAD/decoder, synthetic output/MFi. */
#include "projection_socket_fixture.h"
#include "projection_video_socket_fixture.h"
#include "projection_video_services.h"
#include "projection_audio_services.h"
#include "projection_audio_fixture.h"
#include "projection_h264_source_fixture.h"
#include <iphlpapi.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <cstdlib>

// Report the assertion directly: Windows Clang ASan can mask a failed CHECK
// with a secondary exception-object access violation in a named catch clause.
#undef CHECK
#define CHECK(x) do { if(!(x)) { std::cerr<<#x<<" line "<<__LINE__<<'\n'; std::abort(); } } while(0)

extern "C" int projection_video_services_c_api_test(void);
struct Sink {
    struct Output { uint64_t child,epoch,counter; Bytes pixels; };
    std::vector<Output> seen; std::map<uint64_t,uint64_t> live; std::vector<uint64_t> closed;
    uint64_t next=1; unsigned opens=0,starts=0,configs=0,submits=0,polls=0;
    bool busy=false; int failure=0; uint64_t *clock=nullptr; uint64_t advance=0;
    projection_video_sink provider() { return {this,open,start,configure,submit,poll,close}; }
    static int open(void *p,uint64_t gen,const projection_session_resource *q,uint64_t *child) {
        auto &s=*static_cast<Sink*>(p); CHECK(gen==91&&(q->type==110||q->type==111)); ++s.opens;
        if(s.failure==1) return IAP2_PROVIDER_FAILED;
        *child=s.next++; s.live[*child]=0; return s.failure==2?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static int start(void *p,uint64_t gen,uint64_t child) {
        auto &s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.contains(child)); ++s.starts;
        return s.failure==3?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static int configure(void *p,uint64_t gen,uint64_t child,const projection_video_configuration *c) {
        auto &s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.contains(child)&&c->generation==gen&&!c->authenticated&&c->epoch>s.live[child]);
        ++s.configs; s.live[child]=c->epoch;
        return s.failure==4?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static int submit(void *p,uint64_t gen,uint64_t child,const projection_h264_view *v,const projection_video_metadata *m) {
        auto &s=*static_cast<Sink*>(p); CHECK(gen==91&&s.starts&&s.live.contains(child)); ++s.submits;
        CHECK(v->width==152&&v->height==100&&v->generation==gen&&v->timestamp==m->counter);
        CHECK(m->configuration_epoch==s.live[child]&&m->frame_authenticated&&!m->configuration_authenticated);
        if(s.advance) *s.clock+=s.advance;
        if(s.failure==5) return IAP2_PROVIDER_FAILED;
        if(s.busy) return IAP2_MORE;
        s.seen.push_back({child,m->configuration_epoch,m->counter,Bytes(v->plane[0],v->plane[0]+v->bytes)});
        return IAP2_OK;
    }
    static int poll(void *p,uint64_t gen,uint64_t child,uint64_t) {
        auto &s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.contains(child)); ++s.polls;
        return s.failure==6?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static void close(void *p,uint64_t gen,uint64_t child) {
        auto &s=*static_cast<Sink*>(p); CHECK(gen==91&&s.live.erase(child)==1); s.closed.push_back(child);
        // seen is a test history, never a live renderer queue.
    }
};
struct Service {
    Sink sink; projection_video_services_config cfg{}; projection_video_services *s=nullptr;
    uint64_t now=ms; unsigned clocks=0;
    explicit Service(bool v6=false,bool init=true) {
        cfg.local=cfg.peer=loopback(v6); cfg.clock_ns=clock; cfg.clock_context=this;
        cfg.video={1920,1088,1000,2000,2,1}; cfg.sink=sink.provider(); cfg.accept_ms=1000; cfg.poll_ms=2;
        sink.clock=&now; if(init) create();
    }
    ~Service() { projection_video_services_destroy(s); }
    static uint64_t clock(void *p) { auto &s=*static_cast<Service*>(p); ++s.clocks; return s.now; }
    void create() { CHECK(projection_video_services_create(&cfg,91,&s)==IAP2_OK&&clocks==0&&s); }
    projection_session_provider provider() { return projection_video_services_provider(s); }
    projection_session_endpoint open(unsigned type=110,const uint8_t *key=nullptr) {
        projection_session_keys k{}; if(key) std::memcpy(k.read,key,32);
        projection_session_resource q{}; q.type=type; q.connection_id=type;
        projection_session_endpoint e{}; auto p=provider(); CHECK(p.open(p.context,91,&q,cfg.enabled_features,&k,&e)==IAP2_OK&&e.lease&&e.data_port); return e;
    }
    void start(uint64_t lease) { auto p=provider(); CHECK(p.start(p.context,91,&lease,1)==IAP2_OK); }
    void poll() { CHECK(projection_video_services_poll(s,91)==IAP2_OK); }
    template<class F> void until(F condition) {
        auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(!condition()) { CHECK(std::chrono::steady_clock::now()<end); poll(); if(!condition()) Sleep(1); }
    }
    void failure(int expected) {
        auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2); int r=IAP2_OK;
        while(r==IAP2_OK) { CHECK(std::chrono::steady_clock::now()<end); r=projection_video_services_poll(s,91); if(!r) Sleep(1); }
        CHECK(r==PROJECTION_VIDEO_SERVICES_CLOSED&&projection_video_services_error(s)==expected&&sink.live.empty());
        CHECK(projection_video_services_next_delay(s,91)==UINT32_MAX);
    }
};
static void validation() {
    for(unsigned mode=0;mode<16;++mode) {
        Service f(false,false);
        if(mode==0) f.cfg.local={}; if(mode==1) f.cfg.peer=loopback(true); if(mode==2) f.cfg.peer.bytes[0]=224;
        if(mode==3) f.cfg.clock_ns=nullptr; if(mode==4) f.cfg.accept_ms=0; if(mode==5) f.cfg.poll_ms=1001;
        if(mode==6) f.cfg.video.allow_clear_config=0; if(mode==7) f.cfg.video.queue_frames=1; if(mode==8) f.cfg.video.max_width=1919;
        if(mode==9) f.cfg.enabled_features=PROJECTION_SESSION_HEVC; if(mode==10) f.cfg.sink.configure=nullptr; if(mode==11) f.cfg.sink.submit=nullptr;
        if(mode==12) f.cfg.sink.close=nullptr; if(mode==13) f.cfg.other.start=SessionBackend::start;
        if(mode==14) f.cfg.other.poll=SessionBackend::poll; if(mode==15) f.cfg.video.receive_ms=0;
        CHECK(projection_video_services_create(&f.cfg,91,&f.s)==IAP2_ARGUMENT&&!f.s&&!f.clocks&&!f.sink.opens);
    }
    Service f; auto p=f.provider(); projection_session_keys k{}; projection_session_resource q{}; q.type=111; projection_session_endpoint e{};
    CHECK(p.open(p.context,91,&q,0,&k,&e)==IAP2_UNSUPPORTED&&!e.lease&&!f.clocks);
    q.type=110; k.has_write=1; CHECK(p.open(p.context,91,&q,0,&k,&e)==IAP2_UNSUPPORTED);
    CHECK(projection_video_services_poll(f.s,90)==IAP2_INVALID&&!f.clocks);
    CHECK(projection_video_services_poll(f.s,91)==IAP2_MORE&&!f.clocks);
    CHECK(projection_video_services_next_delay(f.s,91)==UINT32_MAX);
    projection_video_services_close(f.s); projection_video_services_close(f.s);
}
static void transport(const Media &m,bool v6) {
    Service f(v6); uint8_t key[32]{}; Socket phone(SOCK_STREAM,v6); auto e=f.open(); auto p=f.provider();
    if(!v6) { Socket foreign(SOCK_STREAM,false,2); foreign.connect_to(e.data_port); f.poll(); CHECK(f.sink.configs==0); }
    phone.connect_to(e.data_port);
    phone.send_bytes(record(1,{})); phone.send_bytes(record(1,Bytes{0,0,0,0,'a','v','c','C'}));
    phone.send_bytes(Bytes(m.config.begin(),m.config.begin()+31)); f.poll(); CHECK(!f.sink.configs);
    auto tail=Bytes(m.config.begin()+31,m.config.end()); auto first=m.frame(key,0); tail.insert(tail.end(),first.begin(),first.end());
    phone.send_bytes(tail); f.until([&]{return f.sink.configs==1;}); for(unsigned i=0;i<5;++i) f.poll();
    CHECK(!f.sink.starts&&!f.sink.submits&&!f.sink.polls); f.start(e.lease); f.until([&]{return f.sink.seen.size()==1;});
    Bytes baseline=f.sink.seen[0].pixels; CHECK(f.sink.seen[0].counter==0);
    Bytes rest; for(unsigned i=1;i<10;++i) {
        auto empty=record(1,{}),repeat=i%2?m.config:m.reserved_config(),frame=m.frame(key,i,i+2);
        for(const auto &part:{empty,repeat,frame}) rest.insert(rest.end(),part.begin(),part.end());
    }
    phone.send_bytes(rest); f.until([&]{return f.sink.seen.size()==10;});
    CHECK(f.sink.configs==1); // No callbacks, frame retirement or IDR gate for config keepalives/repeats.
    for(unsigned i=0;i<10;++i) CHECK(f.sink.seen[i].counter==i&&f.sink.seen[i].epoch==1);
    Media replacement=m; replacement.nals[0]=source_fixture::sps(source_fixture::Spec{}); replacement.configure();
    auto changed=replacement.config; auto next=m.frame(key,10); changed.insert(changed.end(),next.begin(),next.end()); phone.send_bytes(changed);
    f.until([&]{return f.sink.seen.size()==11;}); CHECK(f.sink.configs==2&&f.sink.seen.back().epoch==2&&f.sink.seen.back().pixels==baseline);
    phone.send_bytes(m.frame(key,0)); f.failure(PROJECTION_VIDEO_AUTH); CHECK(f.sink.closed==std::vector<uint64_t>{1});
    p.close(p.context,91,e.lease); CHECK(f.sink.closed.size()==1);
    Socket reuse(SOCK_STREAM,v6,1,e.data_port); // Real listener/client were released.
}
static void deadlines_and_failures(const Media &m) {
    uint8_t key[32]{};
    { Service f; auto e=f.open(); Socket wrong(SOCK_STREAM,false,2); f.now+=999*ms; wrong.connect_to(e.data_port); f.poll();
      CHECK(projection_video_services_next_delay(f.s,91)==1); f.now+=ms; f.failure(PROJECTION_VIDEO_DEADLINE); }
    { Service f; auto e=f.open(); Socket phone(SOCK_STREAM); phone.connect_to(e.data_port); phone.send_bytes(Bytes(m.config.begin(),m.config.begin()+10)); f.poll();
      f.now+=999*ms; phone.send_bytes(Bytes{m.config[10]}); f.poll(); f.now+=ms; f.failure(PROJECTION_VIDEO_DEADLINE); }
    { Service f; auto e=f.open(); Socket phone(SOCK_STREAM); phone.connect_to(e.data_port); f.poll(); phone.close(); f.failure(IAP2_END); }
    // One write carries a config and two records. Before RECORD, the first
    // decoded picture leaves fewer than two free child slots. The owned TCP
    // tail must expire before the child's longer queued-picture budget.
    { Service f; auto e=f.open(); Socket phone(SOCK_STREAM); phone.connect_to(e.data_port);
      auto wire=m.config; auto first=m.frame(key,0),second=m.frame(key,1,3);
      wire.insert(wire.end(),first.begin(),first.end()); wire.insert(wire.end(),second.begin(),second.end()); phone.send_bytes(wire);
      f.until([&]{return f.sink.configs==1;}); for(unsigned i=0;i<10;++i) f.poll(); CHECK(!f.sink.submits);
      f.now+=999*ms; f.poll(); CHECK(projection_video_services_next_delay(f.s,91)==1);
      f.now+=ms; f.failure(PROJECTION_VIDEO_DEADLINE); }
    { Service f; auto e=f.open(); (void)e; --f.now; f.failure(IAP2_INVALID); }
    for(unsigned mode=0;mode<3;++mode) {
        Service f; auto e=f.open(); f.start(e.lease); f.sink.busy=true; Socket phone(SOCK_STREAM); phone.connect_to(e.data_port);
        phone.send_bytes(m.config); phone.send_bytes(m.frame(key,0)); f.until([&]{return f.sink.submits!=0;});
        phone.send_bytes(record(1,{})); phone.send_bytes(m.reserved_config()); // Cannot clear or renew held output.
        CHECK(f.sink.seen.empty()); f.now+=1999*ms;
        if(mode==0) { f.sink.busy=false; f.until([&]{return f.sink.seen.size()==1;}); CHECK(f.sink.seen[0].counter==0); }
        if(mode==1) { f.poll(); f.now+=ms; f.failure(PROJECTION_VIDEO_DEADLINE); }
        if(mode==2) { f.sink.advance=2*ms; f.failure(PROJECTION_VIDEO_DEADLINE); }
    }
    for(int failure=1;failure<=6;++failure) {
        Service f; auto p=f.provider(); projection_session_keys k{}; projection_session_resource q{}; q.type=110; projection_session_endpoint e{};
        f.sink.failure=failure;
        int r=p.open(p.context,91,&q,0,&k,&e);
        if(failure<=2) { CHECK(r==PROJECTION_VIDEO_SERVICES_CLOSED&&!e.lease&&f.sink.closed.size()==size_t(failure==2)); continue; }
        CHECK(r==IAP2_OK); r=p.start(p.context,91,&e.lease,1);
        if(failure==3) { CHECK(r==PROJECTION_VIDEO_SERVICES_CLOSED&&f.sink.live.empty()); continue; }
        CHECK(r==IAP2_OK); Socket phone(SOCK_STREAM); phone.connect_to(e.data_port); phone.send_bytes(m.config); phone.send_bytes(m.frame(key,0));
        f.failure(IAP2_PROVIDER_FAILED);
    }
}
static bool listening(uint16_t port,bool v6) {
    DWORD size=0; ULONG family=v6?AF_INET6:AF_INET;
    CHECK(GetExtendedTcpTable(nullptr,&size,FALSE,family,TCP_TABLE_OWNER_PID_LISTENER,0)==ERROR_INSUFFICIENT_BUFFER);
    std::vector<uint64_t> storage;
    ULONG result=ERROR_INSUFFICIENT_BUFFER;
    for(unsigned i=0;i<4&&result==ERROR_INSUFFICIENT_BUFFER;++i) {
        CHECK(size<=2*1024*1024); storage.resize((size+7u)/8u);
        result=GetExtendedTcpTable(storage.data(),&size,FALSE,family,TCP_TABLE_OWNER_PID_LISTENER,0);
    }
    CHECK(result==NO_ERROR); const auto *data=reinterpret_cast<const uint8_t*>(storage.data());
    DWORD count=0; CHECK(size>=sizeof(count)); std::memcpy(&count,data,sizeof(count));
    auto search=[&](auto row,size_t offset) {
        CHECK(offset<=size&&count<=(size-offset)/sizeof(row));
        for(DWORD i=0;i<count;++i) {
            std::memcpy(&row,data+offset+size_t(i)*sizeof(row),sizeof(row));
            if(row.dwOwningPid==GetCurrentProcessId()&&ntohs(static_cast<u_short>(row.dwLocalPort))==port) return true;
        }
        return false;
    };
    return v6?search(MIB_TCP6ROW_OWNER_PID{},offsetof(MIB_TCP6TABLE_OWNER_PID,table)):
              search(MIB_TCPROW_OWNER_PID{},offsetof(MIB_TCPTABLE_OWNER_PID,table));
}
static void screens(const Media &m,bool v6) {
    Service f(v6,false); f.cfg.enabled_features=PROJECTION_SESSION_ALT_SCREEN; f.create();
    uint8_t key[32]{}; key[0]=91; auto main=f.open(),alt=f.open(111,key); auto p=f.provider();
    CHECK(main.lease!=alt.lease&&main.data_port!=alt.data_port);
    CHECK(listening(main.data_port,v6)&&listening(alt.data_port,v6));
    uint64_t duplicate[]={main.lease,main.lease}; CHECK(p.start(p.context,91,duplicate,2)==IAP2_INVALID&&!f.sink.starts);
    uint64_t leases[]={main.lease,alt.lease}; CHECK(p.start(p.context,91,leases,2)==IAP2_OK&&f.sink.starts==2);
    Socket first(SOCK_STREAM,v6),second(SOCK_STREAM,v6); first.connect_to(main.data_port); second.connect_to(alt.data_port);
    uint8_t main_key[32]{}; first.send_bytes(m.config); first.send_bytes(m.frame(main_key,0)); second.send_bytes(m.config); second.send_bytes(m.frame(key,0));
    f.until([&]{return f.sink.seen.size()==2;}); CHECK(f.sink.configs==2&&f.sink.seen[0].child!=f.sink.seen[1].child);
    CHECK(f.sink.seen[0].pixels==f.sink.seen[1].pixels);
    // Inspect actual kernel listener state: this Windows host can leave a new
    // connect pending after closing an exclusive listener with a live client.
    // Do not mistake a connect-notification timeout for an open listener.
    CHECK(!listening(main.data_port,v6)&&!listening(alt.data_port,v6));
    Socket reconnect(SOCK_STREAM,v6); int n=0; auto addr=address(loopback(v6),main.data_port,n);
    int result=connect(reconnect.value,reinterpret_cast<SOCKADDR*>(&addr),n);
    CHECK(result==SOCKET_ERROR); int error=WSAGetLastError();
    if(error==WSAEWOULDBLOCK) {
        fd_set writing,failed; FD_ZERO(&writing); FD_ZERO(&failed); FD_SET(reconnect.value,&writing); FD_SET(reconnect.value,&failed);
        timeval timeout{0,100000}; int ready=select(0,nullptr,&writing,&failed,&timeout); CHECK(ready>=0);
        if(ready) { n=sizeof(error); CHECK(getsockopt(reconnect.value,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&n)==0); }
    }
    CHECK(error==WSAECONNREFUSED||error==WSAEWOULDBLOCK);
    p.close(p.context,91,main.lease); CHECK(f.sink.live.size()==1&&f.sink.closed==std::vector<uint64_t>{1});
    second.send_bytes(m.frame(key,1,3)); f.until([&]{return f.sink.seen.size()==3;}); CHECK(f.sink.seen.back().child==2&&f.sink.seen.back().counter==1);
    second.close(); f.failure(IAP2_END); CHECK(f.sink.closed==std::vector<uint64_t>({1,2}));
}
struct Audio {
    projection_audio_services s{}; Bytes storage=Bytes(3*4*256),network=Bytes(292); unsigned starts=0,submits=0,closes=0;
    explicit Audio(Service &f) {
        projection_audio_services_config c{}; c.local=f.cfg.local; c.peer=f.cfg.peer; c.clock_ns=f.cfg.clock_ns; c.clock_context=f.cfg.clock_context; c.poll_ms=2;
        projection_audio_default_config(&c.audio); c.audio.slots=4; c.audio.payload_capacity=256; c.audio.reorder_ms=0;
        c.sink={this,open,start,submit,poll,playback,close};
        CHECK(projection_audio_services_init(&s,&c,storage.data(),storage.size(),network.data(),network.size(),91)==IAP2_OK);
    }
    ~Audio() { projection_audio_services_close(&s); }
    static int open(void*,uint64_t,const projection_session_resource*,const projection_audio_format*,uint64_t *child) { *child=1; return IAP2_OK; }
    static int start(void *p,uint64_t,uint64_t) { ++static_cast<Audio*>(p)->starts; return IAP2_OK; }
    static int submit(void *p,uint64_t,uint64_t,const projection_audio_format*,const projection_audio_packet *packet) {
        CHECK(packet->size==8); ++static_cast<Audio*>(p)->submits; return IAP2_OK;
    }
    static int poll(void*,uint64_t,uint64_t,uint64_t) { return IAP2_OK; }
    static int playback(void*,uint64_t,uint64_t,projection_playback_position *out) { *out={0,0,16000,0}; return IAP2_OK; }
    static void close(void *p,uint64_t,uint64_t) { ++static_cast<Audio*>(p)->closes; }
};
struct CloseService { Service &f; ~CloseService() { projection_video_services_close(f.s); } };
static void mixed(const Media &m,const Vectors &av) {
    Service f(false,false); Audio audio(f); CloseService cleanup{f}; f.cfg.other=projection_audio_services_provider(&audio.s); f.create();
    auto video=f.open(); auto p=f.provider(); projection_session_resource q{}; q.type=100; q.connection_id=21; q.audio_format=16; q.audio_type=PROJECTION_AUDIO_MEDIA;
    projection_session_keys k{}; projection_session_endpoint e{}; CHECK(p.open(p.context,91,&q,0,&k,&e)==IAP2_OK&&e.lease!=video.lease);
    uint64_t leases[]={video.lease,e.lease}; CHECK(p.start(p.context,91,leases,2)==IAP2_OK&&audio.starts==1&&f.sink.starts==1);
    Socket phone(SOCK_STREAM),sound; phone.connect_to(video.data_port); phone.send_bytes(m.config); phone.send_bytes(m.frame(k.read,0));
    sound.datagram(audio_packet(k.read,0,0,av.at("pcm_plain")),e.data_port);
    f.until([&]{return f.sink.seen.size()==1&&audio.submits==1;});
    projection_playback_position position{}; CHECK(p.playback(p.context,91,e.lease,&position)==IAP2_OK&&position.sample_rate==16000&&!position.has_position);
    CHECK(p.playback(p.context,91,video.lease,&position)==IAP2_INVALID);
    phone.close(); f.failure(IAP2_END); CHECK(audio.closes==1&&!audio.s.count&&!audio.s.wsa);
    projection_video_services_close(f.s); CHECK(audio.closes==1);
}
static void delegate_contracts() {
    for(unsigned mode=0;mode<7;++mode) {
        Service f(false,false); SessionBackend other; CloseService cleanup{f}; f.cfg.other=other.config(true).provider;
        f.cfg.other.poll=SessionBackend::poll; f.cfg.other.next_delay=SessionBackend::next_delay; f.cfg.other.flush=SessionBackend::flush;
        f.create(); auto p=f.provider(); auto video=f.open(); projection_session_endpoint e{}; projection_session_resource q{}; q.type=100;
        projection_session_keys keys{};
        q.type=130; CHECK(p.open(p.context,91,&q,0,&keys,&e)==IAP2_UNSUPPORTED&&!other.opens); q.type=100;
        if(mode==0) other.fail_open=1;
        int r=p.open(p.context,91,&q,0,&keys,&e);
        if(mode==0) { CHECK(r==PROJECTION_VIDEO_SERVICES_CLOSED&&!e.lease&&other.live.empty()&&other.closed.size()==1&&f.sink.live.empty()); continue; }
        CHECK(r==IAP2_OK&&e.lease!=video.lease&&other.live==std::vector<uint64_t>{1});
        if(mode==6) {
            other.bad_output=6; q.type=101; projection_session_endpoint duplicate{};
            CHECK(p.open(p.context,91,&q,0,&keys,&duplicate)==PROJECTION_VIDEO_SERVICES_CLOSED&&!duplicate.lease);
            CHECK(other.live.empty()&&other.closed==std::vector<uint64_t>{1}&&f.sink.live.empty()); continue;
        }
        uint64_t leases[]={video.lease,e.lease};
        if(mode==1) other.start_error=IAP2_PROVIDER_FAILED;
        r=p.start(p.context,91,leases,2);
        if(mode==1) { CHECK(r==PROJECTION_VIDEO_SERVICES_CLOSED&&other.live.empty()&&f.sink.live.empty()); continue; }
        CHECK(r==IAP2_OK&&other.started==std::vector<uint64_t>{1});
        if(mode==2) { other.poll_error=IAP2_PROVIDER_FAILED; f.failure(IAP2_PROVIDER_FAILED); CHECK(other.live.empty()); continue; }
        if(mode==3) {
            projection_audio_flush_request request{12,34}; CHECK(p.flush(p.context,91,e.lease,&request)==IAP2_OK&&other.flushed_lease==1);
            CHECK(p.start(p.context,91,&e.lease,1)==IAP2_INVALID); CHECK(p.flush(p.context,91,e.lease,nullptr)==IAP2_OK&&other.resumes==1);
            CHECK(p.flush(p.context,91,video.lease,&request)==IAP2_INVALID);
        }
        if(mode==4) { other.playback_error=IAP2_PROVIDER_FAILED; projection_playback_position position{};
            CHECK(p.playback(p.context,91,e.lease,&position)==PROJECTION_VIDEO_SERVICES_CLOSED&&zeroed(&position,sizeof(position))&&other.live.empty()); continue; }
        auto before=f.clocks; p.close(p.context,90,video.lease); CHECK(f.sink.live.size()==1&&f.clocks==before);
        p.close(p.context,91,video.lease); CHECK(f.sink.live.empty()&&other.live.size()==1);
        p.close(p.context,91,e.lease); CHECK(other.live.empty()&&other.closed==std::vector<uint64_t>{1});
    }
}
struct Root {
    projection_services s{}; std::array<uint8_t,274> rx{},tx{}; std::array<uint8_t,256> plain{}; std::array<uint8_t,512> network{};
    explicit Root(Service &video) {
        projection_services_config c{}; projection_services_default_config(&c); c.local=video.cfg.local; c.peer=video.cfg.peer;
        c.clock_ns=video.cfg.clock_ns; c.clock_context=video.cfg.clock_context; c.ntp_origin=UINT64_C(0x1234567800000000); c.event.payload_limit=256;
        c.media=video.provider(); projection_services_storage b{rx.data(),plain.data(),tx.data(),network.data(),rx.size(),plain.size(),tx.size(),network.size()};
        CHECK(projection_services_init(&s,&c,&b,91)==IAP2_OK);
    }
    ~Root() { projection_services_close(&s); }
};
static int control(Harness &h,const Bytes &body={},const char *method="SETUP") {
    auto wire=outer(body,30,"rtsp://127.0.0.1/video",method,"application/x-apple-binary-plist"); int r=IAP2_MORE;
    for(size_t at=0;at<wire.size();) {
        size_t end=std::min(at+256,wire.size()); r=h.feed(h.frame(Bytes(wire.begin()+at,wire.begin()+end))); at=end;
        if(at<wire.size()) CHECK(r==IAP2_MORE);
    }
    return r;
}
static int available_video(void*,uint64_t gen,const projection_info_profile *p) {
    CHECK(gen==91&&p->display_count==1&&!p->audio_count&&!p->hevc); return IAP2_OK; // Synthetic output, NOT hardware readiness.
}
template<class F> static void receiver_until(Harness &h,F condition) {
    auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(!condition()) { CHECK(std::chrono::steady_clock::now()<end); CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK); if(!condition()) Sleep(1); }
}
static Bytes media_key(const Vectors &v,unsigned id) {
    auto salt=bytes("DataStream-Salt"+std::to_string(id)),label=bytes("DataStream-Output-Encryption-Key"); Bytes key(32);
    CHECK(pair_hkdf_sha512(v.at("pv_shared_secret").data(),32,salt.data(),salt.size(),label.data(),label.size(),key.data(),key.size())==IAP2_OK); return key;
}
static void receiver_integration(const Media &m,const Vectors &v,const Vectors &setup,const Vectors &sv) {
    for(unsigned mode=0;mode<3;++mode) {
        bool v6=mode==1; Service f(v6); Root root(f); Socket timing(SOCK_DGRAM,v6),events(SOCK_STREAM,v6),phone(SOCK_STREAM,v6);
        auto profile=info_fixture(1); profile.audio_count=profile.latency_count=profile.hid_count=profile.extension_count=0;
        profile.resource_count=1; profile.keep_alive_low_power=1; // Session fixture requests the root's real keepalive endpoint.
        Bytes scratch(PROJECTION_INFO_LIMIT); auto harness=std::make_unique<Harness>(v,setup); auto &h=*harness;
        projection_receiver_info_config info{}; projection_receiver_info_default_config(&info);
        info.profile=&profile; info.available=available_video; info.buffer=scratch.data(); info.capacity=scratch.size();
        CHECK(projection_receiver_enable_info(&h.s,91,&info,0)==IAP2_OK);
        projection_session_config config{projection_services_provider(&root.s),0,0}; CHECK(projection_receiver_enable_session(&h.s,91,&config,0)==IAP2_OK);
        h.pair(); CHECK(h.feed(h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT);
        h.drain(true,MFI_SAP_DRAINED);
        auto body=sv.at("session"); const Bytes encoded_port{0x11,0x69,0x79}; auto pos=std::search(body.begin(),body.end(),encoded_port.begin(),encoded_port.end()); CHECK(pos!=body.end());
        pos[1]=uint8_t(timing.port>>8); pos[2]=uint8_t(timing.port); CHECK(control(h,body)==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        events.connect_to(h.s.session.slots[0].endpoint.event_port); receiver_until(h,[&]{return root.s.connected!=0;});
        CHECK(control(h,sv.at("screen_new"))==RTSP_CHANNEL_OUTPUT&&f.sink.opens==1&&!f.sink.starts); h.drain(true,IAP2_OK);
        auto e=h.s.session.slots[1].endpoint; auto key=media_key(v,7); phone.connect_to(e.data_port); phone.send_bytes(m.config); phone.send_bytes(m.frame(key.data(),0));
        receiver_until(h,[&]{return f.sink.configs==1;}); for(unsigned i=0;i<5;++i) CHECK(projection_receiver_poll(&h.s,91,1)==IAP2_OK);
        CHECK(f.sink.seen.empty()&&!f.sink.starts);
        CHECK(control(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT&&!f.sink.starts); h.drain(true,IAP2_OK); CHECK(f.sink.starts==1);
        receiver_until(h,[&]{return f.sink.seen.size()==1;});
        if(mode==2) {
            auto bad=m.frame(key.data(),1,3); bad.back()^=1; phone.send_bytes(bad);
            int r=IAP2_OK; auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
            while(r==IAP2_OK) { CHECK(std::chrono::steady_clock::now()<end); r=projection_receiver_poll(&h.s,91,1); }
            CHECK(r==PROJECTION_RECEIVER_CLOSED&&f.sink.live.empty()&&root.s.failed&&root.s.media_count==0); h.cleared(); continue;
        }
        CHECK(control(h,sv.at("teardown_screen"),"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&f.sink.live.empty()); h.drain(true,IAP2_OK);
        body=sv.at("screen_new"); const Bytes pair{0x10,0x6e,0x10,0x07}; pos=std::search(body.begin(),body.end(),pair.begin(),pair.end()); CHECK(pos!=body.end()); pos[3]=8;
        CHECK(control(h,body)==RTSP_CHANNEL_OUTPUT&&f.sink.opens==2&&f.sink.starts==1); h.drain(true,IAP2_OK); CHECK(f.sink.starts==2);
        auto replacement=h.s.session.slots[1].endpoint; CHECK(replacement.lease!=e.lease); Socket next(SOCK_STREAM,v6); key=media_key(v,8);
        next.connect_to(replacement.data_port); next.send_bytes(m.config); next.send_bytes(m.frame(key.data(),0)); receiver_until(h,[&]{return f.sink.seen.size()==2;});
        CHECK(f.sink.seen.back().child==2&&f.sink.seen.back().counter==0);
        CHECK(control(h,{},"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&f.sink.live.empty()&&!root.s.media_count); h.drain(true,PROJECTION_RECEIVER_CLOSED); h.cleared();
        CHECK(f.sink.closed==std::vector<uint64_t>({1,2}));
    }
}
int main(int argc,char **argv) {
    try {
        CHECK(argc==6&&projection_video_services_c_api_test()); Winsock sockets; Media media(argv[1]); auto av=load_vectors(argv[4],13);
        auto v=load_vectors(argv[2],39),setup=load_vectors(argv[3],51),sv=load_vectors(argv[5],42);
        validation(); transport(media,false); transport(media,true); deadlines_and_failures(media); screens(media,false); screens(media,true);
        mixed(media,av); delegate_contracts(); receiver_integration(media,v,setup,sv);
        std::cout << "video services: real TCP/decoder IPv4+IPv6, epochs/deadlines, concurrent audio UDP, delegated FLUSH and paired/MFi SETUP/RECORD/TEARDOWN passed\n";
        return 0;
    } catch(...) { std::cerr << "Unexpected exception in video-service test\n"; return 1; }
}
