/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_pcm_output.hpp"
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do { if(!(x)) throw std::runtime_error(std::string(__func__)+":"+std::to_string(__LINE__)+": " #x); } while(0)
using projection_pcm::Device;
using projection_pcm::Output;
static constexpr uint64_t ms=1000000;
struct Fixture;
struct Mock final:Device {
    Fixture& f; std::vector<uint8_t> buffer,emitted;
    uint32_t pad=0,acquired=0; uint64_t pos=0,qpc=0;
    int starts=0,resets=0,paddings=0,positions=0;
    int bad_padding=0,bad_acquire=0,bad_release=0,bad_start=0,bad_reset=0,bad_position=0;
    bool null_buffer=false; uint64_t release_delay=0;
    explicit Mock(Fixture&,uint32_t);
    ~Mock() noexcept override;
    int padding(uint32_t& n) noexcept override { ++paddings; n=pad; return bad_padding; }
    int acquire(uint32_t n,uint8_t*& p) noexcept override {
        acquired=n; buffer.resize(size_t(n)*4); p=null_buffer?nullptr:buffer.data(); return bad_acquire;
    }
    int release(uint32_t n) noexcept override;
    int start() noexcept override { ++starts; return bad_start; }
    int reset() noexcept override { ++resets; pos=pad=0; return bad_reset; }
    int position(uint64_t& p,uint64_t& q) noexcept override;
};
struct Fixture {
    uint64_t now=100*ms; int opened=0,closed=0,open_error=0; bool thread=true,partial=true;
    uint32_t device_capacity=800; uint64_t device_frequency=32000,device_period=5*ms;
    std::unique_ptr<Output> output;
    projection_audio_sink api{}; projection_audio_format format{}; uint64_t lease=0;
    Mock *last=nullptr;
    explicit Fixture(uint32_t startup=0,uint32_t bit=4) {
        CHECK(projection_audio_format_get(bit,&format)==IAP2_OK);
        output=std::make_unique<Output>(projection_pcm::Bindings{this,open,clock,on_thread},91,100,startup);
        api=output->sink();
    }
    ~Fixture() { output.reset(); }
    static bool on_thread(void* p) noexcept { return static_cast<Fixture*>(p)->thread; }
    static uint64_t clock(void* p) noexcept { return static_cast<Fixture*>(p)->now; }
    static int open(void* p,const projection_audio_format& f,uint32_t,Device*& d) noexcept {
        auto& h=*static_cast<Fixture*>(p); ++h.opened;
        d=nullptr; if(!h.open_error||h.partial) { h.last=new Mock(h,f.clock_rate); d=h.last; }
        return h.open_error;
    }
    int prepare(uint32_t type=100,uint64_t *out=nullptr) {
        projection_session_resource r{}; r.type=type; r.audio_format=format.bit;
        return api.open(api.context,91,&r,&format,out?out:&lease);
    }
    void ready() { CHECK(prepare()==IAP2_OK&&lease); CHECK(api.start(api.context,91,lease)==IAP2_OK); }
    int submit(uint32_t sample,size_t frames=100,uint8_t high=0x12,uint8_t low=0x34) {
        std::vector<uint8_t> data(frames*2*format.channels);
        for(size_t i=0;i<data.size();i+=2) { data[i]=high; data[i+1]=low; }
        projection_audio_packet p{}; p.data=data.data(); p.size=data.size(); p.frames=static_cast<uint32_t>(frames); p.sample_time=sample;
        return api.submit(api.context,91,lease,&format,&p);
    }
    int poll() { return api.poll(api.context,91,lease,now); }
    projection_playback_position observe() {
        projection_playback_position p{}; CHECK(api.playback(api.context,91,lease,&p)==IAP2_OK); return p;
    }
};
Mock::Mock(Fixture& owner,uint32_t):f(owner) { capacity=f.device_capacity; frequency=f.device_frequency; period_ns=f.device_period; }
Mock::~Mock() noexcept { ++f.closed; }
int Mock::release(uint32_t n) noexcept {
    f.now+=release_delay; pad+=n; emitted.insert(emitted.end(),buffer.begin(),buffer.begin()+size_t(n)*2*f.format.channels); return bad_release;
}
int Mock::position(uint64_t& p,uint64_t& q) noexcept { ++positions; p=pos; q=qpc?qpc:f.now; return bad_position; }
static void arithmetic() {
    uint64_t n=99;
    CHECK(projection_pcm::scale(7,3,2,n)&&n==4);
    CHECK(projection_pcm::scale(UINT64_MAX,1000000000,48000,n)&&n==885443715538058);
    CHECK(projection_pcm::scale(UINT64_MAX,1,1,n)&&n==UINT64_MAX);
    CHECK(!projection_pcm::scale(UINT64_MAX,1,2,n)&&n==UINT64_MAX);
    CHECK(!projection_pcm::scale(1,UINT64_MAX,48000,n));
    CHECK(!projection_pcm::scale(1,0,48000,n)&&!projection_pcm::scale(1,1,0,n));
}
static void startup_and_pcm() {
    Fixture f(20); CHECK(f.prepare()==IAP2_OK); auto& d=*f.last;
    CHECK(!f.observe().has_position&&f.observe().sample_rate==8000);
    CHECK(f.submit(0)==IAP2_INVALID&&d.starts==0);
    CHECK(f.api.start(f.api.context,91,f.lease)==IAP2_OK);
    CHECK(f.api.start(f.api.context,91,f.lease)==IAP2_INVALID);
    CHECK(f.submit(UINT32_MAX-49,100)==IAP2_OK);
    CHECK(f.poll()==IAP2_MORE&&!d.starts);
    f.now+=19*ms; CHECK(f.poll()==IAP2_MORE);
    f.now+=ms; CHECK(f.poll()==IAP2_OK&&d.starts==1&&d.emitted.size()==200);
    for(size_t i=0;i<d.emitted.size();i+=2) CHECK(d.emitted[i]==0x34&&d.emitted[i+1]==0x12);
    CHECK(!f.observe().has_position); // Device zero is not a played sample.
    d.pos=240; f.now+=ms; auto p=f.observe(); // frequency=32000, not frames/sec.
    CHECK(p.has_position&&p.sample_time==10&&p.raw_ns==f.now&&p.sample_rate==8000);
    CHECK(f.submit(50,0)==IAP2_OK); // No timestamp/queue mutation on empty payload.
    CHECK(f.submit(50,100)==IAP2_OK);
    CHECK(f.submit(999,100)==IAP2_UNSUPPORTED&&f.closed==1); // Never splice a false timeline.
    f.api.close(f.api.context,91,f.lease); CHECK(f.closed==1);
}
static void queue_and_wrap() {
    Fixture f; f.ready(); uint32_t sample=0;
    for(int i=0;i<8;++i) { CHECK(f.submit(sample,4096)==IAP2_OK); sample+=4096; }
    CHECK(f.submit(sample,1)==IAP2_MORE);
    CHECK(f.poll()==IAP2_OK&&f.last->acquired==800);
    CHECK(f.submit(sample,800,0x56,0x78)==IAP2_OK); sample+=800;
    auto& d=*f.last;
    // Advance through enough real device periods to cross the queue ring edge.
    for(int i=0;i<90;++i) {
        f.now+=50*ms; d.pos+=1600; d.pad=400;
        CHECK(f.poll()==IAP2_OK);
        CHECK(f.submit(sample,400)==IAP2_OK); sample+=400;
    }
    CHECK(d.emitted.size()>65536);
    CHECK(d.emitted[65536]==0x78&&d.emitted[65537]==0x56);
    CHECK(f.api.poll(f.api.context,92,f.lease,UINT64_MAX)==IAP2_INVALID);
}
static void drain_and_restart() {
    Fixture f; f.ready(); CHECK(f.submit(1000,800)==IAP2_OK&&f.poll()==IAP2_OK);
    auto& d=*f.last; CHECK(f.submit(1800,200)==IAP2_OK);
    d.pad=40; d.pos=2800; f.now+=90*ms;
    CHECK(f.poll()==IAP2_MORE&&d.emitted.size()==1600&&d.starts==1);
    auto p=f.observe(); CHECK(p.has_position&&p.sample_time==1700);
    d.pad=0; d.pos=3200; f.now+=20*ms;
    CHECK(!f.observe().has_position); // Exact end cannot claim an unsupplied sample.
    CHECK(f.poll()==IAP2_OK&&d.resets==1&&d.starts==2&&d.emitted.size()==2000);
    CHECK(!f.observe().has_position);
    d.pos=400; f.now+=15*ms; p=f.observe(); CHECK(p.has_position&&p.sample_time==1900);
    d.pos=800; d.pad=0; f.now+=20*ms; CHECK(f.poll()==IAP2_MORE&&d.resets==2);
    CHECK(f.submit(90000,100)==IAP2_OK&&f.poll()==IAP2_OK); // Explicit idle epoch permits new origin.
    d.pos=4; f.now+=ms; p=f.observe(); CHECK(p.has_position&&p.sample_time==90001);
}
static void cleanup_and_failure() {
    for(int fault=0;fault<8;++fault) {
        Fixture f; f.ready(); uint64_t sibling=0; CHECK(f.prepare(101,&sibling)==IAP2_OK);
        f.api.close(f.api.context,91,sibling); CHECK(f.closed==1);
        f.api.close(f.api.context,91,f.lease); CHECK(f.closed==2);
        CHECK(f.prepare()==IAP2_OK); CHECK(f.api.start(f.api.context,91,f.lease)==IAP2_OK);
        auto& d=*f.last;
        CHECK(f.submit(1000,800)==IAP2_OK);
        if(fault==0) d.bad_padding=IAP2_PROVIDER_FAILED;
        if(fault==1) d.bad_acquire=IAP2_PROVIDER_FAILED;
        if(fault==2) d.bad_release=IAP2_PROVIDER_FAILED;
        if(fault==3) d.bad_start=IAP2_PROVIDER_FAILED;
        if(fault==4) d.null_buffer=true;
        if(fault<=4) CHECK(f.poll()==IAP2_PROVIDER_FAILED&&f.closed==3);
        else {
            CHECK(f.poll()==IAP2_OK);
            if(fault==5) { d.bad_position=IAP2_PROVIDER_FAILED; CHECK(f.poll()==IAP2_PROVIDER_FAILED); }
            if(fault==6) { d.pos=3200; d.bad_reset=IAP2_PROVIDER_FAILED; CHECK(f.poll()==IAP2_PROVIDER_FAILED); }
            if(fault==7) {
                d.pad=400; d.pos=1600; d.release_delay=d.period_ns;
                CHECK(f.submit(1800,400)==IAP2_OK&&f.poll()==IAP2_PROVIDER_FAILED);
            }
            CHECK(f.closed==3);
        }
        f.api.close(f.api.context,91,f.lease); CHECK(f.closed==3);
        CHECK(f.prepare()==IAP2_ARGUMENT);
    }
    for(bool partial:{false,true}) {
        Fixture f; f.ready(); f.open_error=IAP2_PROVIDER_FAILED; f.partial=partial;
        uint64_t child=99; CHECK(f.prepare(101,&child)==IAP2_PROVIDER_FAILED&&!child&&f.closed==(partial?2:1));
    }
    Fixture f; f.ready(); auto old=f.lease;
    f.api.close(f.api.context,92,old); CHECK(f.closed==0);
    f.api.close(f.api.context,91,old); CHECK(f.closed==1);
    CHECK(f.prepare()==IAP2_OK&&f.lease>old);
    f.api.close(f.api.context,91,old); CHECK(f.closed==1);
}
static void observations() {
    for(int fault=0;fault<6;++fault) {
        Fixture f; f.ready(); CHECK(f.submit(0,800)==IAP2_OK&&f.poll()==IAP2_OK); auto& d=*f.last;
        d.pos=4; f.now+=ms; CHECK(f.observe().has_position);
        if(fault==0) d.qpc=f.now+1;
        if(fault==1) d.qpc=1;
        if(fault==2) d.pos=3;
        if(fault==3) { f.now+=ms; d.qpc=f.now-2*ms; }
        if(fault==4) f.now=0;
        if(fault==5) f.now=UINT64_MAX;
        projection_playback_position p{1,2,3,1};
        CHECK(f.api.playback(f.api.context,91,f.lease,&p)==IAP2_PROVIDER_FAILED&&f.closed==1&&!p.has_position&&!p.raw_ns);
    }
    Fixture f; f.ready(); CHECK(f.submit(7,800)==IAP2_OK&&f.poll()==IAP2_OK);
    f.last->bad_position=IAP2_MORE; CHECK(!f.observe().has_position&&f.observe().sample_rate==8000&&f.closed==0);
    f.last->bad_position=0; f.last->pos=UINT64_MAX; CHECK(!f.observe().has_position);
}
static void validation() {
    Fixture f; f.ready(); auto& d=*f.last;
    uint64_t duplicate=99; CHECK(f.prepare(100,&duplicate)==IAP2_INVALID&&!duplicate&&f.opened==1);
    projection_audio_packet p{}; p.size=1; uint8_t b=0; p.data=&b;
    CHECK(f.api.submit(f.api.context,91,f.lease,&f.format,&p)==IAP2_INVALID);
    p.size=2; p.data=nullptr; p.frames=1;
    CHECK(f.api.submit(f.api.context,91,f.lease,&f.format,&p)==IAP2_INVALID);
    p={}; CHECK(f.api.submit(f.api.context,91,f.lease,&f.format,&p)==IAP2_OK);
    f.thread=false; CHECK(f.submit(1)==IAP2_INVALID&&d.starts==0); f.thread=true;
    for(uint32_t bit:{0x400000u,0x800000u,0x10000000u}) { Fixture c(0,bit); CHECK(c.prepare()==IAP2_UNSUPPORTED&&c.opened==0); }
    for(int bad=0;bad<5;++bad) {
        Fixture c;
        if(bad==0) c.device_capacity=0;
        if(bad==1) c.device_capacity=48001;
        if(bad==2) c.device_frequency=UINT64_MAX;
        if(bad==3) c.device_period=UINT64_MAX;
        if(bad==4) c.device_capacity=160;
        CHECK(c.prepare()==IAP2_UNSUPPORTED&&c.closed==1&&!c.lease);
    }
    for(uint32_t bit:{4u,8u,16u,32u,64u,128u,256u,512u,1024u,2048u,16384u,32768u}) {
        Fixture c(0,bit); c.device_capacity=c.format.clock_rate/10; c.device_frequency=c.format.clock_rate;
        c.ready(); CHECK(c.submit(17,64,0x80,0)==IAP2_OK&&c.poll()==IAP2_OK);
        CHECK(c.last->emitted.size()==128*c.format.channels&&c.last->emitted[0]==0&&c.last->emitted[1]==0x80);
    }
}
int main() {
    try {
        arithmetic(); startup_and_pcm(); queue_and_wrap(); drain_and_restart(); cleanup_and_failure(); observations(); validation();
        std::cout<<"PASS: 7 PCM output groups; device seam is synthetic, no speaker/microphone access.\n";
        std::cout<<"x64 PCM output owner bytes: "<<sizeof(Output)<<" (includes three 65536-byte queues; device/OS allocations additional)\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
