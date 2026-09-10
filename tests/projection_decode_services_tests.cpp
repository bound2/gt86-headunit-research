/* SPDX-License-Identifier: GPL-3.0-only; real UDP/codecs, synthetic final device. */
#include "projection_socket_fixture.h"
#include "projection_audio_fixture.h"
#include "projection_decode_sink.h"
#include "projection_pcm_output.hpp"
#include <memory>
struct Pipeline {
    uint64_t now=ms; unsigned closed=0;
    struct Device final:projection_pcm::Device {
        Pipeline& owner; projection_audio_format format; Bytes pending,data;
        uint32_t pad=0; uint64_t pos=0; unsigned starts=0; bool broken=false;
        Device(Pipeline& p,const projection_audio_format& f):owner(p),format(f) { capacity=6000; frequency=uint64_t(f.clock_rate)*4; period_ns=ms; }
        ~Device() noexcept override { ++owner.closed; }
        int padding(uint32_t& n) noexcept override { n=pad; return broken?IAP2_PROVIDER_FAILED:IAP2_OK; }
        int acquire(uint32_t n,uint8_t*& p) noexcept override { pending.resize(size_t(n)*2*format.channels); p=pending.data(); return IAP2_OK; }
        int release(uint32_t n) noexcept override { data.insert(data.end(),pending.begin(),pending.end()); pad+=n; return IAP2_OK; }
        int start() noexcept override { ++starts; return IAP2_OK; }
        int reset() noexcept override { pad=0; pos=0; return IAP2_OK; }
        int position(uint64_t& p,uint64_t& q) noexcept override { p=pos; q=owner.now; return IAP2_OK; }
    };
    std::vector<Device*> devices;
    projection_pcm::Output output{{this,open_device,clock,thread},91,100,0};
    std::unique_ptr<projection_decode_sink,decltype(&projection_decode_sink_destroy)> decoder{nullptr,projection_decode_sink_destroy};
    projection_audio_services audio{};
    Bytes storage=Bytes(3*8*8192+1,0xaa),network=Bytes(8192+36+1,0xaa);
    explicit Pipeline(bool v6=false) {
        projection_decode_sink_config dc{output.sink(),clock,this,100}; projection_decode_sink* raw=nullptr;
        CHECK(projection_decode_sink_create(&dc,91,&raw)==IAP2_OK); decoder.reset(raw);
        projection_audio_services_config cfg{}; cfg.local=cfg.peer=loopback(v6); cfg.clock_ns=clock; cfg.clock_context=this; cfg.poll_ms=2;
        cfg.sink=projection_decode_sink_provider(decoder.get()); projection_audio_default_config(&cfg.audio);
        cfg.audio.slots=8; cfg.audio.payload_capacity=8192; cfg.audio.reorder_ms=10;
        CHECK(projection_audio_services_init(&audio,&cfg,storage.data(),storage.size(),network.data(),network.size(),91)==IAP2_OK);
    }
    ~Pipeline() { projection_audio_services_close(&audio); }
    static bool thread(void*) noexcept { return true; }
    static uint64_t clock(void* p) noexcept { return static_cast<Pipeline*>(p)->now; }
    static int open_device(void* p,const projection_audio_format& f,uint32_t,projection_pcm::Device*& out) noexcept {
        auto& s=*static_cast<Pipeline*>(p); auto device=new Device(s,f); s.devices.push_back(device); out=device; return IAP2_OK;
    }
    projection_session_endpoint open(unsigned type,uint32_t bit) {
        projection_session_resource q{}; q.type=type; q.audio_format=bit; q.audio_type=PROJECTION_AUDIO_MEDIA;
        projection_session_keys keys{}; std::fill(keys.read,keys.read+32,9); auto provider=projection_audio_services_provider(&audio);
        projection_session_endpoint e{}; CHECK(provider.open(provider.context,91,&q,0,&keys,&e)==IAP2_OK&&e.lease); return e;
    }
    void start(uint64_t lease) { auto p=projection_audio_services_provider(&audio); CHECK(p.start(p.context,91,&lease,1)==IAP2_OK); }
    int poll() { return projection_audio_services_poll(&audio,91); }
    template<class F> void until(F condition) {
        auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(!condition()) { CHECK(std::chrono::steady_clock::now()<end); CHECK(poll()==IAP2_OK); if(!condition()) Sleep(1); }
    }
    void cleared() {
        CHECK(audio.failed&&!audio.count&&!audio.wsa&&closed==devices.size());
        for(auto& slot:audio.slots) CHECK(!slot.occupied&&zeroed(slot.audio.key,32)&&slot.data_socket==static_cast<uintptr_t>(INVALID_SOCKET));
        CHECK(zeroed(network.data(),network.size()-1)&&network.back()==0xaa);
        projection_audio_services_close(&audio); CHECK(zeroed(storage.data(),storage.size()-1)&&storage.back()==0xaa);
    }
};
static Bytes expected(uint32_t bit,const std::vector<Bytes>& packets,uint32_t sample,uint32_t duration) {
    projection_decode* raw=nullptr; CHECK(projection_decode_create(bit,91,&raw)==IAP2_OK);
    std::unique_ptr<projection_decode,decltype(&projection_decode_destroy)> decoder(raw,projection_decode_destroy); Bytes result;
    for(size_t i=0;i<packets.size();++i) { projection_audio_packet p{}; p.data=packets[i].data(); p.size=packets[i].size(); p.counter=i; p.sample_time=sample+uint32_t(i)*duration;
        projection_decoded_audio out{}; CHECK(projection_decode_packet(raw,91,&p,&out)==IAP2_OK);
        for(size_t j=0;j<size_t(out.frames)*out.channels;++j) { auto n=static_cast<uint16_t>(out.samples[j]); result.push_back(static_cast<uint8_t>(n)); result.push_back(static_cast<uint8_t>(n>>8)); }
    } return result;
}
static void codecs(const Vectors& v,bool v6) {
    struct Case { const char* name; uint32_t bit,duration,count; };
    for(auto c:{Case{"aac44100",0x400000,1024,5},Case{"aac48000",0x800000,1024,5},Case{"opus20",0x10000000,960,5},Case{"opus120",0x40000000,5760,1}}) {
        auto owner=std::make_unique<Pipeline>(v6); auto& f=*owner; Socket phone(SOCK_DGRAM,v6); auto e=f.open(100,c.bit); auto device=f.devices[0];
        std::vector<Bytes> packets; uint32_t sample=UINT32_MAX-511; uint8_t key[32]; std::fill(key,key+32,9);
        for(unsigned i=0;i<c.count;++i) packets.push_back(v.at(std::string(c.name)+"_"+std::to_string(i)));
        // Arrive out of order, including before RECORD's media start gate.
        for(unsigned i=c.count;i>0;--i) phone.datagram(audio_packet(key,i-1,sample+(i-1)*c.duration,packets[i-1],static_cast<uint16_t>(i-1)),e.data_port);
        f.until([&]{return f.audio.slots[0].audio.count==c.count;}); CHECK(!device->starts&&device->data.empty()); f.start(e.lease); f.now+=10*ms;
        auto pcm=expected(c.bit,packets,sample,c.duration); CHECK(!pcm.empty());
        f.until([&]{return device->data.size()==pcm.size();}); CHECK(device->data==pcm&&device->starts==1&&!f.audio.slots[0].audio.count);
        auto p=projection_audio_services_provider(&f.audio); projection_playback_position pos{};
        CHECK(p.playback(p.context,91,e.lease,&pos)==IAP2_OK&&!pos.has_position); // Decoding is not observed playback.
        device->pos=4; f.now+=ms;
        uint32_t origin=sample+(c.bit<0x10000000?1024u:0u); // FAAD's first raw AU primes, not played.
        CHECK(p.playback(p.context,91,e.lease,&pos)==IAP2_OK&&pos.has_position&&pos.sample_time==origin+1&&pos.sample_rate==device->format.clock_rate&&pos.raw_ns==f.now);
        p.close(p.context,91,e.lease); CHECK(f.closed==1&&!f.audio.count&&!f.audio.wsa); Socket reuse(SOCK_DGRAM,v6,1,e.data_port);
    }
}
static void failures(const Vectors& v) {
    for(unsigned fault=0;fault<4;++fault) {
        auto owner=std::make_unique<Pipeline>(); auto& f=*owner; Socket phone; auto a=f.open(100,0x10000000),b=f.open(101,0x800000),c=f.open(102,0x400000);
        f.start(a.lease); f.start(b.lease); f.start(c.lease); uint8_t key[32]; std::fill(key,key+32,9);
        phone.datagram(audio_packet(key,0,0,v.at("opus20_0")),a.data_port); f.until([&]{return f.audio.slots[0].audio.count==1;}); f.now+=10*ms;
        f.until([&]{return f.devices[0]->starts==1;});
        if(fault==0) f.devices[0]->broken=true;
        if(fault==1) phone.datagram(audio_packet(key,1,961,v.at("opus20_1")),a.data_port); // Missing timestamp range: no guessed PLC.
        if(fault==2) phone.datagram(audio_packet(key,1,960,{0xff}),a.data_port); // Authenticated, invalid codec syntax.
        if(fault==3) --f.now;
        int r=IAP2_OK; auto end=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(r==IAP2_OK) { CHECK(std::chrono::steady_clock::now()<end); r=f.poll(); }
        CHECK(r==PROJECTION_AUDIO_CLOSED); f.cleared(); Socket reuse(SOCK_DGRAM,false,1,a.data_port);
    }
}
int main(int argc,char** argv) {
    try { CHECK(argc==2); Winsock wsa; auto v=load_vectors(argv[1],33); codecs(v,false); codecs(v,true); failures(v);
        std::cout<<"PASS: 3 decode service groups; real IPv4/IPv6 authenticated UDP, AAC/Opus, PCM ownership and device-clock seam; no physical playback\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
