/* SPDX-License-Identifier: GPL-3.0-only; real UDP/codecs, synthetic final device. */
#include "projection_socket_fixture.h"
#include "projection_audio_fixture.h"
#include "projection_decode_sink.h"
#include "projection_pcm_output.hpp"
#include <memory>
struct Pipeline {
    uint64_t now=ms; unsigned closed=0; bool automatic=false;
    struct Device final:projection_pcm::Device {
        Pipeline& owner; projection_audio_format format; Bytes pending,data;
        uint32_t pad=0; uint64_t pos=0,released=0,start_ns=0; unsigned starts=0; bool broken=false,running=false;
        Device(Pipeline& p,const projection_audio_format& f):owner(p),format(f) { capacity=6000; frequency=uint64_t(f.clock_rate)*4; period_ns=ms; }
        ~Device() noexcept override { ++owner.closed; }
        void tick() noexcept { if(owner.automatic&&running) { uint64_t frames=(owner.now-start_ns)*format.clock_rate/1000000000;
            pos=frames*4; pad=frames<released?static_cast<uint32_t>(released-frames):0; } }
        int padding(uint32_t& n) noexcept override { tick(); n=pad; return broken?IAP2_PROVIDER_FAILED:IAP2_OK; }
        int acquire(uint32_t n,uint8_t*& p) noexcept override { pending.resize(size_t(n)*2*format.channels); p=pending.data(); return IAP2_OK; }
        int release(uint32_t n) noexcept override { data.insert(data.end(),pending.begin(),pending.end()); pad+=n; released+=n; return IAP2_OK; }
        int start() noexcept override { ++starts; running=true; start_ns=owner.now; return IAP2_OK; }
        int reset() noexcept override { pad=0; pos=released=0; running=false; return IAP2_OK; }
        int position(uint64_t& p,uint64_t& q) noexcept override { tick(); p=pos; q=owner.now; return IAP2_OK; }
    };
    std::vector<Device*> devices;
    projection_pcm::Output output{{this,open_device,clock,thread},91,100,0};
    std::unique_ptr<projection_decode_sink,decltype(&projection_decode_sink_destroy)> decoder{nullptr,projection_decode_sink_destroy};
    projection_audio_services audio{};
    Bytes storage=Bytes(3*8*8192+1,0xaa),network=Bytes(8192+36+1,0xaa);
    explicit Pipeline(bool v6=false,bool paced=false):automatic(paced) {
        projection_decode_sink_config dc{output.sink(),clock,this,100,paced?120u:0u,paced?40u:0u,static_cast<uint8_t>(paced)}; projection_decode_sink* raw=nullptr;
        CHECK(projection_decode_sink_create(&dc,91,&raw)==IAP2_OK); decoder.reset(raw);
        projection_audio_services_config cfg{}; cfg.local=cfg.peer=loopback(v6); cfg.clock_ns=clock; cfg.clock_context=this; cfg.poll_ms=2;
        cfg.sink=projection_decode_sink_provider(decoder.get()); projection_audio_default_config(&cfg.audio);
        cfg.audio.slots=paced?64:8; cfg.audio.payload_capacity=8192; cfg.audio.reorder_ms=10;
        if(paced) storage.resize(3*64*8192+1,0xaa);
        CHECK(projection_audio_services_init(&audio,&cfg,storage.data(),storage.size(),network.data(),network.size(),91)==IAP2_OK);
    }
    ~Pipeline() { projection_audio_services_close(&audio); }
    static bool thread(void*) noexcept { return true; }
    static uint64_t clock(void* p) noexcept { return static_cast<Pipeline*>(p)->now; }
    static int open_device(void* p,const projection_audio_format& f,uint32_t,projection_pcm::Device*& out) noexcept {
        auto& s=*static_cast<Pipeline*>(p); auto device=new Device(s,f); s.devices.push_back(device); out=device; return IAP2_OK;
    }
    projection_session_endpoint open(unsigned type,uint32_t bit,uint32_t latency=0) {
        projection_session_resource q{}; q.type=type; q.audio_format=bit; q.audio_type=PROJECTION_AUDIO_MEDIA; q.audio_latency_ms=latency;
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
static void flush_codecs(const Vectors& v) {
    struct Case { const char* name; uint32_t bit,duration,count; };
    for(bool rendered:{false,true}) for(auto c:{Case{"aac44100",0x400000,1024,2},Case{"aac48000",0x800000,1024,2},Case{"opus20",0x10000000,960,1},Case{"opus120",0x40000000,5760,1}}) {
        auto owner=std::make_unique<Pipeline>(); auto& f=*owner; Socket phone; auto e=f.open(100,c.bit); auto device=f.devices[0];
        auto p=projection_audio_services_provider(&f.audio); CHECK(p.flush); uint8_t key[32]; std::fill(key,key+32,9); std::vector<Bytes> packets;
        for(unsigned i=0;i<c.count;++i) { packets.push_back(v.at(std::string(c.name)+"_"+std::to_string(i)));
            phone.datagram(audio_packet(key,i,UINT32_MAX-10000+i*c.duration,packets.back()),e.data_port); }
        f.until([&]{return f.audio.slots[0].audio.count==c.count;}); f.start(e.lease); f.now+=10*ms;
        f.until([&]{return !f.audio.slots[0].audio.count;}); if(rendered) f.until([&]{return device->starts!=0;});
        projection_audio_flush_request q{UINT32_MAX,65535};
        auto before=snapshot(f.audio); CHECK(p.flush(p.context,92,e.lease,&q)==IAP2_INVALID&&snapshot(f.audio)==before);
        CHECK(p.flush(p.context,91,e.lease,&q)==IAP2_OK&&!f.audio.slots[0].started&&f.audio.slots[0].flushing);
        CHECK(!device->pad&&!device->pos&&zeroed(f.storage.data(),f.audio.stream_bytes));
        CHECK(Bytes(f.audio.slots[0].audio.key,f.audio.slots[0].audio.key+32)==Bytes(key,key+32)&&f.audio.slots[0].peer_port==phone.port);
        CHECK(p.start(p.context,91,&e.lease,1)==IAP2_INVALID);
        projection_playback_position pos{}; CHECK(p.playback(p.context,91,e.lease,&pos)==IAP2_OK&&!pos.has_position);
        phone.datagram(audio_packet(key,c.count-1,0,packets[0]),e.data_port); CHECK(f.poll()==IAP2_OK&&!f.audio.slots[0].audio.count);
        phone.datagram(audio_packet(key,c.count,UINT32_MAX-1,packets[0]),e.data_port); CHECK(f.poll()==IAP2_OK&&!f.audio.slots[0].audio.count);
        for(unsigned i=0;i<c.count;++i) phone.datagram(audio_packet(key,c.count+1+i,i*c.duration,packets[i],static_cast<uint16_t>(123+i)),e.data_port);
        f.until([&]{return f.audio.slots[0].audio.count==c.count;}); auto log=device->data; unsigned starts=device->starts;
        CHECK(f.poll()==IAP2_OK&&device->data==log&&device->starts==starts);
        CHECK(p.flush(p.context,91,e.lease,nullptr)==IAP2_OK); f.now+=10*ms;
        auto pcm=expected(c.bit,packets,0,c.duration);
        f.until([&]{return device->data.size()==log.size()+pcm.size();}); CHECK(device->starts==starts+1);
        CHECK(Bytes(device->data.begin()+log.size(),device->data.end())==pcm); // Fresh codec history, including AAC priming.
        device->pos=4; ++f.now;
        CHECK(p.playback(p.context,91,e.lease,&pos)==IAP2_OK&&pos.has_position&&pos.sample_time==(c.count==2?1025u:1u));
        p.close(p.context,91,e.lease); CHECK(f.closed==1&&!f.audio.wsa);
    }
}
static void sustained_loss(const Vectors& v) {
    for(bool ipv6:{false,true}) for(bool aac:{false,true}) {
        auto owner=std::make_unique<Pipeline>(ipv6,true); auto& f=*owner; Socket phone(SOCK_DGRAM,ipv6);
        uint32_t bit=aac?0x400000:0x10000000,duration=aac?1024:960,rate=aac?44100:48000,start=UINT32_MAX-999;
        const unsigned count=160; auto e=f.open(100,bit,100); auto d=f.devices[0]; auto p=projection_audio_services_provider(&f.audio);
        f.start(e.lease); uint64_t beginning=f.now; unsigned sent=0,source_positions=0,concealed_positions=0; uint8_t key[32]; std::fill(key,key+32,9);
        auto packet=[&](unsigned i) { return audio_packet(key,i,start+i*duration,v.at(std::string(aac?"aac44100_":"opus20_")+std::to_string(i%5))); };
        uint64_t finish=uint64_t(count)*duration*1000000000/rate+200*ms;
        for(uint64_t elapsed=0;elapsed<=finish;elapsed+=ms) {
            f.now=beginning+elapsed;
            if(sent<count&&elapsed>=uint64_t(sent)*duration*1000000000/rate) {
                for(unsigned end=std::min(count,sent+5);sent<end;++sent) {
                    if(sent==17||sent==67) continue;
                    phone.datagram(packet(sent),e.data_port);
                    f.until([&]{return f.audio.slots[0].audio.received&&f.audio.slots[0].audio.highest==sent;});
                    if(sent==70) { auto seen=f.audio.slots[0].audio.seen; phone.datagram(packet(17),e.data_port);
                        CHECK(f.poll()==IAP2_OK&&f.audio.slots[0].audio.highest==sent&&f.audio.slots[0].audio.seen==seen); }
                }
            }
            CHECK(f.poll()==IAP2_OK); projection_playback_position observed{};
            CHECK(p.playback(p.context,91,e.lease,&observed)==IAP2_OK);
            if(elapsed<100*ms) CHECK(!d->starts&&!observed.has_position);
            uint64_t frame=d->pos/4;
            if(d->running&&frame&&frame<d->released) {
                uint64_t source_frame=frame+(aac?1024:0),index=source_frame/duration;
                bool concealed=index==17||index==67||(aac&&(index==18||index==68));
                if(concealed) { CHECK(!observed.has_position); ++concealed_positions; }
                else { CHECK(observed.has_position&&observed.sample_time==start+static_cast<uint32_t>(source_frame)); ++source_positions; }
            }
        }
        CHECK(sent==count&&d->starts==1&&source_positions>1000&&concealed_positions>30);
        CHECK(d->data.size()==size_t(count-(aac?1:0))*duration*(aac?4:2)&&!f.audio.slots[0].audio.count);
        CHECK(f.audio.slots[0].audio.highest==count-1&&f.audio.slots[0].peer_port==phone.port);
        p.close(p.context,91,e.lease); CHECK(f.closed==1&&!f.audio.wsa); Socket reuse(SOCK_DGRAM,ipv6,1,e.data_port);
    }
}
int main(int argc,char** argv) {
    try { CHECK(argc==2); Winsock wsa; auto v=load_vectors(argv[1],33); codecs(v,false); codecs(v,true); failures(v); flush_codecs(v); sustained_loss(v);
        std::cout<<"PASS: 5 decode service groups; real IPv4/IPv6 authenticated UDP, AAC/Opus, sustained timed loss recovery, flush epochs and device-clock seam; no physical playback\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
