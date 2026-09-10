/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_test_support.h"
#include "projection_decode_sink.h"
#include <iomanip>
static constexpr uint64_t ms=1000000;
static Vectors vectors;
struct Decoder {
    projection_decode *p=nullptr; projection_audio_format format{};
    explicit Decoder(uint32_t bit) { CHECK(projection_audio_format_get(bit,&format)==IAP2_OK); CHECK(projection_decode_create(bit,91,&p)==IAP2_OK&&p); }
    ~Decoder() { projection_decode_destroy(p); }
    int decode(const Bytes& data,uint64_t counter,uint32_t sample,projection_decoded_audio& out) {
        projection_audio_packet packet{}; packet.data=data.data(); packet.size=data.size(); packet.counter=counter; packet.sample_time=sample;
        if(format.codec==PROJECTION_AUDIO_PCM16) packet.frames=static_cast<uint32_t>(data.size()/(2*format.channels));
        return projection_decode_packet(p,91,&packet,&out);
    }
};
static Bytes pcm_bytes(const projection_decoded_audio& out,bool big=false) {
    Bytes bytes; for(size_t i=0;i<size_t(out.frames)*out.channels;++i) {
        auto v=static_cast<uint16_t>(out.samples[i]);
        bytes.push_back(static_cast<uint8_t>(big?v>>8:v)); bytes.push_back(static_cast<uint8_t>(big?v:v>>8));
    } return bytes;
}
static void packets(bool emit) {
    struct Case { const char* name; uint32_t bit,duration,count; };
    for(auto c:{Case{"aac44100",0x400000,1024,5},Case{"aac48000",0x800000,1024,5},Case{"opus20",0x10000000,960,5},Case{"opus120",0x40000000,5760,3},
                Case{"aac44100_np",0x400000,1024,5},Case{"aac48000_np",0x800000,1024,5},Case{"opus20_celt",0x40000000,960,5}}) {
        Decoder d(c.bit); uint32_t sample=UINT32_MAX-511;
        for(uint32_t i=0;i<c.count;++i) {
            std::string name=std::string(c.name)+"_"+std::to_string(i); projection_decoded_audio out{};
            CHECK(d.decode(vectors.at(name),i,sample,out)==IAP2_OK);
            bool priming=d.format.codec==PROJECTION_AUDIO_AAC_LC&&i==0;
            CHECK(out.duration==c.duration&&out.frames==(priming?0u:c.duration)&&out.priming==static_cast<uint8_t>(priming)&&out.sample_time==sample&&out.channels==d.format.channels);
            if(out.frames) { int peak=0; for(size_t n=0;n<size_t(out.frames)*out.channels;++n) peak=std::max(peak,std::abs(int(out.samples[n]))); CHECK(peak>1000); }
            if(emit) { std::cout<<name<<'='<<std::hex<<std::setfill('0'); for(auto b:pcm_bytes(out)) std::cout<<std::setw(2)<<unsigned(b); std::cout<<std::dec<<'\n'; }
            auto borrowed=out.samples; auto count=size_t(out.frames)*out.channels;
            CHECK(projection_decode_discard(d.p,92)==IAP2_INVALID);
            CHECK(projection_decode_discard(d.p,91)==IAP2_OK&&(!borrowed||zeroed(borrowed,count*sizeof(int16_t))));
            sample+=c.duration;
        }
    }
}
static void formats_and_invalid() {
    for(uint32_t bit:{4u,8u,16u,32u,64u,128u,256u,512u,1024u,2048u,16384u,32768u,0x400000u,0x800000u,0x10000000u,0x20000000u,0x40000000u}) {
        Decoder d(bit); projection_audio_format pcm{}; CHECK(projection_decode_pcm_format(bit,&pcm)==IAP2_OK&&pcm.codec==PROJECTION_AUDIO_PCM16&&pcm.clock_rate==d.format.clock_rate&&pcm.channels==d.format.channels);
        if(d.format.codec==PROJECTION_AUDIO_PCM16) {
            projection_decoded_audio out{}; auto raw=hex("8000000000017fff");
            CHECK(d.decode(raw,1,UINT32_MAX,out)==IAP2_OK&&out.frames==4/d.format.channels&&out.duration==out.frames);
            CHECK(pcm_bytes(out)==hex("008000000100ff7f"));
            projection_audio_packet p{}; p.data=raw.data(); p.size=3;
            CHECK(projection_decode_packet(d.p,91,&p,&out)==IAP2_INVALID&&!out.samples);
            CHECK(d.decode({},2,0,out)==IAP2_OK&&!out.frames&&!out.duration&&!out.samples);
        } else if(d.format.codec==PROJECTION_AUDIO_OPUS) {
            projection_decoded_audio out{}; CHECK(d.decode(vectors.at("opus20_0"),0,1,out)==IAP2_OK&&out.frames==960&&out.channels==1);
        }
    }
    for(uint32_t bit:{0u,12u,4096u,UINT32_MAX}) { projection_decode *p=reinterpret_cast<projection_decode*>(1); CHECK(projection_decode_create(bit,91,&p)!=IAP2_OK&&!p);
        projection_audio_format out{}; std::memset(&out,0xaa,sizeof(out)); CHECK(projection_decode_pcm_format(bit,&out)!=IAP2_OK&&zeroed(&out,sizeof(out))); }
    projection_decode *p=reinterpret_cast<projection_decode*>(1); CHECK(projection_decode_create(4,0,&p)==IAP2_ARGUMENT&&!p); projection_decode_destroy(nullptr);
    for(int bad=0;bad<5;++bad) {
        Decoder d(0x10000000); projection_decoded_audio out{};
        CHECK(d.decode(vectors.at("opus20_0"),5,0,out)==IAP2_OK);
        if(bad==0) CHECK(d.decode(vectors.at("opus20_1"),5,960,out)==IAP2_UNSUPPORTED);
        if(bad==1) CHECK(d.decode(vectors.at("opus20_1"),6,961,out)==IAP2_UNSUPPORTED);
        if(bad==2) CHECK(d.decode(Bytes{3,0xff},6,960,out)==IAP2_INVALID);
        if(bad==3) { auto stereo=vectors.at("opus20_1"); stereo[0]|=4; CHECK(d.decode(stereo,6,960,out)==IAP2_INVALID); }
        if(bad==4) CHECK(d.decode(Bytes{0xff},6,960,out)==IAP2_INVALID);
        CHECK(!out.samples&&d.decode(vectors.at("opus20_1"),6,960,out)==IAP2_INVALID);
    }
    for(auto bad:{Bytes{0xff,0xf1,0,0,0,0,0},Bytes{'A','D','I','F'},Bytes{0xe0},Bytes(128,'T')}) {
        Decoder d(0x400000); projection_decoded_audio out{}; CHECK(d.decode(bad,0,0,out)==IAP2_INVALID&&!out.samples);
    }
}
struct Renderer {
    projection_audio_sink api{this,open,start,submit,poll,playback,close};
    uint64_t next=1; std::map<uint64_t,projection_audio_format> live; std::vector<uint64_t> closed;
    std::vector<Bytes> bytes; std::vector<uint32_t> samples,frames; unsigned starts=0,polls=0;
    bool busy=false; int fault=0; projection_playback_position position{};
    static int open(void* p,uint64_t gen,const projection_session_resource* r,const projection_audio_format* f,uint64_t* lease) {
        auto& s=*static_cast<Renderer*>(p); CHECK(gen==91&&f->codec==PROJECTION_AUDIO_PCM16&&r->audio_format==f->bit&&r->frames_per_packet==0);
        if(s.fault==1) return IAP2_PROVIDER_FAILED;
        *lease=s.next++; s.live[*lease]=*f; return s.fault==2?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static int start(void* p,uint64_t,uint64_t lease) { auto& s=*static_cast<Renderer*>(p); CHECK(s.live.contains(lease)); ++s.starts; return s.fault==3?IAP2_PROVIDER_FAILED:IAP2_OK; }
    static int submit(void* p,uint64_t,uint64_t lease,const projection_audio_format* f,const projection_audio_packet* packet) {
        auto& s=*static_cast<Renderer*>(p); CHECK(s.live.contains(lease)&&f->bit==s.live.at(lease).bit&&packet->frames*2*f->channels==packet->size&&packet->size<=8192);
        if(s.fault==4) return IAP2_PROVIDER_FAILED; if(s.busy) return IAP2_MORE;
        s.bytes.emplace_back(packet->data,packet->data+packet->size); s.samples.push_back(packet->sample_time); s.frames.push_back(packet->frames); return IAP2_OK;
    }
    static int poll(void* p,uint64_t,uint64_t lease,uint64_t) { auto& s=*static_cast<Renderer*>(p); CHECK(s.live.contains(lease)); ++s.polls; return s.fault==5?IAP2_PROVIDER_FAILED:IAP2_OK; }
    static int playback(void* p,uint64_t,uint64_t lease,projection_playback_position* out) {
        auto& s=*static_cast<Renderer*>(p); *out=s.position; out->sample_rate=s.live.at(lease).clock_rate; if(s.fault==7) ++out->sample_rate; return s.fault==6?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static void close(void* p,uint64_t,uint64_t lease) { auto& s=*static_cast<Renderer*>(p); CHECK(s.live.erase(lease)==1); s.closed.push_back(lease); }
};
struct Bridge {
    Renderer renderer; uint64_t now=100*ms; projection_decode_sink *p=nullptr; projection_audio_sink api{};
    projection_audio_format format{}; uint64_t lease=0;
    explicit Bridge(uint32_t bit=0x40000000) {
        CHECK(projection_audio_format_get(bit,&format)==IAP2_OK);
        projection_decode_sink_config c{renderer.api,clock,this,100}; CHECK(projection_decode_sink_create(&c,91,&p)==IAP2_OK); api=projection_decode_sink_provider(p);
    }
    ~Bridge() { projection_decode_sink_destroy(p); }
    static uint64_t clock(void* p) { return static_cast<Bridge*>(p)->now; }
    int open(uint32_t type=100,uint64_t* child=nullptr) { projection_session_resource r{}; r.type=type; r.audio_format=format.bit; return api.open(api.context,91,&r,&format,child?child:&lease); }
    void ready() { CHECK(open()==IAP2_OK&&api.start(api.context,91,lease)==IAP2_OK); }
    int submit(const Bytes& data,uint64_t counter=0,uint32_t sample=UINT32_MAX-5000) {
        projection_audio_packet q{}; q.data=data.data(); q.size=data.size(); q.counter=counter; q.sample_time=sample;
        if(format.codec==PROJECTION_AUDIO_PCM16) q.frames=static_cast<uint32_t>(data.size()/(2*format.channels));
        return api.submit(api.context,91,lease,&format,&q);
    }
    int poll() { return api.poll(api.context,91,lease,now); }
};
static void bridge_chunks() {
    Bridge b; CHECK(b.open()==IAP2_OK); CHECK(b.submit(vectors.at("opus120_0"))==IAP2_INVALID);
    CHECK(b.api.start(b.api.context,91,b.lease)==IAP2_OK);
    auto raw=vectors.at("opus120_0"); CHECK(b.submit(raw)==IAP2_OK); raw.assign(raw.size(),0xff);
    CHECK(b.submit(vectors.at("opus120_1"),1,759)==IAP2_MORE);
    b.renderer.busy=true; CHECK(b.poll()==IAP2_MORE&&b.renderer.bytes.empty());
    b.renderer.busy=false; CHECK(b.poll()==IAP2_OK&&b.renderer.frames==std::vector<uint32_t>{4096});
    CHECK(b.submit(vectors.at("opus120_1"),1,759)==IAP2_MORE);
    CHECK(b.poll()==IAP2_OK&&(b.renderer.frames==std::vector<uint32_t>{4096,1664}));
    CHECK((b.renderer.samples==std::vector<uint32_t>{UINT32_MAX-5000,UINT32_MAX-904}));
    Decoder d(0x40000000); projection_decoded_audio decoded{}; CHECK(d.decode(vectors.at("opus120_0"),0,0,decoded)==IAP2_OK);
    auto joined=b.renderer.bytes[0]; joined.insert(joined.end(),b.renderer.bytes[1].begin(),b.renderer.bytes[1].end()); CHECK(joined==pcm_bytes(decoded,true));
    CHECK(b.submit(vectors.at("opus120_1"),1,759)==IAP2_OK);
    projection_playback_position position{}; CHECK(b.api.playback(b.api.context,91,b.lease,&position)==IAP2_OK&&!position.has_position&&position.sample_rate==48000);
    b.renderer.position={b.now,777,48000,1}; CHECK(b.api.playback(b.api.context,91,b.lease,&position)==IAP2_OK&&position.sample_time==777);
    auto old=b.lease; b.api.close(b.api.context,91,old); CHECK(b.renderer.closed.size()==1);
    CHECK(b.open()==IAP2_OK&&b.lease>old); b.api.close(b.api.context,91,old); CHECK(b.renderer.closed.size()==1);
    for(auto bit:{0x400000u,0x800000u}) {
        Bridge a(bit); a.ready(); auto name=bit==0x400000?"aac44100_":"aac48000_";
        CHECK(a.submit(vectors.at(std::string(name)+"0"),0,0)==IAP2_OK&&a.poll()==IAP2_MORE&&a.renderer.bytes.empty());
        CHECK(a.submit(vectors.at(std::string(name)+"1"),1,1024)==IAP2_OK&&a.poll()==IAP2_OK&&a.renderer.frames[0]==1024&&a.renderer.samples[0]==1024);
    }
}
static void bridge_failures() {
    for(int fault=1;fault<=7;++fault) {
        Bridge b; b.ready(); uint64_t second=0; b.renderer.fault=fault;
        if(fault<=2) { CHECK(b.open(101,&second)==IAP2_PROVIDER_FAILED&&!second&&b.renderer.live.empty()&&b.renderer.closed.size()==(fault==2?2u:1u)); continue; }
        CHECK(b.open(101,&second)==IAP2_OK);
        if(fault==3) CHECK(b.api.start(b.api.context,91,second)==IAP2_PROVIDER_FAILED);
        if(fault==4||fault==5) { CHECK(b.submit(vectors.at("opus120_0"))==IAP2_OK); CHECK(b.poll()==IAP2_PROVIDER_FAILED); }
        if(fault>=6) { projection_playback_position out{}; CHECK(b.api.playback(b.api.context,91,b.lease,&out)==IAP2_PROVIDER_FAILED&&!out.has_position); }
        CHECK(b.renderer.live.empty()&&b.renderer.closed.size()==2);
    }
    { Bridge b; b.ready(); CHECK(b.submit(vectors.at("opus120_0"))==IAP2_OK); b.now+=99*ms; CHECK(b.poll()==IAP2_OK); b.now+=ms; CHECK(b.poll()==IAP2_PROVIDER_FAILED&&b.renderer.closed.size()==1&&b.renderer.bytes.size()==1); }
    { Bridge b; b.ready(); --b.now; CHECK(b.poll()==IAP2_PROVIDER_FAILED&&b.renderer.live.empty()); }
    { Bridge b; b.ready(); CHECK(b.submit(Bytes{3,0xff})==IAP2_INVALID&&b.renderer.live.empty()); }
    { Bridge b; b.ready(); projection_playback_position out{}; b.renderer.position={b.now+1,1,48000,1}; CHECK(b.api.playback(b.api.context,91,b.lease,&out)==IAP2_PROVIDER_FAILED&&!out.has_position); }
    { Bridge b; b.ready(); CHECK(b.api.poll(b.api.context,92,b.lease,UINT64_MAX)==IAP2_INVALID&&b.renderer.live.size()==1); }
}
static void mutations() {
    uint32_t random=0x718ea441;
    for(unsigned i=0;i<1000;++i) {
        uint32_t bit=i&1?0x400000u:0x10000000u; Decoder d(bit); Bytes data;
        if(i%3==0) data=vectors.at(i&1?"aac44100_0":"opus20_0");
        else data.resize(i%193+1);
        for(auto& b:data) { random=random*1664525+1013904223; if(i%3||!(random&7)) b^=static_cast<uint8_t>(random>>24); }
        projection_decoded_audio out{}; uint32_t sample=0;
        if(i&2) { CHECK(d.decode(vectors.at(i&1?"aac44100_0":"opus20_0"),0,0,out)==IAP2_OK); sample=out.duration; }
        int r=d.decode(data,(i&2)?1:0,sample,out);
        CHECK(r==IAP2_OK||r==IAP2_INVALID);
        if(!r) CHECK(out.frames<=PROJECTION_DECODE_FRAMES&&out.channels<=2);
        else CHECK(!out.samples&&!out.frames);
    }
}
int main(int argc,char** argv) {
    try {
        CHECK(argc==2||argc==3); vectors=load_vectors(argv[1],33); bool emit=argc==3&&std::string(argv[2])=="--emit";
        packets(emit); if(emit) return 0;
        formats_and_invalid(); bridge_chunks(); bridge_failures(); mutations();
        std::cout<<"PASS: 5 decode/adapter groups, 33 synthetic encoded packets, all formats, real AAC/Opus PCM, chunk backpressure/clock/cleanup and 1000 mutations; no device playback\n";
        std::cout<<"Code from FAAD2 is copyright (c) Nero AG, www.nero.com\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
