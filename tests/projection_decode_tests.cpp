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
    projection_audio_sink api{this,open,start,submit,poll,playback,close,flush,PROJECTION_AUDIO_SINK_CONCEALMENT|PROJECTION_AUDIO_SINK_TIMED};
    uint64_t next=1; std::map<uint64_t,projection_audio_format> live; std::vector<uint64_t> closed;
    std::vector<Bytes> bytes; std::vector<uint32_t> samples,frames; unsigned starts=0,polls=0;
    bool busy=false; int fault=0,flush_fault=0; projection_playback_position position{};
    unsigned flushes=0,resumes=0;
    std::vector<uint8_t> concealed,timed; std::vector<uint64_t> due,counters;
    static int open(void* p,uint64_t gen,const projection_session_resource* r,const projection_audio_format* f,uint64_t* lease) {
        auto& s=*static_cast<Renderer*>(p); CHECK(gen==91&&f->codec==PROJECTION_AUDIO_PCM16&&r->audio_format==f->bit&&r->frames_per_packet==0);
        if(s.fault==1) return IAP2_PROVIDER_FAILED;
        *lease=s.next++; s.live[*lease]=*f; return s.fault==2?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static int start(void* p,uint64_t,uint64_t lease) { auto& s=*static_cast<Renderer*>(p); CHECK(s.live.contains(lease)); ++s.starts; return s.fault==3?IAP2_PROVIDER_FAILED:IAP2_OK; }
    static int submit(void* p,uint64_t,uint64_t lease,const projection_audio_format* f,const projection_audio_packet* packet) {
        auto& s=*static_cast<Renderer*>(p); CHECK(s.live.contains(lease)&&f->bit==s.live.at(lease).bit&&packet->frames*2*f->channels==packet->size&&packet->size<=8192);
        if(s.fault==4) return IAP2_PROVIDER_FAILED; if(s.busy) return IAP2_MORE;
        s.bytes.emplace_back(packet->data,packet->data+packet->size); s.samples.push_back(packet->sample_time); s.frames.push_back(packet->frames);
        s.concealed.push_back(packet->concealed); s.timed.push_back(packet->timed); s.due.push_back(packet->presentation_ns); s.counters.push_back(packet->counter); return IAP2_OK;
    }
    static int poll(void* p,uint64_t,uint64_t lease,uint64_t) { auto& s=*static_cast<Renderer*>(p); CHECK(s.live.contains(lease)); ++s.polls; return s.fault==5?IAP2_PROVIDER_FAILED:IAP2_OK; }
    static int playback(void* p,uint64_t,uint64_t lease,projection_playback_position* out) {
        auto& s=*static_cast<Renderer*>(p); *out=s.position; out->sample_rate=s.live.at(lease).clock_rate; if(s.fault==7) ++out->sample_rate; return s.fault==6?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
    static void close(void* p,uint64_t,uint64_t lease) { auto& s=*static_cast<Renderer*>(p); CHECK(s.live.erase(lease)==1); s.closed.push_back(lease); }
    static int flush(void* p,uint64_t gen,uint64_t lease,const projection_audio_flush_request* request) {
        auto& s=*static_cast<Renderer*>(p); CHECK(gen==91&&s.live.contains(lease));
        if(request) ++s.flushes; else ++s.resumes;
        return s.flush_fault==(request?1:2)?IAP2_PROVIDER_FAILED:IAP2_OK;
    }
};
struct Bridge {
    Renderer renderer; uint64_t now=100*ms; projection_decode_sink *p=nullptr; projection_audio_sink api{};
    projection_audio_format format{}; uint64_t lease=0;
    uint32_t latency=0;
    explicit Bridge(uint32_t bit=0x40000000,uint32_t gap=0,bool paced=false,uint32_t ahead=0,uint32_t delay=0):latency(delay) {
        CHECK(projection_audio_format_get(bit,&format)==IAP2_OK);
        projection_decode_sink_config c{renderer.api,clock,this,100,gap,ahead,static_cast<uint8_t>(paced)}; CHECK(projection_decode_sink_create(&c,91,&p)==IAP2_OK); api=projection_decode_sink_provider(p);
    }
    ~Bridge() { projection_decode_sink_destroy(p); }
    static uint64_t clock(void* p) { return static_cast<Bridge*>(p)->now; }
    int open(uint32_t type=100,uint64_t* child=nullptr) { projection_session_resource r{}; r.type=type; r.audio_format=format.bit; r.audio_latency_ms=latency; return api.open(api.context,91,&r,&format,child?child:&lease); }
    void ready() { CHECK(open()==IAP2_OK&&api.start(api.context,91,lease)==IAP2_OK); }
    int submit(const Bytes& data,uint64_t counter=0,uint32_t sample=UINT32_MAX-5000) {
        projection_audio_packet q{}; q.data=data.data(); q.size=data.size(); q.counter=counter; q.sample_time=sample; q.received_ns=now;
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
    for(int failure=0;failure<3;++failure) {
        Bridge b; b.ready(); uint64_t second=0; CHECK(b.open(101,&second)==IAP2_OK);
        CHECK(b.submit(vectors.at("opus120_0"))==IAP2_OK); projection_audio_flush_request q{0,0}; b.renderer.flush_fault=failure;
        CHECK(b.api.flush(b.api.context,92,b.lease,&q)==IAP2_INVALID&&!b.renderer.flushes);
        int r=b.api.flush(b.api.context,91,b.lease,&q); CHECK(r==(failure==1?IAP2_PROVIDER_FAILED:IAP2_OK));
        if(failure!=1) {
            CHECK(b.poll()==IAP2_OK&&b.renderer.bytes.empty()&&b.api.start(b.api.context,91,b.lease)==IAP2_INVALID);
            CHECK(b.submit(vectors.at("opus120_1"))==IAP2_INVALID);
            r=b.api.flush(b.api.context,91,b.lease,nullptr); CHECK(r==(failure==2?IAP2_PROVIDER_FAILED:IAP2_OK));
        }
        if(failure) CHECK(b.renderer.live.empty()&&b.renderer.closed.size()==2);
        else { CHECK(b.submit(vectors.at("opus120_0"),99,0)==IAP2_OK); CHECK(b.poll()==IAP2_OK&&b.renderer.samples.back()==0); }
    }
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
static void concealment() {
    for(uint32_t bit:{4u,8u,2048u,32768u,0x10000000u,0x20000000u,0x40000000u}) {
        Decoder d(bit); projection_decoded_audio out{};
        CHECK(projection_decode_conceal(d.p,91,120,&out)==IAP2_INVALID&&!out.samples);
        auto raw=d.format.codec==PROJECTION_AUDIO_OPUS?vectors.at("opus20_0"):hex("1234567801234567");
        uint32_t start=UINT32_MAX-999; CHECK(d.decode(raw,10,start,out)==IAP2_OK); uint32_t next=start+out.duration;
        auto before=pcm_bytes(out); auto borrowed=out.samples;
        CHECK(projection_decode_conceal(d.p,92,120,&out)==IAP2_INVALID&&!out.samples);
        CHECK(Bytes(reinterpret_cast<const uint8_t*>(borrowed),reinterpret_cast<const uint8_t*>(borrowed)+before.size())==before);
        CHECK(projection_decode_conceal(d.p,91,0,&out)==IAP2_ARGUMENT);
        CHECK(projection_decode_conceal(d.p,91,5761,&out)==IAP2_ARGUMENT);
        if(d.format.codec==PROJECTION_AUDIO_OPUS) CHECK(projection_decode_conceal(d.p,91,121,&out)==IAP2_ARGUMENT);
        CHECK(projection_decode_conceal(d.p,91,5760,&out)==IAP2_OK&&out.concealed&&out.frames==5760&&out.sample_time==next);
        if(d.format.codec==PROJECTION_AUDIO_PCM16) CHECK(zeroed(out.samples,out.frames*out.channels*2));
        else CHECK(!zeroed(out.samples,out.frames*out.channels*2)); // Real Opus PLC, not a zero-fill stand-in.
        CHECK(d.decode(raw,12,next+5760,out)==IAP2_OK&&!out.concealed);
    }
    { Decoder d(0x10000000); projection_decoded_audio out{}; CHECK(d.decode(vectors.at("opus20_0"),10,0,out)==IAP2_OK);
      CHECK(projection_decode_conceal(d.p,91,960,&out)==IAP2_OK); CHECK(d.decode(vectors.at("opus20_1"),10,1920,out)==IAP2_UNSUPPORTED); } // PLC cannot reset nonce checks.
    for(auto name:{std::string("aac44100"),std::string("aac48000")}) {
        uint32_t bit=name=="aac44100"?0x400000:0x800000; Decoder d(bit),fresh(bit); projection_decoded_audio out{},reference{};
        CHECK(d.decode(vectors.at(name+"_0"),0,0,out)==IAP2_OK&&!out.frames);
        CHECK(d.decode(vectors.at(name+"_1"),1,1024,out)==IAP2_OK&&out.frames==1024);
        CHECK(projection_decode_conceal(d.p,91,1023,&out)==IAP2_ARGUMENT);
        CHECK(projection_decode_conceal(d.p,91,1024,&out)==IAP2_OK&&out.concealed&&out.sample_time==2048&&zeroed(out.samples,4096));
        CHECK(d.decode(vectors.at(name+"_3"),3,3072,out)==IAP2_OK&&out.priming&&out.concealed&&out.frames==1024&&zeroed(out.samples,4096));
        CHECK(fresh.decode(vectors.at(name+"_3"),3,3072,reference)==IAP2_OK&&!reference.frames);
        CHECK(d.decode(vectors.at(name+"_4"),4,4096,out)==IAP2_OK&&!out.concealed);
        CHECK(fresh.decode(vectors.at(name+"_4"),4,4096,reference)==IAP2_OK&&pcm_bytes(reference)==pcm_bytes(out));
    }
}
static void recovery_and_pacing() {
    { Bridge b(0x10000000,120); b.ready(); uint32_t start=UINT32_MAX-500;
      CHECK(b.submit(vectors.at("opus20_0"),10,start)==IAP2_OK&&b.poll()==IAP2_OK);
      auto packet=vectors.at("opus20_2"); CHECK(b.submit(packet,12,start+1920)==IAP2_OK); packet.assign(packet.size(),0xff);
      CHECK(b.submit(packet,13,start+2880)==IAP2_MORE); b.renderer.busy=true; CHECK(b.poll()==IAP2_MORE);
      b.renderer.busy=false; CHECK(b.poll()==IAP2_OK&&b.poll()==IAP2_OK);
      CHECK((b.renderer.concealed==std::vector<uint8_t>{0,1,0})&&(b.renderer.counters==std::vector<uint64_t>{10,0,12}));
      CHECK((b.renderer.samples==std::vector<uint32_t>{start,start+960,start+1920})); }
    { Bridge b(0x10000000,500); b.ready(); CHECK(b.submit(vectors.at("opus20_0"),0,0)==IAP2_OK&&b.poll()==IAP2_OK);
      CHECK(b.submit(vectors.at("opus20_2"),26,24960)==IAP2_OK);
      for(unsigned i=0;i<10;++i) CHECK(b.poll()==IAP2_OK);
      uint32_t frames=0; for(auto n:b.renderer.frames) frames+=n; CHECK(frames==25920&&b.renderer.concealed.back()==0); }
    for(unsigned bad=0;bad<5;++bad) { Bridge b(0x10000000,120); b.ready(); CHECK(b.submit(vectors.at("opus20_0"),10,0)==IAP2_OK&&b.poll()==IAP2_OK);
        uint32_t sample=1920; uint64_t counter=12;
        if(bad==0) sample=961; if(bad==1) sample=6721; if(bad==2) sample=959;
        if(bad==3) counter=11; if(bad==4) counter=10;
        CHECK(b.submit(vectors.at("opus20_2"),counter,sample)==IAP2_UNSUPPORTED&&b.renderer.live.empty()); }
    { Bridge b(0x10000000,120); b.ready(); CHECK(b.submit(vectors.at("opus20_0"),0,0)==IAP2_OK&&b.poll()==IAP2_OK);
      CHECK(b.submit(vectors.at("opus20_2"),2,1920)==IAP2_OK); b.renderer.busy=true; b.now+=99*ms; CHECK(b.poll()==IAP2_MORE);
      b.now+=ms; CHECK(b.poll()==IAP2_PROVIDER_FAILED&&b.renderer.live.empty()); }
    { Bridge b(0x10000000,120,true,10,60); b.ready(); CHECK(b.submit(vectors.at("opus20_0"),0,0)==IAP2_OK);
      b.now=150*ms-1; CHECK(b.poll()==IAP2_MORE&&b.renderer.bytes.empty()); ++b.now;
      CHECK(b.poll()==IAP2_OK&&b.renderer.due.back()==160*ms&&b.renderer.timed.back());
      CHECK(b.submit(vectors.at("opus20_1"),1,960)==IAP2_OK&&b.poll()==IAP2_MORE);
      b.now=170*ms; CHECK(b.poll()==IAP2_OK&&b.renderer.due.back()==180*ms); }
    { Bridge b(0x400000,120,true,0,100); b.ready(); uint32_t start=UINT32_MAX-511;
      for(unsigned i=0;i<50;++i) { CHECK(b.submit(vectors.at("aac44100_"+std::to_string(i%5)),i,start+i*1024)==IAP2_OK);
        if(!i) { CHECK(b.poll()==IAP2_MORE); continue; }
        uint64_t due=200*ms+uint64_t(i)*1024*1000000000/44100; b.now=due-1; CHECK(b.poll()==IAP2_MORE); ++b.now;
        CHECK(b.poll()==IAP2_OK&&b.renderer.due.back()==due&&b.renderer.samples.back()==start+i*1024); } }
    { Bridge b(0x10000000,120,true,0,20); b.ready(); CHECK(b.submit(vectors.at("opus20_0"),0,0)==IAP2_OK);
      b.now=120*ms; CHECK(b.poll()==IAP2_OK&&b.submit(vectors.at("opus20_2"),2,1920)==IAP2_OK&&b.poll()==IAP2_MORE);
      projection_audio_flush_request q{9999,0}; CHECK(b.api.flush(b.api.context,91,b.lease,&q)==IAP2_OK&&b.api.flush(b.api.context,91,b.lease,nullptr)==IAP2_OK);
      b.now=150*ms; CHECK(b.submit(vectors.at("opus20_0"),3,9999)==IAP2_OK&&b.poll()==IAP2_MORE&&b.renderer.bytes.size()==1);
      b.now=170*ms; CHECK(b.poll()==IAP2_OK&&b.renderer.samples.back()==9999&&b.renderer.due.back()==170*ms&&!b.renderer.concealed.back()); }
    { Bridge b(0x10000000,120,true,0,60000); b.ready(); CHECK(b.submit(vectors.at("opus20_0"),0,0)==IAP2_OK);
      b.now=60100*ms-1; CHECK(b.poll()==IAP2_MORE&&b.renderer.bytes.empty());
      b.renderer.busy=true; b.now=60320*ms-1; CHECK(b.poll()==IAP2_MORE); ++b.now;
      CHECK(b.poll()==IAP2_PROVIDER_FAILED&&b.renderer.live.empty()); }
    for(unsigned bad=0;bad<5;++bad) { Renderer r; uint64_t now=0; projection_decode_sink *out=reinterpret_cast<projection_decode_sink*>(1);
        projection_decode_sink_config c{r.api,[](void* p)->uint64_t{return *static_cast<uint64_t*>(p);},&now,100,120,10,1};
        if(bad==0) c.max_gap_ms=1001; if(bad==1) c.ahead_ms=501; if(bad==2) c.paced=2;
        if(bad==3) c.paced=0; if(bad==4) c.pcm.features=0;
        CHECK(projection_decode_sink_create(&c,91,&out)==IAP2_ARGUMENT&&!out); }
    { Bridge b(0x10000000,120,true,0,60); b.now=UINT64_MAX-50*ms; b.ready();
      CHECK(b.submit(vectors.at("opus20_0"),0,0)==IAP2_INVALID&&b.renderer.live.empty()); }
}
int main(int argc,char** argv) {
    try {
        CHECK(argc==2||argc==3); vectors=load_vectors(argv[1],33); bool emit=argc==3&&std::string(argv[2])=="--emit";
        packets(emit); if(emit) return 0;
        formats_and_invalid(); bridge_chunks(); bridge_failures(); mutations(); concealment(); recovery_and_pacing();
        std::cout<<"PASS: 7 decode/adapter groups, 33 synthetic packets, bounded loss recovery, timed delivery, ownership/clock/cleanup and 1000 mutations; no device playback\n";
        std::cout<<"Code from FAAD2 is copyright (c) Nero AG, www.nero.com\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
