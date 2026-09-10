/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_audio_fixture.h"
#include <iomanip>
static Vectors vectors;
static constexpr uint64_t ms=1000000;
template<class T> static Bytes snapshot(const T& s) { auto p=reinterpret_cast<const uint8_t*>(&s); return {p,p+sizeof(s)}; }
static void emit(const char* name,const Bytes& b) {
    std::cout<<name<<'='<<std::hex<<std::setfill('0'); for(auto v:b) std::cout<<std::setw(2)<<unsigned(v); std::cout<<std::dec<<'\n';
}
struct Audio {
    projection_audio s{}; projection_audio_config cfg{}; Bytes storage; uint64_t now=0;
    explicit Audio(uint32_t format=4,size_t slots=8,size_t payload=2048):storage(slots*payload+2,0xaa) {
        projection_audio_default_config(&cfg); cfg.format=format; cfg.slots=slots; cfg.payload_capacity=payload;
        CHECK(projection_audio_init(&s,&cfg,storage.data(),storage.size(),vectors.at("key").data(),91,0)==IAP2_OK&&storage[0]==0xaa);
    }
    ~Audio() noexcept(false) { projection_audio_close(&s); CHECK(zeroed(storage.data(),storage.size()-2)&&storage.back()==0xaa); }
    int feed(const Bytes& packet) { return projection_audio_feed(&s,91,packet.data(),packet.size(),now); }
    void push(uint64_t counter,uint32_t sample=0,const Bytes& plain={1,2}) { CHECK(feed(audio_packet(vectors.at("key").data(),counter,sample,plain))==PROJECTION_AUDIO_PACKET); }
    void start() { CHECK(projection_audio_start(&s,91,now)==IAP2_OK); }
    projection_audio_packet take(uint64_t counter,uint64_t skipped=0) {
        projection_audio_packet p{}; projection_audio_key key{};
        CHECK(projection_audio_peek(&s,91,&p,&key,now)==PROJECTION_AUDIO_PACKET&&p.counter==counter&&p.skipped_packets==skipped);
        auto old=snapshot(s); CHECK(projection_audio_release(&s,{91,key.token+1},UINT64_MAX)==IAP2_INVALID&&snapshot(s)==old);
        CHECK(projection_audio_release(&s,key,now)==IAP2_OK); return p;
    }
};
static void formats(bool output=false) {
    const uint32_t bits[]={4,8,16,32,64,128,256,512,1024,2048,16384,32768,0x400000,0x800000,0x10000000,0x20000000,0x40000000};
    Bytes encoded;
    for(auto bit:bits) { projection_audio_format f{}; CHECK(projection_audio_format_get(bit,&f)==IAP2_OK&&f.bit==bit);
        for(auto word:{f.bit,f.clock_rate,f.input_rate}) for(unsigned i=0;i<4;++i) encoded.push_back(static_cast<uint8_t>(word>>(8*i)));
        encoded.push_back(f.codec); encoded.push_back(f.channels); encoded.push_back(static_cast<uint8_t>(f.aac_config)); encoded.push_back(static_cast<uint8_t>(f.aac_config>>8));
        CHECK((f.codec==PROJECTION_AUDIO_OPUS&&f.clock_rate==48000)||(f.codec!=PROJECTION_AUDIO_OPUS&&f.clock_rate==f.input_rate));
    }
    if(output) emit("formats",encoded);
    for(uint32_t bit:{0u,1u,2u,3u,12u,4096u,0x80000000u,UINT32_MAX}) { projection_audio_format f{1,2,3,4,5,6}; auto old=snapshot(f);
        CHECK(projection_audio_format_get(bit,&f)!=IAP2_OK&&snapshot(f)==old); }
    projection_audio_format f{}; CHECK(projection_audio_format_get(8,&f)==IAP2_OK); Bytes out(8,0xaa); size_t used=99;
    CHECK(projection_audio_pcm16le(&f,vectors.at("pcm_plain").data(),8,out.data(),8,&used)==IAP2_OK&&used==8&&out==hex("008000000100ff7f"));
    for(size_t cap=0;cap<8;++cap) { auto old=out; CHECK(projection_audio_pcm16le(&f,vectors.at("pcm_plain").data(),8,out.data(),cap,&used)==IAP2_NO_SPACE&&used==0&&old==out); }
    auto old=out; CHECK(projection_audio_pcm16le(&f,out.data(),3,out.data()+4,4,&used)==IAP2_INVALID&&old==out); // Rejected before either range is touched.
    f.clock_rate=0; CHECK(projection_audio_pcm16le(&f,vectors.at("pcm_plain").data(),8,out.data(),8,&used)==IAP2_INVALID&&old==out);
    CHECK(projection_audio_format_get(0x400000,&f)==IAP2_OK&&projection_audio_pcm16le(&f,vectors.at("pcm_plain").data(),8,out.data(),8,&used)==IAP2_UNSUPPORTED);
}
static void external_packets(bool output=false) {
    for(const char* name:{"native","pcm","aac","opus"}) {
        std::string n=name; uint32_t fmt=n=="pcm"?0x8000u:n=="opus"?0x10000000u:0x400000u;
        Audio h(fmt); CHECK(h.feed(vectors.at(n))==PROJECTION_AUDIO_PACKET); projection_audio_packet p{}; projection_audio_key key{};
        h.now=20*ms; CHECK(projection_audio_peek(&h.s,91,&p,&key,h.now)==IAP2_MORE&&!key.token); h.start();
        CHECK(projection_audio_peek(&h.s,91,&p,&key,h.now)==PROJECTION_AUDIO_PACKET&&p.ssrc==0xaabbccdd&&p.sequence==(n=="pcm"?65535:0));
        CHECK(Bytes(p.data,p.data+p.size)==vectors.at(n+"_plain"));
        if(n=="pcm") { CHECK(p.frames==2&&p.sample_time==UINT32_MAX&&p.counter==UINT64_MAX); Bytes le(p.size); size_t used=0;
            CHECK(projection_audio_pcm16le(&h.s.format,p.data,p.size,le.data(),le.size(),&used)==IAP2_OK&&used==le.size()); if(output) emit("pcm_le",le); }
        else { CHECK(!p.frames); if(output) emit((n+"_plain").c_str(),Bytes(p.data,p.data+p.size)); }
        CHECK(projection_audio_release(&h.s,key,h.now)==IAP2_OK&&h.s.count==0); CHECK(h.feed(vectors.at(n))==PROJECTION_AUDIO_DROPPED);
    }
}
static void order_and_gaps() {
    Audio h; h.start(); h.push(2,400); h.now=1; h.push(0,200); h.now=2; h.push(1,300);
    projection_audio_packet p{}; projection_audio_key key{};
    h.now=20*ms; CHECK(projection_audio_peek(&h.s,91,&p,&key,h.now)==IAP2_MORE&&projection_audio_next_delay(&h.s)==1);
    h.now=20*ms+1; CHECK(h.take(0).sample_time==200&&h.take(1).sample_time==300&&h.take(2).sample_time==400);
    h.push(5,700); ++h.now; h.push(4,600); h.now+=20*ms;
    CHECK(projection_audio_peek(&h.s,91,&p,&key,h.now)==PROJECTION_AUDIO_PACKET&&p.counter==4&&p.skipped_packets==1);
    CHECK(h.feed(audio_packet(vectors.at("key").data(),3,500,{1,2}))==PROJECTION_AUDIO_DROPPED); // Earlier than already borrowed output, not yet retired.
    CHECK(projection_audio_release(&h.s,key,h.now)==IAP2_OK&&h.take(5).sample_time==700);
    CHECK(h.feed(audio_packet(vectors.at("key").data(),3,500,{1,2}))==PROJECTION_AUDIO_DROPPED);
    { Audio w; w.start(); w.push(64); w.push(1); CHECK(w.feed(audio_packet(vectors.at("key").data(),0,0,{1,2}))==PROJECTION_AUDIO_DROPPED);
      w.push(65); CHECK(w.feed(audio_packet(vectors.at("key").data(),1,0,{1,2}))==PROJECTION_AUDIO_DROPPED); w.now=20*ms; w.take(1); w.take(64,62); w.take(65); }
    { Audio w; w.start(); w.push(UINT64_MAX-1,UINT32_MAX); w.push(UINT64_MAX,0); w.now=20*ms; w.take(UINT64_MAX-1); w.take(UINT64_MAX);
      CHECK(w.feed(audio_packet(vectors.at("key").data(),0,1,{1,2}))==PROJECTION_AUDIO_DROPPED); }
}
static void authentication_and_headers() {
    auto original=vectors.at("native");
    for(size_t i=4;i<original.size();++i) { Audio h(0x400000); auto b=original; b[i]^=1;
        CHECK(h.feed(b)==PROJECTION_AUDIO_DROPPED&&!h.s.received&&!h.s.count&&h.feed(original)==PROJECTION_AUDIO_PACKET); }
    for(uint8_t prefix:{uint8_t(0),uint8_t(0x81),uint8_t(0x90),uint8_t(0xa0),uint8_t(0xc0)}) { Audio h(0x400000); auto b=original; b[0]=prefix; CHECK(h.feed(b)==PROJECTION_AUDIO_DROPPED&&!h.s.received); }
    { Audio h(0x400000); auto b=original; b[1]=95; CHECK(h.feed(b)==PROJECTION_AUDIO_DROPPED&&!h.s.received);
      b[1]=0xff; b[2]=0xff; b[3]=0xff; CHECK(h.feed(b)==PROJECTION_AUDIO_PACKET); h.start(); h.now=20*ms; auto p=h.take(0); CHECK(p.sequence==65535&&p.payload_type==127&&p.marker); }
    { Audio h; h.push(0); auto b=audio_packet(vectors.at("key").data(),1,5,{1,2},0,5); CHECK(h.feed(b)==PROJECTION_AUDIO_DROPPED&&h.s.count==1&&h.s.highest==0); h.push(1); }
    { Audio h; CHECK(h.feed(original)==PROJECTION_AUDIO_DROPPED&&!h.s.received); } // Odd PCM payload rejected, not exposed.
    { Audio h; h.start(); h.push(0,0,{}); h.now=20*ms; CHECK(!h.take(0).frames); } // Authenticated empty payload carries no fabricated sample.
}
static void ownership_and_limits() {
    for(size_t slots:{size_t(1),size_t(8),size_t(64)}) { Audio h(4,slots,8); h.start();
        for(size_t i=0;i<slots;++i) h.push(i,static_cast<uint32_t>(i));
        auto old=snapshot(h.s); CHECK(h.feed(audio_packet(vectors.at("key").data(),slots,0,{1,2}))==PROJECTION_AUDIO_BUSY&&snapshot(h.s)==old);
        h.now=20*ms; for(size_t i=0;i<slots;++i) h.take(i); CHECK(!h.s.count); h.push(slots); CHECK(h.take(slots).counter==slots);
    }
    { Audio h; h.start(); h.push(0); h.now=20*ms; projection_audio_packet p{}; projection_audio_key key{};
      CHECK(projection_audio_peek(&h.s,91,&p,&key,h.now)==PROJECTION_AUDIO_PACKET&&projection_audio_next_delay(&h.s)==1000);
      auto old=snapshot(h.s); CHECK(projection_audio_release(&h.s,{92,key.token},UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==old);
      CHECK(projection_audio_release(&h.s,key,h.now-1)==IAP2_ARGUMENT&&snapshot(h.s)==old);
      CHECK(projection_audio_peek(&h.s,91,&p,&key,h.now+1000*ms-1)==PROJECTION_AUDIO_PACKET&&projection_audio_next_delay(&h.s)==1);
      CHECK(projection_audio_release(&h.s,key,h.now+1000*ms)==PROJECTION_AUDIO_CLOSED&&zeroed(h.s.key,32)); }
    { Audio h; h.start(); h.push(0); h.now=20*ms; h.s.next_token=UINT64_MAX; h.take(0); h.push(1); projection_audio_packet p{}; projection_audio_key key{};
      CHECK(projection_audio_peek(&h.s,91,&p,&key,h.now)==PROJECTION_AUDIO_CLOSED&&!key.token); }
    for(unsigned mode=0;mode<9;++mode) { Audio h; auto cfg=h.cfg; auto old=snapshot(h.s),memory=h.storage;
        if(mode==0) cfg.slots=0; if(mode==1) cfg.slots=65; if(mode==2) cfg.payload_capacity=0; if(mode==3) cfg.payload_capacity=8193;
        if(mode==4) cfg.reorder_ms=1001; if(mode==5) cfg.hold_ms=0; if(mode==6) cfg.hold_ms=60001; if(mode==7) cfg.format=0;
        CHECK(projection_audio_init(&h.s,&cfg,h.storage.data(),mode==8?1:h.storage.size(),vectors.at("key").data(),91,UINT64_MAX)!=IAP2_OK&&snapshot(h.s)==old&&h.storage==memory); }
    { Audio h; auto old=snapshot(h.s); CHECK(projection_audio_feed(&h.s,92,nullptr,0,UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==old);
      CHECK(projection_audio_feed(&h.s,91,nullptr,1,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(h.s)==old); }
    { Audio h; auto cfg=h.cfg; cfg.payload_capacity=1; auto old=snapshot(h.s);
      CHECK(projection_audio_init(&h.s,&cfg,h.storage.data(),h.storage.size(),vectors.at("key").data(),91,0)==IAP2_NO_SPACE&&snapshot(h.s)==old); }
}
static void malformed() {
    for(size_t n=0;n<vectors.at("native").size();++n) { Audio h(0x400000); CHECK(h.feed(Bytes(vectors.at("native").begin(),vectors.at("native").begin()+n))==PROJECTION_AUDIO_DROPPED&&!h.s.received); }
    { Audio h(4,2,2); CHECK(h.feed(audio_packet(vectors.at("key").data(),0,0,{1,2,3,4}))==PROJECTION_AUDIO_DROPPED); }
    uint32_t random=0x19a38c2d;
    for(unsigned i=0;i<5000;++i) { Audio h(0x400000); auto b=vectors.at("native"); random=random*1664525u+1013904223u;
        b[random%b.size()]^=static_cast<uint8_t>(1u<<(random>>29)); if(i%3==0) b.resize(random%b.size());
        int r=h.feed(b); CHECK(r==PROJECTION_AUDIO_DROPPED||r==PROJECTION_AUDIO_PACKET); if(r==PROJECTION_AUDIO_DROPPED) CHECK(!h.s.count&&!h.s.received);
    }
}
int main(int argc,char** argv) {
    try { CHECK(argc==2||argc==3); vectors=load_vectors(argv[1],13);
        bool output=argc==3; if(output) CHECK(std::string(argv[2])=="--emit"); formats(output); external_packets(output); if(output) return 0;
        order_and_gaps(); authentication_and_headers(); ownership_and_limits(); malformed();
        std::cout<<"PASS: 6 audio groups; exact formats, real AEAD, RTP/replay/order/gaps, PCM conversion, ownership/limits and 5000 mutations; no playback claim\n";
        std::cout<<"x64 audio owner bytes: "<<sizeof(projection_audio)<<"; caller packet storage additional\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
