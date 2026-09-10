/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_session_fixture.h"
#include <iomanip>

static Vectors vectors;
struct Harness {
    SessionBackend backend; projection_info_profile profile=info_fixture(2);
    projection_session s{}; Bytes scratch=Bytes(PROJECTION_INFO_LIMIT,0xa5); unsigned available_calls=0; int available_error=0;
    explicit Harness(bool feedback=false) { auto cfg=backend.config(feedback); CHECK(projection_session_init(&s,&profile,available,this,&cfg,91)==IAP2_OK); CHECK(backend.opens==0&&available_calls==0); }
    ~Harness() noexcept(false) { projection_session_close(&s); CHECK(backend.live.empty()); }
    static int available(void* context,uint64_t gen,const projection_info_profile* p) {
        auto& self=*static_cast<Harness*>(context); CHECK(gen==91&&p==&self.profile); ++self.available_calls; return self.available_error;
    }
    int message(const Bytes& body,const char* method="SETUP",const char* target="rtsp://127.0.0.1/123") {
        auto req=session_message(body,method,target); return projection_session_request(&s,&req,vectors.at("shared").data(),scratch.data(),scratch.size());
    }
    int send(const std::string& fixture,const char* method="SETUP") { return message(vectors.at(fixture),method); }
    Bytes reply() const { return {s.reply,s.reply+s.reply_size}; }
    void release() { CHECK(projection_session_release(&s)==IAP2_OK); CHECK(zeroed(s.reply,sizeof(s.reply))); }
    void begin(bool streams=false) { CHECK(send("session")==IAP2_OK); release(); if(streams) { CHECK(send("streams")==IAP2_OK); release(); } }
};
static void emit(const std::string& name,const uint8_t* p,size_t n) {
    std::cout<<name<<'='<<std::hex<<std::setfill('0'); for(size_t i=0;i<n;++i) std::cout<<std::setw(2)<<unsigned(p[i]); std::cout<<std::dec<<'\n';
}
static void lifecycle(bool output=false) {
    Harness h; CHECK(h.send("session")==IAP2_OK&&h.s.state==PROJECTION_SESSION_HELD&&h.backend.opens==1);
    CHECK(h.backend.keys[0].has_write); if(output) emit("session_reply",h.s.reply,h.s.reply_size);
    CHECK(h.send("streams")==RTSP_BUSY&&h.backend.opens==1); h.release();
    CHECK(h.send("streams")==IAP2_OK&&h.backend.opens==7&&h.s.count==7&&h.s.used_count==6&&h.backend.starts==0);
    if(output) { emit("streams_reply",h.s.reply,h.s.reply_size);
        for(size_t i=0;i<h.backend.keys.size();++i) { auto prefix=i?"stream_"+std::to_string(h.backend.requests[i].type):"session";
            emit(prefix+"_read",h.backend.keys[i].read,32); emit(prefix+"_write",h.backend.keys[i].write,32); } }
    CHECK(h.backend.keys[3].has_write); CHECK(!h.backend.keys[1].has_write&&zeroed(h.backend.keys[1].write,32));
    h.release(); CHECK(h.message({},"RECORD")==IAP2_OK&&h.backend.starts==0&&!h.s.recording); h.release();
    CHECK(h.backend.starts==1&&h.backend.started.size()==7&&h.s.recording);
    CHECK(h.send("teardown_audio","TEARDOWN")==IAP2_OK&&h.backend.closed.size()==1&&h.s.count==6&&h.s.used_count==6); h.release();
    CHECK(h.send("audio_new")==IAP2_OK&&h.backend.starts==1&&h.s.used_count==7);
    if(output) { emit("replacement_reply",h.s.reply,h.s.reply_size); emit("replacement_read",h.backend.keys.back().read,32); emit("replacement_write",h.backend.keys.back().write,32); }
    h.release(); CHECK(h.backend.starts==2&&h.backend.started.size()==8);
    CHECK(h.message({},"TEARDOWN")==IAP2_OK&&h.backend.live.empty()); CHECK(projection_session_release(&h.s)==IAP2_END);
    CHECK(h.s.state==PROJECTION_SESSION_DEAD&&zeroed(h.s.used_ids,sizeof(h.s.used_ids))); projection_session_close(&h.s);
}
static void schemas_and_boundaries() {
    unsigned bad=0;
    for(const auto& [name,value]:vectors) if(name.starts_with("bad_")&&name!="bad_id_reuse") {
        Harness h; if(name.find("format")!=std::string::npos||name.find("id_")!=std::string::npos||name.find("audio_")!=std::string::npos||
            name.find("mic_")!=std::string::npos||name.find("latency")!=std::string::npos||name.find("iap_")!=std::string::npos||
            name=="bad_stream_encryption"||name=="bad_unknown_stream"||name=="bad_seven_streams"||name=="bad_duplicate_type") h.begin();
        auto calls=h.backend.opens,available=h.available_calls; CHECK(h.message(value)!=IAP2_OK&&h.backend.opens==calls&&h.available_calls==available&&h.backend.live.empty()); ++bad;
    }
    CHECK(bad>=30);
    const auto& b=vectors.at("session");
    for(size_t n=0;n<b.size();++n) { Harness h; CHECK(h.message(Bytes(b.begin(),b.begin()+n))!=IAP2_OK&&h.backend.opens==0); }
    for(int kind=0;kind<5;++kind) { Harness h; auto r=session_message(b);
        if(kind==0) r.headers[0].value=info_text("application/xml"); if(kind==1) { r.headers[1]=r.headers[0]; r.header_count=2; }
        if(kind==2) r.header_count=0; if(kind==3) r.target={}; if(kind==4) r.method=info_text("POST");
        CHECK(projection_session_request(&h.s,&r,vectors.at("shared").data(),h.scratch.data(),h.scratch.size())!=IAP2_OK&&h.backend.opens==0); }
    { Harness h; CHECK(h.message(b)==IAP2_OK&&zeroed(h.scratch.data(),h.scratch.size())); }
    for(const char* method:{"RECORD","TEARDOWN"}) { Harness h; CHECK(h.message({},method)!=IAP2_OK&&h.backend.opens==0); }
    { Harness h; h.begin(); CHECK(h.message({},"RECORD")!=IAP2_OK&&h.backend.starts==0); }
    { Harness h; h.begin(); CHECK(h.send("session")!=IAP2_OK&&h.backend.opens==1); }
    { Harness h; h.begin(); CHECK(h.message(vectors.at("streams"),"SETUP","/different")!=IAP2_OK&&h.backend.opens==1); }
    { Harness h; h.begin(true); CHECK(h.send("teardown_wrong_id","TEARDOWN")!=IAP2_OK&&h.backend.live.empty()); }
    { Harness h; h.begin(true); CHECK(h.send("teardown_audio","TEARDOWN")==IAP2_OK); h.release(); CHECK(h.send("bad_id_reuse")!=IAP2_OK&&h.backend.opens==7); }
    { Harness h; h.begin(true); CHECK(h.send("teardown_screen","TEARDOWN")==IAP2_OK); h.release(); CHECK(h.send("streams")!=IAP2_OK&&h.backend.opens==7); }
    { Harness h; h.begin(); h.s.used_count=PROJECTION_SESSION_IDS; // Deliberate bounded exhaustion seam.
      CHECK(h.send("screen_new")==IAP2_NO_SPACE&&h.backend.opens==1); }
    { Harness h; auto req=session_message(vectors.at("session"));
      CHECK(projection_session_request(&h.s,&req,vectors.at("shared").data(),h.scratch.data(),1)==IAP2_NO_SPACE&&h.backend.opens==0); }
    { Harness h; CHECK(h.message(Bytes(PROJECTION_INFO_LIMIT+1,0))!=IAP2_OK&&h.backend.opens==0); }
    { Harness h; h.begin(true); CHECK(h.message({},"RECORD")==IAP2_OK); h.release(); CHECK(h.message({},"RECORD")!=IAP2_OK&&h.backend.starts==1); }
    { Harness h; h.begin(); auto mixed=vectors.at("streams"); const auto needle=bytes("E9459FD0-BCAD-4C45-820F-1E72447EF2F2");
      auto pos=std::search(mixed.begin(),mixed.end(),needle.begin(),needle.end()); CHECK(pos!=mixed.end()); *pos='e';
      CHECK(h.message(mixed)==IAP2_OK&&h.backend.opens==7); }
    uint32_t state=0x32476810;
    for(unsigned attempt=0;attempt<600;++attempt) {
        Harness h; h.begin(); auto mutated=vectors.at("streams"); state=state*1664525u+1013904223u;
        mutated[state%mutated.size()]^=static_cast<uint8_t>(1u<<(state>>29)); if(attempt%3==0) mutated.resize(state%mutated.size());
        int r=h.message(mutated); CHECK(r==IAP2_OK||r==IAP2_INVALID||r==IAP2_NO_SPACE||r==IAP2_UNSUPPORTED);
        if(r!=IAP2_OK) CHECK(h.backend.live.empty()&&h.s.state==PROJECTION_SESSION_DEAD);
    }
}
static void allocation_failures() {
    for(unsigned fail=1;fail<=7;++fail) { Harness h; h.backend.fail_open=fail;
        if(fail==1) CHECK(h.send("session")==-55); else { h.begin(); CHECK(h.send("streams")==-55); }
        CHECK(h.backend.closed.size()==fail&&h.backend.live.empty()); }
    for(unsigned fail=1;fail<=4;++fail) { Harness h;
        if(fail==2) { h.backend.bad_output=2; CHECK(h.send("session")==IAP2_INVALID); }
        else { h.begin(); h.backend.bad_output=static_cast<int>(fail); CHECK(h.send("streams")==IAP2_INVALID); }
        CHECK(h.backend.live.empty()&&h.backend.closed.size()==h.backend.opens); }
    for(int mode=5;mode<=8;++mode) { Harness h;
        if(mode==6||mode==7) { h.begin(); h.backend.bad_output=mode; CHECK(h.send("streams")==IAP2_INVALID); }
        else { h.backend.bad_output=mode; CHECK(h.send("session")==IAP2_INVALID); }
        CHECK(h.backend.live.empty()); CHECK(h.backend.closed.size()+(mode==5||mode==6?1:0)==h.backend.opens); }
    { Harness h; h.available_error=-66; CHECK(h.send("session")==-66&&h.backend.opens==0); }
    { Harness h; h.begin(); h.available_error=-66; CHECK(h.send("streams")==-66&&h.backend.live.empty()&&h.backend.opens==1); }
    { Harness h; h.begin(true); h.backend.start_error=-77; CHECK(h.message({},"RECORD")==IAP2_OK); CHECK(projection_session_release(&h.s)==-77&&h.backend.live.empty()); }
    { Harness h; h.begin(true); CHECK(h.message({},"RECORD")==IAP2_OK); h.release();
      CHECK(h.send("teardown_audio","TEARDOWN")==IAP2_OK); h.release(); h.backend.start_error=-77;
      CHECK(h.send("audio_new")==IAP2_OK); CHECK(projection_session_release(&h.s)==-77&&h.backend.live.empty()); }
    { Harness h; h.begin(true); h.available_error=-66; CHECK(h.send("empty","TEARDOWN")==IAP2_OK&&h.backend.live.empty()); CHECK(projection_session_release(&h.s)==IAP2_END); }
    { Harness h; h.backend.same_ports=true; h.begin(true); CHECK(h.backend.opens==7); } // Port number alone does not identify protocol/address ownership.
}
static void capabilities_and_config() {
    for(unsigned mode=0;mode<6;++mode) { Harness h; auto cfg=h.backend.config(); auto saved=h.s;
        if(mode==0) cfg.provider.open=nullptr; if(mode==1) cfg.provider.close=nullptr; if(mode==2) cfg.provider.start=nullptr; if(mode==3) cfg.enabled_features=16;
        if(mode==4) h.profile.hevc=0; if(mode==5) h.profile.display_count=1;
        CHECK(projection_session_init(&h.s,&h.profile,Harness::available,&h,&cfg,91)!=IAP2_OK&&std::memcmp(&h.s,&saved,sizeof(saved))==0&&h.backend.opens==0); }
    { Harness h; h.profile.keep_alive_low_power=0; CHECK(h.send("session")==IAP2_UNSUPPORTED&&h.backend.opens==0); }
    for(unsigned mode=0;mode<4;++mode) { Harness h;
        if(mode==0) h.profile.audio[5].output_formats=0; // Deliberate test-only invalidated advertised availability.
        if(mode==1) h.profile.audio[5].input_formats=0;
        if(mode==2) h.s.config.enabled_features&=~PROJECTION_SESSION_ALT_SCREEN;
        if(mode==3) h.s.config.enabled_features&=~PROJECTION_SESSION_IAP;
        h.begin(); CHECK(h.send("streams")==IAP2_UNSUPPORTED&&h.backend.opens==1); }
}
static FeedbackValues feedback_request(Harness& h,const char* output=nullptr) {
    CHECK(h.message({},"POST","/feedback")==IAP2_OK&&h.s.pending==6&&h.s.state==PROJECTION_SESSION_HELD);
    if(output) emit(output,h.s.reply,h.s.reply_size);
    auto values=feedback_values({h.s.reply,h.s.reply_size}); auto count=h.backend.playback_calls;
    CHECK(h.message({},"POST","/feedback")==RTSP_BUSY&&h.backend.playback_calls==count); h.release(); return values;
}
static void feedback_lifecycle(bool output=false) {
    Harness h(true); h.begin(); CHECK(feedback_request(h,output?"empty":nullptr).empty()&&h.backend.clock_calls==0&&h.backend.playback_calls==0);
    CHECK(h.send("streams")==IAP2_OK); h.release(); auto values=feedback_request(h,output?"prepared":nullptr);
    CHECK(values.size()==3&&h.backend.starts==0&&h.backend.observed_leases==std::vector<uint64_t>({4,5,6}));
    for(const auto& f:values) CHECK(f.size()==2);
    CHECK(h.message({},"RECORD")==IAP2_OK); h.release(); values=feedback_request(h,output?"playing":nullptr);
    CHECK(values.size()==3&&values[0].at("streamConnectionID")==UINT64_C(0x8000000000000000));
    for(const auto& f:values) CHECK(f.size()==6&&f.at("sampleTime")==UINT32_MAX&&f.at("timestampRawNs")==1000000&&f.at("timestamp")==UINT64_C(0x7fffffffe0000000));
    CHECK(values[2].at("sampleRate")==44100&&h.backend.starts==1&&h.available_calls==3);
    CHECK(h.send("teardown_audio","TEARDOWN")==IAP2_OK); h.release(); values=feedback_request(h,output?"retired":nullptr);
    CHECK(values.size()==2&&values[0].at("type")==101);
    CHECK(h.send("audio_new")==IAP2_OK); h.release(); values=feedback_request(h,output?"replacement":nullptr);
    CHECK(values.size()==3&&values.back().at("streamConnectionID")==UINT64_MAX&&h.backend.observed_leases.back()==8&&h.backend.starts==2);
    h.backend.position={UINT64_MAX-1,0,8000,1}; h.backend.observed_clock={UINT64_MAX,0,1};
    values=feedback_request(h,output?"wrap":nullptr);
    for(const auto& f:values) CHECK(f.at("timestamp")==UINT64_MAX-3&&f.at("sampleTime")==0&&f.at("timestampRawNs")==UINT64_MAX-1);
    h.backend.position={0,0,8000,0}; values=feedback_request(h,output?"missing":nullptr);
    for(const auto& f:values) CHECK(f.size()==2);
}
static void feedback_limits() {
    for(unsigned mode=0;mode<4;++mode) { Harness h; auto cfg=h.backend.config(true); auto saved=h.s;
        if(mode==0) cfg.feedback_max_age_ms=60001; if(mode==1) cfg.provider.playback=nullptr; if(mode==2) cfg.provider.clock=nullptr;
        if(mode==3) { cfg.provider.playback=nullptr; cfg.feedback_max_age_ms=0; }
        int r=projection_session_init(&h.s,&h.profile,Harness::available,&h,&cfg,91);
        CHECK(mode==3?r==IAP2_OK:(r==IAP2_ARGUMENT&&std::memcmp(&h.s,&saved,sizeof(saved))==0)); }
    for(unsigned mode=0;mode<10;++mode) { Harness h(true); h.begin(true); CHECK(h.message({},"RECORD")==IAP2_OK); h.release();
        auto& p=h.backend.position; auto& c=h.backend.observed_clock;
        if(mode==0) p.sample_rate=0; if(mode==1) p.sample_rate=384001; if(mode==2) p.has_position=2;
        if(mode==3) { p.has_position=0; p.raw_ns=0; } if(mode==4) p.raw_ns=c.raw_ns+1;
        if(mode==5) c.synchronized=2; if(mode==6) h.backend.playback_error=-55; if(mode==7) h.backend.clock_error=-66;
        if(mode==8) p.has_position=0; if(mode==9) { p.has_position=0; p.sample_time=0; }
        CHECK(h.message({},"POST","/feedback")!=IAP2_OK&&h.backend.live.empty()&&h.s.state==PROJECTION_SESSION_DEAD&&h.s.reply_size==0&&zeroed(h.s.reply,sizeof(h.s.reply)));
    }
    for(uint64_t age:{UINT64_C(0),UINT64_C(999999999),UINT64_C(1000000000),UINT64_C(1000000001),UINT64_MAX}) {
        Harness h(true); h.begin(true); CHECK(h.message({},"RECORD")==IAP2_OK); h.release();
        h.backend.position.raw_ns=0; h.backend.observed_clock.raw_ns=age;
        auto v=feedback_request(h); for(const auto& f:v) CHECK(f.size()==(age<=1000000000?6u:2u));
    }
    { Harness h(true); h.begin(true); CHECK(h.message({},"RECORD")==IAP2_OK); h.release(); h.backend.observed_clock.synchronized=0;
      for(const auto& f:feedback_request(h)) CHECK(f.size()==2); }
    { Harness h(true); h.begin(true); CHECK(h.message({},"RECORD")==IAP2_OK); h.release();
      h.backend.positions[6]={0,0,44100,0}; auto values=feedback_request(h);
      CHECK(values[0].size()==6&&values[1].size()==6&&values[2].size()==2); }
    { Harness h(true); h.begin(true); CHECK(h.message({},"RECORD")==IAP2_OK); h.release();
      h.backend.positions[6]={0,0,0,0}; CHECK(h.message({},"POST","/feedback")==IAP2_INVALID&&h.backend.playback_calls==3&&h.backend.live.empty()&&h.s.reply_size==0); }
    { Harness h(true); h.s.config.feedback_max_age_ms=60000; // Deliberate upper-bound seam.
      h.begin(true); CHECK(h.message({},"RECORD")==IAP2_OK); h.release(); h.backend.position.raw_ns=0; h.backend.observed_clock={60000000000,0,1};
      for(const auto& f:feedback_request(h)) CHECK(f.at("timestamp")==UINT64_C(0xffffffc400000000)); }
    for(const char* name:{"bad_array","bad_duplicate_key","bad_xml"}) { Harness h(true); h.begin(true);
        CHECK(h.message(vectors.at(name),"POST","/feedback")!=IAP2_OK&&h.backend.playback_calls==0&&h.backend.live.empty()); }
    for(const char* method:{"GET","SETUP","RECORD","TEARDOWN"}) { Harness h(true); h.begin(true);
        CHECK(h.message({},method,"/feedback")==IAP2_UNSUPPORTED&&h.backend.playback_calls==0&&h.backend.live.empty()); }
    { Harness h(true); CHECK(h.message({},"POST","/feedback")==IAP2_INVALID&&h.backend.opens==0); }
    { Harness h; h.begin(true); CHECK(h.message({},"POST","/feedback")==IAP2_UNSUPPORTED&&h.backend.playback_calls==0); }
    { Harness h(true); h.begin(true); CHECK(h.message(vectors.at("session"),"POST","/feedback")==IAP2_OK&&h.backend.opens==7); } // Bounded dict metadata has no effect.
}
int main(int argc,char** argv) {
    try { CHECK(argc==2||argc==3); vectors=load_vectors(argv[1],42);
        if(argc==3) { auto mode=std::string(argv[2]); CHECK(mode=="--emit"||mode=="--feedback"); if(mode=="--emit") lifecycle(true); else feedback_lifecycle(true); return 0; }
        lifecycle(); schemas_and_boundaries(); allocation_failures(); capabilities_and_config(); feedback_lifecycle(); feedback_limits();
        std::cout<<"PASS: 6 session groups; typed allocation, keys, teardown, capability/state gates and observed playback feedback; synthetic endpoints only\n";
        std::cout<<"x64 session bytes: "<<sizeof(projection_session)<<"; caller scratch/stack additional\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
