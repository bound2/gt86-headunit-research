/* SPDX-License-Identifier: GPL-3.0-only
 * Public synthetic phone keys / opaque MFi provider; actual protocol crypto.
 */
#include "projection_receiver.h"
#include "pair_store.h"
#include "pair_test_support.h"
#include "projection_info_fixture.h"

template<class T> static auto snapshot(const T& s) {
    std::array<uint8_t,sizeof(T)> b{}; std::memcpy(b.data(),&s,sizeof(T)); return b;
}
static Bytes outer(const Bytes& body, unsigned seq, const std::string& route,
                   const std::string& method="POST", const std::string& type="application/pairing+tlv8") {
    auto b=bytes(method+" "+route+" RTSP/1.0\r\nCSeq: "+std::to_string(seq)+
        "\r\nContent-Type: "+type+"\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n");
    b.insert(b.end(),body.begin(),body.end()); return b;
}
static std::array<uint8_t,12> nonce(uint64_t counter) {
    std::array<uint8_t,12> b{};
    for(size_t i=0;i<8;++i) b[4+i]=static_cast<uint8_t>(counter>>(8*i));
    return b;
}
struct Harness {
    const Vectors& v; const Vectors& setup_v;
    projection_receiver s{}; projection_receiver_config cfg{}; pair_store_data store{};
    Bytes initial=Bytes(8192),rx=Bytes(8192),tx=Bytes(8192),crx=Bytes(274),plain=Bytes(256),ctx=Bytes(274);
    bool enrolling=false,known=true; unsigned random_calls=0,lookups=0,commits=0,identities=0,signatures=0;
    int commit_error=0,random_error=0,identity_error=0; uint64_t incoming=0,outgoing=0;
    std::vector<rtsp_channel_key> completed;
    Harness(const Vectors& a,const Vectors& b,bool setup=false,uint64_t now=0,size_t control_capacity=8192)
        :v(a),setup_v(b),initial(control_capacity),rx(control_capacity),tx(control_capacity),enrolling(setup) {
        const auto& id=v.at("pv_own_identifier");
        CHECK(pair_store_init(&store,v.at("pv_own_seed").data(),v.at("pv_own_public").data(),id.data(),id.size())==IAP2_OK);
        if(!setup) CHECK(pair_store_add(&store,v.at("pv_ctrl_identifier").data(),v.at("pv_ctrl_identifier").size(),v.at("pv_ctrl_public").data())==IAP2_OK);
        projection_receiver_default_config(&cfg); cfg.enrollment_enabled=setup?1:0; cfg.auth.control.cipher.payload_limit=256;
        auto p=providers(); auto bfr=storage();
        CHECK(projection_receiver_init(&s,&p,&cfg,&bfr,91,92,now)==IAP2_OK);
        CHECK(random_calls==0&&lookups==0&&commits==0&&identities==0&&s.state==PROJECTION_RECEIVER_ROUTING);
    }
    ~Harness() { projection_receiver_close(&s); pair_store_clear(&store); }
    Harness(const Harness&)=delete; Harness& operator=(const Harness&)=delete;
    projection_receiver_storage storage() {
        return {initial.data(),initial.size(),{rx.data(),tx.data(),crx.data(),plain.data(),ctx.data(),
            rx.size(),tx.size(),crx.size(),plain.size(),ctx.size()}};
    }
    projection_receiver_providers providers() {
        return {&store.identity,random,this,lookup,this,enrolling?commit:nullptr,this,{this,identity,sign}};
    }
    static int random(void* p,uint8_t* out,size_t n) {
        auto& h=*static_cast<Harness*>(p); ++h.random_calls;
        const Bytes *b=nullptr;
        if(h.enrolling&&h.random_calls<=2) b=&h.setup_v.at(h.random_calls==1?"salt":"b");
        else b=&h.v.at(h.random_calls==(h.enrolling?3u:1u)?"pv_own_ephemeral_secret":"own_secret");
        CHECK(n==b->size()); std::copy(b->begin(),b->end(),out); return h.random_error;
    }
    static int lookup(void* p,const uint8_t* id,size_t n,uint8_t* key) {
        auto& h=*static_cast<Harness*>(p); ++h.lookups;
        return h.known?pair_store_lookup(&h.store,id,n,key):IAP2_END;
    }
    static int commit(void* p,uint64_t gen,uint64_t authority,const uint8_t* id,size_t n,const uint8_t* key) {
        auto& h=*static_cast<Harness*>(p); CHECK(gen==91&&authority==77); ++h.commits;
        if(h.commit_error) return h.commit_error;
        int r=pair_store_add(&h.store,id,n,key); return r==IAP2_END?IAP2_OK:r; // Memory-only commit simulation.
    }
    static int identity(void* p,uint64_t gen,uint8_t* out,size_t cap,size_t* n,uint8_t* major) {
        auto& h=*static_cast<Harness*>(p); CHECK(gen==92&&cap>=h.v.at("certificate").size()); ++h.identities;
        const auto& b=h.v.at("certificate"); std::copy(b.begin(),b.end(),out); *n=b.size(); *major=3;
        return h.identity_error;
    }
    static int sign(void* p,uint64_t gen,const uint8_t* digest,size_t n,uint8_t* out,size_t cap,size_t* written) {
        auto& h=*static_cast<Harness*>(p); CHECK(gen==92&&Bytes(digest,digest+n)==h.v.at("digest3")); ++h.signatures;
        const auto& b=h.v.at("signature3"); CHECK(cap>=b.size()); std::copy(b.begin(),b.end(),out); *written=b.size(); return IAP2_OK;
    }
    int feed(const Bytes& b,uint64_t now=1,size_t* consumed=nullptr) {
        size_t n=0; int r=projection_receiver_feed(&s,91,b.data(),b.size(),&n,now);
        if(consumed) *consumed=n; else CHECK(n==b.size());
        return r;
    }
    int fragment(const Bytes& b,size_t chunk=1) {
        size_t offset=0; int r=IAP2_MORE;
        while(offset<b.size()) {
            CHECK(r==IAP2_MORE); size_t n=0,offered=std::min(chunk,b.size()-offset);
            r=projection_receiver_feed(&s,91,b.data()+offset,offered,&n,1); CHECK(n==offered); offset+=n;
        }
        return r;
    }
    Bytes frame(const Bytes& b) {
        CHECK(b.size()<=256); Bytes out(b.size()+18); size_t n=0; auto nn=nonce(incoming++);
        out[0]=static_cast<uint8_t>(b.size()); out[1]=static_cast<uint8_t>(b.size()>>8);
        CHECK(pair_aead_seal(v.at("pv_accessory_read_key").data(),nn.data(),out.data(),2,b.data(),b.size(),out.data()+2,out.size()-2,&n)==IAP2_OK);
        return out;
    }
    Bytes drain(bool encrypted,int expected,bool release=true) {
        rtsp_slice output{}; rtsp_channel_key key{}; Bytes wire; int r;
        CHECK(projection_receiver_output(&s,91,&output,&key,1)==RTSP_CHANNEL_OUTPUT&&key.generation==91);
        auto saved=snapshot(s);
        CHECK(projection_receiver_release(&s,key,UINT64_MAX)==RTSP_BUSY&&snapshot(s)==saved);
        while((r=projection_receiver_output(&s,91,&output,&key,1))==RTSP_CHANNEL_OUTPUT) {
            size_t n=std::min(size_t(3),output.size); wire.insert(wire.end(),output.data,output.data+n);
            int consumed=projection_receiver_consume(&s,key,n,1);
            CHECK(consumed==RTSP_CHANNEL_OUTPUT||consumed==RTSP_CHANNEL_OUTPUT_DONE);
        }
        CHECK(r==RTSP_CHANNEL_OUTPUT_DONE); Bytes decoded;
        if(encrypted) {
            for(size_t off=0;off<wire.size();) {
                CHECK(wire.size()-off>=18); size_t n=wire[off]+(size_t(wire[off+1])<<8),used=0;
                CHECK(n<=256&&wire.size()-off>=n+18); Bytes b(n); auto nn=nonce(outgoing++);
                CHECK(pair_aead_open(v.at("pv_accessory_write_key").data(),nn.data(),wire.data()+off,2,
                    wire.data()+off+2,n+16,b.data(),b.size(),&used)==IAP2_OK&&used==n);
                decoded.insert(decoded.end(),b.begin(),b.end()); off+=n+18;
            }
        } else decoded=wire;
        if(release) {
            CHECK(projection_receiver_release(&s,key,1)==expected); completed.push_back(key);
            saved=snapshot(s);
            CHECK(projection_receiver_release(&s,key,UINT64_MAX)==IAP2_INVALID&&snapshot(s)==saved);
        }
        return decoded;
    }
    static void reply(const Bytes& b,const Bytes& expected,unsigned seq) {
        rtsp_message m{}; size_t n=0;
        CHECK(rtsp_message_decode(b.data(),b.size(),&m,&n)==IAP2_OK&&n==b.size()&&m.status==200&&m.cseq==seq);
        CHECK(Bytes(m.body.data,m.body.data+m.body.size)==expected);
    }
    void pair() {
        for(unsigned step:{1u,3u}) {
            CHECK(fragment(outer(v.at("pv_m"+std::to_string(step)),step,"/pair-verify"),7)==RTSP_CHANNEL_OUTPUT);
            reply(drain(false,step==1?IAP2_OK:PROJECTION_CONTROL_SECURE),v.at("pv_m"+std::to_string(step+1)),step);
        }
        CHECK(s.state==PROJECTION_RECEIVER_AUTH&&s.auth.control.state==PROJECTION_CONTROL_ENCRYPTED&&identities==0);
    }
    void to_candidate(bool preauthorize=false) {
        if(preauthorize) CHECK(projection_receiver_authorize(&s,91,77,1)==IAP2_OK);
        auto first=outer(setup_v.at("setup_1"),1,"/pair-setup");
        CHECK(fragment(first)==(preauthorize?RTSP_CHANNEL_OUTPUT:PROJECTION_RECEIVER_AUTHORIZE));
        if(!preauthorize) {
            CHECK(random_calls==0&&commits==0&&identities==0&&lookups==0);
            CHECK(projection_receiver_authorize(&s,91,77,1)==RTSP_CHANNEL_OUTPUT);
        }
        CHECK(zeroed(initial.data(),initial.size()));
        reply(drain(false,IAP2_OK),setup_v.at("setup_2"),1);
        CHECK(fragment(outer(setup_v.at("setup_3"),3,"/pair-setup"),13)==RTSP_CHANNEL_OUTPUT);
        reply(drain(false,IAP2_OK),setup_v.at("setup_4"),3);
        CHECK(fragment(outer(setup_v.at("setup_5"),5,"/pair-setup"),11)==PAIR_SETUP_APPROVAL);
        CHECK(commits==0&&store.count==0);
    }
    void cleared() {
        CHECK(s.state==PROJECTION_RECEIVER_DEAD&&s.authorization==0&&s.key.token==0&&s.child_key.token==0);
        CHECK(zeroed(&s.providers,sizeof(s.providers))&&zeroed(initial.data(),initial.size()));
        CHECK(zeroed(rx.data(),rx.size())&&zeroed(tx.data(),tx.size()));
        CHECK(zeroed(crx.data(),crx.size())&&zeroed(plain.data(),plain.size())&&zeroed(ctx.data(),ctx.size()));
    }
};

static void known_route(const Vectors& v,const Vectors& setup_v) {
    const auto first=outer(v.at("pv_m1"),1,"/pair-verify");
    for(size_t split=0;split<=first.size();++split) {
        Harness part(v,setup_v); size_t used=999;
        int r=projection_receiver_feed(&part.s,91,first.data(),split,&used,1);
        CHECK(used==split&&r==(split==first.size()?RTSP_CHANNEL_OUTPUT:IAP2_MORE));
        if(split<first.size()) {
            CHECK(part.random_calls==0);
            CHECK(projection_receiver_feed(&part.s,91,first.data()+split,first.size()-split,&used,1)==RTSP_CHANNEL_OUTPUT&&used==first.size()-split);
        }
        Harness::reply(part.drain(false,IAP2_OK),v.at("pv_m2"),1);
        CHECK(part.random_calls==1&&part.lookups==0&&part.identities==0);
    }
    Harness h(v,setup_v); h.pair(); CHECK(!h.s.enrolled&&h.commits==0&&h.random_calls==1);
    CHECK(zeroed(h.initial.data(),h.initial.size())&&h.s.initial.state==RTSP_CHANNEL_DEAD);
    auto auth=outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream");
    auto tail=bytes("GET /info RTSP/1.0\r\nCSeq: 8\r\n\r\n"); auth.insert(auth.end(),tail.begin(),tail.end());
    CHECK(h.fragment(h.frame(auth))==RTSP_CHANNEL_OUTPUT);
    Harness::reply(h.drain(true,MFI_SAP_DRAINED),v.at("response3"),7);
    CHECK(h.identities==1&&h.signatures==1&&h.random_calls==2);
    CHECK(h.feed({})==RTSP_CHANNEL_REQUEST);
    rtsp_message req{}; rtsp_channel_key key{};
    CHECK(projection_receiver_request(&h.s,&req,&key)==RTSP_CHANNEL_REQUEST&&req.cseq==8&&key.token==4&&key.generation==91);
    rtsp_response response={501,{},nullptr,0,{}};
    CHECK(projection_receiver_respond(&h.s,key,&response,1)==RTSP_CHANNEL_OUTPUT);
    auto b=h.drain(true,IAP2_OK); size_t n=0;
    CHECK(rtsp_message_decode(b.data(),b.size(),&req,&n)==IAP2_OK&&req.status==501&&req.cseq==8);
    for(size_t i=0;i<h.completed.size();++i) CHECK(h.completed[i].token==i+1&&h.completed[i].generation==91);
    projection_receiver_close(&h.s); h.cleared();
}
static void enrollment_route(const Vectors& v,const Vectors& setup_v) {
    for(bool preauthorize:{false,true}) {
        Harness h(v,setup_v,true); h.to_candidate(preauthorize);
        pair_setup_candidate candidate{}; rtsp_channel_key key{};
        CHECK(projection_receiver_pending(&h.s,&candidate,&key)==PAIR_SETUP_APPROVAL&&key.token==3);
        CHECK(Bytes(candidate.identifier,candidate.identifier+candidate.identifier_size)==v.at("pv_ctrl_identifier"));
        CHECK(equal(candidate.public_key,v.at("pv_ctrl_public")));
        auto saved=snapshot(h.s); auto wrong=key; ++wrong.token;
        CHECK(projection_receiver_decide(&h.s,wrong,1,UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==saved&&h.commits==0);
        CHECK(projection_receiver_decide(&h.s,key,2,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(h.s)==saved);
        CHECK(projection_receiver_decide(&h.s,key,1,1)==RTSP_CHANNEL_OUTPUT&&h.commits==1&&h.s.enrolled);
        auto next=outer(v.at("pv_m1"),1,"/pair-verify"); size_t used=99;
        CHECK(h.feed(next,1,&used)==RTSP_BUSY&&used==0&&h.s.state==PROJECTION_RECEIVER_SETUP);
        Harness::reply(h.drain(false,PAIR_SETUP_COMPLETE),setup_v.at("setup_6"),5);
        CHECK(h.s.state==PROJECTION_RECEIVER_AUTH&&h.s.setup.state==PAIR_SETUP_CHANNEL_DETACHED);
        CHECK(h.s.generation==91&&h.s.auth.generation==92&&h.s.enrolled&&h.random_calls==2&&h.identities==0);
        CHECK(h.feed(next)==RTSP_CHANNEL_OUTPUT&&h.s.key.token==4&&h.s.child_key.token==1&&h.s.child_key.generation==92);
        saved=snapshot(h.s);
        CHECK(projection_receiver_consume(&h.s,h.completed.front(),1,UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==saved);
        CHECK(projection_receiver_release(&h.s,h.s.child_key,UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==saved);
        Harness::reply(h.drain(false,IAP2_OK),v.at("pv_m2"),1);
        auto m3=outer(v.at("pv_m3"),3,"/pair-verify");
        auto auth=h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream"));
        auto pipeline=m3; pipeline.insert(pipeline.end(),auth.begin(),auth.end());
        CHECK(h.feed(pipeline,1,&used)==RTSP_CHANNEL_OUTPUT&&used==m3.size()&&h.identities==0);
        CHECK(h.feed(auth,1,&used)==RTSP_BUSY&&used==0&&h.identities==0);
        Harness::reply(h.drain(false,PROJECTION_CONTROL_SECURE),v.at("pv_m4"),3);
        CHECK(h.fragment(auth)==RTSP_CHANNEL_OUTPUT);
        Harness::reply(h.drain(true,MFI_SAP_DRAINED),v.at("response3"),7);
        CHECK(h.commits==1&&h.store.count==1&&h.random_calls==4&&h.signatures==1);
        for(size_t i=0;i<h.completed.size();++i) CHECK(h.completed[i].token==i+1);
        projection_receiver_close(&h.s); CHECK(h.s.enrolled&&h.store.count==1); h.cleared();
    }
}
static void permission_and_failure(const Vectors& v,const Vectors& setup_v) {
    { Harness h(v,setup_v); auto saved=snapshot(h.s);
      CHECK(projection_receiver_authorize(&h.s,91,77,UINT64_MAX)==IAP2_UNSUPPORTED&&snapshot(h.s)==saved);
      CHECK(h.feed(outer(setup_v.at("setup_1"),1,"/pair-setup"))==PROJECTION_RECEIVER_CLOSED&&h.random_calls==0); h.cleared(); }
    { Harness h(v,setup_v,true);
      auto b=outer(setup_v.at("setup_1"),1,"/pair-setup"),tail=outer(v.at("pv_m1"),2,"/pair-verify"); size_t exact=b.size(),used=0;
      b.insert(b.end(),tail.begin(),tail.end()); CHECK(h.feed(b,1,&used)==PROJECTION_RECEIVER_AUTHORIZE&&used==exact);
      rtsp_slice output{}; rtsp_channel_key key{}; pair_setup_candidate candidate{};
      CHECK(projection_receiver_output(&h.s,91,&output,&key,1)==RTSP_BUSY&&!output.data&&!key.token);
      CHECK(projection_receiver_pending(&h.s,&candidate,&key)==IAP2_MORE&&zeroed(&candidate,sizeof(candidate)));
      auto saved=snapshot(h.s);
      CHECK(projection_receiver_authorize(&h.s,92,77,UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==saved);
      CHECK(projection_receiver_authorize(&h.s,91,0,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(h.s)==saved);
      CHECK(h.feed(tail,1,&used)==RTSP_BUSY&&used==0&&h.random_calls==0);
      projection_receiver_close(&h.s); h.cleared(); CHECK(h.commits==0&&h.random_calls==0); }
    for(int choice:{0,1}) { Harness h(v,setup_v,true); h.to_candidate();
        pair_setup_candidate candidate{}; rtsp_channel_key key{};
        CHECK(projection_receiver_pending(&h.s,&candidate,&key)==PAIR_SETUP_APPROVAL);
        if(choice) h.commit_error=PAIR_STORE_UNCERTAIN;
        CHECK(projection_receiver_decide(&h.s,key,choice,1)==PROJECTION_RECEIVER_CLOSED);
        CHECK(h.commits==unsigned(choice)&&h.store.count==0&&!h.s.enrolled&&h.identities==0); h.cleared();
    }
    { Harness h(v,setup_v); h.known=false;
      CHECK(h.feed(outer(v.at("pv_m1"),1,"/pair-verify"))==RTSP_CHANNEL_OUTPUT); h.drain(false,IAP2_OK);
      CHECK(h.feed(outer(v.at("pv_m3"),3,"/pair-verify"))==PROJECTION_RECEIVER_CLOSED&&h.lookups==1&&h.identities==0); h.cleared(); }
    { Harness h(v,setup_v); h.random_error=-1;
      CHECK(h.feed(outer(v.at("pv_m1"),1,"/pair-verify"))==PROJECTION_RECEIVER_CLOSED&&h.random_calls==1); h.cleared(); }
    { Harness h(v,setup_v); h.pair(); h.identity_error=-99;
      CHECK(h.feed(h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==PROJECTION_RECEIVER_CLOSED&&h.identities==1&&h.signatures==0); h.cleared(); }
}
static void invalid_routes(const Vectors& v,const Vectors& setup_v) {
    for(unsigned mode=0;mode<11;++mode) {
        Harness h(v,setup_v,true); Bytes b; std::string path="/pair-verify",method="POST",type="application/pairing+tlv8";
        if(mode==0) path="/info";
        if(mode==1) path="/auth-setup";
        if(mode==2) path="rtsp://unit/pair-verify";
        if(mode==3) path="/PAIR-VERIFY";
        if(mode==4) path="/pair-verify?x=1";
        if(mode==5) method="GET";
        if(mode==6) type="application/octet-stream";
        if(mode==7) type+="\r\nContent-Type: application/pairing+tlv8";
        b=outer(v.at("pv_m1"),1,path,method,type);
        if(mode==8) b=bytes("POST /pair-verify RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n");
        if(mode==9) b=bytes("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n");
        if(mode==10) b=outer({},1,"/pair-verify");
        size_t used=0; CHECK(h.feed(b,1,&used)==PROJECTION_RECEIVER_CLOSED&&used<=b.size());
        CHECK(h.random_calls==0&&h.lookups==0&&h.commits==0&&h.identities==0); h.cleared();
    }
    { Harness h(v,setup_v,true); CHECK(projection_receiver_authorize(&h.s,91,77,1)==IAP2_OK);
      CHECK(h.feed(outer(setup_v.at("setup_3"),1,"/pair-setup"))==PROJECTION_RECEIVER_CLOSED&&h.random_calls==0); h.cleared(); }
    { Harness h(v,setup_v); CHECK(h.feed(outer(v.at("pv_m1"),1,"/pair-verify"))==RTSP_CHANNEL_OUTPUT); h.drain(false,IAP2_OK);
      CHECK(h.feed(outer(setup_v.at("setup_1"),3,"/pair-setup"))==PROJECTION_RECEIVER_CLOSED&&h.commits==0); h.cleared(); }
}
static void initial_lifetimes(const Vectors& v,const Vectors& setup_v) {
    { Harness h(v,setup_v); CHECK(projection_receiver_next_delay(&h.s)==30000);
      CHECK(projection_receiver_check(&h.s,91,29999)==IAP2_OK&&projection_receiver_next_delay(&h.s)==1);
      CHECK(projection_receiver_check(&h.s,91,30000)==PROJECTION_RECEIVER_CLOSED); h.cleared(); }
    { Harness h(v,setup_v); auto b=bytes("P"); CHECK(h.feed(b,1)==IAP2_MORE);
      CHECK(h.feed(bytes("O"),10000)==IAP2_MORE&&projection_receiver_next_delay(&h.s)==1);
      size_t used=9; CHECK(h.feed(bytes("S"),10001,&used)==PROJECTION_RECEIVER_CLOSED&&used==0); h.cleared(); }
    { Harness h(v,setup_v,true); CHECK(h.feed(outer(setup_v.at("setup_1"),1,"/pair-setup"))==PROJECTION_RECEIVER_AUTHORIZE);
      CHECK(projection_receiver_check(&h.s,91,30000)==IAP2_OK&&projection_receiver_next_delay(&h.s)==1);
      CHECK(projection_receiver_authorize(&h.s,91,77,30001)==PROJECTION_RECEIVER_CLOSED&&h.random_calls==0); h.cleared(); }
    { Harness h(v,setup_v); CHECK(h.feed(bytes("POST"))==IAP2_MORE);
      CHECK(projection_receiver_eof(&h.s,91,1)==PROJECTION_RECEIVER_CLOSED); h.cleared(); }
    { Harness h(v,setup_v,true); CHECK(projection_receiver_authorize(&h.s,91,77,1)==IAP2_OK); auto saved=snapshot(h.s);
      CHECK(projection_receiver_authorize(&h.s,91,78,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved);
      CHECK(projection_receiver_check(&h.s,91,30000)==PROJECTION_RECEIVER_CLOSED&&h.random_calls==0); h.cleared(); }
    { Harness h(v,setup_v,false,UINT64_MAX-10);
      CHECK(projection_receiver_check(&h.s,91,UINT64_MAX)==IAP2_OK&&projection_receiver_next_delay(&h.s)==29990);
      auto saved=snapshot(h.s); CHECK(projection_receiver_check(&h.s,91,0)==IAP2_ARGUMENT&&snapshot(h.s)==saved); }
}
static void transactionality(const Vectors& v,const Vectors& setup_v) {
    Harness h(v,setup_v,true); auto saved=snapshot(h.s); auto first=outer(setup_v.at("setup_1"),1,"/pair-setup"); size_t used=99;
    CHECK(projection_receiver_feed(&h.s,92,first.data(),first.size(),&used,UINT64_MAX)==IAP2_INVALID&&used==0&&snapshot(h.s)==saved);
    CHECK(projection_receiver_feed(&h.s,91,nullptr,1,&used,UINT64_MAX)==IAP2_ARGUMENT&&used==0&&snapshot(h.s)==saved);
    CHECK(projection_receiver_check(&h.s,91,1)==IAP2_OK); saved=snapshot(h.s);
    CHECK(projection_receiver_feed(&h.s,91,first.data(),first.size(),&used,0)==IAP2_ARGUMENT&&used==0&&snapshot(h.s)==saved);
    // Nonzero sentinels detect forbidden writes even when a failing initializer
    // would only zero buffers. No live request/child has used these buffers yet.
    for(auto* buffer:{&h.initial,&h.rx,&h.tx,&h.crx,&h.plain,&h.ctx}) std::fill(buffer->begin(),buffer->end(),0xa5);
    for(unsigned mode=0;mode<11;++mode) {
        auto cfg=h.cfg; auto p=h.providers(); auto b=h.storage(); uint64_t gen=91,verify=92;
        if(mode==0) verify=gen;
        if(mode==1) gen=0;
        if(mode==2) cfg.enrollment_enabled=2;
        if(mode==3) p.commit=nullptr;
        if(mode==4) p.mfi.sign=nullptr;
        if(mode==5) cfg.auth.auth_hold_ms=0;
        if(mode==6) cfg.setup.setup.exchange_ms=0;
        if(mode==7) cfg.initial.receive_ms=0;
        if(mode==8) b.initial_capacity=b.control.request_capacity+1;
        if(mode==9) b.control.response_capacity=64;
        if(mode==10) b.initial=nullptr;
        auto buffers=h.initial; auto rx=h.rx,tx=h.tx,crx=h.crx,plain=h.plain,ctx=h.ctx;
        CHECK(projection_receiver_init(&h.s,&p,&cfg,&b,gen,verify,1)==IAP2_ARGUMENT&&snapshot(h.s)==saved);
        CHECK(h.initial==buffers&&h.rx==rx&&h.tx==tx&&h.crx==crx&&h.plain==plain&&h.ctx==ctx&&h.random_calls==0);
    }
    for(auto* buffer:{&h.initial,&h.rx,&h.tx,&h.crx,&h.plain,&h.ctx}) std::fill(buffer->begin(),buffer->end(),0);
    CHECK(projection_receiver_authorize(&h.s,91,77,1)==IAP2_OK&&h.feed(first)==RTSP_CHANNEL_OUTPUT);
    rtsp_slice out{}; rtsp_channel_key key{};
    CHECK(projection_receiver_output(&h.s,91,&out,&key,1)==RTSP_CHANNEL_OUTPUT); saved=snapshot(h.s);
    CHECK(projection_receiver_consume(&h.s,key,0,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(h.s)==saved);
    CHECK(projection_receiver_consume(&h.s,key,out.size+1,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(h.s)==saved);
    auto wrong=key; ++wrong.token;
    CHECK(projection_receiver_consume(&h.s,wrong,1,UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==saved);
    CHECK(projection_receiver_release(&h.s,key,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved);
    CHECK(projection_receiver_consume(&h.s,key,1,0)==IAP2_ARGUMENT&&snapshot(h.s)==saved);
    CHECK(projection_receiver_eof(&h.s,91,1)==PROJECTION_RECEIVER_CLOSED); h.cleared(); saved=snapshot(h.s);
    projection_receiver_close(&h.s); CHECK(snapshot(h.s)==saved);
}
static void exhausted_and_late(const Vectors& v,const Vectors& setup_v) {
    { Harness h(v,setup_v); h.s.next_token=UINT64_MAX; // Deliberate test-only counter-exhaustion seam.
      CHECK(h.feed(outer(v.at("pv_m1"),1,"/pair-verify"))==RTSP_CHANNEL_OUTPUT&&h.s.key.token==UINT64_MAX);
      h.drain(false,IAP2_OK); size_t used=9;
      CHECK(h.feed(outer(v.at("pv_m3"),3,"/pair-verify"),1,&used)==PROJECTION_RECEIVER_CLOSED&&used==0&&h.lookups==0);
      CHECK(h.s.reason==PROJECTION_RECEIVER_REASON_TOKEN); h.cleared(); }
    { Harness h(v,setup_v); h.pair(); CHECK(h.feed(h.frame(outer(v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT);
      h.drain(true,MFI_SAP_DRAINED,false); auto key=h.s.key;
      CHECK(projection_receiver_release(&h.s,key,5001)==PROJECTION_RECEIVER_CLOSED&&h.s.auth.auth.state==MFI_SAP_DEAD); h.cleared(); }
    { Harness h(v,setup_v,true); h.to_candidate(); pair_setup_candidate candidate{}; rtsp_channel_key key{};
      CHECK(projection_receiver_pending(&h.s,&candidate,&key)==PAIR_SETUP_APPROVAL);
      CHECK(projection_receiver_decide(&h.s,key,1,1)==RTSP_CHANNEL_OUTPUT&&h.commits==1);
      h.drain(false,PAIR_SETUP_COMPLETE,false);
      CHECK(projection_receiver_release(&h.s,key,10001)==PROJECTION_RECEIVER_CLOSED&&h.s.enrolled&&h.store.count==1);
      CHECK(h.s.auth.generation==0&&h.identities==0); h.cleared(); }
}
struct InfoBackend {
    projection_info_profile profile;
    Bytes scratch=Bytes(PROJECTION_INFO_LIMIT,0xa5); unsigned calls=0; int result=0;
    explicit InfoBackend(unsigned variant=1):profile(info_fixture(variant)) {}
    static int available(void* context,uint64_t generation,const projection_info_profile* profile) {
        auto& self=*static_cast<InfoBackend*>(context); CHECK(generation==91&&profile==&self.profile);
        ++self.calls; return self.result; // Explicit synthetic availability attestation, not a real driver.
    }
    projection_receiver_info_config config(bool initial=false) {
        projection_receiver_info_config cfg{}; projection_receiver_info_default_config(&cfg);
        cfg.profile=&profile; cfg.available=available; cfg.context=this; cfg.buffer=scratch.data(); cfg.capacity=scratch.size(); cfg.allow_initial=initial?1:0;
        return cfg;
    }
    void enable(Harness& h,bool initial=false) { auto cfg=config(initial); auto saved=scratch;
        CHECK(projection_receiver_enable_info(&h.s,91,&cfg,0)==IAP2_OK&&calls==0&&scratch==saved&&h.random_calls==0); }
    void reply(const Bytes& encoded,bool http=false) {
        rtsp_message response{}; size_t n=0; auto expected=info_encode(profile);
        CHECK(rtsp_message_decode(encoded.data(),encoded.size(),&response,&n)==IAP2_OK&&response.status==200&&n==encoded.size());
        CHECK(Bytes(response.body.data,response.body.data+response.body.size)==expected);
        rtsp_slice type{}; CHECK(rtsp_header_get(&response,info_text("Content-Type"),&type)==IAP2_OK);
        CHECK(Bytes(type.data,type.data+type.size)==bytes("application/x-apple-binary-plist"));
        if(http) CHECK(response.protocol==RTSP_HTTP_11&&!response.has_cseq);
        CHECK(zeroed(scratch.data(),expected.size()));
    }
};
static Bytes empty_dictionary() {
    return hex("62706c6973743030d0080000000000000101000000000000000100000000000000000000000000000009");
}
static void info_routes(const Vectors& v,const Vectors& setup_v) {
    { InfoBackend info; Harness h(v,setup_v); info.enable(h,true);
      auto get=bytes("GET /info HTTP/1.1\r\n\r\n"),next=outer(v.at("pv_m1"),1,"/pair-verify"); auto pipeline=get; pipeline.insert(pipeline.end(),next.begin(),next.end()); size_t used=0;
      CHECK(h.feed(pipeline,1,&used)==RTSP_CHANNEL_OUTPUT&&used==get.size()&&info.calls==1&&h.random_calls==0&&h.s.state==PROJECTION_RECEIVER_DISCOVERY);
      CHECK(h.feed(next,1,&used)==RTSP_BUSY&&used==0&&info.calls==1);
      auto old=snapshot(h.s); rtsp_response fake={501,{},nullptr,0,{}};
      CHECK(projection_receiver_respond(&h.s,h.s.key,&fake,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==old);
      info.reply(h.drain(false,IAP2_OK),true); CHECK(h.s.state==PROJECTION_RECEIVER_ROUTING&&h.s.initial_info_count==1);
      h.pair(); CHECK(h.s.info.profile==&info.profile);
      auto post=outer(empty_dictionary(),7,"/info","POST","application/x-apple-binary-plist");
      CHECK(h.fragment(h.frame(post))==RTSP_CHANNEL_OUTPUT&&info.calls==2&&h.identities==0&&h.s.info_pending);
      rtsp_message request{}; rtsp_channel_key key{};
      CHECK(projection_receiver_request(&h.s,&request,&key)==IAP2_MORE&&!key.token);
      info.reply(h.drain(true,IAP2_OK)); CHECK(!h.s.info_pending);
      auto full=outer(info_encode(info.profile),71,"/info","POST","application/x-apple-binary-plist");
      for(size_t offset=0;offset<full.size();) {
          size_t end=std::min(offset+256,full.size()); Bytes piece(full.begin()+offset,full.begin()+end);
          CHECK(h.feed(h.frame(piece))==(end==full.size()?RTSP_CHANNEL_OUTPUT:IAP2_MORE)); offset=end;
      }
      CHECK(info.calls==3); info.reply(h.drain(true,IAP2_OK));
      CHECK(h.feed(h.frame(outer(v.at("request"),8,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT);
      Harness::reply(h.drain(true,MFI_SAP_DRAINED),v.at("response3"),8);
      auto get_encrypted=bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n"),tail=bytes("GET /unimplemented RTSP/1.0\r\nCSeq: 10\r\n\r\n");
      get_encrypted.insert(get_encrypted.end(),tail.begin(),tail.end());
      CHECK(h.feed(h.frame(get_encrypted))==RTSP_CHANNEL_OUTPUT&&info.calls==4); info.reply(h.drain(true,IAP2_OK));
      CHECK(h.feed({})==RTSP_CHANNEL_REQUEST&&info.calls==4);
      CHECK(projection_receiver_request(&h.s,&request,&key)==RTSP_CHANNEL_REQUEST&&request.cseq==10);
      CHECK(projection_receiver_respond(&h.s,key,&fake,1)==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
      for(size_t i=0;i<h.completed.size();++i) CHECK(h.completed[i].token==i+1);
      CHECK(h.random_calls==2&&h.signatures==1); }
    { InfoBackend info; Harness h(v,setup_v,true); info.enable(h,true);
      CHECK(h.feed(bytes("GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n"))==RTSP_CHANNEL_OUTPUT); info.reply(h.drain(false,IAP2_OK));
      h.to_candidate(); pair_setup_candidate candidate{}; rtsp_channel_key key{};
      CHECK(projection_receiver_pending(&h.s,&candidate,&key)==PAIR_SETUP_APPROVAL&&key.token==4);
      CHECK(projection_receiver_decide(&h.s,key,1,1)==RTSP_CHANNEL_OUTPUT); h.drain(false,PAIR_SETUP_COMPLETE); h.pair();
      CHECK(h.feed(h.frame(bytes("GET /info RTSP/1.0\r\nCSeq: 8\r\n\r\n")))==RTSP_CHANNEL_OUTPUT&&info.calls==2);
      info.reply(h.drain(true,IAP2_OK)); CHECK(h.s.enrolled&&h.commits==1&&h.s.info.profile==&info.profile); }
    { InfoBackend info(2); Harness h(v,setup_v,false,0,32768); info.enable(h,true);
      CHECK(h.fragment(outer(info_encode(info.profile),1,"/info","POST","application/x-apple-binary-plist"),31)==RTSP_CHANNEL_OUTPUT&&info.calls==1);
      info.reply(h.drain(false,IAP2_OK)); h.pair();
      CHECK(h.feed(h.frame(bytes("GET /info RTSP/1.0\r\nCSeq: 7\r\n\r\n")))==RTSP_CHANNEL_OUTPUT&&info.calls==2);
      info.reply(h.drain(true,IAP2_OK)); CHECK(h.outgoing>100&&h.identities==0); }
}
static void info_policy_and_errors(const Vectors& v,const Vectors& setup_v) {
    { InfoBackend info; Harness h(v,setup_v); info.enable(h);
      CHECK(h.feed(bytes("GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n"))==PROJECTION_RECEIVER_CLOSED&&info.calls==0&&h.random_calls==0); h.cleared(); }
    { InfoBackend info; Harness h(v,setup_v); info.result=-55; info.enable(h,true);
      CHECK(h.feed(bytes("GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n"))==PROJECTION_RECEIVER_CLOSED&&info.calls==1&&h.s.last_error==-55&&h.random_calls==0);
      CHECK(zeroed(info.scratch.data(),info_encode(info.profile).size())); h.cleared(); }
    for(unsigned mode=0;mode<8;++mode) {
        InfoBackend info; Harness h(v,setup_v); info.enable(h); h.pair();
        auto body=empty_dictionary(); std::string type="application/x-apple-binary-plist",method="POST";
        if(mode==0) method="GET";
        if(mode==1) method="PATCH";
        if(mode==2) type="application/octet-stream";
        if(mode==3) type+="\r\nContent-Type: application/x-apple-binary-plist";
        if(mode==4) body=bytes("<plist><dict/></plist>");
        if(mode==5) body[8]=0xa0; // Valid binary empty array, wrong root type.
        if(mode==6) body.back()=0;
        if(mode==7) body[8]=0x09; // Valid boolean, wrong root type.
        CHECK(h.feed(h.frame(outer(body,7,"/info",method,type)))==PROJECTION_RECEIVER_CLOSED&&info.calls==0&&h.identities==0); h.cleared();
    }
    { InfoBackend info; Harness h(v,setup_v); info.enable(h,true);
      CHECK(h.feed(outer(Bytes(4097,0),1,"/info","POST","application/x-apple-binary-plist"))==PROJECTION_RECEIVER_CLOSED&&info.calls==0); h.cleared(); }
    { InfoBackend info; Harness h(v,setup_v); info.enable(h); h.pair();
      auto wire=h.frame(bytes("GET /info RTSP/1.0\r\nCSeq: 7\r\n\r\n")); wire.back()^=1;
      CHECK(h.feed(wire)==PROJECTION_RECEIVER_CLOSED&&info.calls==0); h.cleared(); }
    { InfoBackend info; Harness h(v,setup_v); info.enable(h); h.pair();
      CHECK(h.feed(h.frame(bytes("GET /info RTSP/1.0\r\nCSeq: 7\r\n\r\n")))==RTSP_CHANNEL_OUTPUT&&info.calls==1);
      h.drain(true,IAP2_OK,false); auto key=h.s.key;
      CHECK(projection_receiver_release(&h.s,key,5001)==PROJECTION_RECEIVER_CLOSED&&info.calls==1); h.cleared(); }
}
static void info_configuration_and_limits(const Vectors& v,const Vectors& setup_v) {
    { InfoBackend info; Harness h(v,setup_v); auto saved=snapshot(h.s); auto scratch=info.scratch;
      for(unsigned mode=0;mode<9;++mode) {
          auto cfg=info.config(true); auto invalid=info.profile;
          if(mode==0) cfg.available=nullptr;
          if(mode==1) cfg.profile=nullptr;
          if(mode==2) cfg.buffer=nullptr;
          if(mode==3) cfg.initial_ms=0;
          if(mode==4) cfg.initial_limit=17;
          if(mode==5) cfg.allow_initial=2;
          if(mode==6) cfg.capacity=1;
          if(mode==7) { invalid.name={}; cfg.profile=&invalid; }
          if(mode==8) { invalid=info_fixture(2); cfg.profile=&invalid; }
          int r=projection_receiver_enable_info(&h.s,91,&cfg,UINT64_MAX);
          CHECK(r==(mode==6||mode==8?IAP2_NO_SPACE:(mode==7?IAP2_INVALID:IAP2_ARGUMENT))&&snapshot(h.s)==saved&&info.scratch==scratch&&info.calls==0);
      }
      auto cfg=info.config(); CHECK(projection_receiver_enable_info(&h.s,92,&cfg,UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==saved);
      info.enable(h); saved=snapshot(h.s);
      CHECK(projection_receiver_enable_info(&h.s,91,&cfg,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved); }
    { InfoBackend info; Harness h(v,setup_v); CHECK(h.feed(bytes("G"))==IAP2_MORE); auto cfg=info.config(true); auto saved=snapshot(h.s);
      CHECK(projection_receiver_enable_info(&h.s,91,&cfg,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved&&info.calls==0); }
    { InfoBackend info; Harness h(v,setup_v); auto cfg=info.config(true); cfg.initial_limit=1;
      CHECK(projection_receiver_enable_info(&h.s,91,&cfg,0)==IAP2_OK);
      auto get=bytes("GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n"); CHECK(h.feed(get)==RTSP_CHANNEL_OUTPUT); h.drain(false,IAP2_OK);
      CHECK(h.feed(get)==PROJECTION_RECEIVER_CLOSED&&info.calls==1); h.cleared(); }
    { InfoBackend info; Harness h(v,setup_v); auto cfg=info.config(true); cfg.initial_ms=3;
      CHECK(projection_receiver_enable_info(&h.s,91,&cfg,0)==IAP2_OK&&projection_receiver_next_delay(&h.s)==3);
      auto get=bytes("GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n"); CHECK(h.feed(get)==RTSP_CHANNEL_OUTPUT); h.drain(false,IAP2_OK);
      CHECK(h.feed(get,2)==RTSP_CHANNEL_OUTPUT&&projection_receiver_next_delay(&h.s)==1&&info.calls==2);
      CHECK(projection_receiver_check(&h.s,91,3)==PROJECTION_RECEIVER_CLOSED&&h.random_calls==0); h.cleared(); }
}
int main(int argc,char** argv) {
    try {
        CHECK(argc==3); auto v=load_vectors(argv[1],39),setup_v=load_vectors(argv[2],51);
        known_route(v,setup_v); enrollment_route(v,setup_v); permission_and_failure(v,setup_v);
        invalid_routes(v,setup_v); initial_lifetimes(v,setup_v); transactionality(v,setup_v); exhausted_and_late(v,setup_v);
        info_routes(v,setup_v); info_policy_and_errors(v,setup_v); info_configuration_and_limits(v,setup_v);
        std::cout<<"PASS: 10 receiver-router groups; enrollment/verification/MFi, explicit capabilities, bounded discovery, stable tokens and failure gates\n";
        std::cout<<"x64 receiver bytes: "<<sizeof(projection_receiver)<<"; caller buffers/stack additional; synthetic credentials only\n";
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
