/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_receiver_fixture.h"

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
static int encrypted_session(Harness& h,const Bytes& body,const char* method="SETUP",unsigned seq=10,const char* target="rtsp://127.0.0.1/123") {
    auto wire=outer(body,seq,target,method,"application/x-apple-binary-plist"); int result=IAP2_MORE;
    for(size_t offset=0;offset<wire.size();) {
        auto end=std::min(offset+256,wire.size()); auto frame=h.frame(Bytes(wire.begin()+offset,wire.begin()+end));
        size_t used=0; result=h.feed(frame,1,&used); CHECK(used==frame.size()); offset=end;
        if(offset<wire.size()) CHECK(result==IAP2_MORE);
    }
    return result;
}
static void session_enable(Harness& h,InfoBackend& info,SessionBackend& backend,bool feedback=false) {
    info.profile=session_profile(); info.enable(h); auto cfg=backend.config(feedback);
    CHECK(projection_receiver_enable_session(&h.s,91,&cfg,0)==IAP2_OK&&backend.opens==0);
}
static void session_mfi(Harness& h) {
    CHECK(h.feed(h.frame(outer(h.v.at("request"),7,"/auth-setup","POST","application/octet-stream")))==RTSP_CHANNEL_OUTPUT);
    h.drain(true,MFI_SAP_DRAINED);
}
static void session_routes(const Vectors& v,const Vectors& setup_v,const Vectors& sv) {
    for(bool enroll:{false,true}) {
        InfoBackend info(2); SessionBackend backend; Harness h(v,setup_v,enroll); session_enable(h,info,backend);
        if(enroll) { h.to_candidate(); pair_setup_candidate candidate{}; rtsp_channel_key key{};
            CHECK(projection_receiver_pending(&h.s,&candidate,&key)==PAIR_SETUP_APPROVAL);
            CHECK(projection_receiver_decide(&h.s,key,1,1)==RTSP_CHANNEL_OUTPUT); h.drain(false,PAIR_SETUP_COMPLETE); }
        h.pair(); session_mfi(h);
        CHECK(encrypted_session(h,sv.at("session"))==RTSP_CHANNEL_OUTPUT&&backend.opens==1&&info.calls==1);
        auto saved=snapshot(h.s); rtsp_response fake={501,{},nullptr,0,{}};
        CHECK(projection_receiver_respond(&h.s,h.s.key,&fake,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved);
        rtsp_message req{}; rtsp_channel_key key{}; CHECK(projection_receiver_request(&h.s,&req,&key)==IAP2_MORE&&!key.token);
        CHECK(backend.keys[0].has_write); h.drain(true,IAP2_OK);
        CHECK(encrypted_session(h,sv.at("streams"))==RTSP_CHANNEL_OUTPUT&&backend.opens==7&&backend.starts==0);
        auto reply=h.drain(true,IAP2_OK); size_t decoded=0;
        CHECK(rtsp_message_decode(reply.data(),reply.size(),&req,&decoded)==IAP2_OK&&req.status==200&&req.body.size>0);
        CHECK(encrypted_session(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT&&backend.starts==0);
        h.drain(true,IAP2_OK); CHECK(backend.starts==1&&h.s.session.recording);
        CHECK(encrypted_session(h,sv.at("teardown_audio"),"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&backend.closed.size()==1); h.drain(true,IAP2_OK);
        CHECK(encrypted_session(h,sv.at("audio_new"))==RTSP_CHANNEL_OUTPUT&&backend.starts==1); h.drain(true,IAP2_OK); CHECK(backend.starts==2);
        CHECK(encrypted_session(h,{},"TEARDOWN")==RTSP_CHANNEL_OUTPUT&&backend.live.empty()); h.drain(true,PROJECTION_RECEIVER_CLOSED); h.cleared();
        for(size_t i=1;i<h.completed.size();++i) CHECK(h.completed[i].token>h.completed[i-1].token);
    }
}
static void session_gates_and_cleanup(const Vectors& v,const Vectors& setup_v,const Vectors& sv) {
    { InfoBackend info(2); SessionBackend backend; Harness h(v,setup_v); session_enable(h,info,backend); h.pair();
      CHECK(encrypted_session(h,sv.at("session"))==PROJECTION_RECEIVER_CLOSED&&backend.opens==0&&info.calls==0); }
    { InfoBackend info(2); SessionBackend backend; Harness h(v,setup_v); session_enable(h,info,backend);
      auto wire=outer(sv.at("session"),1,"/session","SETUP","application/x-apple-binary-plist"); size_t n=0;
      CHECK(h.feed(wire,1,&n)==PROJECTION_RECEIVER_CLOSED&&backend.opens==0&&h.random_calls==0); }
    for(unsigned mode=0;mode<8;++mode) {
        InfoBackend info(2); SessionBackend backend; Harness h(v,setup_v); session_enable(h,info,backend); h.pair(); session_mfi(h);
        CHECK(encrypted_session(h,sv.at("session"))==RTSP_CHANNEL_OUTPUT&&backend.opens==1);
        if(mode==0) { CHECK(projection_receiver_eof(&h.s,91,1)==PROJECTION_RECEIVER_CLOSED); }
        else if(mode==1) { CHECK(projection_receiver_check(&h.s,91,30001)==PROJECTION_RECEIVER_CLOSED); }
        else if(mode==2) { h.drain(true,IAP2_OK,false); CHECK(projection_receiver_release(&h.s,h.s.key,30001)==PROJECTION_RECEIVER_CLOSED); }
        else {
            h.drain(true,IAP2_OK);
            if(mode==3) { backend.fail_open=4; CHECK(encrypted_session(h,sv.at("streams"))==PROJECTION_RECEIVER_CLOSED&&backend.opens==4); }
            if(mode==4) { info.result=-55; CHECK(encrypted_session(h,sv.at("streams"))==PROJECTION_RECEIVER_CLOSED&&backend.opens==1); }
            if(mode==5) { CHECK(encrypted_session(h,sv.at("bad_format_real"))==PROJECTION_RECEIVER_CLOSED&&backend.opens==1&&info.calls==1); }
            if(mode==6) { auto frame=h.frame(bytes("RECORD rtsp://127.0.0.1/123 RTSP/1.0\r\nCSeq: 30\r\n\r\n")); frame.back()^=1; size_t n=0;
                CHECK(h.feed(frame,1,&n)==PROJECTION_RECEIVER_CLOSED&&backend.opens==1); }
            if(mode==7) { CHECK(encrypted_session(h,sv.at("streams"))==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
                CHECK(encrypted_session(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT); backend.start_error=-88; h.drain(true,PROJECTION_RECEIVER_CLOSED); }
        }
        CHECK(backend.live.empty()&&backend.closed.size()==backend.opens); h.cleared();
    }
    { InfoBackend info(2); SessionBackend backend; Harness h(v,setup_v); auto cfg=backend.config(); auto saved=snapshot(h.s);
      CHECK(projection_receiver_enable_session(&h.s,91,&cfg,0)==RTSP_BUSY&&snapshot(h.s)==saved); info.profile=session_profile(); info.enable(h); saved=snapshot(h.s);
      CHECK(projection_receiver_enable_session(&h.s,90,&cfg,UINT64_MAX)==IAP2_INVALID&&snapshot(h.s)==saved);
      auto bad=cfg; bad.provider.open=nullptr;
      CHECK(projection_receiver_enable_session(&h.s,91,&bad,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(h.s)==saved);
      CHECK(projection_receiver_enable_session(&h.s,91,&cfg,0)==IAP2_OK); saved=snapshot(h.s);
      CHECK(projection_receiver_enable_session(&h.s,91,&cfg,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved); }
    { InfoBackend info; SessionBackend backend; Harness h(v,setup_v); info.enable(h,true);
      CHECK(h.feed(bytes("GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n"))==RTSP_CHANNEL_OUTPUT); h.drain(false,IAP2_OK);
      auto cfg=backend.config(); auto saved=snapshot(h.s);
      CHECK(projection_receiver_enable_session(&h.s,91,&cfg,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved&&backend.opens==0); }
    { InfoBackend info; SessionBackend backend; Harness h(v,setup_v); info.enable(h);
      CHECK(h.feed(bytes("P"))==IAP2_MORE); auto cfg=backend.config(); auto saved=snapshot(h.s);
      CHECK(projection_receiver_enable_session(&h.s,91,&cfg,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved&&backend.opens==0); }
    { InfoBackend info(2); SessionBackend backend; Harness h(v,setup_v); session_enable(h,info,backend); h.pair(); session_mfi(h);
      CHECK(encrypted_session(h,sv.at("session"))==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
      CHECK(encrypted_session(h,sv.at("streams"))==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
      auto record=bytes("RECORD rtsp://127.0.0.1/123 RTSP/1.0\r\nCSeq: 21\r\n\r\n"),next=bytes("GET /unknown RTSP/1.0\r\nCSeq: 22\r\n\r\n");
      record.insert(record.end(),next.begin(),next.end()); CHECK(h.feed(h.frame(record))==RTSP_CHANNEL_OUTPUT&&backend.starts==0);
      h.drain(true,IAP2_OK); CHECK(backend.starts==1); CHECK(h.feed({})==RTSP_CHANNEL_REQUEST);
      rtsp_message req{}; rtsp_channel_key key{}; CHECK(projection_receiver_request(&h.s,&req,&key)==RTSP_CHANNEL_REQUEST&&req.cseq==22);
      rtsp_response response={501,{},nullptr,0,{}}; CHECK(projection_receiver_respond(&h.s,key,&response,1)==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
      projection_receiver_close(&h.s); CHECK(backend.live.empty()); }
}
static void feedback_routes(const Vectors& v,const Vectors& setup_v,const Vectors& sv) {
    for(unsigned mode=0;mode<9;++mode) {
        InfoBackend info(2); SessionBackend backend; Harness h(v,setup_v); session_enable(h,info,backend,mode!=8);
        auto wire=bytes("POST /feedback RTSP/1.0\r\nCSeq: 31\r\n\r\n");
        if(mode==0) { CHECK(h.feed(wire)==PROJECTION_RECEIVER_CLOSED&&backend.playback_calls==0); continue; }
        h.pair();
        if(mode==1) { CHECK(h.feed(h.frame(wire))==PROJECTION_RECEIVER_CLOSED&&backend.playback_calls==0); continue; }
        session_mfi(h);
        if(mode==2) { CHECK(h.feed(h.frame(wire))==PROJECTION_RECEIVER_CLOSED&&backend.playback_calls==0); continue; }
        CHECK(encrypted_session(h,sv.at("session"))==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        CHECK(encrypted_session(h,sv.at("streams"))==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        CHECK(encrypted_session(h,{},"RECORD")==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK);
        if(mode==3) wire=bytes("GET /feedback RTSP/1.0\r\nCSeq: 31\r\n\r\n");
        if(mode==5) backend.playback_error=-55;
        if(mode==7) { auto tail=bytes("POST /feedback RTSP/1.0\r\nCSeq: 32\r\n\r\n"); wire.insert(wire.end(),tail.begin(),tail.end()); }
        auto encrypted=h.frame(wire); if(mode==4) encrypted.back()^=1;
        int r=h.feed(encrypted);
        if(mode==3||mode==4||mode==5) { CHECK(r==PROJECTION_RECEIVER_CLOSED&&backend.live.empty()); h.cleared(); continue; }
        if(mode==8) { CHECK(r==RTSP_CHANNEL_REQUEST&&backend.playback_calls==0); rtsp_message req{}; rtsp_channel_key key{};
            CHECK(projection_receiver_request(&h.s,&req,&key)==RTSP_CHANNEL_REQUEST); rtsp_response response{501,{},nullptr,0,{}};
            CHECK(projection_receiver_respond(&h.s,key,&response,1)==RTSP_CHANNEL_OUTPUT); h.drain(true,IAP2_OK); continue; }
        CHECK(r==RTSP_CHANNEL_OUTPUT&&backend.playback_calls==3&&backend.clock_calls==1&&backend.starts==1);
        rtsp_response fake{200,{},nullptr,0,{}}; auto saved=snapshot(h.s);
        CHECK(projection_receiver_respond(&h.s,h.s.key,&fake,UINT64_MAX)==RTSP_BUSY&&snapshot(h.s)==saved);
        rtsp_message req{}; rtsp_channel_key key{}; CHECK(projection_receiver_request(&h.s,&req,&key)==IAP2_MORE&&!key.token);
        CHECK(feedback_response(h.drain(true,IAP2_OK,mode!=6),31).size()==3);
        if(mode==6) { CHECK(projection_receiver_release(&h.s,h.s.key,5001)==PROJECTION_RECEIVER_CLOSED&&backend.live.empty()); h.cleared(); }
        if(mode==7) { CHECK(h.feed({})==RTSP_CHANNEL_OUTPUT&&backend.playback_calls==6&&backend.clock_calls==2);
            CHECK(feedback_response(h.drain(true,IAP2_OK),32).size()==3&&backend.starts==1); }
    }
}
int main(int argc,char** argv) {
    try {
        CHECK(argc==4); auto v=load_vectors(argv[1],39),setup_v=load_vectors(argv[2],51),session_v=load_vectors(argv[3],42);
        known_route(v,setup_v); enrollment_route(v,setup_v); permission_and_failure(v,setup_v);
        invalid_routes(v,setup_v); initial_lifetimes(v,setup_v); transactionality(v,setup_v); exhausted_and_late(v,setup_v);
        info_routes(v,setup_v); info_policy_and_errors(v,setup_v); info_configuration_and_limits(v,setup_v);
        session_routes(v,setup_v,session_v); session_gates_and_cleanup(v,setup_v,session_v); feedback_routes(v,setup_v,session_v);
        std::cout<<"PASS: 13 receiver-router groups; enrollment/verification/MFi, capabilities, sessions, observed feedback and failure gates\n";
        std::cout<<"x64 receiver bytes: "<<sizeof(projection_receiver)<<"; caller buffers/stack additional; synthetic credentials only\n";
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
