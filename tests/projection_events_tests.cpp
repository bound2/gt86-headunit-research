/* SPDX-License-Identifier: GPL-3.0-only; public synthetic profiles/bodies only. */
#include "projection_events.h"
#include "projection_command.h"
#include "projection_info_fixture.h"
template<class T> static auto snapshot(const T& value) { std::array<uint8_t,sizeof(T)> b{}; std::memcpy(b.data(),&value,sizeof(T)); return b; }
static Bytes encoded(const projection_info_profile& p,projection_command c,uint8_t features=15) {
    size_t n=0; CHECK(projection_command_encode(&p,features,&c,nullptr,0,&n)==IAP2_OK); Bytes b(n+2,0xa5); size_t used=0;
    CHECK(projection_command_encode(&p,features,&c,b.data()+1,n-1,&used)==IAP2_NO_SPACE&&used==0&&std::all_of(b.begin(),b.end(),[](auto v){return v==0xa5;}));
    CHECK(projection_command_encode(&p,features,&c,b.data()+1,n,&used)==IAP2_OK&&used==n&&b.front()==0xa5&&b.back()==0xa5); return {b.begin()+1,b.end()-1};
}
static Vectors commands() {
    auto p=info_fixture(2); auto data=hex("01020300ff"); Vectors out;
    out["hid"]=encoded(p,{PROJECTION_COMMAND_HID,p.hids[0].uuid,{data.data(),data.size()},0});
    out["night_on"]=encoded(p,{PROJECTION_COMMAND_NIGHT,{},{},1}); out["night_off"]=encoded(p,{PROJECTION_COMMAND_NIGHT,{},{},0});
    out["siri_down"]=encoded(p,{PROJECTION_COMMAND_SIRI,{},{},2}); out["siri_up"]=encoded(p,{PROJECTION_COMMAND_SIRI,{},{},3});
    out["iap"]=encoded(p,{PROJECTION_COMMAND_IAP,{},{data.data(),data.size()},0});
    out["keyframe_main"]=encoded(p,{PROJECTION_COMMAND_KEYFRAME,p.displays[0].uuid,{},0});
    out["keyframe_alt"]=encoded(p,{PROJECTION_COMMAND_KEYFRAME,p.displays[1].uuid,{},0}); return out;
}
static Bytes request(uint32_t seq=77,const std::string& protocol="RTSP/1.0") { return bytes("POST /command "+protocol+"\r\nCSeq: "+std::to_string(seq)+"\r\nContent-Length: 3\r\n\r\nabc"); }
static Bytes response(uint32_t seq,unsigned code=200,const std::string& protocol="RTSP/1.0") { return bytes(protocol+" "+std::to_string(code)+" Test\r\nCSeq: "+std::to_string(seq)+"\r\nContent-Length: 3\r\n\r\nxyz"); }
struct Events {
    projection_events s{}; projection_events_config cfg{};
    Bytes rx=Bytes(4096),reply=Bytes(4096),tx=Bytes(4*4096);
    explicit Events(bool start=true,uint32_t first=1,uint64_t now=0) {
        projection_events_default_config(&cfg); cfg.first_cseq=first; auto b=storage(); CHECK(projection_events_init(&s,&cfg,&b,91,now)==IAP2_OK);
        if(start) CHECK(projection_events_start(&s,91,now)==IAP2_OK);
    }
    ~Events() { projection_events_close(&s); }
    projection_events_storage storage() { return {rx.data(),reply.data(),tx.data(),rx.size(),reply.size(),4096,tx.size(),4}; }
    std::vector<rtsp_channel_key> queue(const std::vector<Bytes>& bodies,uint64_t now=0) {
        std::vector<rtsp_slice> slices; for(const auto& b:bodies) slices.push_back({b.data(),b.size()}); std::vector<rtsp_channel_key> keys(bodies.size());
        CHECK(projection_events_queue(&s,91,slices.data(),slices.size(),keys.data(),now)==PROJECTION_EVENTS_OUTPUT); return keys;
    }
    int feed(const Bytes& b,uint64_t now=1,size_t* used=nullptr) { size_t n=0; int r=projection_events_feed(&s,91,b.data(),b.size(),&n,now); if(used) *used=n; else CHECK(n==b.size()); return r; }
    Bytes drain(rtsp_channel_key expected,bool command=true,bool finish=true,uint64_t now=1) {
        Bytes out; rtsp_slice b{}; rtsp_channel_key key{}; int cmd=0,r;
        while((r=projection_events_output(&s,91,&b,&key,&cmd,now))==PROJECTION_EVENTS_OUTPUT) {
            CHECK(key.token==expected.token&&key.generation==91&&bool(cmd)==command&&b.size); auto n=std::min(b.size,size_t(3)); out.insert(out.end(),b.data,b.data+n);
            auto saved=snapshot(s); CHECK(projection_events_consume(&s,{90,key.token},n,UINT64_MAX)==IAP2_INVALID&&snapshot(s)==saved);
            CHECK(projection_events_consume(&s,key,b.size+1,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(s)==saved);
            CHECK(projection_events_drain(&s,key,UINT64_MAX)==RTSP_BUSY&&snapshot(s)==saved);
            int next=projection_events_consume(&s,key,n,now); CHECK(next==(n==b.size?PROJECTION_EVENTS_DRAIN:PROJECTION_EVENTS_OUTPUT));
        }
        CHECK(r==PROJECTION_EVENTS_DRAIN&&key.token==expected.token);
        if(finish) { CHECK(projection_events_drain(&s,key,now)==IAP2_OK); auto saved=snapshot(s);
            CHECK(projection_events_drain(&s,key,UINT64_MAX)==IAP2_INVALID&&snapshot(s)==saved); }
        return out;
    }
    rtsp_channel_key message(int expected,uint32_t seq,uint16_t status=0) {
        rtsp_message m{}; rtsp_channel_key key{}; CHECK(projection_events_message(&s,91,&m,&key)==expected&&m.cseq==seq&&m.status==status&&key.generation==91); return key;
    }
};
static void request_encoder() {
    auto body=hex("00ff0d0a0102");
    for(auto protocol:{RTSP_10,RTSP_HTTP_10,RTSP_HTTP_11}) for(auto seq:{0u,1u,UINT32_MAX}) {
        rtsp_message req{}; req.kind=RTSP_REQUEST; req.protocol=protocol; req.method=info_text("POST"); req.target=info_text("/command"); req.has_cseq=1; req.cseq=seq;
        req.header_count=1; req.headers[0]={info_text("Content-Type"),info_text("application/x-apple-binary-plist")}; req.body={body.data(),body.size()};
        size_t n=0; CHECK(rtsp_request_encode(&req,nullptr,0,&n)==IAP2_OK); Bytes out(n+2,0xab); auto old=out;
        CHECK(rtsp_request_encode(&req,out.data()+1,n-1,&n)==IAP2_NO_SPACE&&out==old); n=out.size()-2;
        CHECK(rtsp_request_encode(&req,out.data()+1,n,&n)==IAP2_OK&&out.front()==0xab&&out.back()==0xab);
        rtsp_message parsed{}; size_t used=0; CHECK(rtsp_message_decode(out.data()+1,n,&parsed,&used)==IAP2_OK&&used==n&&parsed.protocol==protocol&&parsed.cseq==seq&&equal(parsed.body.data,body));
        for(unsigned mode=0;mode<8;++mode) { auto bad=req; out=old;
            if(mode==0) bad.method=info_text("PO ST"); if(mode==1) bad.target=info_text("/x\r\nInjected:1"); if(mode==2) bad.kind=RTSP_RESPONSE;
            if(mode==3) bad.headers[0].name=info_text("CSeq"); if(mode==4) bad.headers[0].name=info_text("Content-Length");
            if(mode==5) bad.headers[0].value=info_text("x\nY"); if(mode==6) { bad.headers[1]=bad.headers[0]; bad.header_count=2; }
            if(mode==7) bad.body={nullptr,1}; CHECK(rtsp_request_encode(&bad,out.data(),out.size(),&n)==IAP2_ARGUMENT&&n==0&&out==old);
        }
    }
}
static void typed_commands() {
    CHECK(commands().size()==8); auto p=info_fixture(2); Bytes data(16384,0x5a); projection_command c{PROJECTION_COMMAND_IAP,{},{data.data(),data.size()},0}; CHECK(encoded(p,c).size()>16384);
    for(unsigned mode=0;mode<11;++mode) {
        auto bad=c; uint8_t features=15; if(mode==0) features=0; if(mode==1) bad.data.size=16385; if(mode==2) bad.data={};
        if(mode==3) bad.value=1; if(mode==4) bad.uuid=info_text("1234");
        if(mode==5) bad={PROJECTION_COMMAND_HID,info_text("1234"),{data.data(),1},0};
        if(mode==6) bad={PROJECTION_COMMAND_HID,p.hids[0].uuid,{data.data(),4097},0};
        if(mode==7) bad={PROJECTION_COMMAND_NIGHT,{},{},2}; if(mode==8) bad={PROJECTION_COMMAND_SIRI,{},{},1};
        if(mode==9) { bad={PROJECTION_COMMAND_KEYFRAME,p.displays[1].uuid,{},0}; features=0; }
        if(mode==10) bad={PROJECTION_COMMAND_KEYFRAME,info_text("no-display"),{},0};
        Bytes out(512,0xa5); auto old=out; size_t used=999;
        CHECK(projection_command_encode(&p,features,&bad,out.data(),out.size(),&used)<0&&used==0&&out==old);
    }
}
static void bidirectional_and_atomic() {
    auto all=commands(); Events f; auto keys=f.queue({all.at("siri_down"),all.at("siri_up"),all.at("night_on"),all.at("night_off")});
    for(size_t i=0;i<keys.size();++i) { auto wire=f.drain(keys[i]); rtsp_message m{}; size_t used=0; CHECK(rtsp_message_decode(wire.data(),wire.size(),&m,&used)==IAP2_OK&&m.cseq==i+1&&m.kind==RTSP_REQUEST&&m.target.size==8); }
    auto incoming=request(1); // Peer namespace can equal our outstanding CSeq1.
    for(size_t i=0;i<incoming.size();++i) CHECK(f.feed({incoming[i]})==(i+1==incoming.size()?PROJECTION_EVENTS_REQUEST:IAP2_MORE));
    auto req=f.message(PROJECTION_EVENTS_REQUEST,1); CHECK(req.token>keys.back().token);
    rtsp_response reject{501,{},nullptr,0,{}}; CHECK(projection_events_respond(&f.s,req,&reject,1)==PROJECTION_EVENTS_OUTPUT);
    CHECK(f.feed(response(4,503,"HTTP/1.1"))==PROJECTION_EVENTS_RESPONSE); auto key=f.message(PROJECTION_EVENTS_RESPONSE,4,503); CHECK(key.token==keys[3].token);
    CHECK(projection_events_release(&f.s,key,1)==IAP2_OK); auto wire=f.drain(req,false); rtsp_message m{}; size_t used=0;
    CHECK(rtsp_message_decode(wire.data(),wire.size(),&m,&used)==IAP2_OK&&m.status==501&&m.cseq==1);
    auto saved=snapshot(f.s); auto old=f.tx; rtsp_slice bodies[2]={{all.at("siri_down").data(),all.at("siri_down").size()},{all.at("siri_up").data(),all.at("siri_up").size()}};
    rtsp_channel_key denied[2]{}; CHECK(projection_events_queue(&f.s,91,bodies,2,denied,UINT64_MAX)==RTSP_BUSY&&snapshot(f.s)==saved&&old==f.tx&&zeroed(denied,sizeof(denied)));
    for(auto seq:{2u,1u,3u}) { CHECK(f.feed(response(seq))==PROJECTION_EVENTS_RESPONSE); key=f.message(PROJECTION_EVENTS_RESPONSE,seq,200); CHECK(projection_events_release(&f.s,key,1)==IAP2_OK); }
    keys=f.queue({all.at("siri_down"),all.at("siri_up")},1); CHECK(f.s.next_cseq==7); CHECK(f.drain(keys[0]).size()>50); CHECK(f.drain(keys[1]).size()>50);
    saved=snapshot(f.s); old=f.tx; bodies[1]={nullptr,1}; CHECK(projection_events_queue(&f.s,91,bodies,2,denied,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(f.s)==saved&&old==f.tx);
    CHECK(zeroed(f.tx.data(),f.tx.size()));
}
static void priority_and_tails() {
    auto cmd=commands().at("night_on"); Events f; auto keys=f.queue({cmd,cmd});
    rtsp_slice out{}; rtsp_channel_key key{}; int command=0; CHECK(projection_events_output(&f.s,91,&out,&key,&command,1)==PROJECTION_EVENTS_OUTPUT&&key.token==keys[0].token);
    CHECK(projection_events_consume(&f.s,key,1,1)==PROJECTION_EVENTS_OUTPUT);
    auto input=request(55),tail=response(1); input.insert(input.end(),tail.begin(),tail.end()); size_t n=0;
    CHECK(f.feed(input,1,&n)==PROJECTION_EVENTS_REQUEST&&n==request(55).size()); auto req=f.message(PROJECTION_EVENTS_REQUEST,55);
    auto saved=snapshot(f.s); CHECK(projection_events_release(&f.s,req,UINT64_MAX)==RTSP_BUSY&&snapshot(f.s)==saved);
    rtsp_response reply{200,{},nullptr,0,{}}; CHECK(projection_events_respond(&f.s,req,&reply,1)==PROJECTION_EVENTS_OUTPUT);
    f.drain(keys[0]); // Finishes active command before queued reply; no interleaving.
    CHECK(f.feed(tail)==PROJECTION_EVENTS_RESPONSE); key=f.message(PROJECTION_EVENTS_RESPONSE,1,200);
    saved=snapshot(f.s); CHECK(projection_events_release(&f.s,{91,key.token+999},UINT64_MAX)==IAP2_INVALID&&snapshot(f.s)==saved);
    CHECK(projection_events_release(&f.s,key,1)==IAP2_OK); f.drain(req,false); f.drain(keys[1]);
    CHECK(f.feed(bytes("POST /unknown HTTP/1.0\r\n\r\n"))==PROJECTION_EVENTS_REQUEST); req=f.message(PROJECTION_EVENTS_REQUEST,0);
    rtsp_response explicit_error{404,{},nullptr,0,{}}; CHECK(projection_events_respond(&f.s,req,&explicit_error,1)==PROJECTION_EVENTS_OUTPUT);
    auto response_bytes=f.drain(req,false); rtsp_message m{}; CHECK(rtsp_message_decode(response_bytes.data(),response_bytes.size(),&m,&n)==IAP2_OK&&!m.has_cseq&&m.protocol==RTSP_HTTP_10&&m.status==404);
}
static void failures_and_deadlines() {
    auto body=commands().at("hid");
    for(unsigned mode=0;mode<6;++mode) { Events f; auto key=f.queue({body})[0];
        if(mode!=0) f.drain(key); Bytes input=response(mode==2?999u:1u,mode==3?100u:200u);
        if(mode==4) input=bytes("HTTP/1.1 200 OK\r\n\r\n"); if(mode==5) input=bytes("RTSP/1.0 200 OK\r\nCSeq: 1\r\nCSeq: 1\r\n\r\n");
        if(mode==1) { CHECK(f.feed(input)==PROJECTION_EVENTS_RESPONSE); CHECK(projection_events_release(&f.s,key,1)==IAP2_OK); }
        size_t n=0; CHECK(f.feed(input,1,&n)==PROJECTION_EVENTS_CLOSED&&f.s.dead&&zeroed(f.tx.data(),f.tx.size())&&zeroed(f.rx.data(),f.rx.size()));
    }
    for(unsigned mode=0;mode<6;++mode) { Events f; uint64_t deadline=5000;
        if(mode==0) { CHECK(f.feed(bytes("P"),0)==IAP2_MORE); deadline=10000; }
        if(mode==1) CHECK(f.feed(request(),0)==PROJECTION_EVENTS_REQUEST);
        if(mode>=2&&mode<=4) { auto key=f.queue({body})[0]; if(mode==3) f.drain(key,true,false,0); if(mode==4) f.drain(key,true,true,0); }
        if(mode==5) { CHECK(f.feed(request(),0)==PROJECTION_EVENTS_REQUEST); auto key=f.message(PROJECTION_EVENTS_REQUEST,77); rtsp_response res{200,{},nullptr,0,{}};
            CHECK(projection_events_respond(&f.s,key,&res,0)==PROJECTION_EVENTS_OUTPUT); }
        CHECK(projection_events_check(&f.s,91,deadline-1)==IAP2_OK&&projection_events_next_delay(&f.s)==1);
        CHECK(projection_events_check(&f.s,91,deadline)==PROJECTION_EVENTS_CLOSED&&projection_events_next_delay(&f.s)==UINT32_MAX);
    }
    Events stopped(false); auto s=snapshot(stopped.s); rtsp_slice b{body.data(),body.size()}; rtsp_channel_key k{};
    CHECK(projection_events_queue(&stopped.s,91,&b,1,&k,UINT64_MAX)==RTSP_BUSY&&snapshot(stopped.s)==s);
    Events last(true,UINT32_MAX); auto key=last.queue({body})[0]; last.drain(key); CHECK(last.feed(response(UINT32_MAX))==PROJECTION_EVENTS_RESPONSE); CHECK(projection_events_release(&last.s,key,1)==IAP2_OK);
    CHECK(projection_events_queue(&last.s,91,&b,1,&k,1)==PROJECTION_EVENTS_CLOSED);
    Events token; token.s.next_token=UINT64_MAX; key=token.queue({body})[0]; CHECK(key.token==UINT64_MAX); token.drain(key);
    CHECK(token.feed(response(1))==PROJECTION_EVENTS_RESPONSE); CHECK(projection_events_release(&token.s,key,1)==IAP2_OK);
    CHECK(projection_events_queue(&token.s,91,&b,1,&k,1)==PROJECTION_EVENTS_CLOSED);
    Events near(true,1,UINT64_MAX-6000); near.queue({body},UINT64_MAX-6000); CHECK(projection_events_check(&near.s,91,UINT64_MAX-1001)==IAP2_OK);
    CHECK(projection_events_check(&near.s,91,UINT64_MAX-1000)==PROJECTION_EVENTS_CLOSED);
}
static void validation_and_mutations() {
    Events f; auto cfg=f.cfg; auto b=f.storage(); auto saved=snapshot(f.s); cfg.response_ms=0;
    CHECK(projection_events_init(&f.s,&cfg,&b,91,0)==IAP2_ARGUMENT&&snapshot(f.s)==saved);
    cfg=f.cfg; b.commands_size=1; CHECK(projection_events_init(&f.s,&cfg,&b,91,0)==IAP2_ARGUMENT&&snapshot(f.s)==saved);
    size_t n=0; auto input=request(); CHECK(projection_events_feed(&f.s,90,input.data(),input.size(),&n,UINT64_MAX)==IAP2_INVALID&&n==0&&snapshot(f.s)==saved);
    CHECK(projection_events_check(&f.s,91,1)==IAP2_OK); saved=snapshot(f.s); CHECK(projection_events_check(&f.s,91,0)==IAP2_ARGUMENT&&snapshot(f.s)==saved);
    uint32_t rng=8751; for(unsigned i=0;i<5000;++i) { Events probe; auto wire=request();
        if(i%2) wire.resize(i%wire.size()); else for(unsigned j=0;j<4;++j) { rng=rng*1664525+1013904223; wire[rng%wire.size()]=static_cast<uint8_t>(rng>>24); }
        int r=probe.feed(wire,1,&n); CHECK(r==IAP2_MORE||r==PROJECTION_EVENTS_REQUEST||r==PROJECTION_EVENTS_CLOSED); CHECK(n<=wire.size()); }
}
int main(int argc,char** argv) {
    try { if(argc==2&&std::string(argv[1])=="--fixtures") { const char* digits="0123456789abcdef"; for(const auto& [name,b]:commands()) { std::cout<<name<<'='; for(auto c:b) std::cout<<digits[c>>4]<<digits[c&15]; std::cout<<'\n'; } return 0; } CHECK(argc==1);
        request_encoder(); typed_commands(); bidirectional_and_atomic(); priority_and_tails(); failures_and_deadlines(); validation_and_mutations();
        std::cout<<"PASS: 6 event/command groups; explicit bidirectional requests, correlated pipelined replies, atomic command batches, typed schemas, deadlines and 5000 mutations\n";
        std::cout<<"x64 event owner bytes: "<<sizeof(projection_events)<<"; caller storage/stack additional; no socket or actual input driver\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
