/* SPDX-License-Identifier: GPL-3.0-only
 * Synthetic projection-control traffic; no device captures or trust records.
 */
#include "rtsp_channel.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#define CHECK(x) do { if(!(x)) throw std::runtime_error(std::string(#x)+" at line "+std::to_string(__LINE__)); } while(0)
using Bytes=std::vector<uint8_t>;
static rtsp_slice literal(const char* s) { return {reinterpret_cast<const uint8_t*>(s),std::strlen(s)}; }
static std::string str(rtsp_slice s) { return s.size?std::string(reinterpret_cast<const char*>(s.data),s.size):""; }
static Bytes bytes(const std::string& s) { return {s.begin(),s.end()}; }
static rtsp_message decode(const Bytes& b) {
    rtsp_message m{}; size_t n=99; CHECK(rtsp_message_decode(b.data(),b.size(),&m,&n)==IAP2_OK); CHECK(n==b.size()); return m;
}
static Bytes request(const std::string& method="POST", const std::string& path="/pair-verify",
                     uint32_t seq=7, const Bytes& body={6,1,3,5,3,0,255,13}) {
    auto b=bytes(method+" "+path+" RTSP/1.0\r\nCSeq: "+std::to_string(seq)+
                 "\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n");
    b.insert(b.end(),body.begin(),body.end()); return b;
}
static bool zeroed(const void* p, size_t n) {
    auto q=static_cast<const uint8_t*>(p); return std::all_of(q,q+n,[](uint8_t c){return c==0;});
}
static void valid_messages() {
    auto b=request(); auto m=decode(b);
    CHECK(m.kind==RTSP_REQUEST&&m.protocol==RTSP_10&&m.has_cseq&&m.cseq==7);
    CHECK(str(m.method)=="POST"&&str(m.target)=="/pair-verify"); CHECK(m.body.size==8&&m.body.data[6]==255);
    rtsp_slice v{}; CHECK(rtsp_header_get(&m,literal("CONTENT-type"),&v)==IAP2_OK);
    CHECK(str(v)=="application/pairing+tlv8"); CHECK(rtsp_header_get(&m,literal("Absent"),&v)==IAP2_END&&!v.data&&!v.size);
    for(size_t i=0;i<b.size();++i) {
        size_t n=1; rtsp_message partial; std::memset(&partial,0x55,sizeof(partial));
        CHECK(rtsp_message_decode(b.data(),i,&partial,&n)==IAP2_MORE); CHECK(n==0&&zeroed(&partial,sizeof(partial)));
    }
    auto second=request("OPTIONS","*",UINT32_MAX,{}); auto both=b;
    both.insert(both.end(),second.begin(),second.end()); size_t n=0;
    CHECK(rtsp_message_decode(both.data(),both.size(),&m,&n)==IAP2_OK&&n==b.size());
    CHECK(decode(second).cseq==UINT32_MAX);
    for(const auto* proto: {"HTTP/1.0","HTTP/1.1"}) {
        auto http=bytes(std::string("GET /info ")+proto+"\r\nX-Case:\t one \t\r\nx-case: two\r\n\r\n");
        m=decode(http); CHECK(!m.has_cseq&&m.header_count==2&&m.body.size==0);
        CHECK(rtsp_header_get(&m,literal("X-CASE"),&v)==IAP2_INVALID&&!v.data&&!v.size);
    }
    auto response=bytes("RTSP/1.0 455 Method Not Valid in This State\r\ncSeQ: 00007\r\nContent-Length: 0\r\n\r\n");
    m=decode(response); CHECK(m.kind==RTSP_RESPONSE&&m.status==455&&m.cseq==7);
    CHECK(str(m.reason)=="Method Not Valid in This State");
    auto abs=request("SETUP","rtsp://[fe80::1234]:7000/12345",0,{}); CHECK(str(decode(abs).method)=="SETUP");
}
static void malformed() {
    const std::vector<std::string> cases={
        "POST /info RTSP/1.0\r\n\r\n", "POST  /info RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "POST /info RTSP/2.0\r\nCSeq: 1\r\n\r\n", "POST /info RTSP/1.0\nCSeq: 1\n\n",
        "POST /info RTSP/1.0\rX\r\n\r\n", "POST /info RTSP/1.0\r\n CSeq: 1\r\n\r\n",
        "POST /info RTSP/1.0\r\nCSeq : 1\r\n\r\n", "POST /info RTSP/1.0\r\nCSeq: 1\r\nBad\r\n\r\n",
        "POST /info RTSP/1.0\r\nCSeq: 1\r\ncseq: 1\r\n\r\n",
        "POST /info RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
        "POST /info RTSP/1.0\r\nCSeq: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /info RTSP/1.0\r\nCSeq: 1\r\nTransfer-Encoding: identity\r\nContent-Length: 0\r\n\r\n",
        "POST /info RTSP/1.0\r\nCSeq: 1\r\nX: a\r\n\tb\r\n\r\n",
        "P(OST /info RTSP/1.0\r\nCSeq: 1\r\n\r\n", "POST /i\tnfo RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "RTSP/1.0 20 OK\r\nCSeq: 1\r\n\r\n", "RTSP/1.0 600 Nope\r\nCSeq: 1\r\n\r\n",
        "RTSP/1.0 099 Nope\r\nCSeq: 1\r\n\r\n", "RTSP/1.0 +20 OK\r\nCSeq: 1\r\n\r\n",
        "POST /info RTSP/1.0 \r\nCSeq: 1\r\n\r\n"
    };
    auto bad=cases;
    for(const auto& value: {"-1","+1","1x","1,1","1 1","","4294967296","99999999999999999999999"}) {
        bad.push_back(std::string("POST /x RTSP/1.0\r\nCSeq: ")+value+"\r\n\r\n");
        bad.push_back(std::string("POST /x RTSP/1.0\r\nCSeq: 1\r\nContent-Length: ")+value+"\r\n\r\n");
    }
    bad.push_back("POST /x RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 65537\r\n\r\n");
    for(const auto& s:bad) {
        rtsp_message m{}; size_t n=9; auto b=bytes(s);
        CHECK(rtsp_message_decode(b.data(),b.size(),&m,&n)<0&&n==0&&zeroed(&m,sizeof(m)));
    }
    auto good=request();
    for(uint8_t ch: {uint8_t(0),uint8_t(1),uint8_t(127),uint8_t(128),uint8_t(255)}) {
        auto b=good; b[0]=ch; rtsp_message m{}; size_t n;
        CHECK(rtsp_message_decode(b.data(),b.size(),&m,&n)==IAP2_INVALID);
    }
    rtsp_message m{};size_t n;const uint8_t interleaved[]={'$',0,0,1,0x80};
    CHECK(rtsp_message_decode(interleaved,sizeof(interleaved),&m,&n)==IAP2_UNSUPPORTED&&n==0);
}
static void limits() {
    const std::string base="POST /x RTSP/1.0\r\nCSeq: 1\r\nX: ";
    auto b=bytes(base+std::string(RTSP_MAX_HEADER_SIZE-base.size()-4,'a')+"\r\n\r\n");
    CHECK(b.size()==RTSP_MAX_HEADER_SIZE); CHECK(decode(b).header_count==2);
    b.insert(b.begin()+static_cast<ptrdiff_t>(base.size()),'b'); rtsp_message m{}; size_t n;
    CHECK(rtsp_message_decode(b.data(),b.size(),&m,&n)==IAP2_NO_SPACE);
    std::string many="GET /info RTSP/1.0\r\nCSeq: 1\r\n";
    for(int i=0;i<31;++i) many+="X-"+std::to_string(i)+": yes\r\n";
    b=bytes(many+"\r\n"); CHECK(decode(b).header_count==32);
    b=bytes(many+"Last: no\r\n\r\n"); CHECK(rtsp_message_decode(b.data(),b.size(),&m,&n)==IAP2_NO_SPACE);
    b=request("POST","/info",1,Bytes(RTSP_MAX_BODY_SIZE,0xa5)); CHECK(decode(b).body.size==RTSP_MAX_BODY_SIZE);
    std::vector<uint8_t> storage(RTSP_MAX_MESSAGE_SIZE); rtsp_stream stream{};
    CHECK(rtsp_stream_init(&stream,storage.data(),storage.size())==IAP2_OK);
    CHECK(rtsp_stream_feed(&stream,b.data(),b.size(),&n)==IAP2_OK&&n==b.size());
    rtsp_stream_clear(&stream); CHECK(zeroed(storage.data(),b.size()));
    CHECK(rtsp_stream_init(&stream,storage.data(),64)==IAP2_OK);
    CHECK(rtsp_stream_feed(&stream,b.data(),b.size(),&n)==IAP2_NO_SPACE); CHECK(zeroed(storage.data(),64));
    CHECK(rtsp_stream_feed(&stream,nullptr,0,&n)==IAP2_NO_SPACE&&n==0);
}
static void streaming() {
    const auto b=request(); const Bytes tail={0x02,0x00,0x7f,0x80,0xff};
    for(size_t split=0;split<=b.size();++split) {
        Bytes storage(512,0xa5); rtsp_stream s{}; CHECK(rtsp_stream_init(&s,storage.data(),storage.size())==IAP2_OK);
        size_t n=99; int r=rtsp_stream_feed(&s,b.data(),split,&n); CHECK(n==split);
        CHECK(r==(split==b.size()?IAP2_OK:IAP2_MORE));
        auto rest=Bytes(b.begin()+static_cast<ptrdiff_t>(split),b.end()); rest.insert(rest.end(),tail.begin(),tail.end());
        r=rtsp_stream_feed(&s,rest.data(),rest.size(),&n);
        CHECK(r==(split==b.size()?RTSP_BUSY:IAP2_OK)&&n==b.size()-split);
        rtsp_message m{}; CHECK(rtsp_stream_message(&s,&m)==IAP2_OK&&str(m.target)=="/pair-verify");
        CHECK(rtsp_stream_feed(&s,tail.data(),tail.size(),&n)==RTSP_BUSY&&n==0);
        rtsp_stream_clear(&s); CHECK(zeroed(storage.data(),b.size())&&storage[b.size()]==0xa5);
    }
    Bytes storage(512); rtsp_stream s{}; CHECK(rtsp_stream_init(&s,storage.data(),storage.size())==IAP2_OK);
    for(size_t i=0;i<b.size();++i) { size_t n; CHECK(rtsp_stream_feed(&s,b.data()+i,1,&n)==(i+1==b.size()?IAP2_OK:IAP2_MORE)&&n==1); }
    auto saved=s; CHECK(rtsp_stream_init(&s,storage.data(),63)==IAP2_ARGUMENT); CHECK(std::memcmp(&saved,&s,sizeof(s))==0);
}
static void responses() {
    auto b=request(); auto req=decode(b); const Bytes body={0,255,13,10,0};
    rtsp_header h={literal("Content-Type"),literal("application/octet-stream")};
    rtsp_response res={200,{},&h,1,{body.data(),body.size()}};
    size_t needed=0,written=99; CHECK(rtsp_response_encode(&req,&res,nullptr,0,&needed)==IAP2_OK);
    Bytes out(needed,0xa5);
    CHECK(rtsp_response_encode(&req,&res,out.data(),out.size()-1,&written)==IAP2_NO_SPACE&&written==0);
    CHECK(std::all_of(out.begin(),out.end(),[](uint8_t v){return v==0xa5;}));
    CHECK(rtsp_response_encode(&req,&res,out.data(),out.size(),&written)==IAP2_OK&&written==needed);
    auto m=decode(out); CHECK(m.kind==RTSP_RESPONSE&&m.status==200&&m.cseq==7&&m.body.size==body.size());
    CHECK(std::equal(body.begin(),body.end(),m.body.data));
    auto expected=bytes("RTSP/1.0 200 OK\r\nCSeq: 7\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\n\r\n");
    expected.insert(expected.end(),body.begin(),body.end()); CHECK(out==expected);
    for(const auto* name: {"Content-Length","content-length","CSEQ","Transfer-Encoding","Bad Name","X\r\nY"}) {
        h.name=literal(name); auto old=out;
        CHECK(rtsp_response_encode(&req,&res,out.data(),out.size(),&written)==IAP2_ARGUMENT&&written==0&&out==old);
    }
    h.name=literal("Content-Type"); h.value=literal("safe\r\nCSeq: 2");
    CHECK(rtsp_response_encode(&req,&res,nullptr,0,&written)==IAP2_ARGUMENT);
    h.value=literal("a"); rtsp_header two[]={h,h}; res.headers=two;res.header_count=2;
    CHECK(rtsp_response_encode(&req,&res,nullptr,0,&written)==IAP2_ARGUMENT);
    res.headers=nullptr;res.header_count=0;res.body={};res.status=499;
    CHECK(rtsp_response_encode(&req,&res,nullptr,0,&written)==IAP2_ARGUMENT);
    res.reason=literal("Explicit Failure"); CHECK(rtsp_response_encode(&req,&res,nullptr,0,&written)==IAP2_OK);
    res.reason=literal("Bad\nInjected"); CHECK(rtsp_response_encode(&req,&res,nullptr,0,&written)==IAP2_ARGUMENT);
    auto http=bytes("GET /info HTTP/1.1\r\n\r\n");req=decode(http);res={404,{},nullptr,0,{}};out.resize(256);
    CHECK(rtsp_response_encode(&req,&res,out.data(),out.size(),&written)==IAP2_OK);
    out.resize(written);m=decode(out);CHECK(m.protocol==RTSP_HTTP_11&&!m.has_cseq&&m.status==404);
    req=decode(b);res={200,{},nullptr,0,{}};
    std::vector<std::string> names;names.reserve(31);std::vector<rtsp_header> headers;
    for(int i=0;i<31;++i) { names.push_back("X-"+std::to_string(i));headers.push_back({literal(names.back().c_str()),literal("v")}); }
    res.headers=headers.data();res.header_count=30;
    CHECK(rtsp_response_encode(&req,&res,nullptr,0,&needed)==IAP2_OK);out.resize(needed);
    CHECK(rtsp_response_encode(&req,&res,out.data(),out.size(),&written)==IAP2_OK&&written==needed);
    CHECK(decode(out).header_count==32);res.header_count=31;
    CHECK(rtsp_response_encode(&req,&res,nullptr,0,&needed)==IAP2_NO_SPACE&&needed==0);
    std::string giant(RTSP_MAX_HEADER_SIZE,'a');res={200,{reinterpret_cast<const uint8_t*>(giant.data()),giant.size()},nullptr,0,{}};
    CHECK(rtsp_response_encode(&req,&res,nullptr,0,&needed)==IAP2_NO_SPACE&&needed==0);
}
struct Channel {
    Bytes rx=Bytes(4096,0xa5),tx=Bytes(4096,0xa5); rtsp_channel c{}; rtsp_channel_config cfg{};
    Channel(uint64_t now=0) { rtsp_channel_default_config(&cfg); CHECK(rtsp_channel_init(&c,&cfg,rx.data(),rx.size(),tx.data(),tx.size(),17,now)==IAP2_OK); }
    rtsp_channel_key receive(const Bytes& b, uint64_t now=1) {
        size_t n=0;CHECK(rtsp_channel_feed(&c,17,b.data(),b.size(),&n,now)==RTSP_CHANNEL_REQUEST&&n==b.size());
        rtsp_message m{};rtsp_channel_key key{};CHECK(rtsp_channel_request(&c,&m,&key)==RTSP_CHANNEL_REQUEST);return key;
    }
    void respond(rtsp_channel_key key, uint64_t now=2) {
        rtsp_response res={501,{},nullptr,0,{}};CHECK(rtsp_channel_respond(&c,key,&res,now)==RTSP_CHANNEL_OUTPUT);
    }
    Bytes drain(rtsp_channel_key key, uint64_t now=3) {
        Bytes out;rtsp_slice part{};int r;
        while((r=rtsp_channel_output(&c,key,&part,now))==RTSP_CHANNEL_OUTPUT) {
            size_t n=std::min(size_t(3),part.size);out.insert(out.end(),part.data,part.data+n);
            CHECK(rtsp_channel_consume(&c,key,n,now)==(n==part.size?RTSP_CHANNEL_OUTPUT_DONE:RTSP_CHANNEL_OUTPUT));
        }
        CHECK(r==RTSP_CHANNEL_OUTPUT_DONE&&!part.data&&!part.size);return out;
    }
};
static void serial_channel() {
    Channel s;auto b=request();auto both=b;const Bytes encrypted_tail={2,0,0x90,0x80,0,1,255};
    both.insert(both.end(),encrypted_tail.begin(),encrypted_tail.end());size_t n;
    CHECK(rtsp_channel_feed(&s.c,17,both.data(),both.size(),&n,1)==RTSP_CHANNEL_REQUEST&&n==b.size());
    rtsp_message m{};rtsp_channel_key key{};CHECK(rtsp_channel_request(&s.c,&m,&key)==RTSP_CHANNEL_REQUEST);
    CHECK(key.generation==17&&key.token==1&&m.body.size==8);
    CHECK(rtsp_channel_release(&s.c,key,UINT64_MAX)==RTSP_BUSY&&s.c.now==1);
    CHECK(rtsp_channel_feed(&s.c,17,encrypted_tail.data(),encrypted_tail.size(),&n,1)==RTSP_BUSY&&n==0);
    rtsp_response response={200,{},nullptr,0,m.body};
    CHECK(rtsp_channel_respond(&s.c,key,&response,2)==RTSP_CHANNEL_OUTPUT); // opaque echo, no verification
    CHECK(rtsp_channel_request(&s.c,&m,&key)==IAP2_MORE&&zeroed(&key,sizeof(key))&&zeroed(&m,sizeof(m)));
    key={17,1};auto out=s.drain(key);m=decode(out);CHECK(m.body.size==8&&m.cseq==7);
    CHECK(s.c.state==RTSP_CHANNEL_SENT&&zeroed(s.tx.data(),out.size()));
    CHECK(rtsp_channel_feed(&s.c,17,b.data(),b.size(),&n,3)==RTSP_BUSY&&n==0);
    CHECK(rtsp_channel_release(&s.c,key,4)==IAP2_OK&&zeroed(s.rx.data(),b.size()));
    auto second=s.receive(request("SETUP","/stream",9,{}),5);CHECK(second.token==2);
    auto saved=s.c;
    CHECK(rtsp_channel_release(&s.c,key,UINT64_MAX)==IAP2_INVALID);
    rtsp_response res={200,{},nullptr,0,{}};
    CHECK(rtsp_channel_respond(&s.c,key,&res,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&saved,&s.c,sizeof(saved))==0);
    s.respond(second,6);out=s.drain(second,7);m=decode(out);CHECK(m.status==501&&m.cseq==9);
    CHECK(rtsp_channel_release(&s.c,second,8)==IAP2_OK);
    CHECK(rtsp_channel_next_delay(&s.c)==s.cfg.idle_ms);
    rtsp_channel_close(&s.c);CHECK(rtsp_channel_next_delay(&s.c)==UINT32_MAX);rtsp_channel_close(&s.c);
}
static void channel_deadlines() {
    { Channel s;CHECK(rtsp_channel_check(&s.c,17,29999)==IAP2_OK&&rtsp_channel_next_delay(&s.c)==1);
      CHECK(rtsp_channel_check(&s.c,17,30000)==RTSP_CHANNEL_CLOSED&&s.c.reason==RTSP_CHANNEL_REASON_DEADLINE); }
    { Channel s;auto b=request();size_t n;
      CHECK(rtsp_channel_feed(&s.c,17,b.data(),1,&n,29999)==IAP2_MORE&&rtsp_channel_next_delay(&s.c)==10000);
      CHECK(rtsp_channel_feed(&s.c,17,b.data()+1,1,&n,39998)==IAP2_MORE&&rtsp_channel_next_delay(&s.c)==1);
      CHECK(rtsp_channel_feed(&s.c,17,b.data()+2,b.size()-2,&n,39999)==RTSP_CHANNEL_CLOSED&&n==0&&zeroed(s.rx.data(),2)); }
    { Channel s;auto key=s.receive(request());rtsp_response res={200,{},nullptr,0,{}};
      CHECK(rtsp_channel_respond(&s.c,key,&res,5001)==RTSP_CHANNEL_CLOSED&&s.c.tx_size==0&&zeroed(s.rx.data(),request().size())); }
    { Channel s;auto key=s.receive(request());s.respond(key,2);rtsp_slice out{};
      auto size=s.c.tx_size;
      CHECK(rtsp_channel_consume(&s.c,key,1,5001)==RTSP_CHANNEL_OUTPUT&&rtsp_channel_next_delay(&s.c)==1);
      CHECK(rtsp_channel_output(&s.c,key,&out,5002)==RTSP_CHANNEL_CLOSED&&!out.data&&!out.size&&zeroed(s.tx.data(),size)); }
    { Channel s;auto key=s.receive(request());s.respond(key);auto out=s.drain(key);
      CHECK(rtsp_channel_release(&s.c,key,5002)==RTSP_CHANNEL_CLOSED&&zeroed(s.tx.data(),out.size())); }
    { Channel s(UINT64_MAX-5);size_t n;const uint8_t first='G';
      CHECK(rtsp_channel_feed(&s.c,17,&first,1,&n,UINT64_MAX-3)==IAP2_MORE);
      CHECK(rtsp_channel_check(&s.c,17,UINT64_MAX)==IAP2_OK&&rtsp_channel_next_delay(&s.c)==9997); }
}
static void channel_invalid_and_eof() {
    Channel s;auto key=s.receive(request());auto saved=s.c;auto rx=s.rx;auto tx=s.tx;size_t n=99;
    CHECK(rtsp_channel_feed(&s.c,18,nullptr,0,&n,UINT64_MAX)==IAP2_INVALID&&n==0);
    CHECK(rtsp_channel_eof(&s.c,18,UINT64_MAX)==IAP2_INVALID);
    CHECK(rtsp_channel_check(&s.c,17,0)==IAP2_ARGUMENT);
    rtsp_response res={100,literal("Continue"),nullptr,0,{}};
    CHECK(rtsp_channel_respond(&s.c,key,&res,UINT64_MAX)==IAP2_ARGUMENT);
    Bytes huge(5000);res={200,{},nullptr,0,{huge.data(),huge.size()}};
    CHECK(rtsp_channel_respond(&s.c,key,&res,UINT64_MAX)==IAP2_NO_SPACE);
    CHECK(std::memcmp(&saved,&s.c,sizeof(saved))==0&&s.rx==rx&&s.tx==tx);
    s.respond(key);saved=s.c;
    CHECK(rtsp_channel_consume(&s.c,key,0,UINT64_MAX)==IAP2_ARGUMENT);
    CHECK(rtsp_channel_consume(&s.c,key,s.c.tx_size+1,UINT64_MAX)==IAP2_ARGUMENT);
    CHECK(rtsp_channel_consume(&s.c,{18,key.token},1,UINT64_MAX)==IAP2_INVALID);
    CHECK(std::memcmp(&saved,&s.c,sizeof(saved))==0);
    auto nt=s.c.tx_size,nr=s.c.input.used;
    CHECK(rtsp_channel_eof(&s.c,17,3)==RTSP_CHANNEL_CLOSED&&s.c.reason==RTSP_CHANNEL_REASON_EOF);
    CHECK(zeroed(s.tx.data(),nt)&&zeroed(s.rx.data(),nr));rtsp_channel_close(&s.c);CHECK(s.c.reason==RTSP_CHANNEL_REASON_EOF);
    { Channel partial;const auto b=bytes("POST /");CHECK(rtsp_channel_feed(&partial.c,17,b.data(),b.size(),&n,1)==IAP2_MORE);
      CHECK(rtsp_channel_eof(&partial.c,17,2)==RTSP_CHANNEL_CLOSED&&zeroed(partial.rx.data(),b.size())); }
    { Channel other;auto b=bytes("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");
      CHECK(rtsp_channel_feed(&other.c,17,b.data(),b.size(),&n,1)==RTSP_CHANNEL_CLOSED&&other.c.reason==RTSP_CHANNEL_REASON_PROTOCOL); }
    { Channel malformed_stream;const auto b=bytes("GET /x RTSP/1.0\n\n");
      CHECK(rtsp_channel_feed(&malformed_stream.c,17,b.data(),b.size(),&n,1)==RTSP_CHANNEL_CLOSED);
      CHECK(malformed_stream.c.last_error==IAP2_INVALID); }
    { Channel exhausted;exhausted.c.next_token=UINT64_MAX;auto last=exhausted.receive(request()); // fault-injected boundary
      CHECK(last.token==UINT64_MAX);exhausted.respond(last);exhausted.drain(last);
      CHECK(rtsp_channel_release(&exhausted.c,last,4)==IAP2_OK);auto b=request();
      CHECK(rtsp_channel_feed(&exhausted.c,17,b.data(),b.size(),&n,5)==RTSP_CHANNEL_CLOSED&&exhausted.c.token==0); }
    auto cfg=s.cfg;cfg.receive_ms=0;saved=s.c;
    CHECK(rtsp_channel_init(&s.c,&cfg,s.rx.data(),s.rx.size(),s.tx.data(),s.tx.size(),17,UINT64_MAX)==IAP2_ARGUMENT);
    CHECK(std::memcmp(&saved,&s.c,sizeof(saved))==0);
}
static void mutation_checks() {
    uint32_t rng=0x86123456;auto random=[&](){ rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng; };
    Bytes storage(RTSP_MAX_MESSAGE_SIZE);size_t accepted=0,rejected=0,partial=0;
    for(int trial=0;trial<6000;++trial) {
        auto b=request("POST",trial%2?"/pair-verify":"/info",random(),Bytes(random()%80,0x51));
        if(trial%4==0) b.resize(random()%(b.size()+1));
        else if(trial%4==1) { for(unsigned j=0,n=1+random()%8;j<n;++j) b[random()%b.size()]=static_cast<uint8_t>(random()); }
        else if(trial%4==2) { b.resize(random()%300);for(auto& v:b) v=static_cast<uint8_t>(random()); }
        rtsp_message m{};size_t consumed=0;int expected=rtsp_message_decode(b.data(),b.size(),&m,&consumed);
        rtsp_stream s{};CHECK(rtsp_stream_init(&s,storage.data(),storage.size())==IAP2_OK);
        size_t offset=0;int r=IAP2_MORE;
        while(offset<b.size()&&r==IAP2_MORE) {
            auto take=std::min(b.size()-offset,size_t(1+random()%31));size_t used=0;
            r=rtsp_stream_feed(&s,b.data()+offset,take,&used);CHECK(used<=take);offset+=used;
        }
        CHECK(r==expected);
        if(r==IAP2_OK) { ++accepted;rtsp_message actual{};CHECK(offset==consumed&&rtsp_stream_message(&s,&actual)==IAP2_OK);
            CHECK(actual.kind==m.kind&&actual.cseq==m.cseq&&str(actual.target)==str(m.target)&&str(actual.body)==str(m.body)); }
        else if(r==IAP2_MORE) ++partial; else ++rejected;
        rtsp_stream_clear(&s);
    }
    CHECK(accepted>1000&&rejected>1000&&partial>1000);
}
int main() {
    try {
        valid_messages();malformed();limits();streaming();responses();serial_channel();channel_deadlines();channel_invalid_and_eof();mutation_checks();
        std::cout<<"PASS: 9 RTSP framing/channel groups (including 6000 deterministic mutations)\n";
        std::cout<<"x64 sizes: message="<<sizeof(rtsp_message)<<" stream="<<sizeof(rtsp_stream)<<" channel="<<sizeof(rtsp_channel)<<" bytes; caller buffers additional\n";
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; }
}
