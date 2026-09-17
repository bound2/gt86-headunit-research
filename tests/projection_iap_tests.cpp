/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_iap.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
// Avoid the local Windows clang19/ASan C++ exception-reporting failure. A failed
// assertion still prints its expression/line and exits unsuccessfully; no
// production code or test function loses sanitizer instrumentation.
#define CHECK(x) do { if(!(x)) { std::cerr<<"CHECK failed: " #x " at "<<__LINE__<<'\n';std::exit(1); } } while(0)
using Bytes=std::vector<uint8_t>;
static Bytes bytes(const std::string &s) { return {s.begin(),s.end()}; }
static bool zeroed(const void *p,size_t n) { auto b=static_cast<const uint8_t*>(p);return std::all_of(b,b+n,[](uint8_t c){return c==0;}); }
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
static std::array<uint8_t,32> key() { std::array<uint8_t,32> k{};for(unsigned i=0;i<32;++i) k[i]=uint8_t(i);return k; }
static void be32(Bytes &b,size_t at,uint32_t n) { for(unsigned i=0;i<4;++i) b.at(at+i)=uint8_t(n>>(24-8*i)); }
static Bytes package(const Bytes &body,uint32_t type=PROJECTION_IAP_COMM) {
    Bytes p(32);for(unsigned i=0;i<32;++i) p[i]=uint8_t(i*7+3); // Uninterpreted fields are preserved, not assumed zero.
    be32(p,0,uint32_t(body.size()+32));be32(p,16,type);p.insert(p.end(),body.begin(),body.end());return p;
}
static Bytes seal(const Bytes &plain,uint64_t counter) {
    CHECK(plain.size()<=16384);Bytes out(plain.size()+18);out[0]=uint8_t(plain.size());out[1]=uint8_t(plain.size()>>8);
    uint8_t nonce[12]{};for(unsigned i=0;i<8;++i) nonce[i+4]=uint8_t(counter>>(8*i));size_t written=0;
    CHECK(pair_aead_seal(key().data(),nonce,out.data(),2,plain.data(),plain.size(),out.data()+2,out.size()-2,&written)==IAP2_OK);
    CHECK(written+2==out.size());return out;
}
static Bytes join(Bytes a,const Bytes &b) { a.insert(a.end(),b.begin(),b.end());return a; }
struct Input {
    projection_iap s{};projection_iap_config cfg{};projection_iap_storage storage{};
    Bytes rx,plain,unused,body;
    explicit Input(uint32_t limit=65536,uint32_t record=16384):rx(record+19,0xa5),plain(record+1,0xa5),unused(record+19,0xa5),body(limit+1,0xa5) {
        projection_iap_default_config(&cfg);cfg.package_limit=limit;cfg.records.payload_limit=record;
        storage={rx.data(),plain.data(),unused.data(),body.data(),rx.size(),plain.size(),unused.size(),body.size()};
        CHECK(projection_iap_init(&s,&cfg,&storage,key().data(),91,0)==IAP2_OK);
    }
    ~Input() { projection_iap_close(&s); }
    Input(const Input&)=delete;Input& operator=(const Input&)=delete;
    int feed(const Bytes &wire,uint64_t now=0) {
        size_t used=0;int r=projection_iap_feed(&s,91,wire.data(),wire.size(),&used,now);
        CHECK(used<=wire.size());if(r!=PROJECTION_IAP_CLOSED) CHECK(used==wire.size());return r;
    }
    projection_iap_key view(Bytes &out) const {
        projection_iap_view v{};projection_iap_key token{};CHECK(projection_iap_peek(&s,91,&v,&token)==PROJECTION_IAP_PACKAGE);
        CHECK(v.header.size==32);out.assign(v.body.data,v.body.data+v.body.size);return token;
    }
    void take(const Bytes &expected,uint64_t now=0) {
        Bytes out;auto token=view(out);CHECK(out==expected);
        CHECK(projection_iap_consume(&s,token,out.size(),now)==IAP2_OK);
    }
    void wiped() const {
        CHECK(s.dead&&s.cipher.state==CONTROL_CIPHER_DEAD&&zeroed(s.cipher.read_key,32)&&zeroed(s.cipher.write_key,32));
        CHECK(zeroed(rx.data(),rx.size()-1)&&zeroed(plain.data(),plain.size()-1)&&zeroed(unused.data(),unused.size()-1)&&zeroed(body.data(),body.size()-1));
        CHECK(rx.back()==0xa5&&plain.back()==0xa5&&unused.back()==0xa5&&body.back()==0xa5);
    }
};
static void initialization() {
    Input s;auto saved=s.s;
    for(unsigned mode=0;mode<13;++mode) {
        auto c=s.cfg;auto b=s.storage;auto gen=uint64_t(91);auto stable=key();const uint8_t *k=stable.data();
        switch(mode) { case 0:c.package_limit=31;break;case 1:c.package_limit=PROJECTION_IAP_MAX_PACKAGE+1;break;
        case 2:c.package_ms=0;break;case 3:c.hold_ms=60001;break;case 4:c.records.payload_limit=16385;break;
        case 5:c.records.receive_ms=0;break;case 6:b.package_size=31;break;case 7:b.package=nullptr;break;
        case 8:b.plain_size=0;break;case 9:b.unused_tx_size=0;break;case 10:b.cipher_rx=nullptr;break;
        case 11:gen=0;break;case 12:k=nullptr;break; }
        CHECK(projection_iap_init(&s.s,&c,&b,k,gen,0)==IAP2_ARGUMENT&&std::memcmp(&saved,&s.s,sizeof(saved))==0);
    }
    projection_iap_view v{};projection_iap_key token{};CHECK(projection_iap_peek(&s.s,91,&v,&token)==IAP2_MORE&&!v.body.data&&!token.token);
    CHECK(projection_iap_next_delay(&s.s)==UINT32_MAX);projection_iap_close(&s.s);s.wiped();projection_iap_close(&s.s);s.wiped();
}
static void fragmentation() {
    auto body=bytes("opaque iAP bytes"),p=package(body),wire=seal(p,0);
    for(size_t split=0;split<=wire.size();++split) {
        Input s;size_t used=0;CHECK(projection_iap_feed(&s.s,91,wire.data(),split,&used,0)==(split==wire.size()?PROJECTION_IAP_PACKAGE:IAP2_MORE)&&used==split);
        if(split<wire.size()) CHECK(projection_iap_feed(&s.s,91,wire.data()+split,wire.size()-split,&used,1)==PROJECTION_IAP_PACKAGE&&used==wire.size()-split);
        projection_iap_view v{};projection_iap_key k{};CHECK(projection_iap_peek(&s.s,91,&v,&k)==PROJECTION_IAP_PACKAGE&&k.token==1);
        CHECK(std::equal(p.begin(),p.begin()+32,v.header.data));s.take(body,1);
    }
    for(size_t split=0;split<=p.size();++split) {
        Input s;auto a=seal(Bytes(p.begin(),p.begin()+split),0),b=seal(Bytes(p.begin()+split,p.end()),1);
        CHECK(s.feed(a)==(split==p.size()?PROJECTION_IAP_PACKAGE:IAP2_MORE));
        if(split==p.size()) s.take(body);
        CHECK(s.feed(b)==(split==p.size()?IAP2_MORE:PROJECTION_IAP_PACKAGE));
        if(split<p.size()) s.take(body);
        CHECK(s.s.cipher.read_counter==2);
    }
    Input s;for(size_t i=0;i<wire.size();++i) CHECK(s.feed(Bytes{wire[i]})==(i+1==wire.size()?PROJECTION_IAP_PACKAGE:IAP2_MORE));s.take(body);
}
static void coalescing_and_unknown() {
    auto one=package(bytes("one")),two=package(bytes("two")),other=package(bytes("skip"),0x64617461);
    Input s;auto wire=seal(join(join(one,other),two),0);CHECK(s.feed(wire)==PROJECTION_IAP_PACKAGE);
    CHECK(s.s.cipher.read_counter==1&&s.s.cipher.held);size_t used=77;
    CHECK(projection_iap_feed(&s.s,91,wire.data(),wire.size(),&used,0)==PROJECTION_IAP_BUSY&&!used);
    s.take(bytes("one"));CHECK(projection_iap_next_delay(&s.s)==0);
    CHECK(s.feed({})==PROJECTION_IAP_IGNORED&&s.s.cipher.read_counter==1);
    CHECK(s.feed({})==PROJECTION_IAP_PACKAGE);s.take(bytes("two"));CHECK(!s.s.cipher.held&&projection_iap_next_delay(&s.s)==UINT32_MAX);
    CHECK(s.feed(seal(package({}),1))==PROJECTION_IAP_PACKAGE);Bytes out;auto token=s.view(out);CHECK(out.empty()&&token.token==3);s.take({});
    CHECK(s.feed(seal({},2))==IAP2_MORE&&s.s.next_token==4&&!s.s.used&&s.s.cipher.read_counter==3);
    Input tail;auto first=seal(one,0),second=seal(two,1),both=join(first,second);
    CHECK(projection_iap_feed(&tail.s,91,both.data(),both.size(),&used,0)==PROJECTION_IAP_PACKAGE&&used==first.size());tail.take(bytes("one"));
    CHECK(tail.feed(second)==PROJECTION_IAP_PACKAGE);tail.take(bytes("two"));
}
static void partial_and_stale() {
    Input s;CHECK(s.feed(seal(package(bytes("abcdef")),0))==PROJECTION_IAP_PACKAGE);Bytes out;auto k=s.view(out),stale=k;auto saved=s.s;
    size_t used=19;CHECK(projection_iap_feed(&s.s,92,nullptr,0,&used,UINT64_MAX)==IAP2_INVALID&&!used&&std::memcmp(&saved,&s.s,sizeof(saved))==0);
    stale.token++;CHECK(projection_iap_consume(&s.s,stale,1,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&saved,&s.s,sizeof(saved))==0);
    stale=k;stale.generation++;CHECK(projection_iap_consume(&s.s,stale,1,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&saved,&s.s,sizeof(saved))==0);
    CHECK(projection_iap_consume(&s.s,k,7,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&saved,&s.s,sizeof(saved))==0);
    CHECK(projection_iap_consume(&s.s,k,0,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&saved,&s.s,sizeof(saved))==0);
    CHECK(projection_iap_consume(&s.s,k,2,10)==PROJECTION_IAP_PACKAGE&&zeroed(s.body.data()+32,2));s.view(out);CHECK(out==bytes("cdef"));
    saved=s.s;CHECK(projection_iap_check(&s.s,91,9)==IAP2_ARGUMENT&&std::memcmp(&saved,&s.s,sizeof(saved))==0);
    CHECK(projection_iap_consume(&s.s,k,4,11)==IAP2_OK&&zeroed(s.body.data(),38));saved=s.s;
    CHECK(projection_iap_consume(&s.s,k,0,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&saved,&s.s,sizeof(saved))==0);
    CHECK(s.feed(seal(package(bytes("new")),1),11)==PROJECTION_IAP_PACKAGE);
    CHECK(projection_iap_consume(&s.s,k,1,UINT64_MAX)==IAP2_INVALID&&s.s.now==11);
}
static void limits_and_large() {
    for(uint32_t size:{0u,1u,31u,257u,UINT32_MAX}) { Input s(256);auto p=package({});be32(p,0,size);
        CHECK(s.feed(seal(p,0))==PROJECTION_IAP_CLOSED&&s.s.reason==PROJECTION_IAP_REASON_SIZE);s.wiped(); }
    Input s(PROJECTION_IAP_MAX_PACKAGE);Bytes body(PROJECTION_IAP_MAX_PACKAGE-32);for(size_t i=0;i<body.size();++i) body[i]=uint8_t(i*13);
    auto p=package(body);uint64_t counter=0;
    for(size_t at=0;at<p.size();) { auto n=std::min<size_t>(16384,p.size()-at);auto wire=seal(Bytes(p.begin()+at,p.begin()+at+n),counter++);at+=n;
        CHECK(s.feed(wire)==(at==p.size()?PROJECTION_IAP_PACKAGE:IAP2_MORE)); }
    s.take(body);CHECK(s.s.cipher.read_counter==256);projection_iap_close(&s.s);s.wiped();
    Input short_record(256,64);CHECK(short_record.feed(Bytes{65,0})==PROJECTION_IAP_CLOSED);short_record.wiped();
    Input minimal(32);CHECK(minimal.feed(seal(package({}),0))==PROJECTION_IAP_PACKAGE);minimal.take({});
}
static void deadlines() {
    auto p=package(bytes("body")),wire=seal(p,0);
    { Input s;CHECK(s.feed(Bytes{wire[0]},1)==IAP2_MORE);CHECK(projection_iap_check(&s.s,91,10000)==IAP2_OK&&projection_iap_next_delay(&s.s)==1);
      CHECK(projection_iap_check(&s.s,91,10001)==PROJECTION_IAP_CLOSED);s.wiped(); }
    { Input s;CHECK(s.feed(seal(Bytes(p.begin(),p.begin()+3),0),1)==IAP2_MORE);
      CHECK(s.feed(seal({},1),9999)==IAP2_MORE&&projection_iap_next_delay(&s.s)==2);
      CHECK(s.feed(seal(Bytes(p.begin()+3,p.end()),2),10001)==PROJECTION_IAP_CLOSED&&s.s.reason==PROJECTION_IAP_REASON_DEADLINE);s.wiped(); }
    { Input s;CHECK(s.feed(wire,1)==PROJECTION_IAP_PACKAGE);Bytes out;auto k=s.view(out);
      CHECK(projection_iap_consume(&s.s,k,1,5000)==PROJECTION_IAP_PACKAGE&&projection_iap_next_delay(&s.s)==1);
      CHECK(projection_iap_consume(&s.s,k,3,5001)==PROJECTION_IAP_CLOSED);s.wiped(); }
    { Input s;CHECK(s.feed(seal(join(p,p),0),1)==PROJECTION_IAP_PACKAGE);s.take(bytes("body"),4999);
      CHECK(s.feed({},5000)==PROJECTION_IAP_PACKAGE);Bytes out;auto k=s.view(out);
      CHECK(projection_iap_consume(&s.s,k,4,5001)==IAP2_OK); // Second body has its own hold budget; cipher tail already retired.
    }
    { Input s;CHECK(s.feed(seal(join(p,p),0),1)==PROJECTION_IAP_PACKAGE);s.take(bytes("body"),5000);
      CHECK(s.feed({},5001)==PROJECTION_IAP_CLOSED&&s.s.cipher.reason==CONTROL_CIPHER_REASON_DEADLINE);s.wiped(); }
}
static void authentication_and_eof() {
    auto wire=seal(package(bytes("private")),0);
    for(size_t pos=0;pos<wire.size();++pos) for(unsigned bit=0;bit<8;++bit) {
        Input s;auto bad=wire;bad[pos]^=uint8_t(1u<<bit);size_t used=0;int r=projection_iap_feed(&s.s,91,bad.data(),bad.size(),&used,0);
        CHECK(r==PROJECTION_IAP_CLOSED||r==IAP2_MORE);projection_iap_view v{};projection_iap_key k{};
        CHECK(projection_iap_peek(&s.s,91,&v,&k)!=PROJECTION_IAP_PACKAGE&&!v.body.data);
        if(!s.s.dead) CHECK(projection_iap_eof(&s.s,91,0)==PROJECTION_IAP_CLOSED);s.wiped();
    }
    { Input s;CHECK(s.feed(wire)==PROJECTION_IAP_PACKAGE);s.take(bytes("private"));CHECK(s.feed(wire)==PROJECTION_IAP_CLOSED);s.wiped(); }
    for(size_t n=0;n<wire.size();++n) { Input s;CHECK(s.feed(Bytes(wire.begin(),wire.begin()+n))==IAP2_MORE);
        CHECK(projection_iap_eof(&s.s,91,0)==PROJECTION_IAP_CLOSED);s.wiped(); }
    { Input s;CHECK(s.feed(wire)==PROJECTION_IAP_PACKAGE);CHECK(projection_iap_eof(&s.s,91,0)==PROJECTION_IAP_CLOSED);s.wiped(); }
    { Input s;CHECK(s.feed(seal(package(bytes("wrong")),1))==PROJECTION_IAP_CLOSED);s.wiped(); }
}
static void exhaustion() {
    // White-box boundary injection only; production callers cannot set/reset these.
    { Input s;s.s.cipher.read_counter=UINT64_MAX;CHECK(s.feed(seal(package({}),UINT64_MAX))==PROJECTION_IAP_PACKAGE);s.take({});
      CHECK(s.s.cipher.read_exhausted&&s.feed(seal(package({}),0))==PROJECTION_IAP_CLOSED);s.wiped(); }
    { Input s;s.s.next_token=UINT64_MAX;CHECK(s.feed(seal(package({}),0))==PROJECTION_IAP_PACKAGE);Bytes out;auto k=s.view(out);CHECK(k.token==UINT64_MAX);s.take({});
      CHECK(s.feed(seal(package({},0),1))==PROJECTION_IAP_IGNORED);
      CHECK(s.feed(seal(package({}),2))==PROJECTION_IAP_CLOSED&&s.s.reason==PROJECTION_IAP_REASON_EXHAUSTED);s.wiped(); }
}
static void mutation() {
    uint32_t rng=0x193ac;auto random=[&]{rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;};
    for(unsigned trial=0;trial<2500;++trial) {
        Input s(256,256);Bytes p(random()%257);for(auto &b:p) b=uint8_t(random());
        if(p.size()>=32&&trial%2==0) { be32(p,0,uint32_t(p.size()));be32(p,16,trial%4==0?PROJECTION_IAP_COMM:0); }
        auto w=seal(p,0);size_t at=0;
        while(at<w.size()&&!s.s.dead) { size_t used=0,n=std::min<size_t>(1+random()%19,w.size()-at);
            int r=projection_iap_feed(&s.s,91,w.data()+at,n,&used,0);CHECK(used<=n);at+=used;
            if(r==PROJECTION_IAP_PACKAGE) { Bytes out;auto k=s.view(out);CHECK(out==Bytes(p.begin()+32,p.end()));CHECK(projection_iap_consume(&s.s,k,out.size(),0)==IAP2_OK); }
            else CHECK(r==IAP2_MORE||r==PROJECTION_IAP_IGNORED||r==PROJECTION_IAP_CLOSED);
        }
        projection_iap_close(&s.s);s.wiped();
    }
}
static int stdin_decode() {
#ifdef _WIN32
    CHECK(_setmode(_fileno(stdin),_O_BINARY)!=-1&&_setmode(_fileno(stdout),_O_BINARY)!=-1);
#endif
    Input s(PROJECTION_IAP_MAX_PACKAGE);size_t iterations=0;std::array<uint8_t,997> chunk{};
    while(std::cin) {
        std::cin.read(reinterpret_cast<char*>(chunk.data()),chunk.size());size_t n=size_t(std::cin.gcount()),at=0;
        do {
            size_t used=0;int r=projection_iap_feed(&s.s,91,at<n?chunk.data()+at:nullptr,n-at,&used,0);at+=used;
            CHECK(++iterations<1000000);
            if(r==PROJECTION_IAP_PACKAGE) { projection_iap_view v{};projection_iap_key k{};
                CHECK(projection_iap_peek(&s.s,91,&v,&k)==PROJECTION_IAP_PACKAGE);
                std::cout.write(reinterpret_cast<const char*>(v.header.data),std::streamsize(v.header.size));
                std::cout.write(reinterpret_cast<const char*>(v.body.data),std::streamsize(v.body.size));
                CHECK(projection_iap_consume(&s.s,k,v.body.size,0)==IAP2_OK);
            } else CHECK(r==IAP2_MORE||r==PROJECTION_IAP_IGNORED);
        } while(at<n||s.s.cipher.held);
    }
    CHECK(!s.s.used&&!s.s.cipher.rx_used&&!s.s.held);CHECK(std::cout.good());return 0;
}
int main(int argc,char **argv) {
    if(argc==2&&std::string(argv[1])=="--wire-stdin") return stdin_decode();
    if(argc==2&&std::string(argv[1])=="--failure-test") CHECK(false);
    CHECK(argc==1);
    initialization();fragmentation();coalescing_and_unknown();partial_and_stale();limits_and_large();deadlines();authentication_and_eof();exhaustion();mutation();
    std::cout<<"PASS: 9 iAP DataStream groups, 2500 authenticated mutations, 4MiB package boundary; no socket/phone execution\n";return 0;
}
