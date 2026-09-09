/* SPDX-License-Identifier: GPL-3.0-only */
#include "control_cipher.h"
#include "monocypher-ed25519.h"
#include "pair_test_support.h"
struct Cipher {
    control_cipher c{};control_cipher_config cfg{};Bytes rx,plain,tx;
    explicit Cipher(const Vectors& v,uint32_t limit=16384,bool reverse=false,bool start=true):rx(limit+18,0xa5),plain(limit,0xa5),tx(limit+18,0xa5) {
        control_cipher_default_config(&cfg);cfg.payload_limit=limit;
        CHECK(control_cipher_init(&c,&cfg,rx.data(),rx.size(),plain.data(),plain.size(),tx.data(),tx.size(),91,0)==IAP2_OK);
        if(start) CHECK(control_cipher_start(&c,91,v.at(reverse?"write_key":"read_key").data(),v.at(reverse?"read_key":"write_key").data(),0)==IAP2_OK);
    }
    ~Cipher() { control_cipher_close(&c); }
    Cipher(const Cipher&)=delete;Cipher& operator=(const Cipher&)=delete;
    int feed(const Bytes& b,uint64_t now=1) { size_t used=0;auto r=control_cipher_feed(&c,91,b.data(),b.size(),&used,now);CHECK(used==b.size());return r; }
    Bytes output(control_cipher_key& key) { rtsp_slice s{};CHECK(control_cipher_output(&c,&s,&key)==CONTROL_CIPHER_OUTPUT);return {s.data,s.data+s.size}; }
    Bytes received(control_cipher_key& key) { rtsp_slice s{};CHECK(control_cipher_plain(&c,&s,&key)==CONTROL_CIPHER_FRAME);return {s.data,s.data+s.size}; }
    void cleared() { CHECK(c.state==CONTROL_CIPHER_DEAD&&zeroed(c.read_key,32)&&zeroed(c.write_key,32)&&zeroed(rx.data(),rx.size())&&zeroed(tx.data(),tx.size())&&zeroed(plain.data(),plain.size())); }
};
static void independent_records(const Vectors& v) {
    Cipher s(v);control_cipher_key key{};
    CHECK(s.feed(v.at("read_0"))==CONTROL_CIPHER_FRAME&&s.received(key)==v.at("request")&&key.counter==0);
    CHECK(control_cipher_consume_plain(&s.c,key,v.at("request").size(),1)==IAP2_OK);
    CHECK(s.feed(v.at("read_1"))==CONTROL_CIPHER_FRAME&&s.received(key)==v.at("request")&&key.counter==1);
    CHECK(control_cipher_consume_plain(&s.c,key,v.at("request").size(),1)==IAP2_OK);
    CHECK(s.feed(v.at("read_empty_2"))==CONTROL_CIPHER_FRAME&&s.received(key).empty()&&key.counter==2);
    CHECK(control_cipher_consume_plain(&s.c,key,0,1)==IAP2_OK&&s.c.read_counter==3);
    for(int i=0;i<2;++i) {
        auto& b=v.at("response");CHECK(control_cipher_queue(&s.c,91,b.data(),b.size(),2)==CONTROL_CIPHER_OUTPUT);
        CHECK(s.output(key)==v.at(i?"write_1":"write_0")&&key.counter==static_cast<uint64_t>(i));
        CHECK(control_cipher_consume_output(&s.c,key,b.size()+18,2)==IAP2_OK);
    }
    CHECK(s.c.write_counter==2&&s.c.read_counter==3);
    { Cipher end(v);end.c.read_counter=0x0102030405060708ULL; // Fault injection only, not public API.
      CHECK(end.feed(v.at("read_endian"))==CONTROL_CIPHER_FRAME&&end.received(key)==v.at("request")); }
}
static void fragmentation_and_retirement(const Vectors& v) {
    const auto& wire=v.at("read_0");
    for(size_t split=0;split<=wire.size();++split) {
        Cipher s(v);size_t used=0;control_cipher_key key{};
        CHECK(control_cipher_feed(&s.c,91,wire.data(),split,&used,1)==(split==wire.size()?CONTROL_CIPHER_FRAME:IAP2_MORE)&&used==split);
        if(split<wire.size()) CHECK(control_cipher_feed(&s.c,91,wire.data()+split,wire.size()-split,&used,2)==CONTROL_CIPHER_FRAME&&used==wire.size()-split);
        auto b=s.received(key);CHECK(b==v.at("request"));auto saved=s.c;
        CHECK(control_cipher_feed(&s.c,91,wire.data(),wire.size(),&used,2)==CONTROL_CIPHER_BUSY&&used==0&&s.c.read_counter==1);
        auto stale=key;stale.counter=44;saved=s.c;
        CHECK(control_cipher_consume_plain(&s.c,stale,1,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&saved,&s.c,sizeof(saved))==0);
        for(size_t i=0;i<b.size();++i) {
            CHECK(control_cipher_consume_plain(&s.c,key,1,2)==(i+1==b.size()?IAP2_OK:CONTROL_CIPHER_FRAME));
            CHECK(zeroed(s.plain.data(),i+1));
        }
    }
    Cipher s(v);auto all=wire;all.insert(all.end(),v.at("read_1").begin(),v.at("read_1").end());size_t used=0;
    CHECK(control_cipher_feed(&s.c,91,all.data(),all.size(),&used,1)==CONTROL_CIPHER_FRAME&&used==wire.size());
    const auto& b=v.at("response");CHECK(control_cipher_queue(&s.c,91,b.data(),b.size(),1)==CONTROL_CIPHER_OUTPUT);
    control_cipher_key key{};auto out=s.output(key),saved_out=out;auto saved=s.c;
    CHECK(control_cipher_queue(&s.c,91,b.data(),b.size(),UINT64_MAX)==CONTROL_CIPHER_BUSY&&std::memcmp(&saved,&s.c,sizeof(saved))==0);
    for(size_t i=0;i<out.size();++i) {
        CHECK(s.output(key)==Bytes(saved_out.begin()+static_cast<ptrdiff_t>(i),saved_out.end()));
        CHECK(control_cipher_consume_output(&s.c,key,1,2)==(i+1==out.size()?IAP2_OK:CONTROL_CIPHER_OUTPUT));
        CHECK(s.c.write_counter==1&&zeroed(s.tx.data(),i+1));
    }
    CHECK(control_cipher_consume_output(&s.c,key,1,UINT64_MAX)==IAP2_INVALID&&s.c.now==2);
}
static void auth_and_protocol_failures(const Vectors& v) {
    const auto& wire=v.at("read_0");
    for(size_t pos=0;pos<wire.size();++pos) for(unsigned bit=0;bit<8;++bit) {
        Cipher s(v);auto bad=wire;bad[pos]^=static_cast<uint8_t>(1u<<bit);size_t used=0;
        int r=control_cipher_feed(&s.c,91,bad.data(),bad.size(),&used,1);
        CHECK(r==IAP2_MORE||r==CONTROL_CIPHER_CLOSED);rtsp_slice view{};control_cipher_key key{};
        CHECK(control_cipher_plain(&s.c,&view,&key)!=CONTROL_CIPHER_FRAME&&view.size==0&&view.data==nullptr&&s.c.read_counter==0);
        if(r==IAP2_MORE) CHECK(control_cipher_eof(&s.c,91,2)==CONTROL_CIPHER_CLOSED);
        s.cleared();
    }
    { Cipher s(v);CHECK(s.feed(wire)==CONTROL_CIPHER_FRAME);control_cipher_key key{};auto b=s.received(key);
      CHECK(control_cipher_consume_plain(&s.c,key,b.size(),1)==IAP2_OK);CHECK(s.feed(wire,2)==CONTROL_CIPHER_CLOSED);s.cleared(); }
    { Cipher s(v);size_t used=0;const uint8_t oversized[]={1,64};
      CHECK(control_cipher_feed(&s.c,91,oversized,2,&used,1)==CONTROL_CIPHER_CLOSED&&used==2);s.cleared(); }
    { Cipher s(v,16384,true);CHECK(s.feed(wire)==CONTROL_CIPHER_CLOSED);s.cleared(); }
    for(size_t n=0;n<wire.size();++n) { Cipher s(v);size_t used=0;
      CHECK(control_cipher_feed(&s.c,91,wire.data(),n,&used,1)==IAP2_MORE&&used==n);
      CHECK(control_cipher_eof(&s.c,91,2)==CONTROL_CIPHER_CLOSED);s.cleared(); }
}
static void budgets_and_ownership(const Vectors& v) {
    const auto& wire=v.at("read_0");
    { Cipher s(v);auto saved=s.c;size_t used=55;
      CHECK(control_cipher_feed(&s.c,92,wire.data(),wire.size(),&used,UINT64_MAX)==IAP2_INVALID&&used==0&&std::memcmp(&saved,&s.c,sizeof(saved))==0);
      CHECK(control_cipher_feed(&s.c,91,wire.data(),1,&used,1)==IAP2_MORE);
      CHECK(control_cipher_feed(&s.c,91,wire.data()+1,1,&used,10000)==IAP2_MORE&&control_cipher_next_delay(&s.c)==1);
      saved=s.c;CHECK(control_cipher_check(&s.c,91,9999)==IAP2_ARGUMENT&&std::memcmp(&saved,&s.c,sizeof(saved))==0);
      CHECK(control_cipher_check(&s.c,91,10001)==CONTROL_CIPHER_CLOSED&&s.c.reason==CONTROL_CIPHER_REASON_DEADLINE);s.cleared(); }
    { Cipher s(v);CHECK(s.feed(wire)==CONTROL_CIPHER_FRAME);control_cipher_key key{};s.received(key);
      CHECK(control_cipher_consume_plain(&s.c,key,1,5000)==CONTROL_CIPHER_FRAME&&control_cipher_next_delay(&s.c)==1);
      CHECK(control_cipher_check(&s.c,91,5001)==CONTROL_CIPHER_CLOSED);s.cleared(); }
    { Cipher s(v);CHECK(control_cipher_queue(&s.c,91,nullptr,0,1)==CONTROL_CIPHER_OUTPUT);control_cipher_key key{};s.output(key);
      auto old=key;old.generation=92;auto saved=s.c;
      CHECK(control_cipher_consume_output(&s.c,old,1,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&saved,&s.c,sizeof(saved))==0);
      CHECK(control_cipher_consume_output(&s.c,key,0,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&saved,&s.c,sizeof(saved))==0);
      CHECK(control_cipher_consume_output(&s.c,key,1,5000)==CONTROL_CIPHER_OUTPUT&&control_cipher_next_delay(&s.c)==1);
      CHECK(control_cipher_check(&s.c,91,5001)==CONTROL_CIPHER_CLOSED);s.cleared(); }
    { Cipher s(v,64,false,false);CHECK(s.c.state==CONTROL_CIPHER_DORMANT&&control_cipher_next_delay(&s.c)==UINT32_MAX);
      size_t used=0;CHECK(control_cipher_feed(&s.c,91,wire.data(),wire.size(),&used,1)==CONTROL_CIPHER_BUSY&&used==0);
      auto saved=s.c, cfg=s.c;control_cipher_config bad=s.cfg;bad.payload_limit=0;
      CHECK(control_cipher_init(&s.c,&bad,s.rx.data(),s.rx.size(),s.plain.data(),s.plain.size(),s.tx.data(),s.tx.size(),91,2)==IAP2_ARGUMENT&&std::memcmp(&saved,&s.c,sizeof(saved))==0);
      CHECK(control_cipher_start(&s.c,91,v.at("read_key").data(),v.at("write_key").data(),1)==IAP2_OK);cfg=s.c;
      CHECK(control_cipher_start(&s.c,91,v.at("read_key").data(),v.at("write_key").data(),UINT64_MAX)==CONTROL_CIPHER_BUSY&&std::memcmp(&cfg,&s.c,sizeof(cfg))==0);
      control_cipher_close(&s.c);s.cleared();control_cipher_close(&s.c);CHECK(s.c.reason==CONTROL_CIPHER_REASON_LOCAL); }
}
static void maximums_and_exhaustion(const Vectors& v) {
    { Cipher s(v);Bytes large(16384);for(size_t i=0;i<large.size();++i) large[i]=static_cast<uint8_t>(i);
      CHECK(control_cipher_queue(&s.c,91,large.data(),large.size()+1,UINT64_MAX)==IAP2_ARGUMENT&&s.c.now==0);
      CHECK(control_cipher_queue(&s.c,91,large.data(),large.size(),1)==CONTROL_CIPHER_OUTPUT);control_cipher_key key{};auto out=s.output(key);
      CHECK(out.size()==16402&&out[0]==0&&out[1]==64);std::array<uint8_t,64> hash{};crypto_sha512(hash.data(),out.data(),out.size());
      CHECK(equal(hash.data(),v.at("max_payload_sha512")));Cipher peer(v,16384,true);
      CHECK(peer.feed(out)==CONTROL_CIPHER_FRAME&&peer.received(key)==large); }
    { Cipher s(v);s.c.read_counter=UINT64_MAX;CHECK(s.feed(v.at("read_max"))==CONTROL_CIPHER_FRAME);
      control_cipher_key key{};CHECK(s.received(key)==v.at("request")&&key.counter==UINT64_MAX&&s.c.read_exhausted&&s.c.read_counter==UINT64_MAX);
      CHECK(control_cipher_consume_plain(&s.c,key,v.at("request").size(),1)==IAP2_OK);size_t used=9;
      CHECK(control_cipher_feed(&s.c,91,v.at("read_0").data(),1,&used,2)==CONTROL_CIPHER_CLOSED&&used==0&&s.c.reason==CONTROL_CIPHER_REASON_EXHAUSTED);s.cleared(); }
    { Cipher s(v,16384,true);s.c.write_counter=UINT64_MAX;const auto& req=v.at("request");
      CHECK(control_cipher_queue(&s.c,91,req.data(),req.size(),1)==CONTROL_CIPHER_OUTPUT);control_cipher_key key{};
      CHECK(s.output(key)==v.at("read_max")&&s.c.write_exhausted&&s.c.write_counter==UINT64_MAX);
      CHECK(control_cipher_consume_output(&s.c,key,req.size()+18,1)==IAP2_OK);
      CHECK(control_cipher_queue(&s.c,91,nullptr,0,2)==CONTROL_CIPHER_CLOSED&&s.c.reason==CONTROL_CIPHER_REASON_EXHAUSTED);s.cleared(); }
}
int main(int argc,char** argv) { try { CHECK(argc==2);auto v=load_vectors(argv[1],12);independent_records(v);fragmentation_and_retirement(v);auth_and_protocol_failures(v);budgets_and_ownership(v);maximums_and_exhaustion(v);
    std::cout<<"PASS: 5 control-cipher groups; independent vectors, all split points/bit mutations, replay, deadlines and counter exhaustion\n";
    std::cout<<"x64 control_cipher="<<sizeof(control_cipher)<<" bytes plus caller buffers\n";return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; } }
