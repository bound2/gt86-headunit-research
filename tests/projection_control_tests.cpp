/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_control.h"
#include "pair_test_support.h"
static Bytes request(const Bytes& body,unsigned seq,const std::string& method="POST",const std::string& path="/pair-verify",const std::string& type="application/pairing+tlv8") {
    auto b=bytes(method+" "+path+" RTSP/1.0\r\nCSeq: "+std::to_string(seq)+"\r\nContent-Type: "+type+"\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n");
    b.insert(b.end(),body.begin(),body.end());return b;
}
static std::array<uint8_t,12> nonce(uint64_t count) {
    std::array<uint8_t,12> n{};for(size_t i=0;i<8;++i) { n[i+4]=static_cast<uint8_t>(count);count>>=8; }return n;
}
static Bytes encrypt(const Vectors& v,const Bytes& b,uint64_t counter) {
    Bytes out(b.size()+18);out[0]=static_cast<uint8_t>(b.size());out[1]=static_cast<uint8_t>(b.size()>>8);size_t n=0;auto iv=nonce(counter);
    CHECK(pair_aead_seal(v.at("accessory_read_key").data(),iv.data(),out.data(),2,b.data(),b.size(),out.data()+2,out.size()-2,&n)==IAP2_OK&&n==b.size()+16);return out;
}
static Bytes decrypt(const Vectors& v,const Bytes& b,uint64_t& counter) {
    Bytes plain;size_t off=0;
    while(off<b.size()) { CHECK(b.size()-off>=18);size_t n=b[off]+(size_t(b[off+1])<<8);CHECK(n<=b.size()-off-18);
        Bytes frame(n+1);auto iv=nonce(counter++);size_t written=0;
        CHECK(pair_aead_open(v.at("accessory_write_key").data(),iv.data(),b.data()+off,2,b.data()+off+2,n+16,frame.data(),frame.size(),&written)==IAP2_OK&&written==n);
        plain.insert(plain.end(),frame.begin(),frame.begin()+static_cast<ptrdiff_t>(n));off+=n+18; }
    return plain;
}
struct Session {
    const Vectors& v;pair_identity id{};projection_control c{};projection_control_config cfg{};
    Bytes rx=Bytes(4096,0xa5),tx=Bytes(4096,0xa5),crx=Bytes(146,0xa5),plain=Bytes(128,0xa5),ctx=Bytes(146,0xa5);
    projection_control_storage storage{};int randoms=0,lookups=0;bool unknown=false,fail_random=false;uint64_t now=1;
    static int random(void* context,uint8_t* out,size_t n) { auto& s=*static_cast<Session*>(context);++s.randoms;CHECK(n==32);
        std::copy(s.v.at("own_ephemeral_secret").begin(),s.v.at("own_ephemeral_secret").end(),out);return s.fail_random?-1:0; }
    static int lookup(void* context,const uint8_t* name,size_t n,uint8_t out[32]) { auto& s=*static_cast<Session*>(context);++s.lookups;
        if(s.unknown||Bytes(name,name+n)!=s.v.at("ctrl_identifier")) return IAP2_END;
        std::copy(s.v.at("ctrl_public").begin(),s.v.at("ctrl_public").end(),out);return IAP2_OK; }
    explicit Session(const Vectors& vv):v(vv) {
        const auto& name=v.at("own_identifier");CHECK(pair_identity_import(&id,v.at("own_seed").data(),v.at("own_public").data(),name.data(),name.size())==IAP2_OK);
        projection_control_default_config(&cfg);cfg.cipher.payload_limit=128;
        storage={rx.data(),tx.data(),crx.data(),plain.data(),ctx.data(),rx.size(),tx.size(),crx.size(),plain.size(),ctx.size()};
        CHECK(projection_control_init(&c,&id,random,this,lookup,this,&cfg,&storage,91,0)==IAP2_OK&&randoms==0&&lookups==0);
    }
    ~Session() { projection_control_close(&c);pair_identity_clear(&id); }
    Session(const Session&)=delete;Session& operator=(const Session&)=delete;
    int feed(const Bytes& b,size_t& used) { return projection_control_feed(&c,91,b.data(),b.size(),&used,now); }
    Bytes drain(rtsp_channel_key& key,size_t chunk=3) {
        Bytes sent;rtsp_slice out{};int r;
        while((r=projection_control_output(&c,91,&out,&key,now))==RTSP_CHANNEL_OUTPUT) {
            const auto take=std::min(chunk,out.size);CHECK(take>0);sent.insert(sent.end(),out.data,out.data+take);
            auto q=projection_control_consume(&c,key,take,now);CHECK(q==RTSP_CHANNEL_OUTPUT||q==RTSP_CHANNEL_OUTPUT_DONE);
        }
        CHECK(r==RTSP_CHANNEL_OUTPUT_DONE&&out.data==nullptr&&out.size==0);return sent;
    }
    void phase(unsigned stage,const Bytes& tail={},bool fragmented=false,bool release=true) {
        auto wire=request(v.at(stage==1?"m1":"m3"),stage);size_t exact=wire.size();wire.insert(wire.end(),tail.begin(),tail.end());size_t off=0,used=0;int r=IAP2_MORE;
        while(r==IAP2_MORE) { auto take=fragmented?size_t(1):wire.size()-off;
            r=projection_control_feed(&c,91,wire.data()+off,take,&used,now);off+=used; }
        CHECK(r==RTSP_CHANNEL_OUTPUT&&off==exact&&c.state==PROJECTION_CONTROL_PAIRING&&c.cipher.state==CONTROL_CIPHER_DORMANT);
        rtsp_message msg{};rtsp_channel_key key{};CHECK(projection_control_request(&c,&msg,&key)==IAP2_MORE&&msg.body.data==nullptr&&key.token==0);
        rtsp_slice out{};CHECK(projection_control_output(&c,91,&out,&key,now)==RTSP_CHANNEL_OUTPUT);
        auto saved=c;CHECK(projection_control_release(&c,key,UINT64_MAX)==RTSP_BUSY&&std::memcmp(&saved,&c,sizeof(c))==0);
        auto sent=drain(key);CHECK(rtsp_message_decode(sent.data(),sent.size(),&msg,&used)==IAP2_OK&&used==sent.size());
        CHECK(msg.status==200&&msg.cseq==stage&&Bytes(msg.body.data,msg.body.data+msg.body.size)==v.at(stage==1?"m2":"m4"));
        CHECK(c.state==PROJECTION_CONTROL_PAIRING&&c.cipher.state==CONTROL_CIPHER_DORMANT);
        CHECK(feed(tail,used)==RTSP_BUSY&&used==0);
        if(release) CHECK(projection_control_release(&c,key,now)==(stage==1?IAP2_OK:PROJECTION_CONTROL_SECURE));
    }
    void secure() { phase(1);phase(3);CHECK(c.state==PROJECTION_CONTROL_ENCRYPTED&&c.pairing.state==PAIR_VERIFY_DETACHED&&randoms==1&&lookups==1); }
    rtsp_channel_key held(unsigned seq) {
        rtsp_message req{};rtsp_channel_key key{};CHECK(projection_control_request(&c,&req,&key)==RTSP_CHANNEL_REQUEST&&req.cseq==seq);return key;
    }
    Bytes reply(unsigned seq,const Bytes& body={},uint16_t status=501) {
        auto key=held(seq);rtsp_response res={status,{},nullptr,0,{body.data(),body.size()}};
        CHECK(projection_control_respond(&c,key,&res,now)==RTSP_CHANNEL_OUTPUT);auto sent=drain(key,1);
        CHECK(projection_control_release(&c,key,now)==IAP2_OK);return sent;
    }
    void cleared() {
        CHECK(c.state==PROJECTION_CONTROL_DEAD&&zeroed(c.shared_secret,32)&&zeroed(c.controller_id,64)&&c.controller_id_size==0);
        CHECK(zeroed(&c.pairing.keys,sizeof(c.pairing.keys))&&zeroed(c.cipher.read_key,32)&&zeroed(c.cipher.write_key,32));
        CHECK(zeroed(crx.data(),crx.size())&&zeroed(plain.data(),plain.size())&&zeroed(ctx.data(),ctx.size()));
        CHECK(c.rtsp.input.used==0&&c.rtsp.tx_size==0);
    }
};
static void handoff_and_tail(const Vectors& v) {
    auto app=bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n");auto wire=encrypt(v,app,0);Session s(v);
    s.phase(1,{},true);s.phase(3,wire,true);CHECK(equal(s.c.shared_secret,v.at("shared_secret"))&&s.c.controller_id_size==v.at("ctrl_identifier").size());
    CHECK(zeroed(&s.c.pairing.keys,sizeof(s.c.pairing.keys))&&s.c.cipher.read_counter==0&&s.c.cipher.write_counter==0);
    size_t used=0;CHECK(s.feed(wire,used)==RTSP_CHANNEL_REQUEST&&used==wire.size());
    auto out=s.reply(9);uint64_t counter=0;auto decoded=decrypt(v,out,counter);rtsp_message msg{};
    CHECK(rtsp_message_decode(decoded.data(),decoded.size(),&msg,&used)==IAP2_OK&&msg.status==501&&msg.cseq==9&&counter==1);
    CHECK(s.c.cipher.read_counter==1&&s.c.cipher.write_counter==1);
}
static void fragmented_and_coalesced(const Vectors& v) {
    const auto first=bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n"),second=bytes("GET /next RTSP/1.0\r\nCSeq: 10\r\n\r\n");
    auto frame=encrypt(v,first,0);
    for(size_t split=0;split<=frame.size();++split) {
        Session s(v);s.secure();size_t used=0;
        CHECK(projection_control_feed(&s.c,91,frame.data(),split,&used,1)==(split==frame.size()?RTSP_CHANNEL_REQUEST:IAP2_MORE)&&used==split);
        if(split<frame.size()) CHECK(projection_control_feed(&s.c,91,frame.data()+split,frame.size()-split,&used,1)==RTSP_CHANNEL_REQUEST&&used==frame.size()-split);
        s.held(9);
    }
    { Session s(v);s.secure();auto both=first;both.insert(both.end(),second.begin(),second.end());auto wire=encrypt(v,both,0);
      auto last=encrypt(v,first,1);wire.insert(wire.end(),last.begin(),last.end());size_t used=0;
      CHECK(s.feed(wire,used)==RTSP_CHANNEL_REQUEST&&used==both.size()+18&&s.c.cipher.held);auto tail=Bytes(wire.begin()+static_cast<ptrdiff_t>(used),wire.end());
      CHECK(s.feed(tail,used)==RTSP_BUSY&&used==0);Bytes body(500);for(size_t i=0;i<body.size();++i) body[i]=static_cast<uint8_t>(i);
      uint64_t counter=0;auto response=decrypt(v,s.reply(9,body,200),counter);rtsp_message msg{};
      CHECK(counter>1&&rtsp_message_decode(response.data(),response.size(),&msg,&used)==IAP2_OK&&msg.cseq==9&&Bytes(msg.body.data,msg.body.data+msg.body.size)==body);
      CHECK(projection_control_feed(&s.c,91,nullptr,0,&used,1)==RTSP_CHANNEL_REQUEST&&used==0&&!s.c.cipher.held);s.held(10);
      response=decrypt(v,s.reply(10),counter);CHECK(rtsp_message_decode(response.data(),response.size(),&msg,&used)==IAP2_OK&&msg.cseq==10);
      CHECK(s.feed(tail,used)==RTSP_CHANNEL_REQUEST&&used==tail.size());s.held(9); }
    { Session s(v);s.secure();size_t used=0;auto empty=encrypt(v,{},0);
      CHECK(s.feed(empty,used)==IAP2_MORE&&used==18&&!s.c.cipher.held&&s.c.rtsp.input.used==0);
      for(size_t i=0;i<first.size();++i) { auto part=encrypt(v,Bytes{first[i]},i+1);
        CHECK(s.feed(part,used)==(i+1==first.size()?RTSP_CHANNEL_REQUEST:IAP2_MORE)&&used==19); }s.held(9); }
}
static void reject_unverified(const Vectors& v) {
    for(unsigned mode=0;mode<7;++mode) {
        Session s(v);auto body=v.at("m1");auto method=std::string("POST"),path=std::string("/pair-verify"),type=std::string("application/pairing+tlv8");
        if(mode==0) method="GET";if(mode==1) path="/prefix/pair-verify";if(mode==2) path="/pair-setup";
        if(mode==3) type="application/octet-stream";if(mode==4) type+="\r\ncontent-type: application/pairing+tlv8";
        if(mode==5) body=v.at("m3");if(mode==6) s.fail_random=true;
        auto wire=request(body,1,method,path,type);size_t used=0;CHECK(s.feed(wire,used)==PROJECTION_CONTROL_CLOSED&&used==wire.size());
        CHECK(s.randoms==(mode==6?1:0));s.cleared();
    }
    for(int mode=0;mode<2;++mode) {
        Session s(v);s.phase(1);auto b=v.at("m3");if(mode==0) b.back()^=1;else s.unknown=true;
        auto wire=request(b,3);size_t used=0;CHECK(s.feed(wire,used)==PROJECTION_CONTROL_CLOSED);s.cleared();
        rtsp_slice out{};rtsp_channel_key key{};CHECK(projection_control_output(&s.c,91,&out,&key,1)==PROJECTION_CONTROL_CLOSED&&out.data==nullptr&&key.token==0);
    }
    { Session s(v);s.phase(1);s.phase(3,{},false,false);CHECK(s.c.state==PROJECTION_CONTROL_PAIRING&&s.c.pairing.state==PAIR_VERIFY_M4_HELD);
      CHECK(projection_control_check(&s.c,91,5001)==PROJECTION_CONTROL_CLOSED);s.cleared(); }
}
static void lifecycle_and_fail_closed(const Vectors& v) {
    auto app=bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n");auto wire=encrypt(v,app,0);
    { Session s(v);auto old=s.c;auto bad=s.storage;bad.plain_capacity=1;
      CHECK(projection_control_init(&s.c,&s.id,Session::random,&s,Session::lookup,&s,&s.cfg,&bad,92,1)==IAP2_ARGUMENT&&std::memcmp(&old,&s.c,sizeof(old))==0&&s.randoms==0);
      CHECK(s.rx==Bytes(s.rx.size(),0xa5)&&s.crx==Bytes(s.crx.size(),0xa5)); }
    { Session s(v);s.secure();auto old=s.c;size_t used=9;
      CHECK(projection_control_feed(&s.c,92,wire.data(),wire.size(),&used,UINT64_MAX)==IAP2_INVALID&&used==0&&std::memcmp(&old,&s.c,sizeof(old))==0);
      CHECK(projection_control_check(&s.c,91,0)==IAP2_ARGUMENT&&std::memcmp(&old,&s.c,sizeof(old))==0);
      CHECK(s.feed(wire,used)==RTSP_CHANNEL_REQUEST);auto key=s.held(9),stale=key;stale.token++;old=s.c;rtsp_response response={501,{},nullptr,0,{}};
      CHECK(projection_control_respond(&s.c,stale,&response,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&old,&s.c,sizeof(old))==0);
      response.status=100;CHECK(projection_control_respond(&s.c,key,&response,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&old,&s.c,sizeof(old))==0);
      response.status=501;CHECK(projection_control_respond(&s.c,key,&response,1)==RTSP_CHANNEL_OUTPUT);
      rtsp_slice out{};CHECK(projection_control_output(&s.c,91,&out,&key,1)==RTSP_CHANNEL_OUTPUT&&s.c.rtsp.state==RTSP_CHANNEL_SENT&&s.c.cipher.tx_size>0);
      old=s.c;CHECK(projection_control_release(&s.c,key,UINT64_MAX)==RTSP_BUSY&&std::memcmp(&old,&s.c,sizeof(old))==0);
      CHECK(projection_control_consume(&s.c,stale,1,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&old,&s.c,sizeof(old))==0);
      CHECK(projection_control_consume(&s.c,key,out.size+1,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&old,&s.c,sizeof(old))==0);
      s.drain(key);CHECK(projection_control_check(&s.c,91,5000)==IAP2_OK&&projection_control_next_delay(&s.c)==1);
      CHECK(projection_control_release(&s.c,key,5001)==PROJECTION_CONTROL_CLOSED);s.cleared(); }
    for(int mode=0;mode<5;++mode) {
        Session s(v);s.secure();auto input=wire;size_t used=0;
        if(mode==0) input.back()^=1;
        if(mode==1) input=app; // Plaintext cannot resume after M4.
        if(mode==2) input=encrypt(v,bytes("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"),0);
        if(mode==3) input=encrypt(v,bytes("NOT AN RTSP MESSAGE\r\n\r\n"),0);
        if(mode==4) input={129,0}; // Local frame cap is 128.
        CHECK(s.feed(input,used)==PROJECTION_CONTROL_CLOSED);s.cleared();
        projection_control_close(&s.c);CHECK(projection_control_next_delay(&s.c)==UINT32_MAX);
    }
    { Session s(v);s.secure();size_t used=0;CHECK(projection_control_feed(&s.c,91,wire.data(),1,&used,2)==IAP2_MORE);
      CHECK(projection_control_eof(&s.c,91,3)==PROJECTION_CONTROL_CLOSED&&s.c.reason==PROJECTION_CONTROL_REASON_EOF);s.cleared(); }
    { Session s(v);s.secure();size_t used=0;CHECK(s.feed(wire,used)==RTSP_CHANNEL_REQUEST);s.reply(9);
      CHECK(s.feed(wire,used)==PROJECTION_CONTROL_CLOSED);s.cleared(); }
    { Session s(v);s.secure();CHECK(projection_control_check(&s.c,91,30001)==PROJECTION_CONTROL_CLOSED);s.cleared(); }
}
static void absolute_budgets(const Vectors& v) {
    auto app=bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n");auto wire=encrypt(v,app,0);size_t used=0;
    { Session s(v);s.secure();CHECK(projection_control_feed(&s.c,91,wire.data(),1,&used,1)==IAP2_MORE);
      CHECK(projection_control_feed(&s.c,91,wire.data()+1,1,&used,10000)==IAP2_MORE&&projection_control_next_delay(&s.c)==1);
      CHECK(projection_control_check(&s.c,91,10001)==PROJECTION_CONTROL_CLOSED);s.cleared(); }
    { Session s(v);s.secure();auto partial=encrypt(v,Bytes{app[0]},0);CHECK(s.feed(partial,used)==IAP2_MORE);
      partial=encrypt(v,Bytes{app[1]},1);s.now=10000;CHECK(s.feed(partial,used)==IAP2_MORE&&projection_control_next_delay(&s.c)==1);
      CHECK(projection_control_check(&s.c,91,10001)==PROJECTION_CONTROL_CLOSED);s.cleared(); }
    { Session s(v);s.secure();auto twice=app;twice.insert(twice.end(),app.begin(),app.end());auto input=encrypt(v,twice,0);
      CHECK(s.feed(input,used)==RTSP_CHANNEL_REQUEST&&s.c.cipher.held);s.reply(9);s.now=5000;
      CHECK(projection_control_check(&s.c,91,s.now)==IAP2_OK&&projection_control_next_delay(&s.c)==1);
      CHECK(projection_control_check(&s.c,91,5001)==PROJECTION_CONTROL_CLOSED&&s.c.reason==PROJECTION_CONTROL_REASON_CIPHER);s.cleared(); }
    { Session s(v);s.secure();CHECK(s.feed(wire,used)==RTSP_CHANNEL_REQUEST);auto key=s.held(9);Bytes body(500,7);rtsp_response res={200,{},nullptr,0,{body.data(),body.size()}};
      CHECK(projection_control_respond(&s.c,key,&res,1)==RTSP_CHANNEL_OUTPUT);rtsp_slice out{};
      CHECK(projection_control_output(&s.c,91,&out,&key,4999)==RTSP_CHANNEL_OUTPUT);
      CHECK(projection_control_consume(&s.c,key,out.size,4999)==RTSP_CHANNEL_OUTPUT);
      CHECK(projection_control_output(&s.c,91,&out,&key,5000)==RTSP_CHANNEL_OUTPUT&&projection_control_next_delay(&s.c)==1);
      CHECK(projection_control_check(&s.c,91,5001)==PROJECTION_CONTROL_CLOSED);s.cleared(); }
}
int main(int argc,char** argv) { try { CHECK(argc==2);auto v=load_vectors(argv[1],21);handoff_and_tail(v);fragmented_and_coalesced(v);reject_unverified(v);lifecycle_and_fail_closed(v);absolute_budgets(v);
    std::cout<<"PASS: 5 projection-control groups; real pairing/cipher handoff, retained tails, fragmented duplex replies and fail-closed lifecycle\n";
    std::cout<<"x64 projection_control="<<sizeof(projection_control)<<" bytes plus caller buffers and stack temporaries\n";return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; } }
