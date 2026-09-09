/* SPDX-License-Identifier: GPL-3.0-only
 * Real SRP/Ed25519/AEAD, PUBLIC fixtures and synthetic memory-only trust provider.
 */
#include "pair_setup.h"
#include "pair_setup_channel.h"
#include "projection_control.h"
#include "pair_test_support.h"
struct Random {
    Bytes salt,secret;int calls=0,fail_at=0;
    static int read(void* context,uint8_t* out,size_t n) { auto& r=*static_cast<Random*>(context);++r.calls;
        const auto& b=n==16?r.salt:r.secret;CHECK((n==16||n==32)&&b.size()==n);std::copy(b.begin(),b.end(),out);
        return r.calls==r.fail_at?-1:0; }
};
static bool srp_cleared(const pair_srp& s) { return zeroed(s.secret,32)&&zeroed(s.verifier,384)&&zeroed(s.public_key,384)&&zeroed(s.salt,16); }
static void srp_vectors(const Vectors& v) {
    for(const std::string prefix:{"","edge_a_","edge_s_","edge_b_"}) {
        pair_srp s{};pair_srp_init(&s);Random rng{v.at("salt"),v.at(prefix+"b")};std::array<uint8_t,64> key{},proof{};
        CHECK(pair_srp_start(&s,Random::read,&rng)==IAP2_OK&&rng.calls==2&&equal(s.public_key,v.at(prefix+"B"))&&equal(s.salt,v.at("salt")));
        CHECK(pair_srp_verify(&s,v.at(prefix+"A").data(),v.at(prefix+"M1").data(),key.data(),proof.data())==IAP2_OK);
        CHECK(equal(key.data(),v.at(prefix+"K"))&&equal(proof.data(),v.at(prefix+"M2"))&&s.state==PAIR_SRP_DEAD&&srp_cleared(s));
        auto saved=key;CHECK(pair_srp_verify(&s,v.at("A").data(),v.at("M1").data(),key.data(),proof.data())==IAP2_INVALID&&key==saved);
        CHECK(pair_srp_start(&s,Random::read,&rng)==IAP2_INVALID&&rng.calls==2);
    }
    CHECK(v.at("edge_a_A")[0]==0&&v.at("edge_b_B")[0]==0);
}
static void srp_failures(const Vectors& v) {
    auto invalids=std::vector<Bytes>{Bytes(384),Bytes(384),v.at("N"),v.at("N"),v.at("N")};invalids[1].back()=1;invalids[3].back()--; // N-1
    // N+1 with carry, not a truncated all-ones value.
    for(size_t i=384;i-->0;) { if(++invalids[4][i]!=0) break; }
    for(const auto& a:invalids) {
        pair_srp s{};Random rng{v.at("salt"),v.at("b")};CHECK(pair_srp_start(&s,Random::read,&rng)==IAP2_OK);
        std::array<uint8_t,64> k,p;k.fill(0xa5);p.fill(0xa5);
        CHECK(pair_srp_verify(&s,a.data(),v.at("M1").data(),k.data(),p.data())==IAP2_AUTH_FAILED&&zeroed(k.data(),64)&&zeroed(p.data(),64)&&srp_cleared(s));
    }
    for(size_t i=0;i<64;++i) {
        pair_srp s{};Random rng{v.at("salt"),v.at("b")};CHECK(pair_srp_start(&s,Random::read,&rng)==IAP2_OK);auto proof=v.at("M1");proof[i]^=1;
        std::array<uint8_t,64> k{},p{};CHECK(pair_srp_verify(&s,v.at("A").data(),proof.data(),k.data(),p.data())==IAP2_AUTH_FAILED&&srp_cleared(s)&&zeroed(k.data(),64));
    }
    for(int failure=1;failure<=3;++failure) {
        pair_srp s{};Random rng{v.at("salt"),failure==3?Bytes(32):v.at("b"),0,failure};
        CHECK(pair_srp_start(&s,Random::read,&rng)==IAP2_PROVIDER_FAILED&&srp_cleared(s)&&rng.calls==(failure==1?1:2));
    }
    { pair_srp s{};Random rng{v.at("salt"),v.at("b")};auto old=s;
      CHECK(pair_srp_start(&s,nullptr,&rng)==IAP2_ARGUMENT&&std::memcmp(&old,&s,sizeof(s))==0&&rng.calls==0);
      CHECK(pair_srp_start(&s,Random::read,&rng)==IAP2_OK);old=s;std::array<uint8_t,64> k{},p{};
      CHECK(pair_srp_verify(&s,nullptr,v.at("M1").data(),k.data(),p.data())==IAP2_ARGUMENT&&std::memcmp(&old,&s,sizeof(s))==0);
      pair_srp_clear(&s);CHECK(srp_cleared(s));pair_crypto_wipe(&old,sizeof(old)); }
}
struct Session {
    const Vectors& v;pair_identity id{};Random random;pair_setup s{};pair_setup_config cfg{};
    std::map<std::string,Bytes> trust;int commits=0,commit_error=IAP2_OK;uint64_t now=1;
    static int commit(void* context,uint64_t gen,uint64_t authorization,const uint8_t* id,size_t n,const uint8_t pk[32]) {
        auto& s=*static_cast<Session*>(context);++s.commits;CHECK(gen==91&&authorization==77);
        if(s.commit_error!=IAP2_OK) return s.commit_error;
        std::string name(id,id+n);Bytes key(pk,pk+32);auto found=s.trust.find(name);
        if(found!=s.trust.end()&&found->second!=key) return IAP2_INVALID;
        s.trust[name]=key;return IAP2_OK; // Synthetic durable-success attestation; no filesystem.
    }
    static int lookup(void* context,const uint8_t* id,size_t n,uint8_t pk[32]) {
        auto& s=*static_cast<Session*>(context);auto found=s.trust.find(std::string(id,id+n));
        if(found==s.trust.end()) return IAP2_END;CHECK(found->second.size()==32);std::copy(found->second.begin(),found->second.end(),pk);return IAP2_OK;
    }
    explicit Session(const Vectors& vv):v(vv),random{v.at("salt"),v.at("b")} {
        const auto& name=v.at("pv_own_identifier");CHECK(pair_identity_import(&id,v.at("pv_own_seed").data(),v.at("pv_own_public").data(),name.data(),name.size())==IAP2_OK);
        pair_setup_default_config(&cfg);CHECK(pair_setup_init(&s,&id,Random::read,&random,commit,this,&cfg,91,0)==IAP2_OK);
    }
    ~Session() { pair_setup_close(&s);pair_identity_clear(&id); }
    Session(const Session&)=delete;Session& operator=(const Session&)=delete;
    void authorize() { CHECK(pair_setup_authorize(&s,91,77,now)==IAP2_OK); }
    int send(unsigned step) { const auto& b=v.at("setup_"+std::to_string(step));return pair_setup_request(&s,91,b.data(),b.size(),now); }
    Bytes response(uint64_t& token) { const uint8_t* p=nullptr;size_t n=0;CHECK(pair_setup_response(&s,&p,&n,&token)==PAIR_SETUP_RESPONSE);return {p,p+n}; }
    void release(unsigned step) { uint64_t token;CHECK(response(token)==v.at("setup_"+std::to_string(step))&&token==step/2);
        CHECK(pair_setup_release(&s,91,token,now)==(step==6?PAIR_SETUP_COMPLETE:IAP2_OK)); }
    void pending() { authorize();CHECK(send(1)==PAIR_SETUP_RESPONSE);release(2);CHECK(send(3)==PAIR_SETUP_RESPONSE);release(4);CHECK(send(5)==PAIR_SETUP_APPROVAL); }
    void cleared() { CHECK(srp_cleared(s.srp)&&zeroed(s.session_key,64)&&zeroed(s.output,sizeof(s.output))&&zeroed(&s.candidate,sizeof(s.candidate))&&s.identity==nullptr&&s.commit==nullptr); }
};
static void setup_transcript(const Vectors& v) {
    Session s(v);CHECK(s.random.calls==0&&s.commits==0&&s.trust.empty()&&s.s.state==PAIR_SETUP_WAIT_AUTH);
    CHECK(s.send(1)==PAIR_SETUP_BUSY&&s.random.calls==0);s.pending();CHECK(s.random.calls==2&&s.commits==0&&s.trust.empty()&&zeroed(s.s.session_key,64)&&srp_cleared(s.s.srp));
    pair_setup_candidate candidate{};uint64_t token=0;CHECK(pair_setup_pending(&s.s,&candidate,&token)==PAIR_SETUP_APPROVAL&&token==3);
    CHECK(candidate.identifier_size==v.at("pv_ctrl_identifier").size()&&equal(candidate.identifier,v.at("pv_ctrl_identifier"))&&equal(candidate.public_key,v.at("pv_ctrl_public")));
    const uint8_t* p=reinterpret_cast<const uint8_t*>(1);size_t n=99;uint64_t t=55;
    CHECK(pair_setup_response(&s.s,&p,&n,&t)==IAP2_MORE&&p==nullptr&&n==0&&t==0);
    auto old=s.s;CHECK(pair_setup_release(&s.s,91,token,UINT64_MAX)==PAIR_SETUP_BUSY&&std::memcmp(&old,&s.s,sizeof(old))==0);
    CHECK(pair_setup_decide(&s.s,91,token,1,1)==PAIR_SETUP_RESPONSE&&s.commits==1&&s.s.committed&&s.trust.size()==1);
    old=s.s;CHECK(pair_setup_decide(&s.s,91,token,1,UINT64_MAX)==PAIR_SETUP_BUSY&&s.commits==1&&std::memcmp(&old,&s.s,sizeof(old))==0);
    s.release(6);s.cleared();CHECK(s.s.state==PAIR_SETUP_DONE&&s.s.committed&&s.s.reason==PAIR_SETUP_REASON_NONE);
    CHECK(pair_setup_pending(&s.s,&candidate,&token)==PAIR_SETUP_CLOSED&&zeroed(&candidate,sizeof(candidate))&&token==0);
    CHECK(pair_setup_check(&s.s,91,2)==PAIR_SETUP_CLOSED&&pair_setup_next_delay(&s.s)==UINT32_MAX);pair_setup_close(&s.s);CHECK(s.s.state==PAIR_SETUP_DONE&&s.s.committed);
}
static Bytes encode(std::initializer_list<pair_tlv> fields) { Bytes b(1024);size_t n=0;CHECK(pair_tlv_encode(fields.begin(),fields.size(),b.data(),b.size(),&n)==IAP2_OK);b.resize(n);return b; }
static Bytes changed_m5(const Vectors& v,unsigned mode) {
    auto id=v.at("pv_ctrl_identifier"),pk=v.at("pv_ctrl_public");Bytes sig(64,0x55);const uint8_t state=5;
    if(mode==1) pk=Bytes(32);if(mode==2) id=Bytes(65,'A');if(mode==3) id[0]=0;
    auto plain=encode({{1,id.data(),id.size()},{3,pk.data(),pk.size()},{10,sig.data(),sig.size()}});
    if(mode==4) plain.insert(plain.end(),{1,1,'X'});auto nonce=hex("0000000050532d4d73673035");Bytes sealed(plain.size()+16);size_t n=0;
    CHECK(pair_aead_seal(v.at("encrypt_key").data(),nonce.data(),nullptr,0,plain.data(),plain.size(),sealed.data(),sealed.size(),&n)==IAP2_OK);
    return encode({{6,&state,1},{5,sealed.data(),sealed.size()}});
}
static void malformed_and_proofs(const Vectors& v) {
    for(const auto& extra:std::vector<Bytes>{{6,1,1},{255,0},{0,1,0},{19,1,16},{42},{42,4,1}}) {
        Session s(v);s.authorize();auto b=v.at("setup_1");b.insert(b.end(),extra.begin(),extra.end());
        CHECK(pair_setup_request(&s.s,91,b.data(),b.size(),1)==PAIR_SETUP_CLOSED&&s.random.calls==0&&s.commits==0);s.cleared();
    }
    for(size_t n=0;n<v.at("setup_1").size();++n) { Session s(v);s.authorize();
      CHECK(pair_setup_request(&s.s,91,v.at("setup_1").data(),n,1)==PAIR_SETUP_CLOSED&&s.random.calls==0);s.cleared(); }
    { Session s(v);s.authorize();auto b=v.at("setup_1");b.back()=1;
      CHECK(pair_setup_request(&s.s,91,b.data(),b.size(),1)==PAIR_SETUP_CLOSED&&s.s.last_error==IAP2_UNSUPPORTED&&s.random.calls==0); }
    { Session s(v);s.authorize();auto b=v.at("setup_1");b.insert(b.end(),{42,1,9,19,1,0});
      CHECK(pair_setup_request(&s.s,91,b.data(),b.size(),1)==PAIR_SETUP_RESPONSE); }
    for(int mode=0;mode<4;++mode) { Session s(v);s.authorize();CHECK(s.send(1)==PAIR_SETUP_RESPONSE);s.release(2);auto b=v.at("setup_3");
      if(mode==0) b.back()^=1;if(mode==1) b=v.at("setup_1");if(mode==2) b.pop_back();if(mode==3) b.insert(b.end(),{4,1,0});
      CHECK(pair_setup_request(&s.s,91,b.data(),b.size(),1)==PAIR_SETUP_CLOSED&&s.commits==0);s.cleared(); }
    for(unsigned mode=0;mode<6;++mode) {
        Session s(v);s.authorize();CHECK(s.send(1)==PAIR_SETUP_RESPONSE);s.release(2);CHECK(s.send(3)==PAIR_SETUP_RESPONSE);s.release(4);
        auto b=mode==5?v.at("setup_5"):changed_m5(v,mode);if(mode==5) b.back()^=1;
        CHECK(pair_setup_request(&s.s,91,b.data(),b.size(),1)==PAIR_SETUP_CLOSED&&s.commits==0&&!s.s.committed&&s.trust.empty());s.cleared();
    }
}
static void authorization_and_commit(const Vectors& v) {
    for(int mode=0;mode<5;++mode) {
        Session s(v);s.pending();const auto& id=v.at("pv_ctrl_identifier");std::string name(id.begin(),id.end());
        if(mode==1) s.commit_error=IAP2_PROVIDER_FAILED;if(mode==2) s.trust[name]=v.at("pv_own_public");
        if(mode==3) s.trust[name]=v.at("pv_ctrl_public");auto before=s.trust;
        int r=pair_setup_decide(&s.s,91,3,mode!=0,1);
        CHECK(s.commits==(mode==0?0:1));
        if(mode<=2) { CHECK(r==PAIR_SETUP_CLOSED&&!s.s.committed&&s.trust==before);s.cleared(); }
        else { CHECK(r==PAIR_SETUP_RESPONSE&&s.s.committed&&s.trust.at(name)==v.at("pv_ctrl_public"));
            pair_setup_close(&s.s);s.cleared();CHECK(s.s.committed&&s.trust.size()==1); }
    }
    { Session s(v);auto old=s.s;CHECK(pair_setup_authorize(&s.s,92,77,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&old,&s.s,sizeof(old))==0);
      CHECK(pair_setup_authorize(&s.s,91,0,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&old,&s.s,sizeof(old))==0);s.authorize();old=s.s;
      CHECK(pair_setup_authorize(&s.s,91,78,UINT64_MAX)==PAIR_SETUP_BUSY&&std::memcmp(&old,&s.s,sizeof(old))==0); }
    { Session s(v);s.pending();auto old=s.s;
      CHECK(pair_setup_decide(&s.s,92,3,1,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&old,&s.s,sizeof(old))==0);
      CHECK(pair_setup_decide(&s.s,91,2,1,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&old,&s.s,sizeof(old))==0);
      CHECK(pair_setup_decide(&s.s,91,3,2,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&old,&s.s,sizeof(old))==0);
      CHECK(pair_setup_decide(&s.s,91,3,1,0)==IAP2_ARGUMENT&&std::memcmp(&old,&s.s,sizeof(old))==0&&s.commits==0); }
}
static void lifetimes(const Vectors& v) {
    { Session s(v);auto old=s.s;auto cfg=s.cfg;cfg.approval_ms=0;
      CHECK(pair_setup_init(&s.s,&s.id,Random::read,&s.random,Session::commit,&s,&cfg,91,1)==IAP2_ARGUMENT&&std::memcmp(&old,&s.s,sizeof(old))==0);
      CHECK(pair_setup_check(&s.s,91,60000)==PAIR_SETUP_CLOSED&&s.s.reason==PAIR_SETUP_REASON_DEADLINE&&s.random.calls==0);s.cleared(); }
    for(int phase=2;phase<=6;phase+=2) { Session s(v);s.authorize();CHECK(s.send(1)==PAIR_SETUP_RESPONSE);
      if(phase>=4) { s.release(2);CHECK(s.send(3)==PAIR_SETUP_RESPONSE); }
      if(phase==6) { s.release(4);CHECK(s.send(5)==PAIR_SETUP_APPROVAL);CHECK(pair_setup_decide(&s.s,91,3,1,1)==PAIR_SETUP_RESPONSE); }
      CHECK(pair_setup_check(&s.s,91,10000)==IAP2_OK&&pair_setup_next_delay(&s.s)==1);
      CHECK(pair_setup_check(&s.s,91,10001)==PAIR_SETUP_CLOSED&&s.s.reason==PAIR_SETUP_REASON_DEADLINE);s.cleared();CHECK(s.s.committed==(phase==6)); }
    { Session s(v);s.pending();CHECK(pair_setup_check(&s.s,91,30000)==IAP2_OK&&pair_setup_next_delay(&s.s)==1);
      CHECK(pair_setup_decide(&s.s,91,3,1,30001)==PAIR_SETUP_CLOSED&&s.commits==0);s.cleared(); }
    { Session s(v);s.now=59000;s.pending();CHECK(pair_setup_next_delay(&s.s)==1000);
      CHECK(pair_setup_decide(&s.s,91,3,1,60000)==PAIR_SETUP_CLOSED&&s.commits==0);s.cleared(); }
    { Session s(v);s.authorize();s.random.fail_at=2;CHECK(s.send(1)==PAIR_SETUP_CLOSED&&s.s.reason==PAIR_SETUP_REASON_PROVIDER);s.cleared(); }
    { Session s(v);s.pending();CHECK(pair_setup_decide(&s.s,91,3,1,1)==PAIR_SETUP_RESPONSE);auto saved=s.trust;
      pair_setup_close(&s.s);pair_setup_close(&s.s);CHECK(s.trust==saved&&s.s.committed&&s.s.reason==PAIR_SETUP_REASON_LOCAL);s.cleared(); }
}
static Bytes outer(const Bytes& body,unsigned seq) {
    auto b=bytes("POST /pair-verify RTSP/1.0\r\nCSeq: "+std::to_string(seq)+"\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n");
    b.insert(b.end(),body.begin(),body.end());return b;
}
static void newly_enrolled_control(const Vectors& v) {
    Session s(v);std::array<uint8_t,32> pk{};const auto& name=v.at("pv_ctrl_identifier");
    CHECK(Session::lookup(&s,name.data(),name.size(),pk.data())==IAP2_END);s.pending();
    CHECK(Session::lookup(&s,name.data(),name.size(),pk.data())==IAP2_END);
    CHECK(pair_setup_decide(&s.s,91,3,1,1)==PAIR_SETUP_RESPONSE);s.release(6);
    CHECK(Session::lookup(&s,name.data(),name.size(),pk.data())==IAP2_OK&&equal(pk.data(),v.at("pv_ctrl_public")));
    projection_control c{};projection_control_config cfg{};projection_control_default_config(&cfg);cfg.cipher.payload_limit=256;
    Bytes rx(2048),tx(2048),crx(274),plain(256),ctx(274);
    projection_control_storage storage={rx.data(),tx.data(),crx.data(),plain.data(),ctx.data(),rx.size(),tx.size(),crx.size(),plain.size(),ctx.size()};
    Random random{v.at("salt"),v.at("pv_own_ephemeral_secret")};
    CHECK(projection_control_init(&c,&s.id,Random::read,&random,Session::lookup,&s,&cfg,&storage,92,2)==IAP2_OK);
    for(unsigned phase:{1u,3u}) {
        auto b=outer(v.at(phase==1?"pv_m1":"pv_m3"),phase);size_t off=0;int r=IAP2_MORE;
        while(r==IAP2_MORE) { size_t used=0;r=projection_control_feed(&c,92,b.data()+off,std::min(size_t(3),b.size()-off),&used,2);off+=used; }
        CHECK(r==RTSP_CHANNEL_OUTPUT&&off==b.size());rtsp_channel_key key{};rtsp_slice out{};Bytes sent;
        while((r=projection_control_output(&c,92,&out,&key,2))==RTSP_CHANNEL_OUTPUT) {
            auto n=std::min(size_t(2),out.size);sent.insert(sent.end(),out.data,out.data+n);
            auto retired=projection_control_consume(&c,key,n,2);CHECK(retired==RTSP_CHANNEL_OUTPUT||retired==RTSP_CHANNEL_OUTPUT_DONE);
        }
        CHECK(r==RTSP_CHANNEL_OUTPUT_DONE);rtsp_message response{};size_t used=0;
        CHECK(rtsp_message_decode(sent.data(),sent.size(),&response,&used)==IAP2_OK&&response.cseq==phase&&Bytes(response.body.data,response.body.data+response.body.size)==v.at(phase==1?"pv_m2":"pv_m4"));
        CHECK(projection_control_release(&c,key,2)==(phase==1?IAP2_OK:PROJECTION_CONTROL_SECURE));
    }
    const auto request=bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n");Bytes frame(request.size()+18);frame[0]=static_cast<uint8_t>(request.size());std::array<uint8_t,12> nonce{};size_t written=0;
    CHECK(pair_aead_seal(v.at("pv_accessory_read_key").data(),nonce.data(),frame.data(),2,request.data(),request.size(),frame.data()+2,frame.size()-2,&written)==IAP2_OK);
    size_t used=0;CHECK(projection_control_feed(&c,92,frame.data(),frame.size(),&used,2)==RTSP_CHANNEL_REQUEST&&used==frame.size());
    rtsp_message req{};rtsp_channel_key key{};CHECK(projection_control_request(&c,&req,&key)==RTSP_CHANNEL_REQUEST&&req.cseq==9);
    rtsp_response response={501,{},nullptr,0,{}};CHECK(projection_control_respond(&c,key,&response,2)==RTSP_CHANNEL_OUTPUT);
    rtsp_slice out{};CHECK(projection_control_output(&c,92,&out,&key,2)==RTSP_CHANNEL_OUTPUT);Bytes decoded(256);
    CHECK(pair_aead_open(v.at("pv_accessory_write_key").data(),nonce.data(),out.data,2,out.data+2,out.size-2,decoded.data(),decoded.size(),&written)==IAP2_OK);
    CHECK(rtsp_message_decode(decoded.data(),written,&req,&used)==IAP2_OK&&req.status==501&&req.cseq==9);
    CHECK(projection_control_consume(&c,key,out.size,2)==RTSP_CHANNEL_OUTPUT_DONE&&projection_control_release(&c,key,2)==IAP2_OK);
    projection_control_close(&c);CHECK(s.commits==1&&s.trust.size()==1);
}
struct Enrollment {
    Session provider;pair_setup_channel c{};pair_setup_channel_config cfg{};Bytes rx=Bytes(2048),tx=Bytes(2048);uint64_t now=1;
    explicit Enrollment(const Vectors& v):provider(v) {
        pair_setup_channel_default_config(&cfg);
        CHECK(pair_setup_channel_init(&c,&provider.id,Random::read,&provider.random,Session::commit,&provider,Session::lookup,&provider,
            &cfg,rx.data(),rx.size(),tx.data(),tx.size(),91,0)==IAP2_OK);
    }
    ~Enrollment() { pair_setup_channel_close(&c); }
    Enrollment(const Enrollment&)=delete;Enrollment& operator=(const Enrollment&)=delete;
    void authorize() { CHECK(pair_setup_channel_authorize(&c,91,77,now)==IAP2_OK); }
    static Bytes wire(const Bytes& body,unsigned seq) { auto b=outer(body,seq);auto text=std::string(b.begin(),b.end());
        text.replace(text.find("/pair-verify"),12,"/pair-setup");return bytes(text); }
    rtsp_channel_key phase(unsigned step,const Bytes& tail={},bool approve=true,bool release=true) {
        auto b=wire(provider.v.at("setup_"+std::to_string(step)),step);size_t exact=b.size();b.insert(b.end(),tail.begin(),tail.end());size_t offset=0;int r=IAP2_MORE;
        while(r==IAP2_MORE) { size_t used=0;r=pair_setup_channel_feed(&c,91,b.data()+offset,std::min(size_t(7),b.size()-offset),&used,now);offset+=used; }
        CHECK(r==(step==5?PAIR_SETUP_APPROVAL:RTSP_CHANNEL_OUTPUT)&&offset==exact);rtsp_channel_key key{};rtsp_slice out{};
        if(step==5) { pair_setup_candidate candidate{};CHECK(pair_setup_channel_pending(&c,&candidate,&key)==PAIR_SETUP_APPROVAL&&key.token==3);
            CHECK(pair_setup_channel_output(&c,91,&out,&key,now)==PAIR_SETUP_BUSY&&out.data==nullptr); // output lookup zeroes key
            CHECK(pair_setup_channel_pending(&c,&candidate,&key)==PAIR_SETUP_APPROVAL);
            if(!approve) return key;
            CHECK(pair_setup_channel_decide(&c,key,1,now)==RTSP_CHANNEL_OUTPUT&&provider.commits==1);
        }
        Bytes sent;CHECK(pair_setup_channel_output(&c,91,&out,&key,now)==RTSP_CHANNEL_OUTPUT);auto old=c;
        CHECK(pair_setup_channel_release(&c,key,UINT64_MAX)==PAIR_SETUP_BUSY&&std::memcmp(&old,&c,sizeof(old))==0);
        while((r=pair_setup_channel_output(&c,91,&out,&key,now))==RTSP_CHANNEL_OUTPUT) {
            auto n=std::min(size_t(3),out.size);sent.insert(sent.end(),out.data,out.data+n);
            auto retired=pair_setup_channel_consume(&c,key,n,now);CHECK(retired==RTSP_CHANNEL_OUTPUT||retired==RTSP_CHANNEL_OUTPUT_DONE);
        }
        CHECK(r==RTSP_CHANNEL_OUTPUT_DONE);rtsp_message reply{};size_t used=0;
        CHECK(rtsp_message_decode(sent.data(),sent.size(),&reply,&used)==IAP2_OK&&reply.cseq==step&&reply.status==200&&Bytes(reply.body.data,reply.body.data+reply.body.size)==provider.v.at("setup_"+std::to_string(step+1)));
        CHECK(pair_setup_channel_feed(&c,91,tail.data(),tail.size(),&used,now)==PAIR_SETUP_BUSY&&used==0);
        if(release) CHECK(pair_setup_channel_release(&c,key,now)==(step==5?PAIR_SETUP_COMPLETE:IAP2_OK));return key;
    }
};
static void owning_enrollment(const Vectors& v) {
    Enrollment e(v);auto first=Enrollment::wire(v.at("setup_1"),1);size_t used=99;
    CHECK(pair_setup_channel_feed(&e.c,91,first.data(),first.size(),&used,1)==PAIR_SETUP_BUSY&&used==0&&e.provider.random.calls==0);
    e.authorize();e.phase(1);e.phase(3);auto next=outer(v.at("pv_m1"),1);auto final=e.phase(5,next,true,false);
    projection_control control{};projection_control_config cfg{};projection_control_default_config(&cfg);cfg.cipher.payload_limit=256;
    Bytes crx(274),plain(256),ctx(274);projection_control_storage storage={e.rx.data(),e.tx.data(),crx.data(),plain.data(),ctx.data(),e.rx.size(),e.tx.size(),crx.size(),plain.size(),ctx.size()};
    auto old=e.c;
    CHECK(pair_setup_channel_take(&e.c,final,&control,&cfg,&storage,92,UINT64_MAX)==PAIR_SETUP_BUSY&&std::memcmp(&old,&e.c,sizeof(old))==0&&zeroed(&control,sizeof(control)));
    CHECK(pair_setup_channel_release(&e.c,final,1)==PAIR_SETUP_COMPLETE&&e.c.state==PAIR_SETUP_CHANNEL_DRAINED);old=e.c;
    pair_setup_candidate pending{};rtsp_channel_key pending_key{};
    CHECK(pair_setup_channel_pending(&e.c,&pending,&pending_key)==IAP2_MORE&&pending_key.token==0&&zeroed(&pending,sizeof(pending)));
    auto bad=storage;bad.plain_capacity=1;CHECK(pair_setup_channel_take(&e.c,final,&control,&cfg,&bad,92,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&old,&e.c,sizeof(old))==0&&zeroed(&control,sizeof(control)));
    auto wrong=final;wrong.token=2;CHECK(pair_setup_channel_take(&e.c,wrong,&control,&cfg,&storage,92,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&old,&e.c,sizeof(old))==0);
    CHECK(pair_setup_channel_take(&e.c,final,&control,&cfg,&storage,91,2)==IAP2_ARGUMENT&&std::memcmp(&old,&e.c,sizeof(old))==0);
    CHECK(pair_setup_channel_take(&e.c,final,&control,&cfg,&storage,92,2)==IAP2_OK&&e.c.state==PAIR_SETUP_CHANNEL_DETACHED&&control.state==PROJECTION_CONTROL_PAIRING);
    CHECK(pair_setup_channel_next_delay(&e.c)==UINT32_MAX&&e.provider.commits==1);
    CHECK(projection_control_feed(&control,92,next.data(),next.size(),&used,2)==RTSP_CHANNEL_OUTPUT&&used==next.size());
    auto control_saved=control;auto rx_saved=e.rx,tx_saved=e.tx;pair_setup_channel_close(&e.c);
    CHECK(std::memcmp(&control_saved,&control,sizeof(control))==0&&e.rx==rx_saved&&e.tx==tx_saved);
    CHECK(pair_setup_channel_check(&e.c,91,UINT64_MAX)==PAIR_SETUP_CLOSED&&e.rx==rx_saved&&e.tx==tx_saved);
    CHECK(pair_setup_channel_take(&e.c,final,&control,&cfg,&storage,93,3)==PAIR_SETUP_CLOSED&&std::memcmp(&control_saved,&control,sizeof(control))==0);
    for(unsigned phase:{1u,3u}) {
        if(phase==3) { auto m3=outer(v.at("pv_m3"),3);CHECK(projection_control_feed(&control,92,m3.data(),m3.size(),&used,2)==RTSP_CHANNEL_OUTPUT&&used==m3.size()); }
        rtsp_slice out{};rtsp_channel_key key{};Bytes sent;int r;
        while((r=projection_control_output(&control,92,&out,&key,2))==RTSP_CHANNEL_OUTPUT) {
            sent.insert(sent.end(),out.data,out.data+out.size);CHECK(projection_control_consume(&control,key,out.size,2)==RTSP_CHANNEL_OUTPUT_DONE);
        }
        CHECK(r==RTSP_CHANNEL_OUTPUT_DONE);rtsp_message response{};
        CHECK(rtsp_message_decode(sent.data(),sent.size(),&response,&used)==IAP2_OK&&response.cseq==phase&&Bytes(response.body.data,response.body.data+response.body.size)==v.at(phase==1?"pv_m2":"pv_m4"));
        CHECK(projection_control_release(&control,key,2)==(phase==1?IAP2_OK:PROJECTION_CONTROL_SECURE));
    }
    auto app=bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n");Bytes encrypted(app.size()+18);encrypted[0]=static_cast<uint8_t>(app.size());std::array<uint8_t,12> iv{};size_t written=0;
    CHECK(pair_aead_seal(v.at("pv_accessory_read_key").data(),iv.data(),encrypted.data(),2,app.data(),app.size(),encrypted.data()+2,encrypted.size()-2,&written)==IAP2_OK);
    CHECK(projection_control_feed(&control,92,encrypted.data(),encrypted.size(),&used,2)==RTSP_CHANNEL_REQUEST&&used==encrypted.size());
    rtsp_message request{};rtsp_channel_key request_key{};CHECK(projection_control_request(&control,&request,&request_key)==RTSP_CHANNEL_REQUEST&&request.cseq==9);
    projection_control_close(&control);
}
static void owning_failures(const Vectors& v) {
    { Enrollment e(v);e.authorize();auto bad=outer(v.at("setup_1"),1);size_t used=0;
      CHECK(pair_setup_channel_feed(&e.c,91,bad.data(),bad.size(),&used,1)==PAIR_SETUP_CLOSED&&e.c.reason==PAIR_SETUP_CHANNEL_REASON_ROUTE&&e.provider.random.calls==0); }
    for(int mode=0;mode<4;++mode) { Enrollment e(v);e.authorize();e.phase(1);e.phase(3);auto key=e.phase(5,{},false);auto old=e.c;
      auto wrong=key;wrong.generation=92;CHECK(pair_setup_channel_decide(&e.c,wrong,1,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&old,&e.c,sizeof(old))==0&&e.provider.commits==0);
      if(mode==0) CHECK(pair_setup_channel_decide(&e.c,key,0,1)==PAIR_SETUP_CLOSED&&e.provider.commits==0);
      if(mode==1) { e.provider.commit_error=IAP2_PROVIDER_FAILED;CHECK(pair_setup_channel_decide(&e.c,key,1,1)==PAIR_SETUP_CLOSED&&e.provider.commits==1&&!e.c.setup.committed); }
      if(mode==2) CHECK(pair_setup_channel_decide(&e.c,key,1,30001)==PAIR_SETUP_CLOSED&&e.provider.commits==0);
      if(mode==3) CHECK(pair_setup_channel_eof(&e.c,91,2)==PAIR_SETUP_CLOSED&&e.provider.commits==0);
      CHECK(e.c.rtsp.input.used==0&&e.c.rtsp.tx_size==0&&zeroed(e.c.setup.output,sizeof(e.c.setup.output))&&pair_setup_channel_next_delay(&e.c)==UINT32_MAX);
    }
    { Enrollment e(v);e.authorize();e.phase(1);e.phase(3);auto key=e.phase(5,{},true,false);
      CHECK(pair_setup_channel_check(&e.c,91,10000)==IAP2_OK&&pair_setup_channel_next_delay(&e.c)==1);
      CHECK(pair_setup_channel_release(&e.c,key,10001)==PAIR_SETUP_CLOSED&&e.c.setup.committed&&e.provider.trust.size()==1); }
    { Enrollment e(v);auto old=e.c;auto first=Enrollment::wire(v.at("setup_1"),1);size_t used=0;
      CHECK(pair_setup_channel_feed(&e.c,92,first.data(),first.size(),&used,UINT64_MAX)==IAP2_INVALID&&used==0&&std::memcmp(&old,&e.c,sizeof(old))==0);
      e.authorize();CHECK(pair_setup_channel_feed(&e.c,91,first.data(),1,&used,1)==IAP2_MORE);
      CHECK(pair_setup_channel_check(&e.c,91,10001)==PAIR_SETUP_CLOSED&&e.provider.random.calls==0); }
}
int main(int argc,char** argv) { try { CHECK(argc==2);auto v=load_vectors(argv[1],51);srp_vectors(v);srp_failures(v);setup_transcript(v);malformed_and_proofs(v);authorization_and_commit(v);lifetimes(v);newly_enrolled_control(v);owning_enrollment(v);owning_failures(v);
    std::cout<<"PASS: 9 SRP/setup groups; independent transcripts, approval/commit/drain gates, RTSP enrollment ownership and encrypted control\n";
    std::cout<<"x64 bytes: SRP="<<sizeof(pair_srp)<<" setup="<<sizeof(pair_setup)<<" candidate="<<sizeof(pair_setup_candidate)<<" channel="<<sizeof(pair_setup_channel)<<"; MPI heap/stack additional\n";return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; } }
