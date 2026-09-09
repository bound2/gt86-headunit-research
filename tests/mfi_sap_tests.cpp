/* SPDX-License-Identifier: GPL-3.0-only
 * Real crypto/control; PUBLIC deterministic keys and synthetic chip provider.
 */
#include "mfi_sap.h"
#include "projection_auth.h"
#include "pair_setup_channel.h"
#include "pair_store.h"
#include "monocypher-ed25519.h"
#include "pair_test_support.h"
template<class T> static auto snapshot(const T& s) { std::array<uint8_t,sizeof(T)> b{};std::memcpy(b.data(),&s,sizeof(T));return b; }
struct Random {
    const Vectors& v;bool pairing_first=false;unsigned calls=0,fail_at=0;
    static int read(void* p,uint8_t* out,size_t n) { auto& r=*static_cast<Random*>(p);CHECK(n==32);++r.calls;
        const auto& key=r.v.at(r.pairing_first&&r.calls==1?"pv_own_ephemeral_secret":"own_secret");std::copy(key.begin(),key.end(),out);return r.calls==r.fail_at?-1:0; }
};
struct Signer {
    const Vectors& v;uint8_t major=3;unsigned identities=0,signatures=0;int identity_error=0,sign_error=0;uint64_t generation=91;
    Bytes cert,sig,digest;size_t report_cert=SIZE_MAX,report_sig=SIZE_MAX;
    explicit Signer(const Vectors& vv,uint8_t m=3):v(vv),major(m),cert(v.at("certificate")),sig(v.at(m==2?"signature2":"signature3")) {}
    static int identity(void* p,uint64_t gen,uint8_t* out,size_t cap,size_t* n,uint8_t* major) { auto& s=*static_cast<Signer*>(p);CHECK(gen==s.generation&&cap==MFI_SAP_CERT_MAX);++s.identities;
        std::copy_n(s.cert.data(),std::min(cap,s.cert.size()),out);*n=s.report_cert==SIZE_MAX?s.cert.size():s.report_cert;*major=s.major;return s.identity_error; }
    static int sign(void* p,uint64_t gen,const uint8_t* digest,size_t n,uint8_t* out,size_t cap,size_t* written) { auto& s=*static_cast<Signer*>(p);CHECK(gen==s.generation&&cap==MFI_SAP_SIGNATURE_MAX);++s.signatures;
        s.digest.assign(digest,digest+n);CHECK(s.digest==s.v.at(s.major==2?"digest2":"digest3"));
        std::copy_n(s.sig.data(),std::min(cap,s.sig.size()),out);*written=s.report_sig==SIZE_MAX?s.sig.size():s.report_sig;return s.sign_error; }
    mfi_sap_provider provider() { return {this,identity,sign}; }
};
struct Sap {
    mfi_sap s{};Random rng;Signer signer;
    explicit Sap(const Vectors& v,uint8_t major=3,uint32_t hold=5000):rng{v},signer(v,major) { auto p=signer.provider();CHECK(mfi_sap_init(&s,Random::read,&rng,&p,hold,91,0)==IAP2_OK); }
    ~Sap() { mfi_sap_close(&s); }Sap(const Sap&)=delete;Sap& operator=(const Sap&)=delete;
    int request(const Bytes& b,uint64_t now=1) { return mfi_sap_request(&s,91,b.data(),b.size(),now); }
    Bytes response() { const uint8_t* p=nullptr;size_t n=0;CHECK(mfi_sap_response(&s,&p,&n)==MFI_SAP_RESPONSE);return {p,p+n}; }
    void cleared() { CHECK(zeroed(s.output,sizeof(s.output))&&s.output_size==0&&s.random==nullptr&&zeroed(&s.provider,sizeof(s.provider))); }
};
static void transcripts(const Vectors& v) {
    for(uint8_t major:{2,3}) { Sap s(v,major);CHECK(s.rng.calls==0&&s.signer.identities==0);CHECK(s.request(v.at("request"))==MFI_SAP_RESPONSE);
        CHECK(s.response()==v.at(major==2?"response2":"response3")&&s.signer.identities==1&&s.signer.signatures==1&&s.rng.calls==1&&s.s.protocol_major==major);
        CHECK(s.s.random==nullptr&&zeroed(&s.s.provider,sizeof(s.s.provider)));auto old=snapshot(s.s);
        CHECK(s.request(v.at("request"),UINT64_MAX)==IAP2_INVALID&&snapshot(s.s)==old&&s.signer.signatures==1);
        CHECK(mfi_sap_release(&s.s,92,UINT64_MAX)==IAP2_INVALID&&snapshot(s.s)==old);
        CHECK(mfi_sap_release(&s.s,91,1)==MFI_SAP_DRAINED&&s.s.state==MFI_SAP_DONE);s.cleared();
        CHECK(mfi_sap_release(&s.s,91,2)==MFI_SAP_CLOSED&&s.request(v.at("request"))==MFI_SAP_CLOSED&&mfi_sap_next_delay(&s.s)==UINT32_MAX);
    }
    for(size_t length:{size_t(1),size_t(15),size_t(16),size_t(17),size_t(511),size_t(512)}) { Sap s(v);s.signer.sig=Bytes(v.at("long_signature").begin(),v.at("long_signature").begin()+length);
        CHECK(s.request(v.at("request"))==MFI_SAP_RESPONSE);auto b=s.response();auto offset=40+s.signer.cert.size();
        CHECK(b.size()==offset+length&&std::equal(b.begin()+offset,b.end(),v.at("encrypted_long_signature").begin()));
    }
    { Sap s(v);s.signer.cert.resize(4096);for(size_t i=0;i<4096;++i) s.signer.cert[i]=static_cast<uint8_t>(i*3+1);s.signer.sig=v.at("long_signature");
      CHECK(s.request(v.at("request"))==MFI_SAP_RESPONSE);auto b=s.response();uint8_t hash[64]{};crypto_sha512(hash,b.data(),b.size());
      CHECK(b.size()==MFI_SAP_REPLY_MAX&&equal(hash,v.at("max_response_sha512"))); }
}
static void invalid_and_providers(const Vectors& v) {
    for(size_t n=0;n<33;++n) { Sap s(v);CHECK(mfi_sap_request(&s.s,91,v.at("request").data(),n,1)==MFI_SAP_CLOSED&&s.rng.calls==0&&s.signer.identities==0);s.cleared(); }
    for(unsigned mode=0;mode<4;++mode) { Sap s(v);auto b=v.at("request");if(mode==0) b.push_back(0);if(mode==1) b[0]=2;
        if(mode>=2) { std::fill(b.begin()+1,b.end(),0);if(mode==3) b[1]=1; }
        CHECK(s.request(b)==MFI_SAP_CLOSED&&s.rng.calls==(mode>=2?1u:0u)&&s.signer.identities==0&&s.signer.signatures==0);s.cleared(); }
    { Sap s(v);s.rng.fail_at=1;CHECK(s.request(v.at("request"))==MFI_SAP_CLOSED&&s.s.reason==MFI_SAP_REASON_CRYPTO&&s.s.last_error==IAP2_PROVIDER_FAILED&&s.signer.identities==0);s.cleared(); }
    for(unsigned mode=0;mode<9;++mode) { Sap s(v);
        if(mode==0) s.signer.identity_error=-55;if(mode==1) s.signer.report_cert=0;if(mode==2) s.signer.report_cert=4097;
        if(mode==3) s.signer.major=0;if(mode==4) s.signer.major=1;if(mode==5) s.signer.major=4;
        if(mode==6) s.signer.sign_error=-56;if(mode==7) s.signer.report_sig=0;if(mode==8) s.signer.report_sig=513;
        CHECK(s.request(v.at("request"))==MFI_SAP_CLOSED&&s.s.reason==MFI_SAP_REASON_PROVIDER&&s.signer.identities==1&&s.signer.signatures==(mode>=6?1u:0u));s.cleared();
        if(mode==0) CHECK(s.s.last_error==-55);if(mode==6) CHECK(s.s.last_error==-56);
        CHECK(s.request(v.at("request"))==MFI_SAP_CLOSED&&s.signer.identities==1);
    }
}
static void lifetimes(const Vectors& v) {
    { Sap s(v);auto old=snapshot(s.s);auto provider=s.signer.provider();
      CHECK(mfi_sap_init(&s.s,Random::read,&s.rng,&provider,0,91,0)==IAP2_ARGUMENT&&snapshot(s.s)==old);
      CHECK(mfi_sap_init(&s.s,Random::read,&s.rng,&provider,60001,91,0)==IAP2_ARGUMENT&&snapshot(s.s)==old);
      provider.sign=nullptr;CHECK(mfi_sap_init(&s.s,Random::read,&s.rng,&provider,5000,91,0)==IAP2_ARGUMENT&&snapshot(s.s)==old);
      CHECK(mfi_sap_request(&s.s,92,v.at("request").data(),33,UINT64_MAX)==IAP2_INVALID&&snapshot(s.s)==old);
      CHECK(mfi_sap_request(&s.s,91,nullptr,33,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(s.s)==old&&s.rng.calls==0);
      CHECK(s.request(v.at("request"),1)==MFI_SAP_RESPONSE);old=snapshot(s.s);
      CHECK(mfi_sap_check(&s.s,91,0)==IAP2_ARGUMENT&&snapshot(s.s)==old);
      CHECK(mfi_sap_check(&s.s,91,5000)==IAP2_OK&&mfi_sap_next_delay(&s.s)==1);
      CHECK(mfi_sap_release(&s.s,91,5001)==MFI_SAP_CLOSED&&s.s.reason==MFI_SAP_REASON_DEADLINE);s.cleared(); }
    { Sap s(v);CHECK(s.request(v.at("request"),UINT64_MAX-2)==MFI_SAP_RESPONSE);CHECK(mfi_sap_release(&s.s,91,UINT64_MAX)==MFI_SAP_DRAINED);s.cleared(); }
}
static Bytes outer(const Bytes& body,unsigned seq,const std::string& route,const std::string& method="POST",const std::string& type="application/octet-stream") {
    auto b=bytes(method+" "+route+" RTSP/1.0\r\nCSeq: "+std::to_string(seq)+"\r\nContent-Type: "+type+"\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n");b.insert(b.end(),body.begin(),body.end());return b;
}
static std::array<uint8_t,12> nonce(uint64_t counter) { std::array<uint8_t,12> n{};for(size_t i=0;i<8;++i) n[4+i]=static_cast<uint8_t>(counter>>(8*i));return n; }
struct Receiver {
    const Vectors& v;pair_identity identity{};projection_auth s{};projection_auth_config cfg{};Random rng;Signer signer;bool known=true;
    Bytes rx=Bytes(8192),tx=Bytes(8192),crx=Bytes(274),plain=Bytes(256),ctx=Bytes(274);uint64_t incoming=0,outgoing=0;
    static int lookup(void* p,const uint8_t* id,size_t n,uint8_t* key) { auto& r=*static_cast<Receiver*>(p);if(!r.known||Bytes(id,id+n)!=r.v.at("pv_ctrl_identifier")) return IAP2_END;
        std::copy(r.v.at("pv_ctrl_public").begin(),r.v.at("pv_ctrl_public").end(),key);return IAP2_OK; }
    projection_control_storage storage() { return {rx.data(),tx.data(),crx.data(),plain.data(),ctx.data(),rx.size(),tx.size(),crx.size(),plain.size(),ctx.size()}; }
    explicit Receiver(const Vectors& vv,uint8_t major=3,uint32_t hold=5000):v(vv),rng{v,true},signer(v,major) {
        const auto& id=v.at("pv_own_identifier");CHECK(pair_identity_import(&identity,v.at("pv_own_seed").data(),v.at("pv_own_public").data(),id.data(),id.size())==IAP2_OK);
        projection_auth_default_config(&cfg);cfg.auth_hold_ms=hold;cfg.control.cipher.payload_limit=256;auto st=storage();auto provider=signer.provider();
        CHECK(projection_auth_init(&s,&identity,Random::read,&rng,lookup,this,&provider,&cfg,&st,91,0)==IAP2_OK);
    }
    ~Receiver() { projection_auth_close(&s);pair_identity_clear(&identity); }Receiver(const Receiver&)=delete;Receiver& operator=(const Receiver&)=delete;
    Bytes frame(const Bytes& p) { CHECK(p.size()<=256);Bytes b(p.size()+18);b[0]=static_cast<uint8_t>(p.size());b[1]=static_cast<uint8_t>(p.size()>>8);auto nn=nonce(incoming++);size_t n=0;
        CHECK(pair_aead_seal(v.at("pv_accessory_read_key").data(),nn.data(),b.data(),2,p.data(),p.size(),b.data()+2,b.size()-2,&n)==IAP2_OK);return b; }
    int feed(const Bytes& b,size_t* consumed=nullptr,uint64_t now=1) { size_t n=0;int r=projection_auth_feed(&s,91,b.data(),b.size(),&n,now);if(consumed) *consumed=n;else CHECK(n==b.size());return r; }
    Bytes drain(bool encrypted,int expected,bool release=true) {
        rtsp_slice out{};rtsp_channel_key key{};Bytes wire;int r;CHECK(projection_auth_output(&s,91,&out,&key,1)==RTSP_CHANNEL_OUTPUT);auto old=snapshot(s);
        CHECK(projection_auth_release(&s,key,UINT64_MAX)==RTSP_BUSY&&snapshot(s)==old);
        while((r=projection_auth_output(&s,91,&out,&key,1))==RTSP_CHANNEL_OUTPUT) {
            size_t n=std::min(size_t(3),out.size);wire.insert(wire.end(),out.data,out.data+n);
            int consumed=projection_auth_consume(&s,key,n,1);CHECK(consumed==RTSP_CHANNEL_OUTPUT||consumed==RTSP_CHANNEL_OUTPUT_DONE);
        }
        CHECK(r==RTSP_CHANNEL_OUTPUT_DONE);Bytes message;
        if(encrypted) { for(size_t offset=0;offset<wire.size();) {
            CHECK(wire.size()-offset>=18);size_t n=wire[offset]+(size_t(wire[offset+1])<<8);CHECK(n<=256&&wire.size()-offset>=n+18);Bytes p(n);size_t written=0;auto nn=nonce(outgoing++);
            CHECK(pair_aead_open(v.at("pv_accessory_write_key").data(),nn.data(),wire.data()+offset,2,wire.data()+offset+2,n+16,p.data(),p.size(),&written)==IAP2_OK&&written==n);
            message.insert(message.end(),p.begin(),p.end());offset+=n+18;
        } } else message=wire;
        if(release) CHECK(projection_auth_release(&s,key,1)==expected);return message;
    }
    void pair() { for(unsigned step:{1u,3u}) {
        auto b=outer(v.at("pv_m"+std::to_string(step)),step,"/pair-verify","POST","application/pairing+tlv8");size_t offset=0;int r=IAP2_MORE;
        while(r==IAP2_MORE) { size_t n=0;r=projection_auth_feed(&s,91,b.data()+offset,std::min(size_t(7),b.size()-offset),&n,1);offset+=n; }
        CHECK(r==RTSP_CHANNEL_OUTPUT&&offset==b.size());auto sent=drain(false,step==1?IAP2_OK:PROJECTION_CONTROL_SECURE);rtsp_message msg{};size_t n=0;
        CHECK(rtsp_message_decode(sent.data(),sent.size(),&msg,&n)==IAP2_OK&&Bytes(msg.body.data,msg.body.data+msg.body.size)==v.at("pv_m"+std::to_string(step+1)));
      }CHECK(rng.calls==1&&signer.identities==0&&s.control.state==PROJECTION_CONTROL_ENCRYPTED); }
    void cleared() { CHECK(s.state==PROJECTION_AUTH_DEAD&&s.control.state==PROJECTION_CONTROL_DEAD&&zeroed(s.control.cipher.read_key,32)&&zeroed(s.control.shared_secret,32));
        CHECK(zeroed(s.auth.output,sizeof(s.auth.output))&&zeroed(rx.data(),rx.size())&&zeroed(tx.data(),tx.size())&&zeroed(crx.data(),crx.size())&&zeroed(ctx.data(),ctx.size())); }
};
static void owned_transcript(const Vectors& v) {
    for(uint8_t major:{2,3}) { Receiver r(v,major);r.pair();auto wire=outer(v.at("request"),7,"/auth-setup");auto tail=bytes("GET /info RTSP/1.0\r\nCSeq: 8\r\n\r\n");wire.insert(wire.end(),tail.begin(),tail.end());
        auto encrypted=r.frame(wire);
        for(size_t offset=0;offset<encrypted.size();++offset) { size_t used=0;int status=projection_auth_feed(&r.s,91,encrypted.data()+offset,1,&used,1);
            CHECK(used==1&&status==(offset+1==encrypted.size()?RTSP_CHANNEL_OUTPUT:IAP2_MORE));if(offset+1<encrypted.size()) CHECK(r.signer.identities==0); }
        CHECK(r.signer.identities==1&&r.signer.signatures==1&&r.rng.calls==2&&r.s.internal_reply);
        rtsp_message req{};rtsp_channel_key key{};CHECK(projection_auth_request(&r.s,&req,&key)==IAP2_MORE&&key.token==0);
        auto auth_key=r.s.control.key;auto old=snapshot(r.s);rtsp_response fake={501,{},nullptr,0,{}};
        CHECK(projection_auth_respond(&r.s,auth_key,&fake,UINT64_MAX)==RTSP_BUSY&&snapshot(r.s)==old);
        auto sent=r.drain(true,MFI_SAP_DRAINED);size_t n=0;
        CHECK(rtsp_message_decode(sent.data(),sent.size(),&req,&n)==IAP2_OK&&req.cseq==7&&req.status==200&&Bytes(req.body.data,req.body.data+req.body.size)==v.at(major==2?"response2":"response3"));
        CHECK(r.s.auth.state==MFI_SAP_DONE&&!r.s.internal_reply&&zeroed(r.s.auth.output,sizeof(r.s.auth.output)));
        old=snapshot(r.s);CHECK(projection_auth_release(&r.s,auth_key,UINT64_MAX)==IAP2_INVALID&&snapshot(r.s)==old);
        n=999;CHECK(projection_auth_feed(&r.s,91,nullptr,0,&n,1)==RTSP_CHANNEL_REQUEST&&n==0);
        CHECK(projection_auth_request(&r.s,&req,&key)==RTSP_CHANNEL_REQUEST&&req.cseq==8);CHECK(projection_auth_respond(&r.s,key,&fake,1)==RTSP_CHANNEL_OUTPUT);
        sent=r.drain(true,IAP2_OK);CHECK(rtsp_message_decode(sent.data(),sent.size(),&req,&n)==IAP2_OK&&req.status==501&&req.cseq==8&&r.signer.signatures==1);
        CHECK(r.feed(r.frame(outer(v.at("request"),9,"/auth-setup")))==PROJECTION_AUTH_CLOSED&&r.signer.signatures==1&&r.rng.calls==2);r.cleared();
    }
    { Receiver r(v);r.pair();r.signer.cert.resize(4096);for(size_t i=0;i<4096;++i) r.signer.cert[i]=static_cast<uint8_t>(i*3+1);r.signer.sig=v.at("long_signature");
      CHECK(r.feed(r.frame(outer(v.at("request"),7,"/auth-setup")))==RTSP_CHANNEL_OUTPUT);auto sent=r.drain(true,MFI_SAP_DRAINED);rtsp_message msg{};size_t used=0;uint8_t hash[64]{};
      CHECK(rtsp_message_decode(sent.data(),sent.size(),&msg,&used)==IAP2_OK&&r.outgoing>16);crypto_sha512(hash,msg.body.data,msg.body.size);CHECK(equal(hash,v.at("max_response_sha512"))); }
}
static void owned_failures(const Vectors& v) {
    { Receiver r(v);CHECK(r.feed(outer(v.at("request"),7,"/auth-setup"))==PROJECTION_AUTH_CLOSED&&r.signer.identities==0&&r.rng.calls==0);r.cleared(); }
    { Receiver r(v);r.known=false;CHECK(r.feed(outer(v.at("pv_m1"),1,"/pair-verify","POST","application/pairing+tlv8"))==RTSP_CHANNEL_OUTPUT);r.drain(false,IAP2_OK);
      CHECK(r.feed(outer(v.at("pv_m3"),3,"/pair-verify","POST","application/pairing+tlv8"))==PROJECTION_AUTH_CLOSED&&r.signer.identities==0&&r.rng.calls==1);r.cleared(); }
    for(unsigned mode=0;mode<8;++mode) { Receiver r(v);r.pair();auto body=v.at("request");std::string method="POST",type="application/octet-stream";
        if(mode==0) method="GET";if(mode==1) type="application/pairing+tlv8";if(mode==2) type+="\r\nContent-Type: application/octet-stream";
        if(mode==3) body[0]=2;if(mode==4) r.signer.identity_error=-55;if(mode==5) r.signer.sign_error=-56;if(mode==6) r.signer.major=4;
        auto frame=r.frame(outer(body,7,"/auth-setup",method,type));if(mode==7) frame.back()^=1;
        CHECK(r.feed(frame)==PROJECTION_AUTH_CLOSED);r.cleared();CHECK(r.signer.signatures==(mode==5?1u:0u));if(mode<4||mode==7) CHECK(r.signer.identities==0);
    }
    { Receiver r(v);r.pair();auto old=snapshot(r.s);auto wire=r.frame(outer(v.at("request"),7,"/auth-setup"));size_t n=99;
      CHECK(projection_auth_feed(&r.s,92,wire.data(),wire.size(),&n,UINT64_MAX)==IAP2_INVALID&&n==0&&snapshot(r.s)==old);
      CHECK(projection_auth_feed(&r.s,91,wire.data(),wire.size(),&n,0)==IAP2_ARGUMENT&&n==0&&snapshot(r.s)==old&&r.signer.identities==0);
      CHECK(r.feed(wire)==RTSP_CHANNEL_OUTPUT);old=snapshot(r.s);auto wrong=r.s.control.key;++wrong.token;
      CHECK(projection_auth_consume(&r.s,wrong,1,UINT64_MAX)==IAP2_INVALID&&snapshot(r.s)==old);
      CHECK(projection_auth_consume(&r.s,r.s.control.key,1,UINT64_MAX)==RTSP_BUSY&&snapshot(r.s)==old); // No cipher frame queued yet.
      rtsp_slice out{};rtsp_channel_key key{};CHECK(projection_auth_output(&r.s,91,&out,&key,1)==RTSP_CHANNEL_OUTPUT);old=snapshot(r.s);
      CHECK(projection_auth_consume(&r.s,key,out.size+1,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(r.s)==old);
      CHECK(projection_auth_eof(&r.s,91,1)==PROJECTION_AUTH_CLOSED&&r.signer.signatures==1);r.cleared(); }
    { Receiver r(v,3,2);r.pair();CHECK(r.feed(r.frame(outer(v.at("request"),7,"/auth-setup")))==RTSP_CHANNEL_OUTPUT);
      CHECK(projection_auth_check(&r.s,91,2)==IAP2_OK&&projection_auth_next_delay(&r.s)==1);
      rtsp_slice out{};rtsp_channel_key key{};CHECK(projection_auth_output(&r.s,91,&out,&key,3)==PROJECTION_AUTH_CLOSED&&out.data==nullptr&&key.token==0&&r.s.auth.reason==MFI_SAP_REASON_DEADLINE);r.cleared(); }
    { Receiver r(v,3,2);r.pair();CHECK(r.feed(r.frame(outer(v.at("request"),7,"/auth-setup")))==RTSP_CHANNEL_OUTPUT);r.drain(true,MFI_SAP_DRAINED,false);
      auto key=r.s.control.key;CHECK(projection_auth_release(&r.s,key,3)==PROJECTION_AUTH_CLOSED&&r.s.auth.state==MFI_SAP_DEAD);r.cleared(); }
}
static void explicit_application(const Vectors& v) {
    Receiver r(v);auto old=snapshot(r.s);auto cfg=r.cfg;auto st=r.storage();auto provider=r.signer.provider();st.response_capacity=MFI_SAP_REPLY_MAX;
    CHECK(projection_auth_init(&r.s,&r.identity,Random::read,&r.rng,Receiver::lookup,&r,&provider,&cfg,&st,91,0)==IAP2_ARGUMENT&&snapshot(r.s)==old&&r.rng.calls==0);
    st=r.storage();cfg.auth_hold_ms=0;CHECK(projection_auth_init(&r.s,&r.identity,Random::read,&r.rng,Receiver::lookup,&r,&provider,&cfg,&st,91,0)==IAP2_ARGUMENT&&snapshot(r.s)==old);
    r.pair();CHECK(r.feed(r.frame(bytes("GET /info RTSP/1.0\r\nCSeq: 7\r\n\r\n")))==RTSP_CHANNEL_REQUEST&&r.signer.identities==0&&r.s.auth.state==MFI_SAP_WAIT);
    rtsp_message req{};rtsp_channel_key key{};CHECK(projection_auth_request(&r.s,&req,&key)==RTSP_CHANNEL_REQUEST&&req.cseq==7);
    rtsp_response response={501,{},nullptr,0,{}};CHECK(projection_auth_respond(&r.s,key,&response,1)==RTSP_CHANNEL_OUTPUT);auto out=r.drain(true,IAP2_OK);size_t n=0;
    CHECK(rtsp_message_decode(out.data(),out.size(),&req,&n)==IAP2_OK&&req.status==501&&r.signer.identities==0&&r.s.auth.state==MFI_SAP_WAIT);
}
struct EnrollmentProvider {
    const Vectors& setup;const Vectors& mfi;pair_store_data store{};unsigned random_calls=0,commits=0;
    EnrollmentProvider(const Vectors& a,const Vectors& b):setup(a),mfi(b) { const auto& id=mfi.at("pv_own_identifier");
        CHECK(pair_store_init(&store,mfi.at("pv_own_seed").data(),mfi.at("pv_own_public").data(),id.data(),id.size())==IAP2_OK); }
    ~EnrollmentProvider() { pair_store_clear(&store); }
    static int random(void* p,uint8_t* out,size_t n) { auto& s=*static_cast<EnrollmentProvider*>(p);++s.random_calls;CHECK(s.random_calls<=4);
        const auto& b=s.random_calls==1?s.setup.at("salt"):(s.random_calls==2?s.setup.at("b"):(s.random_calls==3?s.mfi.at("pv_own_ephemeral_secret"):s.mfi.at("own_secret")));
        CHECK(b.size()==n);std::copy(b.begin(),b.end(),out);return 0; }
    static int commit(void* p,uint64_t gen,uint64_t authority,const uint8_t* id,size_t n,const uint8_t* key) { auto& s=*static_cast<EnrollmentProvider*>(p);CHECK(gen==91&&authority==77);++s.commits;
        int r=pair_store_add(&s.store,id,n,key);return r==IAP2_END?IAP2_OK:r; /* Memory-only durable-provider simulation. */ }
    static int lookup(void* p,const uint8_t* id,size_t n,uint8_t* key) { return pair_store_lookup(&static_cast<EnrollmentProvider*>(p)->store,id,n,key); }
};
static void enrollment_handoff(const Vectors& v,const Vectors& setup_v) {
    EnrollmentProvider provider(setup_v,v);Signer signer(v);signer.generation=92;auto mfi=signer.provider();Bytes rx(8192),tx(8192),crx(274),plain(256),ctx(274);
    pair_setup_channel setup{};pair_setup_channel_config cfg{};pair_setup_channel_default_config(&cfg);
    CHECK(pair_setup_channel_init(&setup,&provider.store.identity,EnrollmentProvider::random,&provider,EnrollmentProvider::commit,&provider,EnrollmentProvider::lookup,&provider,
        &cfg,rx.data(),rx.size(),tx.data(),tx.size(),91,0)==IAP2_OK&&pair_setup_channel_authorize(&setup,91,77,1)==IAP2_OK);
    projection_auth receiver{};pair_crypto_wipe(&receiver,sizeof(receiver));projection_auth_config acfg{};projection_auth_default_config(&acfg);acfg.control.cipher.payload_limit=256;
    projection_control_storage storage={rx.data(),tx.data(),crx.data(),plain.data(),ctx.data(),rx.size(),tx.size(),crx.size(),plain.size(),ctx.size()};
    const auto next=outer(v.at("pv_m1"),1,"/pair-verify","POST","application/pairing+tlv8");rtsp_channel_key final{};
    for(unsigned step:{1u,3u,5u}) {
        auto wire=outer(setup_v.at("setup_"+std::to_string(step)),step,"/pair-setup","POST","application/pairing+tlv8");size_t exact=wire.size();if(step==5) wire.insert(wire.end(),next.begin(),next.end());size_t used=0;
        CHECK(pair_setup_channel_feed(&setup,91,wire.data(),wire.size(),&used,1)==(step==5?PAIR_SETUP_APPROVAL:RTSP_CHANNEL_OUTPUT)&&used==exact);
        if(step==5) { pair_setup_candidate candidate{};CHECK(pair_setup_channel_pending(&setup,&candidate,&final)==PAIR_SETUP_APPROVAL&&provider.commits==0);
            CHECK(pair_setup_channel_decide(&setup,final,1,1)==RTSP_CHANNEL_OUTPUT&&provider.commits==1); }
        rtsp_slice output{};rtsp_channel_key key{};Bytes sent;int r;
        while((r=pair_setup_channel_output(&setup,91,&output,&key,1))==RTSP_CHANNEL_OUTPUT) { sent.insert(sent.end(),output.data,output.data+output.size);
            CHECK(pair_setup_channel_consume(&setup,key,output.size,1)==RTSP_CHANNEL_OUTPUT_DONE); }
        CHECK(r==RTSP_CHANNEL_OUTPUT_DONE);rtsp_message reply{};
        CHECK(rtsp_message_decode(sent.data(),sent.size(),&reply,&used)==IAP2_OK&&Bytes(reply.body.data,reply.body.data+reply.body.size)==setup_v.at("setup_"+std::to_string(step+1)));
        if(step==5) { auto saved=snapshot(setup);CHECK(pair_setup_channel_take_auth(&setup,final,&receiver,&acfg,&storage,&mfi,92,UINT64_MAX)==PAIR_SETUP_BUSY&&snapshot(setup)==saved&&zeroed(&receiver,sizeof(receiver))); }
        CHECK(pair_setup_channel_release(&setup,key,1)==(step==5?PAIR_SETUP_COMPLETE:IAP2_OK));
    }
    auto saved=snapshot(setup);auto bad=storage;bad.response_capacity=100;
    CHECK(pair_setup_channel_take_auth(&setup,final,&receiver,&acfg,&bad,&mfi,92,UINT64_MAX)==IAP2_ARGUMENT&&snapshot(setup)==saved&&zeroed(&receiver,sizeof(receiver)));
    CHECK(pair_setup_channel_take_auth(&setup,final,&receiver,&acfg,&storage,&mfi,91,1)==IAP2_ARGUMENT&&snapshot(setup)==saved);
    CHECK(pair_setup_channel_take_auth(&setup,final,&receiver,&acfg,&storage,&mfi,92,1)==IAP2_OK&&setup.state==PAIR_SETUP_CHANNEL_DETACHED&&receiver.auth.state==MFI_SAP_WAIT&&provider.random_calls==2&&signer.identities==0);
    size_t used=0;CHECK(projection_auth_feed(&receiver,92,next.data(),next.size(),&used,1)==RTSP_CHANNEL_OUTPUT&&used==next.size());
    auto saved_receiver=snapshot(receiver);auto saved_rx=rx,saved_tx=tx;pair_setup_channel_close(&setup);
    CHECK(snapshot(receiver)==saved_receiver&&rx==saved_rx&&tx==saved_tx);
    CHECK(pair_setup_channel_take_auth(&setup,final,&receiver,&acfg,&storage,&mfi,93,UINT64_MAX)==PAIR_SETUP_CLOSED&&snapshot(receiver)==saved_receiver);
    for(unsigned step:{1u,3u}) {
        if(step==3) { auto wire=outer(v.at("pv_m3"),3,"/pair-verify","POST","application/pairing+tlv8");CHECK(projection_auth_feed(&receiver,92,wire.data(),wire.size(),&used,1)==RTSP_CHANNEL_OUTPUT&&used==wire.size()); }
        rtsp_slice output{};rtsp_channel_key key{};CHECK(projection_auth_output(&receiver,92,&output,&key,1)==RTSP_CHANNEL_OUTPUT);rtsp_message reply{};
        CHECK(rtsp_message_decode(output.data,output.size,&reply,&used)==IAP2_OK&&Bytes(reply.body.data,reply.body.data+reply.body.size)==v.at("pv_m"+std::to_string(step+1)));
        CHECK(projection_auth_consume(&receiver,key,output.size,1)==RTSP_CHANNEL_OUTPUT_DONE&&projection_auth_release(&receiver,key,1)==(step==1?IAP2_OK:PROJECTION_CONTROL_SECURE));
    }
    auto request=outer(v.at("request"),7,"/auth-setup");CHECK(request.size()<256);Bytes frame(request.size()+18);frame[0]=static_cast<uint8_t>(request.size());auto nn=nonce(0);
    CHECK(pair_aead_seal(v.at("pv_accessory_read_key").data(),nn.data(),frame.data(),2,request.data(),request.size(),frame.data()+2,frame.size()-2,&used)==IAP2_OK);
    CHECK(projection_auth_feed(&receiver,92,frame.data(),frame.size(),&used,1)==RTSP_CHANNEL_OUTPUT&&used==frame.size()&&signer.signatures==1&&provider.random_calls==4);
    Bytes decrypted;uint64_t counter=0;rtsp_slice output{};rtsp_channel_key key{};int r;
    while((r=projection_auth_output(&receiver,92,&output,&key,1))==RTSP_CHANNEL_OUTPUT) {
        Bytes message(256);nn=nonce(counter++);CHECK(pair_aead_open(v.at("pv_accessory_write_key").data(),nn.data(),output.data,2,output.data+2,output.size-2,message.data(),message.size(),&used)==IAP2_OK);
        decrypted.insert(decrypted.end(),message.begin(),message.begin()+used);int consumed=projection_auth_consume(&receiver,key,output.size,1);CHECK(consumed==RTSP_CHANNEL_OUTPUT||consumed==RTSP_CHANNEL_OUTPUT_DONE);
    }
    CHECK(r==RTSP_CHANNEL_OUTPUT_DONE&&projection_auth_release(&receiver,key,1)==MFI_SAP_DRAINED);rtsp_message reply{};
    CHECK(rtsp_message_decode(decrypted.data(),decrypted.size(),&reply,&used)==IAP2_OK&&reply.cseq==7&&Bytes(reply.body.data,reply.body.data+reply.body.size)==v.at("response3"));
    CHECK(provider.commits==1&&provider.store.count==1&&receiver.auth.state==MFI_SAP_DONE);projection_auth_close(&receiver);
}
int main(int argc,char** argv) { try { CHECK(argc==3);auto v=load_vectors(argv[1],39);auto setup_v=load_vectors(argv[2],51);transcripts(v);invalid_and_providers(v);lifetimes(v);owned_transcript(v);owned_failures(v);explicit_application(v);enrollment_handoff(v,setup_v);
    std::cout<<"PASS: 7 MFiSAP/control groups; independent crypto, explicit provider, encrypted route/drain, failures, tails and enrollment handoff\n";
    std::cout<<"x64 bytes: MFiSAP="<<sizeof(mfi_sap)<<" projection_auth="<<sizeof(projection_auth)<<"; caller buffers and stack additional; no real MFi credential\n";return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; } }
