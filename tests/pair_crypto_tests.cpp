/* SPDX-License-Identifier: GPL-3.0-only
 * PUBLIC synthetic keys and deterministic entropy for reproducible tests only.
 */
#include "pair_verify.h"
#include "rtsp_channel.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do { if(!(x)) throw std::runtime_error(std::string(#x)+" line "+std::to_string(__LINE__)); } while(0)
using Bytes=std::vector<uint8_t>;
using Vectors=std::map<std::string,Bytes>;
static Bytes hex(const std::string& s) { CHECK(s.size()%2==0);Bytes b;for(size_t i=0;i<s.size();i+=2) b.push_back(static_cast<uint8_t>(std::stoul(s.substr(i,2),nullptr,16)));return b; }
static Vectors load(const char* path) {
    std::ifstream f(path);CHECK(f.good());Vectors v;std::string line;
    while(std::getline(f,line)) { if(!line.empty()&&line.back()=='\r') line.pop_back();if(line.empty()||line[0]=='#') continue;
        auto p=line.find('=');CHECK(p!=std::string::npos&&v.emplace(line.substr(0,p),hex(line.substr(p+1))).second); }
    CHECK(v.size()==21);return v;
}
static bool zeroed(const void* p,size_t n) { auto b=static_cast<const uint8_t*>(p);return std::all_of(b,b+n,[](uint8_t c){return c==0;}); }
static bool equal(const uint8_t* p,const Bytes& b) { return std::equal(b.begin(),b.end(),p); }
struct Random {
    Bytes bytes;int calls=0;bool failed=false;
    static int read(void* ctx,uint8_t* out,size_t n) { auto& r=*static_cast<Random*>(ctx);++r.calls;
        CHECK(n==32&&r.bytes.size()==32);std::copy(r.bytes.begin(),r.bytes.end(),out);return r.failed?-1:0; }
};
static pair_identity identity(const Vectors& v,const std::string& prefix) {
    pair_identity id{};const auto& name=v.at(prefix+"_identifier");
    CHECK(pair_identity_import(&id,v.at(prefix+"_seed").data(),v.at(prefix+"_public").data(),name.data(),name.size())==IAP2_OK);return id;
}
static void primitive_vectors(const Vectors& v) {
    auto own=identity(v,"own"),ctrl=identity(v,"ctrl");std::array<uint8_t,64> sig{};
    CHECK(pair_identity_sign(&own,nullptr,0,sig.data())==IAP2_OK&&equal(sig.data(),v.at("empty_signature")));
    CHECK(pair_ed25519_verify(own.public_key,nullptr,0,sig.data())==IAP2_OK);
    const uint8_t message=0x72;CHECK(pair_identity_sign(&ctrl,&message,1,sig.data())==IAP2_OK&&equal(sig.data(),v.at("single_signature")));
    CHECK(pair_ed25519_verify(ctrl.public_key,&message,1,sig.data())==IAP2_OK);
    for(size_t i=0;i<sig.size();++i) { sig[i]^=1;CHECK(pair_ed25519_verify(ctrl.public_key,&message,1,sig.data())==IAP2_AUTH_FAILED);sig[i]^=1; }
    std::array<uint8_t,32> sk{},pk{},shared{};Random random{v.at("own_ephemeral_secret")};
    CHECK(pair_x25519_generate(Random::read,&random,sk.data(),pk.data())==IAP2_OK&&random.calls==1);
    CHECK(equal(pk.data(),v.at("own_ephemeral_public"))&&equal(sk.data(),random.bytes));
    CHECK(pair_x25519_shared(sk.data(),v.at("ctrl_ephemeral_public").data(),shared.data())==IAP2_OK&&equal(shared.data(),v.at("shared_secret")));
    std::array<uint8_t,82> derived{};Bytes ikm(22,11),salt(13),info(10);
    for(size_t i=0;i<salt.size();++i) salt[i]=static_cast<uint8_t>(i);
    for(size_t i=0;i<info.size();++i) info[i]=static_cast<uint8_t>(240+i);
    CHECK(pair_hkdf_sha512(ikm.data(),ikm.size(),salt.data(),salt.size(),info.data(),info.size(),derived.data(),derived.size())==IAP2_OK);
    CHECK(equal(derived.data(),v.at("hkdf_82")));
    pair_identity_clear(&own);pair_identity_clear(&ctrl);CHECK(zeroed(&own,sizeof(own))&&zeroed(&ctrl,sizeof(ctrl)));
}
static void aead_rfc() {
    const auto key=hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const auto nonce=hex("070000004041424344454647"),aad=hex("50515253c0c1c2c3c4c5c6c7");
    const std::string message="Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const auto expected=hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
    Bytes out(message.size()+16),plain(message.size(),0xa5);size_t n=0;
    CHECK(pair_aead_seal(key.data(),nonce.data(),aad.data(),aad.size(),reinterpret_cast<const uint8_t*>(message.data()),message.size(),out.data(),out.size(),&n)==IAP2_OK&&n==out.size()&&out==expected);
    CHECK(pair_aead_open(key.data(),nonce.data(),aad.data(),aad.size(),out.data(),out.size(),plain.data(),plain.size(),&n)==IAP2_OK&&n==plain.size());
    CHECK(std::string(plain.begin(),plain.end())==message);
    for(size_t i=0;i<out.size();++i) { out[i]^=1;std::fill(plain.begin(),plain.end(),0xa5);
        CHECK(pair_aead_open(key.data(),nonce.data(),aad.data(),aad.size(),out.data(),out.size(),plain.data(),plain.size(),&n)==IAP2_AUTH_FAILED&&n==0&&zeroed(plain.data(),plain.size()));out[i]^=1; }
    auto altered=aad;altered[0]^=1;CHECK(pair_aead_open(key.data(),nonce.data(),altered.data(),altered.size(),out.data(),out.size(),plain.data(),plain.size(),&n)==IAP2_AUTH_FAILED);
    auto wrong=nonce;wrong[0]^=1;CHECK(pair_aead_open(key.data(),wrong.data(),aad.data(),aad.size(),out.data(),out.size(),plain.data(),plain.size(),&n)==IAP2_AUTH_FAILED);
    auto saved=out;CHECK(pair_aead_seal(key.data(),nonce.data(),nullptr,0,nullptr,0,out.data(),15,&n)==IAP2_NO_SPACE&&n==0&&out==saved);
    CHECK(pair_aead_seal(key.data(),nonce.data(),nullptr,0,nullptr,0,out.data(),16,&n)==IAP2_OK&&n==16);
    CHECK(pair_aead_open(key.data(),nonce.data(),nullptr,0,out.data(),16,plain.data(),0,&n)==IAP2_OK&&n==0);
}
static void crypto_failure_policy(const Vectors& v) {
    auto id=identity(v,"own"),saved=id;auto bad=v.at("own_public");bad[0]^=1;const auto& name=v.at("own_identifier");
    CHECK(pair_identity_import(&id,v.at("own_seed").data(),bad.data(),name.data(),name.size())==IAP2_AUTH_FAILED&&std::memcmp(&id,&saved,sizeof(id))==0);
    Random random{v.at("own_seed"),0,true};
    CHECK(pair_identity_generate(&id,Random::read,&random,name.data(),name.size())==IAP2_PROVIDER_FAILED&&std::memcmp(&id,&saved,sizeof(id))==0);
    CHECK(pair_identity_generate(&id,Random::read,&random,nullptr,0)==IAP2_ARGUMENT&&random.calls==1);
    random.failed=false;pair_identity generated{};
    CHECK(pair_identity_generate(&generated,Random::read,&random,name.data(),name.size())==IAP2_OK&&random.calls==2);
    CHECK(equal(generated.public_key,v.at("own_public"))&&generated.identifier_size==name.size());pair_identity_clear(&generated);
    random.failed=true;
    std::array<uint8_t,32> sk{},pk{},shared{};sk.fill(0xa5);pk.fill(0xa5);
    CHECK(pair_x25519_generate(Random::read,&random,sk.data(),pk.data())==IAP2_PROVIDER_FAILED&&zeroed(sk.data(),32)&&zeroed(pk.data(),32));
    CHECK(pair_x25519_shared(v.at("own_ephemeral_secret").data(),pk.data(),shared.data())==IAP2_AUTH_FAILED&&zeroed(shared.data(),32));
    pk[0]=1;CHECK(pair_x25519_shared(v.at("own_ephemeral_secret").data(),pk.data(),shared.data())==IAP2_AUTH_FAILED);
    // Public low-order/noncanonical A and R must not exploit cofactored verification.
    for(const auto& point: {Bytes(32),hex("0100000000000000000000000000000000000000000000000000000000000000"),
                           hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
                           hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
                           hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")}) {
        Bytes sig(64);sig[0]=1;CHECK(pair_ed25519_verify(point.data(),nullptr,0,sig.data())==IAP2_AUTH_FAILED);
        sig=v.at("empty_signature");std::copy(point.begin(),point.end(),sig.begin());CHECK(pair_ed25519_verify(id.public_key,nullptr,0,sig.data())==IAP2_AUTH_FAILED);
    }
    Bytes huge(PAIR_CRYPTO_MAX_KDF_OUTPUT+1,0xa5),old=huge;
    CHECK(pair_hkdf_sha512(nullptr,0,nullptr,0,nullptr,0,huge.data(),huge.size())==IAP2_ARGUMENT&&huge==old);
    CHECK(pair_hkdf_sha512(nullptr,0,nullptr,0,nullptr,0,huge.data(),PAIR_CRYPTO_MAX_KDF_OUTPUT)==IAP2_OK);
    pair_identity_clear(&id);pair_identity_clear(&saved);
}
struct Session {
    const Vectors& v;pair_identity id;Random random;pair_verify p{};pair_verify_config cfg{};
    int lookups=0,lookup_status=IAP2_OK;bool wrong_key=false;Bytes asked;
    static int lookup(void* ctx,const uint8_t* name,size_t n,uint8_t pk[32]) {
        auto& s=*static_cast<Session*>(ctx);++s.lookups;s.asked.assign(name,name+n);
        if(s.lookup_status!=IAP2_OK) return s.lookup_status;
        if(s.asked!=s.v.at("ctrl_identifier")) return IAP2_END;
        const auto& key=s.v.at(s.wrong_key?"own_public":"ctrl_public");std::copy(key.begin(),key.end(),pk);return IAP2_OK;
    }
    explicit Session(const Vectors& vv):v(vv),id(identity(v,"own")),random{v.at("own_ephemeral_secret")} {
        pair_verify_default_config(&cfg);CHECK(pair_verify_init(&p,&id,Random::read,&random,lookup,this,&cfg,91,0)==IAP2_OK);
    }
    ~Session() { pair_verify_close(&p);pair_identity_clear(&id); }
    void m1(uint64_t now=1) { const auto& b=v.at("m1");CHECK(pair_verify_request(&p,91,b.data(),b.size(),now)==PAIR_VERIFY_RESPONSE); }
    Bytes response(uint64_t& token) { const uint8_t* data=nullptr;size_t n=0;CHECK(pair_verify_response(&p,&data,&n,&token)==PAIR_VERIFY_RESPONSE);return {data,data+n}; }
    void first(uint64_t now=1) { m1(now);uint64_t t;CHECK(response(t)==v.at("m2")&&t==1);CHECK(pair_verify_release(&p,91,t,now+1)==IAP2_OK); }
    void m3(uint64_t now=3) { const auto& b=v.at("m3");CHECK(pair_verify_request(&p,91,b.data(),b.size(),now)==PAIR_VERIFY_RESPONSE); }
};
static void transcript(const Vectors& v) {
    Session s(v);CHECK(s.random.calls==0&&s.lookups==0);s.first();CHECK(s.random.calls==1&&s.lookups==0);
    pair_session_keys keys{};auto saved=s.p;
    CHECK(pair_verify_take(&s.p,91,1,&keys,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&saved,&s.p,sizeof(saved))==0);
    s.m3();uint64_t token;CHECK(s.response(token)==v.at("m4")&&token==2&&s.lookups==1&&s.asked==v.at("ctrl_identifier"));
    CHECK(pair_verify_take(&s.p,91,token,&keys,UINT64_MAX)==PAIR_VERIFY_BUSY&&zeroed(&keys,sizeof(keys))&&s.p.now==3);
    CHECK(pair_verify_release(&s.p,91,token,4)==PAIR_VERIFY_KEYS);
    CHECK(pair_verify_take(&s.p,91,token,&keys,5)==IAP2_OK&&s.p.state==PAIR_VERIFY_DETACHED);
    CHECK(equal(keys.read_key,v.at("accessory_read_key"))&&equal(keys.write_key,v.at("accessory_write_key"))&&equal(keys.shared_secret,v.at("shared_secret")));
    CHECK(keys.controller_id_size==v.at("ctrl_identifier").size()&&equal(keys.controller_id,v.at("ctrl_identifier")));
    CHECK(zeroed(&s.p.keys,sizeof(s.p.keys))&&zeroed(s.p.encrypt_key,32)&&zeroed(s.p.output,sizeof(s.p.output)));
    CHECK(pair_verify_take(&s.p,91,token,&keys,6)==PAIR_VERIFY_CLOSED);pair_crypto_wipe(&keys,sizeof(keys));
}
static Bytes encode(std::initializer_list<pair_tlv> fields) { Bytes b(1024);size_t n=0;CHECK(pair_tlv_encode(fields.begin(),fields.size(),b.data(),b.size(),&n)==IAP2_OK);b.resize(n);return b; }
static Bytes forged_m3(const Vectors& v,bool duplicate=false) {
    const auto& key=v.at("encrypt_key");const auto& name=v.at("ctrl_identifier");Bytes sig(64,0x55);
    auto sub=encode({{1,name.data(),name.size()},{10,sig.data(),sig.size()}});
    if(duplicate) { const Bytes extra={1,1,'X'};sub.insert(sub.end(),extra.begin(),extra.end()); }
    auto nonce=hex("0000000050562d4d73673033");Bytes sealed(sub.size()+16);size_t n=0;const uint8_t state=3;
    CHECK(pair_aead_seal(key.data(),nonce.data(),nullptr,0,sub.data(),sub.size(),sealed.data(),sealed.size(),&n)==IAP2_OK);
    return encode({{6,&state,1},{5,sealed.data(),sealed.size()}});
}
static void rejected_proofs(const Vectors& v) {
    for(int mode=0;mode<6;++mode) {
        Session s(v);s.first();auto b=v.at("m3");
        if(mode==0) b.back()^=1;if(mode==1) b=forged_m3(v);if(mode==2) s.lookup_status=IAP2_END;
        if(mode==3) s.wrong_key=true;if(mode==4) s.lookup_status=IAP2_PROVIDER_FAILED;if(mode==5) b=forged_m3(v,true);
        CHECK(pair_verify_request(&s.p,91,b.data(),b.size(),3)==PAIR_VERIFY_CLOSED);
        CHECK(s.lookups==((mode==0||mode==5)?0:1));CHECK(s.p.state==PAIR_VERIFY_DEAD&&zeroed(&s.p.keys,sizeof(s.p.keys))&&zeroed(s.p.encrypt_key,32));
        pair_session_keys keys;std::memset(&keys,0xa5,sizeof(keys));auto saved=keys;
        CHECK(pair_verify_take(&s.p,91,2,&keys,4)==PAIR_VERIFY_CLOSED&&std::memcmp(&saved,&keys,sizeof(keys))==0);
    }
    { Session s(v);s.random.failed=true;auto b=v.at("m1");CHECK(pair_verify_request(&s.p,91,b.data(),b.size(),1)==PAIR_VERIFY_CLOSED&&s.p.reason==PAIR_VERIFY_REASON_PROVIDER); }
    { Session s(v);auto b=v.at("m1");std::fill(b.end()-32,b.end(),0);CHECK(pair_verify_request(&s.p,91,b.data(),b.size(),1)==PAIR_VERIFY_CLOSED&&s.p.reason==PAIR_VERIFY_REASON_AUTH); }
}
static void lifetime_and_malformed(const Vectors& v) {
    { Session s(v);auto saved=s.p;auto b=v.at("m1");
      CHECK(pair_verify_request(&s.p,92,b.data(),b.size(),UINT64_MAX)==IAP2_INVALID&&s.random.calls==0&&std::memcmp(&saved,&s.p,sizeof(saved))==0);
      s.m1();saved=s.p;CHECK(pair_verify_release(&s.p,91,2,UINT64_MAX)==IAP2_INVALID&&std::memcmp(&saved,&s.p,sizeof(saved))==0);
      CHECK(pair_verify_check(&s.p,91,0)==IAP2_ARGUMENT&&s.p.now==1);
      CHECK(pair_verify_check(&s.p,91,5000)==IAP2_OK&&pair_verify_next_delay(&s.p)==1);
      CHECK(pair_verify_check(&s.p,91,5001)==PAIR_VERIFY_CLOSED&&s.p.reason==PAIR_VERIFY_REASON_DEADLINE); }
    { Session s(v);s.first(6000);CHECK(pair_verify_next_delay(&s.p)==3999);CHECK(pair_verify_check(&s.p,91,10000)==PAIR_VERIFY_CLOSED); }
    { Session s(v);s.first();s.m3();CHECK(pair_verify_release(&s.p,91,2,4)==PAIR_VERIFY_KEYS);
      CHECK(pair_verify_check(&s.p,91,5003)==PAIR_VERIFY_CLOSED); }
    { Session s(v);CHECK(pair_verify_request(&s.p,91,nullptr,0,1)==PAIR_VERIFY_CLOSED&&s.random.calls==0); }
    { Session s(v);s.first();auto b=v.at("m1");CHECK(pair_verify_request(&s.p,91,b.data(),b.size(),3)==PAIR_VERIFY_CLOSED&&s.random.calls==1); }
    for(size_t n=1;n<v.at("m1").size();++n) { Session s(v);CHECK(pair_verify_request(&s.p,91,v.at("m1").data(),n,1)==PAIR_VERIFY_CLOSED&&s.random.calls==0); }
    for(const Bytes& extra:std::vector<Bytes>{{6,1,1},{255,0},{7},{42,5,1}}) {
        Session s(v);auto b=v.at("m1");b.insert(b.end(),extra.begin(),extra.end());
        CHECK(pair_verify_request(&s.p,91,b.data(),b.size(),1)==PAIR_VERIFY_CLOSED&&s.random.calls==0);
    }
    { Session s(v);auto b=v.at("m1");b.insert(b.end(),{42,1,9});CHECK(pair_verify_request(&s.p,91,b.data(),b.size(),1)==PAIR_VERIFY_RESPONSE); }
    { Session s(v);s.m1();pair_verify_close(&s.p);CHECK(zeroed(s.p.output,sizeof(s.p.output))&&zeroed(&s.p.keys,sizeof(s.p.keys)));
      pair_verify_close(&s.p);CHECK(s.p.reason==PAIR_VERIFY_REASON_LOCAL); }
    { Session s(v);auto saved=s.p;auto cfg=s.cfg;cfg.hold_ms=0;
      CHECK(pair_verify_init(&s.p,&s.id,Random::read,&s.random,Session::lookup,&s,&cfg,91,UINT64_MAX)==IAP2_ARGUMENT&&std::memcmp(&saved,&s.p,sizeof(saved))==0); }
    { Session s(v);pair_verify_close(&s.p);pair_verify fresh{};
      CHECK(pair_verify_init(&fresh,&s.id,Random::read,&s.random,Session::lookup,&s,&s.cfg,92,UINT64_MAX-5)==IAP2_OK);
      CHECK(pair_verify_check(&fresh,92,UINT64_MAX)==IAP2_OK&&pair_verify_next_delay(&fresh)==9995);pair_verify_close(&fresh); }
}
static Bytes rtsp_request(const Bytes& body,int seq) {
    auto head=std::string("POST /pair-verify RTSP/1.0\r\nCSeq: ")+std::to_string(seq)+"\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n";
    Bytes b(head.begin(),head.end());b.insert(b.end(),body.begin(),body.end());return b;
}
static void rtsp_integration(const Vectors& v) {
    Session s(v);rtsp_channel c{};rtsp_channel_config cfg{};rtsp_channel_default_config(&cfg);Bytes rx(2048),tx(2048);
    CHECK(rtsp_channel_init(&c,&cfg,rx.data(),rx.size(),tx.data(),tx.size(),91,0)==IAP2_OK);
    uint64_t now=1;
    for(int stage=1;stage<=3;stage+=2) {
        auto wire=rtsp_request(v.at(stage==1?"m1":"m3"),stage);size_t exact=wire.size();
        const Bytes tail={2,0,255,0,128};if(stage==3) wire.insert(wire.end(),tail.begin(),tail.end());
        size_t off=0;int r=IAP2_MORE;
        while(r==IAP2_MORE) { size_t used=0,take=std::min(size_t(7),wire.size()-off);CHECK(take>0);
            r=rtsp_channel_feed(&c,91,wire.data()+off,take,&used,now++);off+=used; }
        CHECK(r==RTSP_CHANNEL_REQUEST&&off==exact);
        rtsp_message req{};rtsp_channel_key key{};CHECK(rtsp_channel_request(&c,&req,&key)==RTSP_CHANNEL_REQUEST);
        CHECK(pair_verify_request(&s.p,91,req.body.data,req.body.size,now++)==PAIR_VERIFY_RESPONSE);
        uint64_t token;auto body=s.response(token);CHECK(body==v.at(stage==1?"m2":"m4"));
        const std::string content="application/pairing+tlv8";rtsp_header header={{reinterpret_cast<const uint8_t*>("Content-Type"),12},{reinterpret_cast<const uint8_t*>(content.data()),content.size()}};
        rtsp_response response={200,{},&header,1,{body.data(),body.size()}};
        CHECK(rtsp_channel_respond(&c,key,&response,now++)==RTSP_CHANNEL_OUTPUT);
        Bytes sent;rtsp_slice out{};
        while(rtsp_channel_output(&c,key,&out,now++)==RTSP_CHANNEL_OUTPUT) {
            size_t take=std::min(size_t(3),out.size);sent.insert(sent.end(),out.data,out.data+take);
            CHECK(rtsp_channel_consume(&c,key,take,now++)==(take==out.size?RTSP_CHANNEL_OUTPUT_DONE:RTSP_CHANNEL_OUTPUT));
        }
        rtsp_message parsed{};size_t used=0;CHECK(rtsp_message_decode(sent.data(),sent.size(),&parsed,&used)==IAP2_OK&&used==sent.size());
        CHECK(parsed.cseq==static_cast<uint32_t>(stage)&&parsed.body.size==body.size()&&equal(parsed.body.data,body));
        CHECK(pair_verify_release(&s.p,91,token,now++)==(stage==1?IAP2_OK:PAIR_VERIFY_KEYS));
        if(stage==1) CHECK(rtsp_channel_release(&c,key,now++)==IAP2_OK);
        else { pair_session_keys keys{};CHECK(pair_verify_take(&s.p,91,token,&keys,now++)==IAP2_OK);
            CHECK(c.state==RTSP_CHANNEL_SENT&&wire.size()-off==tail.size()&&std::equal(tail.begin(),tail.end(),wire.begin()+static_cast<ptrdiff_t>(off)));
            pair_crypto_wipe(&keys,sizeof(keys)); }
    }
    rtsp_channel_close(&c);
}
int main(int argc,char** argv) { try { CHECK(argc==2);auto v=load(argv[1]);primitive_vectors(v);aead_rfc();crypto_failure_policy(v);transcript(v);rejected_proofs(v);lifetime_and_malformed(v);rtsp_integration(v);
    std::cout<<"PASS: 7 real pairing-crypto groups, RFC/PyCA vectors, negative proofs and RTSP handoff simulation\n";
    std::cout<<"x64 bytes: identity="<<sizeof(pair_identity)<<" responder="<<sizeof(pair_verify)<<" keys="<<sizeof(pair_session_keys)<<"; stack temporaries additional\n";return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; } }
