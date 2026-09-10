#ifndef GT86_PROJECTION_RECEIVER_FIXTURE_H
#define GT86_PROJECTION_RECEIVER_FIXTURE_H
/* SPDX-License-Identifier: GPL-3.0-only
 * Public synthetic phone keys / opaque MFi provider; actual protocol crypto.
 */
#include "projection_receiver.h"
#include "pair_store.h"
#include "pair_test_support.h"
#include "projection_info_fixture.h"
#include "projection_session_fixture.h"

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
            CHECK(projection_receiver_release(&s,key,UINT64_MAX)==(expected==PROJECTION_RECEIVER_CLOSED?PROJECTION_RECEIVER_CLOSED:IAP2_INVALID)&&snapshot(s)==saved);
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

#endif
