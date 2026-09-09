#pragma once
// SPDX-License-Identifier: GPL-3.0-only
// Real cryptography, simulated USB only. Ephemeral credentials never leave RAM.
#include "lockdown_tls.h"
#include "lockdown_fixture.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/platform_util.h>
static void crypto(int result, const char *why) {
    if (result) { char message[256]; mbedtls_strerror(result,message,sizeof message); throw std::runtime_error(std::string(why)+": "+std::to_string(result)+" "+message); }
}
struct Random {
    mbedtls_entropy_context entropy{}; mbedtls_ctr_drbg_context drbg{}; bool fail=false;
    Random() {
        mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&drbg);
        const unsigned char label[]="gt86 synthetic TLS tests only";
        crypto(mbedtls_ctr_drbg_seed(&drbg,mbedtls_entropy_func,&entropy,label,sizeof label),"host entropy seed");
    }
    ~Random() { mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&entropy); }
    static int get(void *ctx,unsigned char *out,size_t n) {
        auto& r=*static_cast<Random*>(ctx);
        return r.fail ? MBEDTLS_ERR_ENTROPY_SOURCE_FAILED : mbedtls_ctr_drbg_random(&r.drbg,out,n);
    }
};
struct Identity {
    mbedtls_pk_context key{}; mbedtls_x509_crt cert{}; Bytes der, pem_key; std::string name;
    Identity(Random& rng, const char *cn, unsigned char serial, Identity *issuer=nullptr, bool expired=false, bool rsa=false):name(cn) {
        mbedtls_pk_init(&key); mbedtls_x509_crt_init(&cert);
        crypto(mbedtls_pk_setup(&key,mbedtls_pk_info_from_type(rsa?MBEDTLS_PK_RSA:MBEDTLS_PK_ECKEY)),"key setup");
        if(rsa) crypto(mbedtls_rsa_gen_key(mbedtls_pk_rsa(key),Random::get,&rng,2048,65537),"ephemeral RSA key");
        else crypto(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,mbedtls_pk_ec(key),Random::get,&rng),"ephemeral P256 key");
        mbedtls_x509write_cert writer; mbedtls_x509write_crt_init(&writer);
        mbedtls_x509write_crt_set_version(&writer,MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_x509write_crt_set_md_alg(&writer,MBEDTLS_MD_SHA256);
        mbedtls_x509write_crt_set_subject_key(&writer,&key);
        mbedtls_x509write_crt_set_issuer_key(&writer,issuer?&issuer->key:&key);
        crypto(mbedtls_x509write_crt_set_serial_raw(&writer,&serial,1),"certificate serial");
        crypto(mbedtls_x509write_crt_set_subject_name(&writer,name.c_str()),"certificate subject");
        crypto(mbedtls_x509write_crt_set_issuer_name(&writer,issuer?issuer->name.c_str():name.c_str()),"certificate issuer");
        crypto(mbedtls_x509write_crt_set_validity(&writer,"20200101000000",expired?"20210101000000":"20400101000000"),"certificate dates");
        crypto(mbedtls_x509write_crt_set_basic_constraints(&writer,issuer?0:1,issuer?-1:1),"CA constraint");
        crypto(mbedtls_x509write_crt_set_key_usage(&writer,issuer?MBEDTLS_X509_KU_DIGITAL_SIGNATURE:
            MBEDTLS_X509_KU_KEY_CERT_SIGN|MBEDTLS_X509_KU_CRL_SIGN),"certificate key usage");
        Bytes buffer(4096); int n=mbedtls_x509write_crt_der(&writer,buffer.data(),buffer.size(),Random::get,&rng);
        mbedtls_x509write_crt_free(&writer); check(n>0,"synthetic certificate DER"); der.assign(buffer.end()-n,buffer.end());
        crypto(mbedtls_x509_crt_parse_der(&cert,der.data(),der.size()),"synthetic certificate parse");
        pem_key.resize(4096); crypto(mbedtls_pk_write_key_pem(&key,pem_key.data(),pem_key.size()),"synthetic private key PEM");
        pem_key.resize(std::strlen(reinterpret_cast<const char*>(pem_key.data()))+1);
    }
    ~Identity() { mbedtls_pk_free(&key); mbedtls_x509_crt_free(&cert); mbedtls_platform_zeroize(pem_key.data(),pem_key.size()); }
    Identity(const Identity&)=delete; Identity& operator=(const Identity&)=delete;
};
struct Identities {
    Random rng;
    Identity root{rng,"CN=GT86 synthetic root",1}, host{rng,"CN=GT86 synthetic host",2,&root}, device{rng,"CN=GT86 synthetic device",3,&root};
    Identity other{rng,"CN=GT86 synthetic other",4,&root}, alien{rng,"CN=GT86 unrelated root",5}, expired{rng,"CN=GT86 expired device",6,&root,true};
    lockdown_tls_credentials credentials() { return {view(root.der),view(host.der),view(host.pem_key),view(device.der),Random::get,&rng}; }
};
struct Server {
    mbedtls_ssl_context ssl{}; mbedtls_ssl_config config{};
    std::deque<uint8_t> input,output; Bytes plaintext, pending;
    size_t io_limit=113; bool disabled=false; int error=0;
    explicit Server(Identities& ids, Identity *device=nullptr, bool incompatible=false) {
        mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&config);
        crypto(mbedtls_ssl_config_defaults(&config,MBEDTLS_SSL_IS_SERVER,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT),"server defaults");
        mbedtls_ssl_conf_min_tls_version(&config,MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&config,MBEDTLS_SSL_VERSION_TLS1_2);
        static const int cbc[]={MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,0};
        if(incompatible) mbedtls_ssl_conf_ciphersuites(&config,cbc);
        mbedtls_ssl_conf_rng(&config,Random::get,&ids.rng);
        mbedtls_ssl_conf_authmode(&config,MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&config,&ids.root.cert,nullptr);
        auto& selected=device?*device:ids.device;
        crypto(mbedtls_ssl_conf_own_cert(&config,&selected.cert,&selected.key),"server certificate");
        crypto(mbedtls_ssl_setup(&ssl,&config),"server setup");
        mbedtls_ssl_set_bio(&ssl,this,send,receive,nullptr);
    }
    ~Server() { mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&config); }
    static int send(void *ctx,const unsigned char *data,size_t size) {
        auto& s=*static_cast<Server*>(ctx); size=std::min(size,s.io_limit);
        s.output.insert(s.output.end(),data,data+size); return static_cast<int>(size);
    }
    static int receive(void *ctx,unsigned char *out,size_t size) {
        auto& s=*static_cast<Server*>(ctx); size=std::min({size,s.io_limit,s.input.size()});
        if(!size) return MBEDTLS_ERR_SSL_WANT_READ;
        for(size_t i=0;i<size;++i) { out[i]=s.input.front(); s.input.pop_front(); } return static_cast<int>(size);
    }
    bool ready() { return mbedtls_ssl_is_handshake_over(&ssl)!=0; }
    void step() {
        if(disabled || error) return;
        int status;
        if(!ready()) status=mbedtls_ssl_handshake_step(&ssl);
        else if(!pending.empty()) {
            status=mbedtls_ssl_write(&ssl,pending.data(),pending.size());
            if(status>0) { check(static_cast<size_t>(status)==pending.size(),"server whole write"); pending.clear(); status=0; }
        } else {
            unsigned char data[333]; status=mbedtls_ssl_read(&ssl,data,sizeof data);
            if(status>0) { plaintext.insert(plaintext.end(),data,data+status); status=0; }
        }
        if(status && status!=MBEDTLS_ERR_SSL_WANT_READ && status!=MBEDTLS_ERR_SSL_WANT_WRITE) error=status;
    }
};
static lockdown_tls_handoff bootstrap(Runtime& r,usbmux_handle h) {
    Service service(r,h,4096,4096); lockdown_bootstrap b{};
    Bytes scratch(4096), arena(4096); service_plist_node nodes[64];
    service_plist_storage storage{nodes,64,arena.data(),arena.size()};
    const auto l=bytes("gt86-research"), a=bytes("00000000-0000-4000-8000-000000000001"), u=bytes("00000000-0000-4000-8000-000000000002");
    const auto label=view(l),host=view(a),system=view(u);
    check(lockdown_bootstrap_init(&b,&service.c,&label,scratch.data(),scratch.size(),&storage,r.now)==0,"pre-TLS init");
    reply_with(r,fixture("start-session.xml"),framed(fixture("session-tls.xml")));
    check(lockdown_bootstrap_start_session(&b,&host,&system,r.now)==0,"explicit StartSession");
    for(unsigned i=0;i<15000 && b.state!=LOCKDOWN_BOOTSTRAP_TLS_HELD;++i) {
        int s=lockdown_bootstrap_poll(&b,r.now++);
        check(s==0 || s==IAP2_MORE || s==LOCKDOWN_BOOTSTRAP_TLS,"pre-TLS exchange");
    }
    check(b.state==LOCKDOWN_BOOTSTRAP_TLS_HELD,"validated session reply");
    lockdown_tls_handoff handoff{};
    check(lockdown_bootstrap_take_tls(&b,b.token,&handoff,r.now)==0,"exact token TLS handoff");
    lockdown_bootstrap_close(&b); check(r.d.active,"old bootstrap close cannot cancel handoff");
    return handoff;
}
struct Rig {
    Runtime r; usbmux_handle h{}; lockdown_tls_handoff handoff{}; lockdown_tls tls{}; Server server;
    explicit Rig(Identities& ids, Identity *device=nullptr, bool incompatible=false, size_t capacity=4096, uint32_t send_limit=128):
        r(2,capacity,send_limit),server(ids,device,incompatible) {
        r.peer.read_limit=97; r.peer.write_limit=41; r.ready(); h=r.open(); r.established(h);
        handoff=bootstrap(r,h);
        r.peer.on_data=[this](Peer& peer,uint16_t port,const Bytes& data) {
            if(port==r.conns[h.slot].local_port) server.input.insert(server.input.end(),data.begin(),data.end());
            send(peer,port,{},peer.streams.at(port).host_next);
        };
    }
    ~Rig() { lockdown_tls_close(&tls); usbmux_dispatcher_close(&r.d); }
    void init(lockdown_tls_credentials creds,lockdown_tls_config config={10000,5000,5000}) {
        const auto reads=r.peer.reads,writes=r.peer.writes;
        crypto(lockdown_tls_init(&tls,&handoff,&creds,&config,r.now),"TLS adapter init");
        check(!handoff.dispatcher && !handoff.session_id_size,"handoff consumed only on success");
        check(r.peer.reads==reads && r.peer.writes==writes,"init has no backend I/O");
    }
    void inject_output() {
        if(server.output.empty() || !r.d.active) return;
        auto& c=r.conns[h.slot]; auto& peer=r.peer.streams.at(c.local_port);
        const size_t credit=c.rx_limit-peer.next;
        check(credit<=c.rx_capacity,"peer never exceeds advertised receive credit");
        const size_t n=std::min({credit,server.output.size(),size_t(127)}); if(!n) return;
        Bytes payload; for(size_t i=0;i<n;++i) { payload.push_back(server.output.front()); server.output.pop_front(); }
        send(r.peer,c.local_port,payload,peer.host_next);
    }
    int step() {
        server.step(); inject_output(); const auto reads=r.peer.reads,writes=r.peer.writes;
        const int s=lockdown_tls_poll(&tls,r.now++);
        check(r.peer.reads-reads<=1 && r.peer.writes-writes<=1,"bounded physical callbacks per TLS poll");
        r.canaries(); return s;
    }
    template<class P> void until(P predicate) {
        for(unsigned i=0;i<20000 && !predicate();++i) {
            const int s=step();
            if(s==LOCKDOWN_TLS_CLOSED && !predicate()) throw std::runtime_error("TLS closed unexpectedly: reason="+std::to_string(tls.reason)+" error="+std::to_string(tls.last_error)+" server="+std::to_string(server.error));
            check(s==0 || s==IAP2_MORE || s==USBMUX_DISPATCHER_CONTROL || (s==LOCKDOWN_TLS_CLOSED && predicate()),"TLS expected state");
        }
        check(predicate(),"bounded TLS event loop");
    }
    void ready() { until([&]{return tls.state==LOCKDOWN_TLS_OPEN && server.ready();}); }
    void dead() { until([&]{return tls.state==LOCKDOWN_TLS_DEAD;}); check(r.peer.cancelled.size()==1,"failure cancels shared generation once"); }
    Bytes read(size_t total) {
        Bytes result; until([&]{
            uint8_t buf[79]; size_t n; int s=lockdown_tls_read(&tls,buf,sizeof buf,&n,r.now);
            check(s==0 || s==IAP2_MORE,"decrypted prefix read"); result.insert(result.end(),buf,buf+n); return result.size()>=total;
        }); return result;
    }
};
