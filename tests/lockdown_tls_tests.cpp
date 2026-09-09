#include "support/tls_fixture.h"
static void encrypted_exchange(Identities& ids) {
    for(const uint32_t segment:{1u,128u,512u}) {
        Rig rig(ids,nullptr,false,4096,segment); rig.init(ids.credentials());
        const auto early=bytes("must not be plaintext");
        check(lockdown_tls_write(&rig.tls,early.data(),early.size(),rig.r.now)==LOCKDOWN_TLS_BUSY,"no pre-handshake app writes");
        if(segment==1) { rig.r.peer.read_limit=1024; rig.r.peer.write_limit=65536; }
        rig.ready();
        check(std::string(mbedtls_ssl_get_version(&rig.tls.ssl))=="TLSv1.2" && !mbedtls_ssl_get_verify_result(&rig.tls.ssl),"real verified TLS 1.2");
        check(!mbedtls_ssl_get_verify_result(&rig.server.ssl),"server verified mutual client certificate");
        auto message=framed(fixture("start-service.xml")); const auto expected=message;
        check(lockdown_tls_write(&rig.tls,message.data(),message.size(),rig.r.now)==0,"queue encrypted service bytes");
        std::fill(message.begin(),message.end(),0); // Owned retry buffer, caller can release immediately.
        check(lockdown_tls_write(&rig.tls,early.data(),early.size(),rig.r.now)==LOCKDOWN_TLS_BUSY,"pending write cannot be replaced");
        rig.until([&]{return rig.server.plaintext==expected && !rig.tls.tx_size;});
        const auto& on_wire=rig.r.peer.streams.at(rig.r.conns[rig.h.slot].local_port).received;
        check(std::search(on_wire.begin(),on_wire.end(),expected.begin(),expected.end())==on_wire.end(),"StartService frame absent from raw USBmux ciphertext");
        const auto response=framed(binary_fixture("service_tls")); rig.server.pending=response;
        check(rig.read(response.size())==response,"encrypted binary service response exact after fragmented BIO/TCP/raw I/O");
        check(lockdown_tls_next_delay(&rig.tls)<=5,"bounded scheduler retry");
        lockdown_tls_close(&rig.tls); lockdown_tls_close(&rig.tls);
        check(rig.r.peer.cancelled.size()==1 && rig.tls.tx_size==0 && rig.tls.rx_size==0,"idempotent close frees/clears buffers");
    }
}
static void credential_rejection(Identities& ids) {
    for(unsigned mode=0;mode<5;++mode) {
        Rig rig(ids,mode==2?&ids.expired:nullptr,mode==4); auto creds=ids.credentials();
        if(mode==0) creds.device_der=view(ids.other.der);
        if(mode==1) creds.root=view(ids.alien.der);
        if(mode==2) creds.device_der=view(ids.expired.der);
        if(mode==3) { creds.host_certificate=view(ids.alien.der); creds.host_private_key=view(ids.alien.pem_key); }
        rig.init(creds); rig.dead();
        check(rig.tls.state!=LOCKDOWN_TLS_OPEN && rig.server.plaintext.empty(),"untrusted/expired/client rejected/incompatible TLS never delivers plaintext");
    }
}
static void rsa_mutual_authentication(Identities& ids) {
    Identity host(ids.rng,"CN=GT86 synthetic RSA host",7,&ids.root,false,true);
    Identity device(ids.rng,"CN=GT86 synthetic RSA device",8,&ids.root,false,true);
    Rig rig(ids,&device); auto creds=ids.credentials();
    creds.host_certificate=view(host.der); creds.host_private_key=view(host.pem_key); creds.device_der=view(device.der);
    rig.init(creds); rig.ready();
    const std::string suite=mbedtls_ssl_get_ciphersuite(&rig.tls.ssl);
    check(suite=="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256" || suite=="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384","RSA-authenticated ECDHE/AES-GCM negotiated");
    check(!mbedtls_ssl_get_verify_result(&rig.server.ssl),"RSA client certificate verified");
}
static void small_buffers_and_shared_mux(Identities& ids) {
    Rig rig(ids,nullptr,false,256,128); rig.init(ids.credentials());
    const auto other=rig.r.open(62079);
    rig.until([&]{return rig.r.conns[other.slot].state==USBMUX_CONNECTION_OPEN;});
    rig.r.peer.inject(packet(USBMUX_CONTROL,{5,'t'}));
    rig.until([&]{return rig.r.d.control_pending!=0;});
    const usbmux_frame *frame; uint64_t token;
    check(usbmux_dispatcher_control(&rig.r.d,&frame,&token)==USBMUX_DISPATCHER_CONTROL,"CONTROL survives active TLS handshake");
    check(usbmux_dispatcher_release_control(&rig.r.d,rig.h.physical,token,rig.r.now)==0,"explicit CONTROL release");
    rig.ready();
    Bytes bulk(4096); for(size_t i=0;i<bulk.size();++i) bulk[i]=static_cast<uint8_t>(i*37u);
    check(lockdown_tls_write(&rig.tls,bulk.data(),bulk.size(),rig.r.now)==0,"maximum-size app write on minimum RX ring");
    rig.until([&]{return rig.server.plaintext==bulk && !rig.tls.tx_size;});
    rig.server.pending=bulk;
    check(rig.read(bulk.size())==bulk,"record larger than TLS app and TCP RX buffers remains exact");
    const auto noise=bytes("unrelated stream stays usable");
    check(rig.r.write(other,noise)==noise.size(),"other stream accepts data alongside TLS");
    rig.until([&]{return rig.r.conns[other.slot].tx_size==0 && rig.r.conns[other.slot].flight_count==0;});
    check(rig.r.peer.streams.at(rig.r.conns[other.slot].local_port).received==noise,"independent port routing");
    // A deadline on an unrelated stream must be enforced by timed TLS APIs,
    // even when they would otherwise return an empty read. First drain all ACKs.
    rig.until([&]{return !rig.r.d.owner && !rig.r.host.tx_size && !rig.r.conns[rig.h.slot].tx_size &&
        !rig.r.conns[rig.h.slot].flight_count && !rig.r.conns[other.slot].tx_size && rig.r.peer.incoming.empty();});
    rig.r.peer.on_data=[&](Peer& peer,uint16_t port,const Bytes& data) {
        if(port==rig.r.conns[rig.h.slot].local_port) {
            rig.server.input.insert(rig.server.input.end(),data.begin(),data.end()); send(peer,port,{},peer.streams.at(port).host_next);
        }
    };
    check(rig.r.write(other,noise)==noise.size(),"other stream unacknowledged write");
    rig.until([&]{return rig.r.conns[other.slot].flight_count!=0 && !rig.r.d.owner;});
    const auto& c=rig.r.conns[other.slot]; const auto expiry=c.flights[c.flight_head].sent_at+c.config.ack_ms;
    uint8_t out[4]; size_t n=99;
    check(lockdown_tls_read(&rig.tls,out,sizeof out,&n,expiry)==LOCKDOWN_TLS_CLOSED && !n && rig.r.d.failed_slot==other.slot,
          "timed TLS read checks unrelated ACK deadline without physical I/O");
}
static void invalid_init_and_rng(Identities& ids) {
    Rig rig(ids); const auto before=snapshot(rig.handoff); const auto empty=snapshot(rig.tls); auto creds=ids.credentials();
    lockdown_tls_config cfg{10000,5000,5000};
    for(unsigned i=0;i<6;++i) {
        auto bad=creds;
        if(i==0) bad.random=nullptr;
        if(i==1) bad.root.size=32769;
        if(i==2) bad.device_der.size=0;
        if(i==3) bad.host_private_key.size=16385;
        if(i==4) bad.host_certificate.data=nullptr;
        if(i==5) bad.device_der.size=16385;
        check(lockdown_tls_init(&rig.tls,&rig.handoff,&bad,&cfg,rig.r.now)==IAP2_ARGUMENT && snapshot(rig.tls)==empty,"argument bounds transactional before parse");
    }
    creds.host_private_key=view(ids.other.pem_key);
    const auto reads=rig.r.peer.reads,writes=rig.r.peer.writes;
    check(lockdown_tls_init(&rig.tls,&rig.handoff,&creds,&cfg,rig.r.now)!=0 && !rig.tls.initialized && snapshot(rig.handoff)==before,"mismatched client key rejected without consuming handoff");
    auto malformed=ids.credentials(); const Bytes junk={1,2,3,4}; malformed.root=view(junk);
    check(lockdown_tls_init(&rig.tls,&rig.handoff,&malformed,&cfg,rig.r.now)!=0 && !rig.tls.initialized,"malformed certificate releases partial crypto");
    check(rig.r.peer.reads==reads && rig.r.peer.writes==writes && rig.r.peer.cancelled.empty(),"invalid init never touches transport");
    rig.init(ids.credentials()); ids.rng.fail=true; rig.dead(); ids.rng.fail=false;
    check(rig.tls.reason==LOCKDOWN_TLS_REASON_CRYPTO && rig.server.plaintext.empty(),"RNG failure has no secure fallback");
}
static void deadlines_and_stale(Identities& ids) {
    {
        Rig rig(ids); rig.init(ids.credentials(),{200,100,100}); rig.server.disabled=true;
        check(lockdown_tls_poll(&rig.tls,rig.r.now-1)==IAP2_ARGUMENT,"decreasing time rejected");
        rig.dead(); check(rig.tls.reason==LOCKDOWN_TLS_REASON_DEADLINE,"absolute handshake deadline");
    }
    {
        Rig rig(ids); rig.init(ids.credentials(),{10000,100,100}); rig.ready();
        rig.r.peer.block_write=true; Bytes message(4096,0x51);
        check(lockdown_tls_write(&rig.tls,message.data(),message.size(),rig.r.now)==0,"queue maximum stable write");
        rig.dead(); check(rig.tls.reason==LOCKDOWN_TLS_REASON_DEADLINE,"pending TLS write deadline independent of partial progress");
    }
    {
        Rig rig(ids); rig.init(ids.credentials(),{10000,5000,100}); rig.ready();
        rig.server.pending=bytes("held authenticated plaintext"); rig.until([&]{return rig.tls.rx_size!=0;});
        const auto at=rig.tls.held_at; uint8_t byte; size_t n;
        check(lockdown_tls_read(&rig.tls,&byte,1,&n,rig.r.now)==0 && n==1 && rig.tls.held_at==at,"partial consumption never renews hold timer");
        rig.dead(); check(rig.tls.reason==LOCKDOWN_TLS_REASON_DEADLINE,"held plaintext deadline");
    }
    {
        Rig rig(ids); rig.init(ids.credentials()); rig.ready();
        usbmux_dispatcher_close(&rig.r.d); rig.r.start(2); const auto now=rig.r.d.now, cancelled=rig.r.peer.cancelled.size();
        check(lockdown_tls_poll(&rig.tls,UINT64_MAX)==LOCKDOWN_TLS_CLOSED && rig.tls.reason==LOCKDOWN_TLS_REASON_STALE,"old TLS owner rejected before future clock");
        lockdown_tls_close(&rig.tls);
        check(rig.r.d.active && rig.r.d.now==now && rig.r.peer.cancelled.size()==cancelled,"old close cannot cancel new physical generation");
    }
}
static void corruption_and_eof(Identities& ids) {
    for(unsigned mode=0;mode<3;++mode) {
        Rig rig(ids); rig.init(ids.credentials()); rig.ready();
        if(mode==0) {
            rig.server.pending=bytes("authenticated secret must never escape corrupted record"); rig.server.step();
            check(!rig.server.output.empty(),"encrypted server application record"); rig.server.output.back()^=0x80;
        } else if(mode==1) {
            auto& p=rig.r.peer.streams.at(rig.r.conns[rig.h.slot].local_port);
            send(rig.r.peer,rig.r.conns[rig.h.slot].local_port,{},p.host_next,true);
        } else crypto(mbedtls_ssl_close_notify(&rig.server.ssl),"encrypted close_notify");
        rig.dead();
        check(!rig.tls.rx_size,"no plaintext exposed after corruption/EOF/close");
        check(rig.tls.reason==(mode==0?LOCKDOWN_TLS_REASON_CRYPTO:mode==1?LOCKDOWN_TLS_REASON_TRUNCATED:LOCKDOWN_TLS_REASON_PEER_CLOSE),"authenticated closure distinct from truncation or bad AEAD");
    }
}
int main(int argc,char **argv) {
    try {
        check(argc==2,"fixture directory argument"); fixtures=argv[1]; Identities ids;
        encrypted_exchange(ids); rsa_mutual_authentication(ids); credential_rejection(ids); small_buffers_and_shared_mux(ids); invalid_init_and_rng(ids); deadlines_and_stale(ids); corruption_and_eof(ids);
        std::cout<<"PASS: 7 TLS groups (real EC/RSA mutual handshakes, encrypted framing, trust/key/RNG failures, small buffers/shared mux, deadlines/stale, corruption/EOF); context="<<sizeof(lockdown_tls)<<" bytes plus Mbed TLS heap\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
