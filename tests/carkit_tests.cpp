#include "support/carkit_fixture.h"
static void protected_queries_and_tokens(Identities& ids) {
    ClientRig r(ids); r.reply_chunk=1; r.expect(fixture("get-product-type.xml"),binary_product_fixture());
    const auto k=bytes("ProductType"); const auto key=view(k);
    check(lockdown_client_get_value(&r.client,&key,nullptr,SERVICE_PLIST_STRING,r.base.r.now)==0,"queue protected GetValue");
    check(lockdown_client_get_value(&r.client,&key,nullptr,SERVICE_PLIST_STRING,r.base.r.now)==LOCKDOWN_CLIENT_BUSY,"one RPC in flight");
    r.until([&]{return r.client.state==LOCKDOWN_CLIENT_HELD;});
    const auto token=r.event(); check(r.client.reply.value && r.client.reply.value->type==SERVICE_PLIST_STRING,"typed binary value");
    const auto before=snapshot(r.client);
    check(lockdown_client_release(&r.client,token+1,UINT64_MAX)==USBMUX_DISPATCHER_STALE && snapshot(r.client)==before,"wrong token rejects future clock");
    check(lockdown_client_release(&r.client,token,r.base.r.now)==0,"explicit response release");
    r.base.server.plaintext.clear(); r.reply_chunk=4096;
    r.expect(fixture("start-service.xml"),service_reply()); r.service();
    r.until([&]{return r.client.state==LOCKDOWN_CLIENT_HELD;});
    check(r.event()!=token && r.client.reply.port==54321 && r.client.reply.tls_required,"next command owns new token and typed port");
}
static void ack_and_coalesced_tail(Identities& ids) {
    ClientRig r(ids); r.ack=false; r.expect(fixture("start-service.xml"),service_reply()); r.service();
    r.until([&]{return r.client.used==r.client.expected_size && r.client.used>4;});
    check(r.client.state==LOCKDOWN_CLIENT_EXCHANGE && r.base.r.conns[r.base.h.slot].flight_count,"complete verified response does not waive TCP ACK");
    const auto port=r.base.r.conns[r.base.h.slot].local_port; auto& p=r.base.r.peer.streams.at(port);
    send(r.base.r.peer,port,{},p.host_next); r.ack=true;
    r.until([&]{return r.client.state==LOCKDOWN_CLIENT_HELD;});
    check(lockdown_client_release(&r.client,r.event(),r.base.r.now)==0,"ACK-gated reply release");
    r.base.server.plaintext.clear(); auto both=framed(service_reply()); const auto extra=framed(service_reply(1234)); both.insert(both.end(),extra.begin(),extra.end());
    r.expect(fixture("start-service.xml"),both,true); r.service(); r.until([&]{return r.client.state==LOCKDOWN_CLIENT_HELD;});
    check(r.client.reply.port==54321 && r.base.tls.rx_size>r.base.tls.rx_offset,"following frame preserved outside owned response");
    check(lockdown_client_release(&r.client,r.event(),r.base.r.now)==0,"release first coalesced reply");
    const auto name=bytes("com.apple.carkit.service"); const auto svc=view(name);
    check(lockdown_client_start_service(&r.client,&svc,r.base.r.now)==LOCKDOWN_CLIENT_CLOSED,"known unsolicited tail cannot be attributed to new RPC");
}
static void response_failures(Identities& ids) {
    std::vector<Bytes> bad={service_reply(0),service_reply(65536),xml("StartService","<key>Port</key><string>1234</string>"),
        xml("StartService","<key>Port</key><integer>1234</integer><key>EnableServiceSSL</key><string>true</string>"),
        xml("GetValue","<key>Value</key><string>wrong request</string>"),
        xml("StartService","<key>Port</key><integer>1234</integer><key>Port</key><integer>1235</integer>")};
    for(const auto& body:bad) {
        ClientRig r(ids); r.expect(fixture("start-service.xml"),body); r.service(); r.until([&]{return r.client.state==LOCKDOWN_CLIENT_DEAD;});
        check(r.client.reason==LOCKDOWN_CLIENT_REASON_RESPONSE && !r.client.reply.port,"malformed/mismatched response has no usable port");
    }
    for(const Bytes prefix:{Bytes{0,0,0,0},Bytes{0,1,0,1}}) {
        ClientRig r(ids); r.expect(fixture("start-service.xml"),prefix,true); r.service(); r.until([&]{return r.client.state==LOCKDOWN_CLIENT_DEAD;});
        check(r.client.reason==LOCKDOWN_CLIENT_REASON_RESPONSE,"frame length rejected before body");
    }
    for(unsigned mode=0;mode<2;++mode) {
        ClientRig r(ids,mode==0?16:65540,mode==1?1:256); r.expect(fixture("start-service.xml"),service_reply()); r.service();
        r.until([&]{return r.client.state==LOCKDOWN_CLIENT_DEAD;}); check(r.client.last_error==IAP2_NO_SPACE,"response/parser capacity enforced");
    }
}
static void service_success(Identities& ids) {
    for(int ssl:{1,0,-1}) {
        CarkitRig r(ids,ssl!=1); r.expect(fixture("start-service.xml"),ssl==1?binary_fixture("service_tls"):service_reply(54321,ssl)); r.open(ids);
        size_t n=99; const Bytes early{1,2,3};
        check(carkit_write(&r.channel,early.data(),early.size(),&n,r.base.r.now)==CARKIT_BUSY && !n,"no service application bytes during startup");
        r.ready(); const auto remote=r.base.r.conns[r.channel.handle.slot].remote_port;
        check(remote==r.channel.port && remote!=62078 && r.channel.handle.slot!=r.base.h.slot,"validated service port opens distinct stream");
        check((ssl==1 && r.service_tls.state==LOCKDOWN_TLS_OPEN && r.service_server.ready() && !r.service_tls.session_id_size) ||
              (ssl!=1 && !r.service_tls.initialized),"real second TLS handshake or explicitly reported plain mode; no fake SessionID");
        iap2_frame frame{0x40,17,16,1,1,early.data(),early.size()}; Bytes raw(64); size_t count;
        check(iap2_frame_encode(&frame,raw.data(),raw.size(),&count)==0,"iAP2 wire fixture encode"); raw.resize(count);
        check(carkit_write(&r.channel,raw.data(),raw.size(),&n,r.base.r.now)==0 && n==raw.size(),"raw iAP2 write, no plist envelope");
        r.until([&]{return ssl==1?r.service_server.plaintext==raw:r.raw_received==raw;});
        if(ssl==1) r.service_server.pending=raw;
        Bytes received; r.until([&]{uint8_t data[3]; size_t got; check(carkit_read(&r.channel,data,sizeof data,&got,r.base.r.now)>=0,"service prefix read"); received.insert(received.end(),data,data+got); return received.size()==raw.size();});
        check(received==raw,"raw iAP2 round trip exact");
        if(ssl==1) {
            const auto& wire=r.base.r.peer.streams.at(r.base.r.conns[r.channel.handle.slot].local_port).received;
            check(std::search(wire.begin(),wire.end(),raw.begin(),raw.end())==wire.end(),"TLS service does not emit plaintext iAP2");
        }
        check(r.client.state==LOCKDOWN_CLIENT_IDLE && r.base.tls.state==LOCKDOWN_TLS_OPEN,"protected Lockdown retained beside carkit");
        carkit_close(&r.channel); carkit_close(&r.channel); check(r.base.r.peer.cancelled.size()==1,"both stream owners close once");
    }
}
static void service_policy_and_errors(Identities& ids) {
    for(int mode:{0,-1,2}) {
        CarkitRig r(ids); r.expect(fixture("start-service.xml"),service_reply(mode==2?62078:54321,mode==2?1:mode)); r.open(ids); r.dead();
        check(r.channel.reason==CARKIT_REASON_POLICY && r.base.r.d.next_connection==1,"policy rejects before allocating service connection");
    }
    {
        CarkitRig r(ids); r.expect(fixture("start-service.xml"),xml("StartService","<key>Error</key><string>InvalidService</string><key>Port</key><integer>54321</integer>")); r.open(ids);
        r.until([&]{return r.channel.state==CARKIT_ERROR_HELD;}); r.event(LOCKDOWN_REPLY_REMOTE_ERROR);
        check(!r.client.reply.port && r.client.reply.error && r.base.r.d.next_connection==1,"remote error stays explicit, never opens port or retries");
        r.dead(); check(r.channel.reason==CARKIT_REASON_LOCKDOWN,"held remote error has bounded lifetime");
    }
    {
        CarkitRig r(ids,false,&ids.other); r.expect(fixture("start-service.xml"),service_reply());
        carkit_config cfg{}; carkit_default_config(&cfg); cfg.policy=CARKIT_ALLOW_PLAIN_IF_REPORTED; r.open(ids,cfg,false); r.dead();
        check(r.channel.reason==CARKIT_REASON_TLS && r.service_server.plaintext.empty(),"bad service certificate never downgrades even when plain mode was allowed");
    }
}
static void lifetimes_and_bounds(Identities& ids) {
    {
        CarkitRig r(ids); carkit_config cfg{}; carkit_default_config(&cfg); cfg.startup_ms=200;
        r.expect(fixture("start-service.xml"),service_reply()); r.open(ids,cfg,false); r.drop_syn=true; r.dead();
        check(r.channel.reason==CARKIT_REASON_DEADLINE,"absolute service startup timeout includes port open");
    }
    {
        CarkitRig r(ids); r.expect(fixture("start-service.xml"),service_reply()); r.open(ids); r.ready();
        usbmux_dispatcher_close(&r.base.r.d); r.base.r.start(2); const auto now=r.base.r.d.now, count=r.base.r.peer.cancelled.size();
        check(carkit_poll(&r.channel,UINT64_MAX)==CARKIT_CLOSED,"stale two-stream owner fails before clock"); carkit_close(&r.channel);
        check(r.base.r.d.active && r.base.r.d.now==now && r.base.r.peer.cancelled.size()==count,"old carkit close cannot cancel new generation");
    }
    {
        ClientRig r(ids,65540,256,{150,100}); r.expect(fixture("start-service.xml"),Bytes{},true); r.service();
        r.until([&]{return r.client.state==LOCKDOWN_CLIENT_DEAD;}); check(r.client.reason==LOCKDOWN_CLIENT_REASON_DEADLINE,"protected request has absolute exchange budget");
    }
    {
        ClientRig r(ids,65540,256,{10000,100}); r.expect(fixture("start-service.xml"),service_reply()); r.service(); r.until([&]{return r.client.state==LOCKDOWN_CLIENT_HELD;});
        const auto token=r.event(), reads=r.base.r.peer.reads,writes=r.base.r.peer.writes;
        check(lockdown_client_release(&r.client,token,r.client.held_at+100)==LOCKDOWN_CLIENT_CLOSED,"expired release cannot authorize service open");
        check(r.base.r.peer.reads==reads && r.base.r.peer.writes==writes,"expired release checks timers without backend I/O");
    }
    {
        ClientRig r(ids); const auto creds=ids.credentials(); carkit c{}; lockdown_tls tls{}; carkit_config cfg{}; carkit_default_config(&cfg);
        cfg.policy=static_cast<carkit_policy>(99); const auto before=snapshot(r.client);
        check(carkit_open(&c,&r.client,&tls,&creds,&cfg,UINT64_MAX)==IAP2_ARGUMENT && snapshot(r.client)==before,"invalid carkit config transactional before clock");
        check(lockdown_tls_init_service(&tls,&r.base.r.d,&r.base.h,&creds,&cfg.tls,r.base.r.now)==IAP2_UNSUPPORTED,"service TLS initializer cannot bypass Lockdown startup");
        lockdown_client duplicate{}; const auto label_bytes=bytes("gt86-research"),name=bytes("com.apple.carkit.service"); const auto label=view(label_bytes),svc=view(name);
        check(lockdown_client_start_service(&r.client,&svc,r.base.r.now)==0,"initial application request");
        service_plist_storage storage{r.nodes.data(),r.nodes.size(),r.arena.data()+1,r.arena.size()-2};
        check(lockdown_client_init(&duplicate,&r.base.tls,&label,r.request.data()+1,4096,r.response.data()+1,65540,&storage,&r.client.config,r.base.r.now)==LOCKDOWN_CLIENT_BUSY,"cannot rebind used TLS app stream as fresh RPC session");
    }
}
static void identity_and_close_boundaries(Identities& ids) {
    {
        CarkitRig r(ids); r.expect(fixture("start-service.xml"),service_reply());
        auto creds=ids.credentials(); creds.host_certificate=view(ids.other.der); creds.host_private_key=view(ids.other.pem_key);
        carkit_config cfg{}; carkit_default_config(&cfg);
        check(carkit_open(&r.channel,&r.client,&r.service_tls,&creds,&cfg,r.base.r.now)==0,"queue service with explicit but mismatched host identity");
        r.dead(); check(r.channel.reason==CARKIT_REASON_TLS && r.channel.last_error==IAP2_AUTH_FAILED && r.service_server.input.empty(),"parsed pairing identity mismatch rejected before service ClientHello");
    }
    for(unsigned which=0;which<2;++which) {
        CarkitRig r(ids); r.expect(fixture("start-service.xml"),service_reply()); r.open(ids); r.ready();
        crypto(mbedtls_ssl_close_notify(which?&r.service_server.ssl:&r.base.server.ssl),"authenticated stream closure");
        r.dead(); check(r.channel.reason==(which?CARKIT_REASON_TLS:CARKIT_REASON_LOCKDOWN),"either stream closure terminates retained two-stream owner");
    }
    {
        CarkitRig r(ids,true); r.expect(fixture("start-service.xml"),service_reply(54321,0)); r.open(ids); r.ready();
        auto& p=r.base.r.peer.streams.at(r.base.r.conns[r.channel.handle.slot].local_port);
        send(r.base.r.peer,r.base.r.conns[r.channel.handle.slot].local_port,{},p.host_next,true);
        r.until([&]{return r.base.r.conns[r.channel.handle.slot].peer_fin!=0;});
        uint8_t out[4]; size_t n=99;
        check(carkit_read(&r.channel,out,sizeof out,&n,r.base.r.now)==CARKIT_CLOSED && !n,"plain service EOF closes both owners without phantom bytes");
    }
}
int main(int argc,char **argv) {
    try {
        check(argc==2,"fixture directory"); fixtures=argv[1]; Identities ids;
        protected_queries_and_tokens(ids); ack_and_coalesced_tail(ids); response_failures(ids);
        service_success(ids); service_policy_and_errors(ids); lifetimes_and_bounds(ids); identity_and_close_boundaries(ids);
        std::cout<<"PASS: 7 protected RPC/carkit groups; real dual TLS or explicit plain service; client="<<sizeof(lockdown_client)<<" carkit="<<sizeof(carkit)<<" TLS="<<sizeof(lockdown_tls)<<" bytes plus caller buffers/crypto heap\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
