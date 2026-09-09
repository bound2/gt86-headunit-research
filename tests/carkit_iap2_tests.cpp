// SPDX-License-Identifier: GPL-3.0-only
// Actual TLS, synthetic USB/iAP2 peer and synthetic accessory-auth provider.
#include "carkit_iap2.h"
#include "iap2_carplay.h"
#include "iap2_power.h"
#include "support/carkit_fixture.h"
#include <memory>
static Bytes message(uint16_t id,const Bytes *body=nullptr) {
    const iap2_param param{0,body?body->data():nullptr,body?body->size():0}; Bytes out(4096); size_t n;
    check(iap2_message_encode(id,body?&param:nullptr,body?1:0,out.data(),out.size(),&n)==0,"synthetic CSM encode"); out.resize(n); return out;
}
struct Session {
    CarkitRig wire; iap2_control endpoint{}; carkit_iap2 bridge{}; iap2_link peer{};
    iap2_control_config config{}; iap2_transport_config pump_config{};
    std::array<uint8_t,4098> receive{},reply{},scratch{};
    unsigned certificates=0,signatures=0,stage=0; bool fail_provider=false,run_peer=true,full=false,requested=false,ack_service=true;
    bool power_queued=false,app_queued=false,replied=false; uint32_t old_ack=0;
    Bytes signed_challenge,peer_input,peer_output,received,information,app_request,app_reply;
    const Bytes certificate_bytes=Bytes(257,0x37),signature_bytes=Bytes(32,0x52),challenge=Bytes(16,0x71);
    const Bytes power_bytes{0x40,0x40,0,17,0xae,3,0,6,0,0,0,0,0,5,0,1,0};
    iap2_carplay_wired_start wired_start{};
    static int certificate(void *ctx,uint8_t *out,size_t cap,size_t *n) {
        auto& s=*static_cast<Session*>(ctx); ++s.certificates;
        if(s.fail_provider) return IAP2_PROVIDER_FAILED;
        check(cap>=s.certificate_bytes.size(),"provider capacity"); std::copy(s.certificate_bytes.begin(),s.certificate_bytes.end(),out); *n=s.certificate_bytes.size(); return 0;
    }
    static int sign(void *ctx,const uint8_t *data,size_t size,uint8_t *out,size_t cap,size_t *n) {
        auto& s=*static_cast<Session*>(ctx); ++s.signatures; s.signed_challenge.assign(data,data+size);
        check(cap>=s.signature_bytes.size(),"signature capacity"); std::copy(s.signature_bytes.begin(),s.signature_bytes.end(),out); *n=s.signature_bytes.size(); return 0;
    }
    explicit Session(Identities& ids,bool plain=false,bool enable=true,uint32_t send_limit=128,bool bind=true):wire(ids,plain,nullptr,send_limit) {
        wire.expect(fixture("start-service.xml"),service_reply(54321,plain?0:1)); wire.open(ids); wire.ready();
        wire.until([&]{return carkit_write_drained(&wire.channel,wire.base.r.now)==0;});
        receive.fill(0xa5); reply.fill(0xa5); scratch.fill(0xa5);
        iap2_control_default_config(&config); config.startup_order=IAP2_CONTROL_IDENTIFICATION_FIRST; config.link.offer.packet_size=64;
        const iap2_auth_provider provider{this,certificate,sign};
        const iap2_control_buffers buffers{receive.data()+1,reply.data()+1,scratch.data()+1,4096,4096,4086};
        check(iap2_control_init(&endpoint,&config,&provider,&buffers)==0,"receiver endpoint init");
        if(enable) identify();
        iap2_transport_default_config(&pump_config);
        if(bind) check(carkit_iap2_init(&bridge,&wire.channel,&endpoint,&pump_config)==0,"bind unused carkit to existing pump");
        old_ack=wire.base.r.conns[wire.channel.handle.slot].tx_una;
        wire.base.r.peer.on_data=[this](Peer& p,uint16_t port,const Bytes& data) {
            if(port==wire.base.r.conns[wire.base.h.slot].local_port) {
                wire.base.server.input.insert(wire.base.server.input.end(),data.begin(),data.end()); send(p,port,{},p.streams.at(port).host_next);
            } else {
                if(wire.plain) peer_input.insert(peer_input.end(),data.begin(),data.end());
                else wire.service_server.input.insert(wire.service_server.input.end(),data.begin(),data.end());
                if(ack_service) send(p,port,{},p.streams.at(port).host_next);
            }
        };
        const auto available=Bytes{0,5,0,0,1}; app_request=message(0x4300,&available);
        wired_start.address_count=1; wired_start.addresses[0]={"fe80::1",7}; wired_start.has_port=1; wired_start.port=5000;
        wired_start.device_identifier={"PC-TEST",7}; wired_start.public_key={"00",2}; wired_start.source_version={"test-1",6};
        // Advertised test address/key are deliberately synthetic; no listener/media server is supplied.
        app_reply.resize(1024); size_t n; check(iap2_carplay_wired_start_encode(&wired_start,app_reply.data(),app_reply.size(),&n)==0,"wired-start expected fixture"); app_reply.resize(n);
    }
    ~Session() { carkit_iap2_close(&bridge); }
    void identify() {
        const auto span=[](const char *s){return iap2_identification_text{s,std::strlen(s)};};
        iap2_identification_metadata m{};
        m.name=span("PC TEST ONLY"); m.model=span("SYNTHETIC"); m.manufacturer=span("Test fixture"); m.serial=span("NOT-A-DEVICE-SERIAL");
        m.firmware=span("test-1"); m.hardware=span("none"); m.current_language=m.languages[0]=span("en"); m.languages[1]=span("de"); m.language_count=2; m.power_capability=2;
        const iap2_identification_wired wired{7,span("USB TEST ONLY"),4}; information.resize(1024); size_t n;
        check(iap2_identification_encode_wired(&m,&wired,information.data(),information.size(),&n)==0 &&
              iap2_control_enable_wired_identification(&endpoint,&m,&wired)==0,"explicit wired identification"); information.resize(n);
    }
    void start() {
        const auto reads=wire.base.r.peer.reads,writes=wire.base.r.peer.writes;
        check(carkit_iap2_start(&bridge,73,wire.base.r.now)==0,"one-shot endpoint start");
        check(wire.base.r.peer.reads==reads && wire.base.r.peer.writes==writes,"start does not call physical backend");
        auto peer_config=config.link; peer_config.initial_sequence=42;
        check(iap2_link_init(&peer,&peer_config)==0 && iap2_link_start(&peer,wire.base.r.now)==0,"synthetic phone link start");
    }
    void inject_service(Bytes& bytes) {
        if(bytes.empty() || !wire.base.r.d.active) return;
        auto& c=wire.base.r.conns[wire.channel.handle.slot]; auto& p=wire.base.r.peer.streams.at(c.local_port);
        const size_t credit=c.rx_limit-p.next; check(credit<=c.rx_capacity,"peer credit");
        const size_t n=std::min({credit,bytes.size(),size_t(113)}); if(!n) return;
        send(wire.base.r.peer,c.local_port,Bytes(bytes.begin(),bytes.begin()+n),ack_service?p.host_next:old_ack); bytes.erase(bytes.begin(),bytes.begin()+n);
    }
    void queue(const Bytes& body) { check(iap2_link_send(&peer,10,body.data(),body.size(),wire.base.r.now)==0,"peer control message queue"); }
    void protocol_peer() {
        size_t used;
        const int s=iap2_link_feed(&peer,peer_input.data(),peer_input.size(),&used,wire.base.r.now);
        check(s==0 || s==IAP2_LINK_BUSY,"peer consumes raw iAP2 stream"); peer_input.erase(peer_input.begin(),peer_input.begin()+used);
        if(full && peer.state==IAP2_LINK_NORMAL && !requested) { queue(message(0x1d00)); requested=true; }
        uint8_t session,data[1024]; size_t n;
        while(iap2_link_receive(&peer,&session,data,sizeof data,&n)==0) {
            check(session==10,"control session routing"); received.insert(received.end(),data,data+n);
        }
        while(full && received.size()>=6) {
            const size_t size=static_cast<size_t>(received[2])<<8|received[3]; if(received.size()<size) break;
            const Bytes body(received.begin(),received.begin()+size); received.erase(received.begin(),received.begin()+size);
            const Bytes expected=stage==0?information:stage==1?message(0xaa01,&certificate_bytes):stage==2?message(0xaa03,&signature_bytes):stage==3?power_bytes:app_reply;
            check(stage<=4 && body==expected,"full identification/auth/power/CarPlay reply matches expected bytes");
            if(stage==0) { auto combined=message(0x1d02); const auto cert=message(0xaa00); combined.insert(combined.end(),cert.begin(),cert.end()); queue(combined); }
            if(stage==1) queue(message(0xaa02,&challenge));
            if(stage==2) queue(message(0xaa05));
            ++stage;
        }
        if(peer_output.empty() && (wire.plain || (wire.service_server.pending.empty() && wire.service_server.output.empty()))) {
            const int out=iap2_link_output(&peer,data,sizeof data,&n,wire.base.r.now);
            check(out==0 || out==IAP2_MORE,"peer link output"); if(n) peer_output.assign(data,data+n);
        }
    }
    void server_step() {
        wire.server_step();
        if(!wire.plain) {
            wire.service_server.step(); peer_input.insert(peer_input.end(),wire.service_server.plaintext.begin(),wire.service_server.plaintext.end()); wire.service_server.plaintext.clear();
        }
        if(run_peer) protocol_peer();
        if(wire.plain) inject_service(peer_output);
        else {
            if(!peer_output.empty() && wire.service_server.pending.empty() && wire.service_server.output.empty()) { wire.service_server.pending=peer_output; peer_output.clear(); }
            Bytes ciphertext(wire.service_server.output.begin(),wire.service_server.output.end());
            const auto before=ciphertext.size(); inject_service(ciphertext);
            for(size_t i=0;i<before-ciphertext.size();++i) wire.service_server.output.pop_front();
        }
    }
    int at(uint64_t now,bool server=true) {
        if(server) server_step();
        const auto reads=wire.base.r.peer.reads,writes=wire.base.r.peer.writes;
        const int s=carkit_iap2_poll(&bridge,now);
        check(wire.base.r.peer.reads-reads<=2 && wire.base.r.peer.writes-writes<=2,"two physical polls maximum for full stack");
        check(receive.front()==0xa5 && receive.back()==0xa5 && reply.front()==0xa5 && reply.back()==0xa5 && scratch.front()==0xa5 && scratch[4087]==0xa5,"endpoint buffer canaries"); wire.canaries(); return s;
    }
    int step() { const int s=at(wire.base.r.now); ++wire.base.r.now; return s; }
    template<class P> void until(P p) {
        for(unsigned i=0;i<20000 && !p();++i) {
            const int s=step();
            if(s<0 && !p()) throw std::runtime_error("stack closed: bridge="+std::to_string(bridge.reason)+" pump="+std::to_string(bridge.pump.reason)+" endpoint="+std::to_string(endpoint.reason)+" link="+std::to_string(endpoint.link.reason)+" carkit="+std::to_string(wire.channel.reason));
        }
        check(p(),"bounded full-stack event loop");
    }
};
static void complete_startup(Identities& ids) {
    for(bool plain:{false,true}) {
        auto instance=std::make_unique<Session>(ids,plain); auto& s=*instance; s.full=true; s.start();
        for(unsigned i=0;i<15000 && s.stage<5;++i) {
            const int result=s.step();
            if(result<0) throw std::runtime_error("startup closed: "+std::to_string(s.bridge.reason)+" pump "+std::to_string(s.bridge.pump.reason)+" stage "+std::to_string(s.stage));
            if(s.endpoint.identification.state!=IAP2_IDENTIFICATION_ACCEPTED) check(!s.certificates && !s.signatures,"identification gates actual provider callbacks");
            if(s.stage==3 && s.endpoint.auth.state==IAP2_AUTH_ACCEPTED && !s.power_queued) {
                const iap2_power_source power{1,0,1,0}; check(iap2_power_source_notify(&s.endpoint,&power,s.wire.base.r.now)==0,"explicit zero-intent power notification"); s.power_queued=true;
            }
            if(s.stage==4 && !s.app_queued) { s.queue(s.app_request); s.app_queued=true; }
            if(result==IAP2_CONTROL_MESSAGE) {
                const uint8_t *data; size_t n;
                check(s.app_queued && !s.replied && iap2_control_message(&s.endpoint,&data,&n)==0 && Bytes(data,data+n)==s.app_request,"wired-start request delivered to application");
                check(iap2_carplay_reply_wired_start(&s.endpoint,&s.wired_start,s.wire.base.r.now)==0,"explicit wired-start response, no implied network listener"); s.replied=true;
            }
        }
        check(s.stage==5 && s.power_queued && s.replied && s.certificates==1 && s.signatures==1 && s.signed_challenge==s.challenge,"complete synthetic accessory auth and wired-start exchange");
        s.until([&]{return !s.endpoint.link.tx_count && !s.endpoint.reply_size && !s.bridge.pending_size && !s.bridge.pump.tx_size && !s.peer.tx_count;});
        check(s.endpoint.auth.state==IAP2_AUTH_ACCEPTED && s.endpoint.identification.state==IAP2_IDENTIFICATION_ACCEPTED,"both startup phases accepted only by protocol messages");
        carkit_iap2_close(&s.bridge); carkit_iap2_close(&s.bridge);
        check(s.wire.base.r.peer.cancelled.size()==1 && s.endpoint.auth.state==IAP2_AUTH_IDLE && !s.bridge.pending_size,"full stack cancellation clears auth and tails once");
    }
}
static void copied_is_not_completed(Identities& ids) {
    for(bool plain:{false,true}) {
        auto instance=std::make_unique<Session>(ids,plain); auto& s=*instance; s.ack_service=false; s.start();
        check(s.step()>=0 && s.bridge.pending_size==6 && !s.bridge.submitted && s.bridge.pump.tx_offset==0,"first callback owns marker copy but reports no completion");
        s.until([&]{return s.bridge.submitted==6 && s.wire.base.r.conns[s.wire.channel.handle.slot].flight_count!=0;});
        check(!s.bridge.complete && s.bridge.pump.tx_size==6 && !s.bridge.pump.tx_offset,"ciphertext/plain TCP flight is not a completed pump write");
        for(unsigned i=0;i<15;++i) check(s.step()>=0,"read-side peer progress while write credit held");
        check(!s.bridge.complete && s.bridge.pending_size==6,"lack of TCP ACK retains original frame");
        auto& p=s.wire.base.r.peer.streams.at(s.wire.base.r.conns[s.wire.channel.handle.slot].local_port);
        send(s.wire.base.r.peer,s.wire.base.r.conns[s.wire.channel.handle.slot].local_port,{},p.host_next); s.ack_service=true;
        s.until([&]{return s.endpoint.link.state==IAP2_LINK_NORMAL && !s.bridge.pending_size && !s.bridge.pump.tx_size;});
        check(s.wire.channel.application_used && carkit_write_drained(&s.wire.channel,s.wire.base.r.now)==0,"full copied prefix becomes credit only after drain");
    }
}
static void deadlines_before_physical_io(Identities& ids) {
    {
        auto instance=std::make_unique<Session>(ids); auto& s=*instance; s.start(); s.run_peer=false; s.step(); s.wire.base.r.peer.block_write=true;
        const auto deadline=s.bridge.pump.tx_at+s.bridge.pump.config.pending_ms;
        const auto reads=s.wire.base.r.peer.reads,writes=s.wire.base.r.peer.writes;
        check(s.at(deadline,false)==IAP2_LINK_CLOSED && s.bridge.pump.reason==IAP2_TRANSPORT_REASON_DEADLINE,"absolute retained marker deadline");
        check(s.wire.base.r.peer.reads==reads && s.wire.base.r.peer.writes==writes && s.wire.base.r.peer.cancelled.size()==1,"expired upper layer prevents lower physical I/O");
    }
    {
        auto instance=std::make_unique<Session>(ids); auto& s=*instance; s.start(); s.until([&]{return s.endpoint.link.state==IAP2_LINK_NORMAL && !s.bridge.pump.tx_size && !s.bridge.pending_size;});
        const auto deadline=s.endpoint.identification_at+s.endpoint.identification_ms;
        const auto reads=s.wire.base.r.peer.reads,writes=s.wire.base.r.peer.writes;
        check(s.at(deadline,false)==IAP2_LINK_CLOSED && s.endpoint.reason==IAP2_CONTROL_REASON_TIMEOUT,"eligible identification deadline enforced above TLS");
        check(s.wire.base.r.peer.reads==reads && s.wire.base.r.peer.writes==writes && !s.certificates,"phase timeout invokes neither USB I/O nor signer");
    }
}
static void generation_and_clock(Identities& ids) {
    {
        auto instance=std::make_unique<Session>(ids); auto& s=*instance; s.start(); s.step(); const auto before=snapshot(s.bridge);
        check(carkit_iap2_poll(&s.bridge,s.bridge.now-1)==IAP2_ARGUMENT && snapshot(s.bridge)==before,"decreasing time transactional");
        check(carkit_iap2_start(&s.bridge,74,s.wire.base.r.now)==IAP2_ARGUMENT,"no active restart");
        usbmux_dispatcher_close(&s.wire.base.r.d); s.wire.base.r.start(2); const auto now=s.wire.base.r.d.now, count=s.wire.base.r.peer.cancelled.size();
        check(carkit_iap2_poll(&s.bridge,UINT64_MAX)==IAP2_LINK_CLOSED && s.bridge.reason==CARKIT_IAP2_REASON_STALE,"stale service rejected before future time");
        check(s.wire.base.r.d.active && s.wire.base.r.d.now==now && s.wire.base.r.peer.cancelled.size()==count,"old bridge cannot cancel replacement mux");
        carkit_iap2_close(&s.bridge); check(carkit_iap2_start(&s.bridge,75,s.wire.base.r.now)==IAP2_ARGUMENT,"closed bridge needs new one-shot lifetime");
    }
    {
        auto instance=std::make_unique<Session>(ids,false,false); auto& s=*instance; const auto reads=s.wire.base.r.peer.reads,writes=s.wire.base.r.peer.writes;
        const auto before=snapshot(s.wire.channel);
        check(carkit_iap2_start(&s.bridge,73,UINT64_MAX)==IAP2_ARGUMENT && !s.bridge.pump.active && snapshot(s.wire.channel)==before,"missing metadata rejects before accepting a future lower-layer clock");
        check(s.wire.base.r.peer.reads==reads && s.wire.base.r.peer.writes==writes,"failed start does no backend work");
    }
}
static void failure_and_control(Identities& ids) {
    for(unsigned which=0;which<3;++which) {
        auto instance=std::make_unique<Session>(ids); auto& s=*instance; s.start();
        if(which==2) { s.full=true; s.fail_provider=true; }
        else crypto(mbedtls_ssl_close_notify(which?&s.wire.service_server.ssl:&s.wire.base.server.ssl),"peer TLS close");
        s.until([&]{return s.bridge.state==CARKIT_IAP2_DEAD;});
        check(s.wire.base.r.peer.cancelled.size()==1 && !s.bridge.pump.active && !s.bridge.pending_size,"either TLS stream/provider failure closes every owner");
        if(which==2) check(s.certificates==1 && !s.signatures && s.endpoint.reason==IAP2_CONTROL_REASON_AUTH,"provider failure no silent fake signer/retry");
    }
    auto instance=std::make_unique<Session>(ids); auto& s=*instance; s.start(); s.wire.base.r.peer.inject(packet(USBMUX_CONTROL,{5,'i'}));
    s.until([&]{return s.wire.base.r.d.control_pending!=0;});
    const usbmux_frame *frame; uint64_t token;
    check(usbmux_dispatcher_control(&s.wire.base.r.d,&frame,&token)==USBMUX_DISPATCHER_CONTROL &&
          usbmux_dispatcher_release_control(&s.wire.base.r.d,1,token,s.wire.base.r.now)==0,"CONTROL independently handled under integrated owner");
    s.until([&]{return s.endpoint.link.state==IAP2_LINK_NORMAL;});
}
static void partial_writes_buffered_input_and_binding(Identities& ids) {
    {
        auto instance=std::make_unique<Session>(ids,true,true,3); auto& s=*instance; s.start(); s.step(); const auto original=snapshot(s.bridge.pending);
        s.until([&]{return s.bridge.submitted>0 && s.bridge.submitted<s.bridge.pending_size;});
        check(s.bridge.submitted==3 && !s.bridge.pump.tx_offset && snapshot(s.bridge.pending)==original,"partial plain copy retains full original frame and no upward credit");
        s.until([&]{return s.endpoint.link.state==IAP2_LINK_NORMAL && !s.bridge.pending_size && !s.bridge.pump.tx_size;});
        check(s.peer.state==IAP2_LINK_NORMAL,"small TCP prefix transfers reconstruct link negotiation exactly");
    }
    {
        auto instance=std::make_unique<Session>(ids,false,true,128,false); auto& s=*instance; s.wire.service_server.pending=Bytes(iap2_detect_marker,iap2_detect_marker+6);
        s.wire.until([&]{return s.wire.service_tls.rx_size!=0;});
        check(!s.wire.channel.application_used,"TLS prefetch is not external carkit consumption");
        check(carkit_iap2_init(&s.bridge,&s.wire.channel,&s.endpoint,&s.pump_config)==0,"bind retains early encrypted peer marker");
        s.run_peer=false; s.start(); s.until([&]{return s.endpoint.link.state==IAP2_LINK_SYNCHRONIZE;});
        check(s.wire.channel.application_used,"buffered marker delivered through bridge read");
    }
    {
        auto instance=std::make_unique<Session>(ids,false,true,128,false); auto& s=*instance; auto invalid=s.pump_config; invalid.retry_ms=0;
        const auto before=snapshot(s.bridge); const auto endpoint=snapshot(s.endpoint);
        check(carkit_iap2_init(&s.bridge,&s.wire.channel,&s.endpoint,&invalid)==IAP2_ARGUMENT && snapshot(s.bridge)==before && snapshot(s.endpoint)==endpoint,"invalid bind transactional");
        const Bytes data{1}; size_t n;
        check(carkit_write(&s.wire.channel,data.data(),data.size(),&n,s.wire.base.r.now)==0 && n==1,"external service application use");
        check(carkit_iap2_init(&s.bridge,&s.wire.channel,&s.endpoint,&s.pump_config)==CARKIT_BUSY && snapshot(s.bridge)==before,"used carkit cannot be silently rebound");
    }
    {
        auto instance=std::make_unique<Session>(ids); auto& s=*instance; s.start(); uint8_t data[8]; iap2_transport_result result{};
        const auto reads=s.wire.base.r.peer.reads,writes=s.wire.base.r.peer.writes; const auto before=snapshot(s.bridge);
        s.bridge.pump.backend.read(&s.bridge,72,data,sizeof data,&result);
        check(result.status==IAP2_TRANSPORT_FATAL && !result.count && result.generation==73 && snapshot(s.bridge)==before,"callback records its bound generation, not a stale requested label");
        s.bridge.pump.backend.cancel(&s.bridge,72);
        check(s.wire.base.r.peer.cancelled.empty() && s.wire.base.r.peer.reads==reads && s.wire.base.r.peer.writes==writes,"wrong-generation cancellation and callback perform no device I/O");
    }
}
int main(int argc,char **argv) {
    try {
        check(argc==2,"fixture directory"); fixtures=argv[1]; Identities ids;
        complete_startup(ids); copied_is_not_completed(ids); deadlines_before_physical_io(ids); generation_and_clock(ids); failure_and_control(ids); partial_writes_buffered_input_and_binding(ids);
        std::cout<<"PASS: 6 carkit/iAP2 integration groups; dual real TLS or explicit plain service, synthetic accessory provider; bridge="<<sizeof(carkit_iap2)<<" bytes plus endpoint/carkit/TLS storage\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
