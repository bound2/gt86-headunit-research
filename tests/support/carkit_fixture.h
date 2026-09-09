#pragma once
// SPDX-License-Identifier: GPL-3.0-only
#include "carkit.h"
#include "tls_fixture.h"
static Bytes xml(const char *request,const std::string& fields) {
    return bytes(("<plist version=\"1.0\"><dict><key>Request</key><string>"+std::string(request)+"</string>"+fields+"</dict></plist>").c_str());
}
static Bytes service_reply(unsigned port=54321,int ssl=1) {
    return xml("StartService","<key>Port</key><integer>"+std::to_string(port)+"</integer>"+
        (ssl<0?"":std::string("<key>EnableServiceSSL</key>")+(ssl?"<true/>":"<false/>")));
}
struct ClientRig {
    Rig base; lockdown_client client{};
    Bytes request=Bytes(4098,0xa5),response,arena=Bytes(65538,0xa5);
    std::array<service_plist_node,256> nodes{};
    Bytes expected,answer; size_t answer_offset=0,reply_chunk=65536;
    bool answered=false,ack=true; uint32_t old_ack=0;
    explicit ClientRig(Identities& ids,size_t capacity=65540,size_t node_cap=256,lockdown_channel_config cfg={10000,5000},uint32_t send_limit=128):base(ids,nullptr,false,4096,send_limit),response(capacity+2,0xa5) {
        base.init(ids.credentials()); base.ready();
        const auto label_bytes=bytes("gt86-research"); const auto label=view(label_bytes);
        service_plist_storage storage{nodes.data(),node_cap,arena.data()+1,arena.size()-2};
        check(lockdown_client_init(&client,&base.tls,&label,request.data()+1,request.size()-2,response.data()+1,capacity,&storage,&cfg,base.r.now)==0,"protected RPC init");
        old_ack=base.r.conns[base.h.slot].tx_una;
        base.r.peer.on_data=[this](Peer& p,uint16_t port,const Bytes& data) {
            base.server.input.insert(base.server.input.end(),data.begin(),data.end());
            if(ack) send(p,port,{},p.streams.at(port).host_next);
        };
    }
    virtual ~ClientRig() { lockdown_client_close(&client); }
    void expect(const Bytes& request_body,const Bytes& reply_body,bool already_framed=false) {
        check(base.server.plaintext.empty(),"new expected RPC after prior request cleared");
        expected=framed(request_body); answer=already_framed?reply_body:framed(reply_body); answer_offset=0; answered=false;
    }
    void inject(Server& server,const usbmux_handle& h,bool acknowledge=true) {
        if(!h.physical || server.output.empty() || !base.r.d.active) return;
        auto& c=base.r.conns[h.slot]; auto& p=base.r.peer.streams.at(c.local_port);
        const size_t credit=c.rx_limit-p.next; check(credit<=c.rx_capacity,"server respects receive window");
        const size_t n=std::min({credit,server.output.size(),size_t(113)}); if(!n) return;
        Bytes payload; for(size_t i=0;i<n;++i) { payload.push_back(server.output.front()); server.output.pop_front(); }
        send(base.r.peer,c.local_port,payload,acknowledge?p.host_next:old_ack);
    }
    void server_step() {
        base.server.step();
        if(!expected.empty() && base.server.plaintext.size()>=expected.size()) {
            check(base.server.plaintext==expected,"exact encrypted RPC request and four-byte prefix"); answered=true;
        }
        if(answered && answer_offset<answer.size() && base.server.pending.empty() && base.server.output.empty()) {
            const size_t n=std::min(reply_chunk,answer.size()-answer_offset);
            base.server.pending.assign(answer.begin()+answer_offset,answer.begin()+answer_offset+n); answer_offset+=n;
        }
        inject(base.server,base.h,ack);
    }
    void canaries() {
        check(request.front()==0xa5 && request.back()==0xa5 && response.front()==0xa5 && response.back()==0xa5 && arena.front()==0xa5 && arena.back()==0xa5,"RPC buffer canaries");
        base.r.canaries();
    }
    virtual int step() {
        server_step(); const auto reads=base.r.peer.reads,writes=base.r.peer.writes;
        const int s=lockdown_client_poll(&client,base.r.now++);
        check(base.r.peer.reads-reads<=1 && base.r.peer.writes-writes<=1,"one backend poll per RPC poll"); canaries(); return s;
    }
    template<class P> void until(P p) {
        for(unsigned i=0;i<20000 && !p();++i) {
            const int s=step();
            if(s==LOCKDOWN_CLIENT_CLOSED && !p()) throw std::runtime_error("unexpected RPC/carkit close: RPC="+std::to_string(client.reason)+" TLS="+std::to_string(base.tls.reason));
            check(s==0 || s==IAP2_MORE || s==USBMUX_DISPATCHER_CONTROL || s==LOCKDOWN_CLIENT_REPLY || s==CARKIT_READY || s==LOCKDOWN_REPLY_REMOTE_ERROR || (s==-7 && p()),"expected bounded RPC/carkit state");
        }
        check(p(),"bounded RPC/carkit loop reaches predicate");
    }
    uint64_t event(int expected_status=LOCKDOWN_CLIENT_REPLY) {
        const lockdown_reply *reply; uint64_t token;
        check(lockdown_client_event(&client,&reply,&token)==expected_status && reply==&client.reply && token,"owned response event"); return token;
    }
    void service() {
        const auto name=bytes("com.apple.carkit.service"); const auto value=view(name);
        check(lockdown_client_start_service(&client,&value,base.r.now)==0,"queue explicit protected service request");
    }
};
struct CarkitRig:ClientRig {
    Server service_server; lockdown_tls service_tls{}; carkit channel{};
    Bytes raw_received; bool plain=false,drop_syn=false;
    explicit CarkitRig(Identities& ids,bool plain_service=false,Identity *peer=nullptr,uint32_t send_limit=128):ClientRig(ids,65540,256,{10000,5000},send_limit),service_server(ids,peer),plain(plain_service) {
        base.r.peer.on_data=[this](Peer& p,uint16_t port,const Bytes& data) {
            if(port==base.r.conns[base.h.slot].local_port) base.server.input.insert(base.server.input.end(),data.begin(),data.end());
            else if(plain) { raw_received.insert(raw_received.end(),data.begin(),data.end()); send(p,port,data,p.streams.at(port).host_next); return; }
            else service_server.input.insert(service_server.input.end(),data.begin(),data.end());
            send(p,port,{},p.streams.at(port).host_next);
        };
    }
    ~CarkitRig() override { carkit_close(&channel); lockdown_tls_close(&service_tls); }
    void open(Identities& ids,carkit_config config={},bool use_defaults=true) {
        if(use_defaults) { carkit_default_config(&config); if(plain) config.policy=CARKIT_ALLOW_PLAIN_IF_REPORTED; }
        const auto creds=ids.credentials(); const auto reads=base.r.peer.reads,writes=base.r.peer.writes;
        check(carkit_open(&channel,&client,&service_tls,&creds,&config,base.r.now)==0,"explicit carkit open");
        check(base.r.peer.reads==reads && base.r.peer.writes==writes,"carkit open only queues protected request");
    }
    int step() override {
        server_step(); if(channel.handle.physical && !plain) { service_server.step(); inject(service_server,channel.handle); }
        if(drop_syn && channel.state>=CARKIT_PORT) base.r.peer.respond=false;
        const auto reads=base.r.peer.reads,writes=base.r.peer.writes;
        const int s=carkit_poll(&channel,base.r.now++);
        check(base.r.peer.reads-reads<=2 && base.r.peer.writes-writes<=2,"bounded two-stream TLS polls"); canaries(); return s;
    }
    void ready() { until([&]{return channel.state==CARKIT_OPEN;}); }
    void dead() { until([&]{return channel.state==CARKIT_DEAD;}); check(base.r.peer.cancelled.size()==1,"one shared cancellation"); }
};
