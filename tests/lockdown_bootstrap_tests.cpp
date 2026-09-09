// SPDX-License-Identifier: GPL-3.0-only
#include "lockdown_bootstrap.h"
#include "support/lockdown_fixture.h"
static const Bytes host_id=bytes("00000000-0000-4000-8000-000000000001"), buid=bytes("00000000-0000-4000-8000-000000000002");
static Bytes session_request() {
    const auto l=bytes("gt86-research"); const auto label=view(l), host=view(host_id), system=view(buid);
    Bytes out(4096); size_t n;
    check(lockdown_start_session_encode(&label,&host,&system,out.data(),out.size(),&n)==0,"encode explicit StartSession"); out.resize(n);
    check(out==fixture("start-session.xml"),"independent exact StartSession request"); return out;
}
static Bytes xml_reply(const char *command,const std::string& fields) {
    return bytes(("<plist version=\"1.0\"><dict><key>Request</key><string>"+std::string(command)+"</string>"+fields+"</dict></plist>").c_str());
}
struct Bootstrap {
    Runtime& r; Service channel; lockdown_bootstrap b{}; Bytes scratch=Bytes(4098,0xa5), arena=Bytes(4098,0xa5);
    std::array<service_plist_node,64> nodes{};
    service_plist_storage storage{nodes.data(),nodes.size(),arena.data()+1,arena.size()-2};
    explicit Bootstrap(Runtime& runtime,usbmux_handle h,lockdown_channel_config cfg={5000,5000},size_t request_cap=4096,size_t node_cap=64)
        :r(runtime),channel(runtime,h,4096,4096,cfg) {
        storage.node_capacity=node_cap;
        auto label=bytes("gt86-research"); const auto v=view(label);
        check(lockdown_bootstrap_init(&b,&channel.c,&v,scratch.data()+1,request_cap,&storage,r.now)==0,"bind fresh Lockdown client");
        std::fill(label.begin(),label.end(),0);
    }
    int at(uint64_t now) {
        const auto reads=r.peer.reads,writes=r.peer.writes; const int status=lockdown_bootstrap_poll(&b,now);
        check(r.peer.reads-reads<=1 && r.peer.writes-writes<=1,"one backend read/write maximum per client poll"); return status;
    }
    int step() { return at(r.now++); }
    template<class P> void until(P predicate) {
        for(unsigned i=0;i<15000 && !predicate();++i) {
            const int s=step();
            check(s==0 || s==IAP2_MORE || s==USBMUX_DISPATCHER_CONTROL || s==LOCKDOWN_BOOTSTRAP_VALUE || s==LOCKDOWN_BOOTSTRAP_TLS ||
                  s==LOCKDOWN_REPLY_REMOTE_ERROR || (s==LOCKDOWN_BOOTSTRAP_CLOSED && predicate()),"bootstrap reaches expected live/terminal state");
        }
        check(predicate(),"bounded bootstrap loop completion");
    }
    void query(const char *key="ProductType") {
        const auto data=bytes(key); const auto k=view(data);
        check(lockdown_bootstrap_get_value(&b,&k,nullptr,SERVICE_PLIST_STRING,r.now)==0,"queue typed query");
    }
    void session() {
        auto h=host_id,u=buid; const auto hv=view(h),uv=view(u);
        check(lockdown_bootstrap_start_session(&b,&hv,&uv,r.now)==0,"queue selected pairing identity");
        std::fill(h.begin(),h.end(),0); std::fill(u.begin(),u.end(),0);
    }
    uint64_t event(int status) {
        const lockdown_reply *out=nullptr; uint64_t token=0;
        check(lockdown_bootstrap_event(&b,&out,&token)==status && out==&b.reply && token,"current typed event token"); return token;
    }
    void canaries() {
        check(scratch.front()==0xa5 && scratch.back()==0xa5 && arena.front()==0xa5 && arena.back()==0xa5,"client caller-storage canaries"); channel.canaries();
    }
};
static void request_golden_bounds_and_metadata() {
    const auto expected=session_request(), service_name=bytes("com.apple.carkit.service"); const auto service=view(service_name);
    Bytes out(4098,0xa5); size_t n;
    const auto l=bytes("gt86-research"); const auto label=view(l),host=view(host_id),system=view(buid);
    for(size_t cap=0;cap<expected.size();++cap) {
        check(lockdown_start_session_encode(&label,&host,&system,out.data()+1,cap,&n)==IAP2_NO_SPACE && !n &&
              std::all_of(out.begin(),out.end(),[](uint8_t c){return c==0xa5;}),"all insufficient StartSession capacities transactional");
    }
    check(lockdown_start_service_encode(&service,out.data()+1,out.size()-2,&n)==0 &&
          Bytes(out.begin()+1,out.begin()+1+n)==fixture("start-service.xml"),"exact carkit StartService request, no default fields");
    std::fill(out.begin(),out.end(),0xa5); const auto service_expected=fixture("start-service.xml");
    for(size_t cap=0;cap<service_expected.size();++cap) check(lockdown_start_service_encode(&service,out.data()+1,cap,&n)==IAP2_NO_SPACE &&
        !n && std::all_of(out.begin(),out.end(),[](uint8_t c){return c==0xa5;}),"all insufficient service capacities transactional");
    for(unsigned field=0;field<3;++field) for(size_t count:{size_t(0),size_t(129)}) {
        auto a=label,b=host,c=system; (field==0?a:field==1?b:c).size=count;
        check(lockdown_start_session_encode(&a,&b,&c,out.data(),out.size(),&n)==IAP2_ARGUMENT && !n,"invalid metadata sizes rejected before access");
    }
    const auto metachar=bytes("&<>\"'"); const auto value=view(metachar);
    check(lockdown_start_session_encode(&value,&value,&value,out.data(),out.size(),&n)==0,"escaping accepted");
    const std::string encoded(out.begin(),out.begin()+n), escaped="&amp;&lt;&gt;&quot;&apos;";
    check(encoded.find("<key>HostID</key><string>"+escaped+"</string>")!=std::string::npos &&
          encoded.find("<key>SystemBUID</key><string>"+escaped+"</string>")!=std::string::npos,"identity XML metacharacters exact");
    for(const uint8_t c:{uint8_t(0),uint8_t(31),uint8_t(127),uint8_t(255)}) {
        const lockdown_body bad{&c,1}; const auto before=out;
        check(lockdown_start_service_encode(&bad,out.data(),out.size(),&n)==IAP2_ARGUMENT && !n && out==before,"control/non-ASCII service refused");
        check(lockdown_start_session_encode(&label,&bad,&system,out.data(),out.size(),&n)==IAP2_ARGUMENT && !n && out==before,"control/non-ASCII identity refused");
    }
    check(lockdown_start_session_encode(nullptr,&host,&system,out.data(),out.size(),&n)==IAP2_ARGUMENT &&
          lockdown_start_service_encode(nullptr,out.data(),out.size(),&n)==IAP2_ARGUMENT,"no implicit metadata defaults");
    std::fill(out.begin(),out.end(),0xa5);
    const Bytes max_label(64,'"'),max_id(128,'"'); const auto ml=view(max_label),mi=view(max_id);
    check(lockdown_start_session_encode(&ml,&mi,&mi,out.data()+1,out.size()-2,&n)==0 && n<=4096 &&
          out.front()==0xa5 && out.back()==0xa5,"maximum escaped identity fits bounded request scratch");
    check(lockdown_start_service_encode(&mi,out.data()+1,out.size()-2,&n)==0 && n<=4096,"maximum escaped service name");
}
static void fresh_binding_and_queue_contracts() {
    Runtime r(2,4096,64); r.ready(); const auto h=r.open(),other=r.open(62079); r.established(h); r.established(other);
    Service s(r,h),not_lockdown(r,other); lockdown_bootstrap b{}; const auto before=snapshot(b);
    uint8_t request[512],arena[1024]; service_plist_node nodes[32]; service_plist_storage storage{nodes,32,arena,sizeof arena};
    const auto l=bytes("gt86-research"); const auto label=view(l);
    for(size_t cap:{size_t(0),size_t(4097)}) check(lockdown_bootstrap_init(&b,&s.c,&label,request,cap,&storage,r.now)==IAP2_ARGUMENT && snapshot(b)==before,"request scratch limits");
    check(lockdown_bootstrap_init(&b,&not_lockdown.c,&label,request,sizeof request,&storage,r.now)==IAP2_UNSUPPORTED && snapshot(b)==before,"bootstrap limited to Lockdown port");
    auto invalid=storage; invalid.node_capacity=0;
    check(lockdown_bootstrap_init(&b,&s.c,&label,request,sizeof request,&invalid,r.now)==IAP2_ARGUMENT && snapshot(b)==before,"invalid parser storage transactional");
    const auto reads=r.peer.reads,writes=r.peer.writes;
    check(lockdown_bootstrap_init(&b,&s.c,&label,request,sizeof request,&storage,r.now)==0 && r.peer.reads==reads && r.peer.writes==writes,"binding never sends or reads");
    const auto state=snapshot(b); const lockdown_body empty{nullptr,0}; const auto key_data=bytes("ProductType"); const auto key=view(key_data);
    check(lockdown_bootstrap_get_value(&b,&empty,nullptr,SERVICE_PLIST_STRING,r.now+99)==IAP2_ARGUMENT && snapshot(b)==state,"bad key cannot advance client time");
    check(lockdown_bootstrap_get_value(&b,&key,nullptr,SERVICE_PLIST_KEY,r.now+99)==IAP2_ARGUMENT && snapshot(b)==state,"explicit supported expected value type");
    check(lockdown_bootstrap_get_value(&b,&key,nullptr,SERVICE_PLIST_STRING,r.now)==0 && r.peer.reads==reads && r.peer.writes==writes,"queueing performs no physical I/O");
    const auto pending=snapshot(b);
    check(lockdown_bootstrap_start_session(&b,&label,&label,r.now)==LOCKDOWN_BOOTSTRAP_BUSY && snapshot(b)==pending,"single outstanding RPC");
    lockdown_bootstrap_close(&b); lockdown_bootstrap_close(&b); check(r.peer.cancelled.size()==1,"abort cancels shared generation once");
    Runtime history(1,4096,64); history.ready(); const auto old=history.open(); history.established(old);
    check(history.write(old,{1})==1,"seed earlier application traffic before binding");
    history.until([&]{return history.conns[0].rx_used==1 && !history.conns[0].flight_count;});
    check(history.read_all(old)==Bytes({1}),"drain prior traffic");
    history.until([&]{return !history.d.owner && !history.conns[0].tx_size && !history.conns[0].ack_pending;});
    Service used(history,old); lockdown_bootstrap refused{};
    check(lockdown_bootstrap_init(&refused,&used.c,&label,request,sizeof request,&storage,history.now)==LOCKDOWN_BOOTSTRAP_BUSY &&
          !refused.channel,"a new framing wrapper cannot reset application/TLS history");
}
static void query_then_session_and_tls_tail() {
    Runtime r(1,4096,64); r.ready(); const auto h=r.open(); r.established(h); Bootstrap b(r,h);
    const auto request=get_value(),response=fixture("product-type.xml"); reply_with(r,request,framed(response)); b.query();
    b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_VALUE_HELD;}); const auto first=b.event(LOCKDOWN_BOOTSTRAP_VALUE);
    check(std::string(reinterpret_cast<const char *>(b.b.reply.value->data),b.b.reply.value->size)=="iPhone17,1","typed query result");
    const auto before=snapshot(b.b); const auto clock=r.d.now;
    check(lockdown_bootstrap_release(&b.b,first+1,r.now+999)==USBMUX_DISPATCHER_STALE && snapshot(b.b)==before && r.d.now==clock,"old/wrong release does not advance time");
    lockdown_tls_handoff not_yet{};
    check(lockdown_bootstrap_take_tls(&b.b,first,&not_yet,r.now)==USBMUX_DISPATCHER_STALE && !not_yet.dispatcher,"query cannot authorize TLS handoff");
    check(lockdown_bootstrap_release(&b.b,first,r.now)==0,"explicit query release");
    const Bytes tail{0x16,0x03,0x03,0,4,0xde,0xad,0xbe,0xef}; // Synthetic handoff bytes, not a TLS handshake.
    auto wire=framed(fixture("session-tls.xml")); wire.insert(wire.end(),tail.begin(),tail.end());
    reply_with(r,session_request(),wire); b.session(); b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_TLS_HELD;});
    const auto second=b.event(LOCKDOWN_BOOTSTRAP_TLS); check(second>first && b.b.reply.tls_required,"validated session requests TLS");
    check(lockdown_bootstrap_release(&b.b,second,r.now+999)==IAP2_UNSUPPORTED && b.b.state==LOCKDOWN_BOOTSTRAP_TLS_HELD,"TLS cannot be released back to plaintext");
    const auto key_data=bytes("ProductType"); const auto key=view(key_data);
    check(lockdown_bootstrap_get_value(&b.b,&key,nullptr,SERVICE_PLIST_STRING,r.now)==LOCKDOWN_BOOTSTRAP_BUSY,"no plaintext request after SSL-required reply");
    const auto received=r.peer.streams.at(1).received;
    for(unsigned i=0;i<8;++i) check(b.step()==LOCKDOWN_BOOTSTRAP_TLS,"TLS event stable while polling");
    check(r.peer.streams.at(1).received==received && lockdown_bootstrap_next_delay(&b.b)>0 && r.conns[0].rx_used==tail.size(),"no automatic service request and trailing bytes untouched");
    const auto reads=r.peer.reads,writes=r.peer.writes; lockdown_tls_handoff handoff{};
    check(lockdown_bootstrap_take_tls(&b.b,second,&handoff,r.now)==0 && handoff.dispatcher==&r.d &&
          handoff.handle.connection==h.connection && handoff.handle.physical==h.physical &&
          std::string(handoff.session_id,handoff.session_id+handoff.session_id_size)=="synthetic-session" &&
          r.peer.reads==reads && r.peer.writes==writes,"explicit no-read/write handoff with copied metadata");
    std::fill(b.arena.begin()+1,b.arena.end()-1,0);
    lockdown_bootstrap_close(&b.b); check(r.d.active && r.peer.cancelled.empty() && r.read_all(handoff.handle)==tail,"detached owner cannot cancel TLS stream or lose prefetched bytes");
    check(lockdown_bootstrap_next_delay(&b.b)==UINT32_MAX && lockdown_bootstrap_get_value(&b.b,&key,nullptr,SERVICE_PLIST_STRING,r.now)==LOCKDOWN_BOOTSTRAP_CLOSED,"no post-handoff resume bypass");
    b.canaries();
}
static void session_errors_are_explicit_without_pairing() {
    Runtime r(1,4096,64); r.ready(); const auto h=r.open(); r.established(h); Bootstrap b(r,h);
    const auto request=session_request(); const auto error=xml_reply("StartSession","<key>Error</key><string>InvalidHostID</string>");
    reply_with(r,request,framed(error)); b.session(); b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_ERROR_HELD;});
    const auto token=b.event(LOCKDOWN_REPLY_REMOTE_ERROR); const auto amount=r.peer.streams.at(1).received.size();
    for(unsigned i=0;i<10;++i) check(b.step()==LOCKDOWN_REPLY_REMOTE_ERROR,"remote rejection remains held");
    check(amount==request.size()+4 && r.peer.streams.at(1).received.size()==amount,"no automatic retry or Pair request");
    lockdown_tls_handoff out{};
    check(lockdown_bootstrap_take_tls(&b.b,token,&out,r.now)==USBMUX_DISPATCHER_STALE && !out.dispatcher,"remote error cannot authorize handoff");
    check(lockdown_bootstrap_release(&b.b,token,r.now)==0 && b.b.state==LOCKDOWN_BOOTSTRAP_IDLE,"error requires explicit acknowledgment");
    b.step(); check(r.peer.streams.at(1).received.size()==amount,"acknowledging error does not itself retry");
    reply_with(r,request,framed(fixture("session-tls.xml"))); b.session(); b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_TLS_HELD;});
    check(b.event(LOCKDOWN_BOOTSTRAP_TLS)>token,"explicit later request gets a new token"); b.canaries();
}
static void malformed_responses_abort() {
    for(const auto& response: {xml_reply("GetValue","<key>Value</key><string>x</string>"),
        xml_reply("StartSession","<key>SessionID</key><string>x</string><key>EnableSessionSSL</key><false/>"),
        xml_reply("StartSession","<key>SessionID</key><string>x</string><key>EnableSessionSSL</key><integer>1</integer>"),
        xml_reply("StartSession","<key>Error</key><true/>"),bytes("not a plist")}) {
        Runtime r(2,4096,64); r.ready(); const auto h=r.open(),other=r.open(62079); r.established(h); r.established(other); Bootstrap b(r,h);
        reply_with(r,session_request(),framed(response)); b.session(); b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_DEAD;});
        check(b.b.reason==LOCKDOWN_BOOTSTRAP_REASON_RESPONSE && !b.b.reply.session_id && !b.b.document.nodes &&
              r.peer.cancelled.size()==1 && r.conns[1].state==USBMUX_CONNECTION_DEAD,"malformed/mismatched/downgraded session closes shared transport");
        const lockdown_reply *view=reinterpret_cast<const lockdown_reply *>(1); uint64_t token=1;
        check(lockdown_bootstrap_event(&b.b,&view,&token)==LOCKDOWN_BOOTSTRAP_CLOSED && !view && !token,"no stale metadata after failure"); b.canaries();
    }
}
static void all_session_reply_splits() {
    const auto request=session_request();
    for(const auto& response:{framed(fixture("session-tls.xml")),framed(binary_fixture("session"))})
    for(size_t split=1;split<response.size();++split) {
        Runtime r(1,4096,64); r.ready(); const auto h=r.open(); r.established(h); Bootstrap b(r,h);
        reply_with(r,request,response,split); b.session(); b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_TLS_HELD;});
        check(b.b.reply.session_id && r.peer.streams.at(1).received==framed(request) && !r.conns[0].flight_count,"all response-prefix/body split positions and copied request identity");
        b.canaries();
    }
}
static void channel_and_shared_deadlines_precede_handoff() {
    for(bool tls:{false,true}) {
        Runtime r(2,4096,64,1000); r.ready(); const auto h=r.open(),other=r.open(62079); r.established(h); r.established(other); Bootstrap b(r,h);
        reply_with(r,tls?session_request():get_value(),framed(fixture(tls?"session-tls.xml":"product-type.xml")));
        if(tls) b.session(); else b.query();
        b.until([&]{return b.b.state==(tls?LOCKDOWN_BOOTSTRAP_TLS_HELD:LOCKDOWN_BOOTSTRAP_VALUE_HELD);});
        const auto token=b.event(tls?LOCKDOWN_BOOTSTRAP_TLS:LOCKDOWN_BOOTSTRAP_VALUE);
        r.peer.on_data=[](Peer&,uint16_t,const Bytes&) {};
        check(r.write(other,{1})==1,"other stream deliberately awaits peer ACK");
        // Drain queued physical ACK writes before isolating the other stream's
        // peer-ACK timer; otherwise a 250 ms write timer correctly expires first.
        b.until([&]{return r.conns[1].flight_count==1 && !r.d.owner && !r.conns[0].tx_size &&
                          !r.conns[1].tx_size && !r.conns[0].ack_pending && !r.conns[1].ack_pending;});
        const auto deadline=r.conns[1].flights[r.conns[1].flight_head].sent_at+1000,reads=r.peer.reads,writes=r.peer.writes;
        lockdown_tls_handoff out{};
        const auto status=tls?lockdown_bootstrap_take_tls(&b.b,token,&out,deadline):lockdown_bootstrap_release(&b.b,token,deadline);
        check(status==LOCKDOWN_BOOTSTRAP_CLOSED && !out.dispatcher && r.peer.reads==reads && r.peer.writes==writes &&
              r.d.reason==USBMUX_DISPATCHER_REASON_CONNECTION && r.d.failed_slot==1 && r.peer.cancelled.size()==1,"shared timer expires before release/handoff without physical read/write");
        b.canaries();
    }
    Runtime r(1,4096,64); r.ready(); const auto h=r.open(); r.established(h); Bootstrap b(r,h,{5000,100});
    reply_with(r,session_request(),framed(fixture("session-tls.xml"))); b.session(); b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_TLS_HELD;});
    const auto token=b.event(LOCKDOWN_BOOTSTRAP_TLS),reads=r.peer.reads,writes=r.peer.writes; lockdown_tls_handoff out{};
    check(lockdown_bootstrap_take_tls(&b.b,token,&out,b.channel.c.held_at+100)==LOCKDOWN_BOOTSTRAP_CLOSED &&
          !out.dispatcher && r.peer.reads==reads && r.peer.writes==writes && b.channel.c.reason==LOCKDOWN_CHANNEL_REASON_DEADLINE,"exact hold deadline cannot be rescued by handoff");
}
static void pending_timeout_and_capacity_failures() {
    Runtime r(1,4096,64); r.peer.zero_first_window=true; r.ready(); const auto h=r.open(); r.established(h); Bootstrap b(r,h,{100,100});
    b.session(); for(unsigned i=0;i<10;++i) b.step(); const auto writes=r.peer.writes;
    check(b.channel.c.tx_offset==0 && lockdown_bootstrap_next_delay(&b.b)>0 &&
          b.at(b.channel.c.started_at+100)==LOCKDOWN_BOOTSTRAP_CLOSED && r.peer.writes==writes,"zero peer window cannot renew total operation deadline");
    Runtime small(1,4096,64); small.ready(); const auto sh=small.open(); small.established(sh); Bootstrap tiny(small,sh,{5000,5000},1);
    const auto before=snapshot(tiny.b); const auto host=view(host_id),system=view(buid);
    check(lockdown_bootstrap_start_session(&tiny.b,&host,&system,small.now)==IAP2_NO_SPACE && snapshot(tiny.b)==before,"request encoder capacity does not queue or change phase");
    Runtime parsed(1,4096,64); parsed.ready(); const auto ph=parsed.open(); parsed.established(ph); Bootstrap limited(parsed,ph,{5000,5000},4096,1);
    reply_with(parsed,session_request(),framed(fixture("session-tls.xml"))); limited.session(); limited.until([&]{return limited.b.state==LOCKDOWN_BOOTSTRAP_DEAD;});
    check(limited.b.last_error==IAP2_NO_SPACE && !limited.b.document.nodes && parsed.peer.cancelled.size()==1,"response parser exhaustion cannot expose a partial session");
}
static void stale_lifetime_and_clock_contracts() {
    Runtime r(1,4096,64); r.ready(); const auto h=r.open(); r.established(h); Bootstrap b(r,h);
    reply_with(r,session_request(),framed(fixture("session-tls.xml"))); b.session(); b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_TLS_HELD;});
    const auto token=b.event(LOCKDOWN_BOOTSTRAP_TLS); const auto before=snapshot(b.b);
    check(b.at(b.b.now-1)==IAP2_ARGUMENT && snapshot(b.b)==before,"client clock cannot decrease");
    usbmux_dispatcher_close(&r.d); r.start(2); r.until([&]{return r.host.state==USBMUX_HOST_READY;}); const auto fresh=r.open(); r.established(fresh);
    const auto new_state=snapshot(r.d); lockdown_tls_handoff out{};
    check(lockdown_bootstrap_take_tls(&b.b,token,&out,r.now+999)==LOCKDOWN_BOOTSTRAP_CLOSED && !out.dispatcher &&
          b.b.reason==LOCKDOWN_BOOTSTRAP_REASON_STALE && snapshot(r.d)==new_state && r.peer.cancelled.size()==1,"old owner never ticks/cancels replacement generation");
    lockdown_bootstrap_close(&b.b); check(r.d.active && r.peer.cancelled.size()==1,"stale repeated closure no-op");
    lockdown_bootstrap zero{}; const lockdown_reply *event=nullptr; uint64_t t;
    check(lockdown_bootstrap_poll(nullptr,0)==IAP2_ARGUMENT && lockdown_bootstrap_event(&zero,&event,&t)==IAP2_ARGUMENT &&
          !event && !t && lockdown_bootstrap_next_delay(&zero)==UINT32_MAX,"zero/null object contracts"); lockdown_bootstrap_close(nullptr);
}
static void peer_eof_cannot_be_a_tls_stream() {
    Runtime r(1,4096,64); r.ready(); const auto h=r.open(); r.established(h); Bootstrap b(r,h);
    const auto expected=framed(session_request()),response=framed(fixture("session-tls.xml"));
    r.peer.on_data=[expected,response,offset=size_t(0)](Peer& peer,uint16_t port,const Bytes& data) mutable {
        check(offset+data.size()<=expected.size() && std::equal(data.begin(),data.end(),expected.begin()+offset),"complete session request before synthetic FIN");
        offset+=data.size(); const bool complete=offset==expected.size();
        send(peer,port,complete?response:Bytes{},peer.streams.at(port).host_next,complete);
    };
    b.session(); b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_TLS_HELD;}); const auto token=b.event(LOCKDOWN_BOOTSTRAP_TLS);
    lockdown_tls_handoff out{};
    check(lockdown_bootstrap_take_tls(&b.b,token,&out,r.now)==LOCKDOWN_BOOTSTRAP_CLOSED && !out.dispatcher && r.peer.cancelled.size()==1,"validated response plus peer EOF cannot authorize live TLS stream");
    Runtime query(1,4096,64); query.ready(); const auto qh=query.open(); query.established(qh); Bootstrap q(query,qh);
    query.peer.on_data=[offset=size_t(0)](Peer& peer,uint16_t port,const Bytes& data) mutable {
        offset+=data.size(); const bool complete=offset==framed(get_value()).size();
        send(peer,port,complete?framed(fixture("product-type.xml")):Bytes{},peer.streams.at(port).host_next,complete);
    };
    q.query(); q.until([&]{return q.b.state==LOCKDOWN_BOOTSTRAP_VALUE_HELD;}); const auto qt=q.event(LOCKDOWN_BOOTSTRAP_VALUE);
    check(lockdown_bootstrap_release(&q.b,qt,query.now)==0,"consume final well-typed query value");
    const auto key_data=bytes("ProductType"); const auto key=view(key_data); const auto reads=query.peer.reads,writes=query.peer.writes;
    check(lockdown_bootstrap_get_value(&q.b,&key,nullptr,SERVICE_PLIST_STRING,query.now)==LOCKDOWN_BOOTSTRAP_CLOSED &&
          query.peer.reads==reads && query.peer.writes==writes,"no new query is queued on peer EOF");
}
static void unrelated_control_and_timer_only_check() {
    Runtime r(1,4096,64); r.ready(); const auto h=r.open(); r.established(h); Bootstrap b(r,h);
    const auto reads=r.peer.reads,writes=r.peer.writes;
    r.peer.inject(packet(USBMUX_CONTROL,{5,'c'}));
    check(usbmux_dispatcher_check(&r.d,r.now)==0 && r.peer.reads==reads && r.peer.writes==writes && !r.d.control_pending,"timer-only check does not route/read queued input");
    reply_with(r,get_value(),framed(fixture("product-type.xml"))); b.query();
    b.until([&]{return r.d.control_pending!=0;}); check(b.step()==USBMUX_DISPATCHER_CONTROL,"client preserves unrelated CONTROL");
    const usbmux_frame *frame; uint64_t token;
    check(usbmux_dispatcher_control(&r.d,&frame,&token)==USBMUX_DISPATCHER_CONTROL &&
          usbmux_dispatcher_release_control(&r.d,1,token,r.now)==0,"application explicitly handles CONTROL");
    b.until([&]{return b.b.state==LOCKDOWN_BOOTSTRAP_VALUE_HELD;}); (void)b.event(LOCKDOWN_BOOTSTRAP_VALUE); b.canaries();
}
int main(int argc,char **argv) {
    try {
        check(argc==2,"fixture directory required"); fixtures=argv[1];
        request_golden_bounds_and_metadata(); fresh_binding_and_queue_contracts(); query_then_session_and_tls_tail();
        session_errors_are_explicit_without_pairing(); malformed_responses_abort(); all_session_reply_splits();
        channel_and_shared_deadlines_precede_handoff(); pending_timeout_and_capacity_failures();
        stale_lifetime_and_clock_contracts(); peer_eof_cannot_be_a_tls_stream(); unrelated_control_and_timer_only_check();
        std::cout<<"PASS: 11 Lockdown bootstrap groups; synthetic pre-TLS only. Bootstrap bytes="<<sizeof(lockdown_bootstrap)<<'\n'; return 0;
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
