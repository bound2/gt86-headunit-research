/* SPDX-License-Identifier: GPL-3.0-only */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "projection_iap_services.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <new>

namespace {
constexpr uint64_t ns_ms=1000000;
struct Input {
    SOCKET listener=INVALID_SOCKET,client=INVALID_SOCKET;
    projection_iap input{};
    std::unique_ptr<uint8_t[]> storage;
    std::array<uint8_t,16384> network{};
    size_t used=0,offset=0;
    uint64_t network_at=0;
};
struct Slot {
    uint64_t lease=0,child=0,opened_ns=0;
    uint32_t type=0;
    bool occupied=false,started=false,flushing=false;
    std::unique_ptr<Input> input;
};
bool zero(const uint8_t *p,size_t n) { for(size_t i=0;i<n;++i) if(p[i]) return false;return true; }
bool ip_valid(const projection_ip &a) {
    if(a.family==4) return a.bytes[0]>0&&a.bytes[0]<224&&!a.scope&&zero(a.bytes+4,12);
    if(a.family!=6||zero(a.bytes,16)||a.bytes[0]==255||(zero(a.bytes,10)&&a.bytes[10]==255&&a.bytes[11]==255)) return false;
    return (a.bytes[0]==0xfe&&(a.bytes[1]&0xc0)==0x80)?a.scope!=0:a.scope==0;
}
int address(const projection_ip &ip,SOCKADDR_STORAGE &out) {
    out={};
    if(ip.family==4) { auto &a=reinterpret_cast<SOCKADDR_IN&>(out);a.sin_family=AF_INET;std::memcpy(&a.sin_addr,ip.bytes,4);return sizeof(a); }
    auto &a=reinterpret_cast<SOCKADDR_IN6&>(out);a.sin6_family=AF_INET6;a.sin6_scope_id=ip.scope;std::memcpy(&a.sin6_addr,ip.bytes,16);return sizeof(a);
}
bool peer(const projection_ip &ip,const SOCKADDR_STORAGE &ss,int n) {
    if(ip.family==4&&ss.ss_family==AF_INET&&n==sizeof(SOCKADDR_IN)) return !std::memcmp(&reinterpret_cast<const SOCKADDR_IN&>(ss).sin_addr,ip.bytes,4);
    if(ip.family==6&&ss.ss_family==AF_INET6&&n==sizeof(SOCKADDR_IN6)) {
        auto &a=reinterpret_cast<const SOCKADDR_IN6&>(ss);return a.sin6_scope_id==ip.scope&&!std::memcmp(&a.sin6_addr,ip.bytes,16);
    }
    return false;
}
void socket_close(SOCKET &v) { if(v!=INVALID_SOCKET) { closesocket(v);v=INVALID_SOCKET; } }
bool ms(uint32_t n) { return n&&n<=60000; }
}
struct projection_iap_services {
    projection_iap_services_config config{};
    std::array<Slot,PROJECTION_SESSION_STREAMS> slots{};
    uint64_t generation=0,next_lease=1,now_ns=0;
    bool failed=false,finalized=false,wsa=false;
    int last_error=0;
};
namespace {
int owner(const projection_iap_services *s,uint64_t gen) {
    if(!s||!gen) return IAP2_ARGUMENT;if(s->generation!=gen) return IAP2_INVALID;
    return s->failed?PROJECTION_IAP_SERVICES_CLOSED:IAP2_OK;
}
void cleanup_wsa(projection_iap_services *s) {
    for(const auto &a:s->slots) if(a.occupied&&a.type==130) return;
    if(s->wsa) { WSACleanup();s->wsa=false; }
}
void slot_close(projection_iap_services *s,Slot &a) {
    if(!a.occupied) return;
    if(a.input) {
        socket_close(a.input->client);socket_close(a.input->listener);projection_iap_close(&a.input->input);
        pair_crypto_wipe(a.input->network.data(),a.input->network.size());
    }
    if(a.child) {
        if(a.type==130) s->config.relay.close(s->config.relay.context,s->generation,a.child);
        else s->config.other.close(s->config.other.context,s->generation,a.child);
    }
    a=Slot{};
}
int fail(projection_iap_services *s,int error) {
    if(!s->failed) {
        s->failed=true;s->last_error=error;
        for(auto i=s->slots.rbegin();i!=s->slots.rend();++i) slot_close(s,*i);
        cleanup_wsa(s);
    }
    return PROJECTION_IAP_SERVICES_CLOSED;
}
int refresh(projection_iap_services *s) {
    uint64_t now=s->config.clock_ns(s->config.clock_context);
    if(now<s->now_ns) return fail(s,IAP2_INVALID);s->now_ns=now;
    for(auto &a:s->slots) if(a.occupied&&a.type==130&&a.input) {
        auto &i=*a.input;
        if((i.client==INVALID_SOCKET&&now-a.opened_ns>=uint64_t(s->config.accept_ms)*ns_ms)||
           (i.used&&now-i.network_at>=uint64_t(s->config.input.records.receive_ms)*ns_ms)) return fail(s,IAP2_MORE);
        if(i.input.generation) {
            int r=projection_iap_check(&i.input,s->generation,now/ns_ms);
            if(r!=IAP2_OK) return fail(s,r==PROJECTION_IAP_CLOSED?i.input.last_error:r);
        }
    }
    return IAP2_OK;
}
Slot *find(projection_iap_services *s,uint64_t lease) {
    if(lease) for(auto &a:s->slots) if(a.occupied&&a.lease==lease) return &a;return nullptr;
}
int listen_iap(projection_iap_services *s,Input &i,uint16_t &port) {
    if(!s->wsa) { WSADATA d{};int r=WSAStartup(MAKEWORD(2,2),&d);if(r) return r;s->wsa=true; }
    i.listener=WSASocketW(s->config.local.family==4?AF_INET:AF_INET6,SOCK_STREAM,0,nullptr,0,WSA_FLAG_NO_HANDLE_INHERIT);
    if(i.listener==INVALID_SOCKET) return WSAGetLastError();int one=1;u_long nonblock=1;
    if(setsockopt(i.listener,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&one),sizeof(one))||
       (s->config.local.family==6&&setsockopt(i.listener,IPPROTO_IPV6,IPV6_V6ONLY,reinterpret_cast<const char*>(&one),sizeof(one)))||
       ioctlsocket(i.listener,FIONBIO,&nonblock)) return WSAGetLastError();
    SOCKADDR_STORAGE addr{};int n=address(s->config.local,addr);
    if(bind(i.listener,reinterpret_cast<SOCKADDR*>(&addr),n)||getsockname(i.listener,reinterpret_cast<SOCKADDR*>(&addr),&n)||listen(i.listener,4)) return WSAGetLastError();
    if(!peer(s->config.local,addr,n)) return WSAEINVAL;
    port=ntohs(s->config.local.family==4?reinterpret_cast<SOCKADDR_IN&>(addr).sin_port:reinterpret_cast<SOCKADDR_IN6&>(addr).sin6_port);
    return port?IAP2_OK:WSAEINVAL;
}
int open_resource(void *context,uint64_t gen,const projection_session_resource *q,uint8_t features,
                  const projection_session_keys *keys,projection_session_endpoint *out) {
    if(out) *out={};auto *s=static_cast<projection_iap_services*>(context);int r=owner(s,gen);if(r) return r;
    if(!q||!keys||!out||features!=s->config.enabled_features||!s->next_lease) return IAP2_ARGUMENT;
    if(q->type==130) {
        if(keys->has_write||q->peer_data_port||q->peer_timing_port||q->audio_type||q->audio_format||q->audio_latency_ms||
           q->frames_per_packet||q->keep_alive_low_power) return IAP2_UNSUPPORTED;
    } else if((q->type!=100&&q->type!=101&&q->type!=102&&q->type!=110&&q->type!=111)||!s->config.other.open||
              (q->type==111&&!(features&PROJECTION_SESSION_ALT_SCREEN))) return IAP2_UNSUPPORTED;
    for(const auto &a:s->slots) if(a.occupied&&a.type==q->type) return IAP2_INVALID;
    auto at=std::find_if(s->slots.begin(),s->slots.end(),[](const Slot &a){return !a.occupied;});
    if(at==s->slots.end()) return IAP2_NO_SPACE;if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    Slot &a=*at;a.occupied=true;a.type=q->type;a.opened_ns=s->now_ns;
    projection_session_endpoint e{};uint64_t child=0;
    if(q->type==130) {
        a.input.reset(new(std::nothrow) Input);if(!a.input) return fail(s,IAP2_NO_SPACE);
        auto &i=*a.input;size_t limit=s->config.input.records.payload_limit,total=3*limit+36+s->config.input.package_limit;
        i.storage.reset(new(std::nothrow) uint8_t[total]);if(!i.storage) return fail(s,IAP2_NO_SPACE);
        auto *b=i.storage.get();projection_iap_storage storage{b,b+limit+18,b+2*limit+18,b+3*limit+36,limit+18,limit,limit+18,s->config.input.package_limit};
        r=projection_iap_init(&i.input,&s->config.input,&storage,keys->read,gen,s->now_ns/ns_ms);if(r) return fail(s,r);
        r=s->config.relay.open(s->config.relay.context,gen,q,&child);
    } else { r=s->config.other.open(s->config.other.context,gen,q,features,keys,&e);child=e.lease; }
    if(child) {
        for(const auto &b:s->slots) if(b.occupied&&(b.type==130)==(q->type==130)&&b.child==child) return fail(s,IAP2_INVALID);
        a.child=child;
    }
    if(r||!child) return fail(s,r?r:IAP2_INVALID);
    if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    if(q->type==130) { r=listen_iap(s,*a.input,e.data_port);if(r) return fail(s,r);e.stream_id=s->config.stream_id; }
    if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    a.lease=s->next_lease++;e.lease=a.lease;*out=e;return IAP2_OK;
}
void close_resource(void *context,uint64_t gen,uint64_t lease) {
    auto *s=static_cast<projection_iap_services*>(context);if(!s||s->finalized||s->generation!=gen) return;
    if(auto *a=find(s,lease)) slot_close(s,*a);cleanup_wsa(s);
}
int start_resources(void *context,uint64_t gen,const uint64_t *leases,size_t count) {
    auto *s=static_cast<projection_iap_services*>(context);int r=owner(s,gen);if(r) return r;
    if(!leases||!count||count>s->slots.size()) return IAP2_ARGUMENT;
    std::array<Slot*,PROJECTION_SESSION_STREAMS> list{};std::array<uint64_t,PROJECTION_SESSION_STREAMS> children{};size_t n=0;
    for(size_t j=0;j<count;++j) {
        auto *a=find(s,leases[j]);if(!a||a->started||a->flushing) return IAP2_INVALID;
        for(size_t k=0;k<j;++k) if(leases[j]==leases[k]) return IAP2_INVALID;
        list[j]=a;if(a->type!=130) children[n++]=a->child;
    }
    if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    if(n) { r=s->config.other.start(s->config.other.context,gen,children.data(),n);if(r) return fail(s,r);if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED; }
    for(size_t j=0;j<count;++j) list[j]->started=true;return IAP2_OK;
}
int accept_iap(projection_iap_services *s,Input &i) {
    if(i.client!=INVALID_SOCKET) return IAP2_OK;
    SOCKADDR_STORAGE addr{};int n=sizeof(addr);SOCKET v=accept(i.listener,reinterpret_cast<SOCKADDR*>(&addr),&n);
    if(v==INVALID_SOCKET) { int r=WSAGetLastError();return r==WSAEWOULDBLOCK?IAP2_MORE:fail(s,r); }
    if(!peer(s->config.peer,addr,n)) { closesocket(v);return IAP2_MORE; }
    i.client=v;socket_close(i.listener);
    if(!SetHandleInformation(reinterpret_cast<HANDLE>(v),HANDLE_FLAG_INHERIT,0)) return fail(s,static_cast<int>(GetLastError()));
    u_long nonblock=1;int one=1;
    if(ioctlsocket(v,FIONBIO,&nonblock)||setsockopt(v,IPPROTO_TCP,TCP_NODELAY,reinterpret_cast<const char*>(&one),sizeof(one))) return fail(s,WSAGetLastError());
    return refresh(s);
}
int input_poll(projection_iap_services *s,Slot &a) {
    auto &i=*a.input;int r=s->config.relay.poll(s->config.relay.context,s->generation,a.child,s->now_ns);
    if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    projection_iap_view view{};projection_iap_key key{};
    r=projection_iap_peek(&i.input,s->generation,&view,&key);
    if(r==PROJECTION_IAP_PACKAGE) {
        size_t accepted=0;r=s->config.relay.receive(s->config.relay.context,s->generation,a.child,&view,key,&accepted);
        if(accepted>view.body.size||(r==IAP2_MORE&&accepted)||(r==IAP2_OK&&!accepted&&view.body.size)) return fail(s,IAP2_INVALID);
        if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
        if(r==IAP2_MORE) return IAP2_OK;
        r=projection_iap_consume(&i.input,key,accepted,s->now_ns/ns_ms);
        if(r==PROJECTION_IAP_PACKAGE) return IAP2_OK;
        if(r!=IAP2_OK) return fail(s,r==PROJECTION_IAP_CLOSED?i.input.last_error:r);
    } else if(r!=IAP2_MORE) return fail(s,r);
    r=accept_iap(s,i);if(r==IAP2_MORE) return IAP2_OK;if(r) return r;
    if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    // Cipher-owned coalesced plaintext must drain even if the socket would block.
    if(!i.used&&!i.input.cipher.held) {
        int n=recv(i.client,reinterpret_cast<char*>(i.network.data()),static_cast<int>(i.network.size()),0);
        if(n==SOCKET_ERROR) { r=WSAGetLastError();return r==WSAEWOULDBLOCK?IAP2_OK:fail(s,r); }
        if(!n) return fail(s,(i.input.cipher.rx_used||i.input.used)?IAP2_INVALID:IAP2_END);
        i.used=static_cast<size_t>(n);i.network_at=s->now_ns;
    }
    if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    size_t consumed=0;r=projection_iap_feed(&i.input,s->generation,i.used?i.network.data()+i.offset:nullptr,i.used-i.offset,&consumed,s->now_ns/ns_ms);
    if(r<0) return fail(s,r==PROJECTION_IAP_CLOSED?i.input.last_error:r);
    pair_crypto_wipe(i.network.data()+i.offset,consumed);i.offset+=consumed;
    if(i.offset==i.used) { i.offset=i.used=0;i.network_at=0; }
    return refresh(s);
}
int poll_provider(void *s,uint64_t gen,uint64_t) { return projection_iap_services_poll(static_cast<projection_iap_services*>(s),gen); }
uint32_t delay_provider(const void *s,uint64_t gen) { return projection_iap_services_next_delay(static_cast<const projection_iap_services*>(s),gen); }
int playback(void *context,uint64_t gen,uint64_t lease,projection_playback_position *out) {
    if(out) *out={};auto *s=static_cast<projection_iap_services*>(context);int r=owner(s,gen);if(r) return r;if(!out) return IAP2_ARGUMENT;
    auto *a=find(s,lease);if(!a||a->type<100||a->type>102) return IAP2_INVALID;if(!s->config.other.playback) return IAP2_UNSUPPORTED;
    if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;r=s->config.other.playback(s->config.other.context,gen,a->child,out);
    if(r) { *out={};return fail(s,r); }r=refresh(s);if(r) *out={};return r;
}
int flush(void *context,uint64_t gen,uint64_t lease,const projection_audio_flush_request *q) {
    auto *s=static_cast<projection_iap_services*>(context);int r=owner(s,gen);if(r) return r;
    auto *a=find(s,lease);if(!a||a->type<100||a->type>102||(q?(!a->started||a->flushing):!a->flushing)) return IAP2_INVALID;
    if(!s->config.other.flush) return IAP2_UNSUPPORTED;if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    r=s->config.other.flush(s->config.other.context,gen,a->child,q);if(r) return fail(s,r);if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    a->flushing=q!=nullptr;a->started=q==nullptr;return IAP2_OK;
}
}
extern "C" int projection_iap_services_create(const projection_iap_services_config *c,uint64_t gen,projection_iap_services **out) {
    if(out) *out=nullptr;
    if(!out||!c||!gen||!ip_valid(c->local)||!ip_valid(c->peer)||c->local.family!=c->peer.family||!c->clock_ns||
       !ms(c->accept_ms)||!c->poll_ms||c->poll_ms>1000||!c->stream_id||c->enabled_features>15||!(c->enabled_features&PROJECTION_SESSION_IAP)||
       !c->relay.open||!c->relay.receive||!c->relay.poll||!c->relay.close) return IAP2_ARGUMENT;
    const auto &i=c->input;const auto &r=i.records;const auto &p=c->other;
    if(i.package_limit<32||i.package_limit>PROJECTION_IAP_MAX_PACKAGE||!ms(i.package_ms)||!ms(i.hold_ms)||
       !r.payload_limit||r.payload_limit>CONTROL_CIPHER_MAX_PAYLOAD||!ms(r.receive_ms)||!ms(r.hold_ms)||!ms(r.output_ms)||
       (bool(p.open)!=bool(p.start))||(bool(p.open)!=bool(p.close))||(bool(p.poll)!=bool(p.next_delay))||
       (!p.open&&(p.poll||p.playback||p.flush||p.clock))) return IAP2_ARGUMENT;
    auto *s=new(std::nothrow) projection_iap_services;if(!s) return IAP2_NO_SPACE;
    s->config=*c;s->generation=gen;*out=s;return IAP2_OK;
}
extern "C" projection_session_provider projection_iap_services_provider(projection_iap_services *s) {
    projection_session_provider p{};p.context=s;p.open=open_resource;p.start=start_resources;p.close=close_resource;p.poll=poll_provider;p.next_delay=delay_provider;
    p.playback=s&&s->config.other.playback?playback:nullptr;p.flush=s&&s->config.other.flush?flush:nullptr;return p;
}
extern "C" int projection_iap_services_poll(projection_iap_services *s,uint64_t gen) {
    int r=owner(s,gen);if(r) return r;bool active=false,other=false;
    for(const auto &a:s->slots) if(a.occupied) { active=true;if(a.type!=130) other=true; }
    if(!active) return IAP2_MORE;if(refresh(s)) return PROJECTION_IAP_SERVICES_CLOSED;
    for(auto &a:s->slots) if(a.occupied&&a.type==130) { r=input_poll(s,a);if(r) return r; }
    if(other&&s->config.other.poll) { r=s->config.other.poll(s->config.other.context,gen,s->now_ns/ns_ms);if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r); }
    return refresh(s);
}
extern "C" uint32_t projection_iap_services_next_delay(const projection_iap_services *s,uint64_t gen) {
    if(owner(s,gen)) return UINT32_MAX;uint32_t delay=UINT32_MAX;bool other=false;
    auto deadline=[&](uint64_t elapsed,uint32_t budget) { delay=std::min(delay,elapsed>=budget?0:budget-static_cast<uint32_t>(elapsed)); };
    for(const auto &a:s->slots) if(a.occupied) {
        delay=std::min(delay,s->config.poll_ms);if(a.type!=130) { other=true;continue; }
        const auto &i=*a.input;
        if(i.client==INVALID_SOCKET) deadline((s->now_ns-a.opened_ns)/ns_ms,s->config.accept_ms);
        if(i.used) deadline((s->now_ns-i.network_at)/ns_ms,s->config.input.records.receive_ms);
        delay=std::min(delay,projection_iap_next_delay(&i.input));
    }
    if(other&&s->config.other.next_delay) delay=std::min(delay,s->config.other.next_delay(s->config.other.context,gen));return delay;
}
extern "C" int projection_iap_services_error(const projection_iap_services *s) { return s?s->last_error:IAP2_ARGUMENT; }
extern "C" int projection_iap_services_get_status(const projection_iap_services *s,uint64_t gen,uint64_t lease,projection_iap_services_status *out) {
    if(out) *out={};int r=owner(s,gen);if(r) return r;if(!out||!lease) return IAP2_ARGUMENT;
    for(const auto &a:s->slots) if(a.occupied&&a.lease==lease&&a.type==130) {
        const auto &i=*a.input;const auto &p=i.input;out->network_bytes=i.used-i.offset;
        out->cipher_bytes=p.cipher.rx_used;out->plain_bytes=p.cipher.plain_size-p.cipher.plain_offset;
        out->package_bytes=p.used;out->body_bytes=p.held?p.expected-p.offset:0;
        out->connected=i.client!=INVALID_SOCKET;out->held=p.held;out->started=a.started;return IAP2_OK;
    }
    return IAP2_INVALID;
}
extern "C" void projection_iap_services_close(projection_iap_services *s) {
    if(!s||s->finalized) return;fail(s,IAP2_END);pair_crypto_wipe(&s->config,sizeof(s->config));s->finalized=true;
}
extern "C" void projection_iap_services_destroy(projection_iap_services *s) { if(s) { projection_iap_services_close(s);delete s; } }
