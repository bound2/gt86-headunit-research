/* SPDX-License-Identifier: GPL-3.0-only */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "projection_video_services.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <new>

namespace {
constexpr uint64_t ns_ms = 1000000;
struct Slot {
    uint64_t lease = 0, child = 0, opened_ns = 0, network_at = 0;
    uint32_t type = 0;
    bool occupied = false, started = false, flushing = false;
    SOCKET listener = INVALID_SOCKET, client = INVALID_SOCKET;
    projection_video *video = nullptr;
    projection_h264_frame *held = nullptr;
    projection_video_metadata metadata{};
    std::array<uint8_t, 16384> network{};
    size_t used = 0, offset = 0;
    bool screen() const { return type == 110 || type == 111; }
};
bool zero(const uint8_t *p, size_t n) { for (size_t i=0;i<n;++i) if(p[i]) return false; return true; }
bool ip_valid(const projection_ip &a) {
    if(a.family==4) return a.bytes[0]>0 && a.bytes[0]<224 && !a.scope && zero(a.bytes+4,12);
    if(a.family!=6 || zero(a.bytes,16) || a.bytes[0]==255 || (zero(a.bytes,10)&&a.bytes[10]==255&&a.bytes[11]==255)) return false;
    return (a.bytes[0]==0xfe && (a.bytes[1]&0xc0)==0x80) ? a.scope!=0 : a.scope==0;
}
int address(const projection_ip &ip, SOCKADDR_STORAGE &out) {
    out={};
    if(ip.family==4) { auto &a=reinterpret_cast<SOCKADDR_IN&>(out); a.sin_family=AF_INET; std::memcpy(&a.sin_addr,ip.bytes,4); return sizeof(a); }
    auto &a=reinterpret_cast<SOCKADDR_IN6&>(out); a.sin6_family=AF_INET6; a.sin6_scope_id=ip.scope; std::memcpy(&a.sin6_addr,ip.bytes,16); return sizeof(a);
}
bool peer(const projection_ip &ip,const SOCKADDR_STORAGE &ss,int n) {
    if(ip.family==4 && ss.ss_family==AF_INET && n==sizeof(SOCKADDR_IN))
        return !std::memcmp(&reinterpret_cast<const SOCKADDR_IN&>(ss).sin_addr,ip.bytes,4);
    if(ip.family==6 && ss.ss_family==AF_INET6 && n==sizeof(SOCKADDR_IN6)) {
        auto &a=reinterpret_cast<const SOCKADDR_IN6&>(ss);
        return a.sin6_scope_id==ip.scope && !std::memcmp(&a.sin6_addr,ip.bytes,16);
    }
    return false;
}
void socket_close(SOCKET &v) { if(v!=INVALID_SOCKET) { closesocket(v); v=INVALID_SOCKET; } }
}
struct projection_video_services {
    projection_video_services_config config{};
    std::array<Slot,PROJECTION_SESSION_STREAMS> slots{};
    uint64_t generation=0,next_lease=1,now_ns=0;
    bool failed=false,finalized=false,wsa=false;
    int last_error=0;
};
namespace {
int owner(const projection_video_services *s,uint64_t gen) {
    if(!s||!gen) return IAP2_ARGUMENT;
    if(s->generation!=gen) return IAP2_INVALID;
    return s->failed ? PROJECTION_VIDEO_SERVICES_CLOSED : IAP2_OK;
}
void cleanup_wsa(projection_video_services *s) {
    for(const auto &a:s->slots) if(a.occupied&&a.screen()) return;
    if(s->wsa) { WSACleanup(); s->wsa=false; }
}
void slot_close(projection_video_services *s,Slot &a) {
    if(!a.occupied) return;
    socket_close(a.client); socket_close(a.listener);
    projection_h264_frame_destroy(a.held); projection_video_destroy(a.video);
    if(a.child) {
        if(a.screen()) s->config.sink.close(s->config.sink.context,s->generation,a.child);
        else s->config.other.close(s->config.other.context,s->generation,a.child);
    }
    pair_crypto_wipe(a.network.data(),a.network.size()); a=Slot{};
}
int fail(projection_video_services *s,int error) {
    if(!s->failed) {
        s->failed=true; s->last_error=error;
        for(auto i=s->slots.rbegin();i!=s->slots.rend();++i) slot_close(s,*i);
        cleanup_wsa(s);
    }
    return PROJECTION_VIDEO_SERVICES_CLOSED;
}
int refresh(projection_video_services *s) {
    uint64_t now=s->config.clock_ns(s->config.clock_context);
    if(now<s->now_ns) return fail(s,IAP2_INVALID);
    s->now_ns=now;
    for(auto &a:s->slots) if(a.occupied&&a.screen()) {
        if((a.client==INVALID_SOCKET && now-a.opened_ns>=uint64_t(s->config.accept_ms)*ns_ms) ||
           (a.used && now-a.network_at>=uint64_t(s->config.video.receive_ms)*ns_ms) ||
           (a.held && now/ns_ms-a.metadata.received_ms>=s->config.video.hold_ms)) return fail(s,PROJECTION_VIDEO_DEADLINE);
        if(a.video) { int r=projection_video_check(a.video,s->generation,now/ns_ms); if(r<0) return fail(s,r); }
    }
    return IAP2_OK;
}
Slot *find(projection_video_services *s,uint64_t lease) {
    if(lease) for(auto &a:s->slots) if(a.occupied&&a.lease==lease) return &a;
    return nullptr;
}
int listen_screen(projection_video_services *s,Slot &a,uint16_t &port) {
    if(!s->wsa) { WSADATA d{}; int r=WSAStartup(MAKEWORD(2,2),&d); if(r) return r; s->wsa=true; }
    a.listener=WSASocketW(s->config.local.family==4?AF_INET:AF_INET6,SOCK_STREAM,0,nullptr,0,WSA_FLAG_NO_HANDLE_INHERIT);
    if(a.listener==INVALID_SOCKET) return WSAGetLastError();
    int one=1; u_long nonblock=1;
    if(setsockopt(a.listener,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&one),sizeof(one)) ||
       (s->config.local.family==6 && setsockopt(a.listener,IPPROTO_IPV6,IPV6_V6ONLY,reinterpret_cast<const char*>(&one),sizeof(one))) ||
       ioctlsocket(a.listener,FIONBIO,&nonblock)) return WSAGetLastError();
    SOCKADDR_STORAGE addr{}; int n=address(s->config.local,addr);
    if(bind(a.listener,reinterpret_cast<SOCKADDR*>(&addr),n) || getsockname(a.listener,reinterpret_cast<SOCKADDR*>(&addr),&n) || listen(a.listener,4)) return WSAGetLastError();
    if(!peer(s->config.local,addr,n)) return WSAEINVAL;
    port=ntohs(s->config.local.family==4?reinterpret_cast<SOCKADDR_IN&>(addr).sin_port:reinterpret_cast<SOCKADDR_IN6&>(addr).sin6_port);
    return port ? IAP2_OK : WSAEINVAL;
}
int open_resource(void *context,uint64_t gen,const projection_session_resource *q,uint8_t features,
                  const projection_session_keys *keys,projection_session_endpoint *out) {
    if(out) *out={}; auto *s=static_cast<projection_video_services*>(context); int r=owner(s,gen); if(r) return r;
    if(!q||!keys||!out||features!=s->config.enabled_features||!s->next_lease) return IAP2_ARGUMENT;
    bool screen=q->type==110||q->type==111;
    if(screen) {
        if(keys->has_write || q->peer_data_port || q->audio_format || q->frames_per_packet || q->audio_latency_ms ||
           q->peer_timing_port || q->audio_type || q->keep_alive_low_power ||
           (q->type==111 && !(features&PROJECTION_SESSION_ALT_SCREEN))) return IAP2_UNSUPPORTED;
    } else if((q->type!=100&&q->type!=101&&q->type!=102&&q->type!=130)||!s->config.other.open||
              (q->type==130 && !(features&PROJECTION_SESSION_IAP))) return IAP2_UNSUPPORTED;
    for(const auto &a:s->slots) if(a.occupied&&a.type==q->type) return IAP2_INVALID;
    auto at=std::find_if(s->slots.begin(),s->slots.end(),[](const Slot &a){return !a.occupied;});
    if(at==s->slots.end()) return IAP2_NO_SPACE;
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    Slot &a=*at; a.occupied=true; a.type=q->type; a.opened_ns=s->now_ns;
    projection_session_endpoint e{}; uint64_t child=0;
    if(screen) {
        r=projection_video_create(&s->config.video,keys->read,gen,s->now_ns/ns_ms,&a.video);
        if(r<0) return fail(s,r);
        r=s->config.sink.open(s->config.sink.context,gen,q,&child);
    } else { r=s->config.other.open(s->config.other.context,gen,q,features,keys,&e); child=e.lease; }
    if(child) {
        for(const auto &b:s->slots) if(b.occupied && b.screen()==screen && b.child==child) return fail(s,IAP2_INVALID);
        a.child=child;
    }
    if(r||!child) return fail(s,r?r:IAP2_INVALID);
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    if(screen) { r=listen_screen(s,a,e.data_port); if(r) return fail(s,r); }
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    a.lease=s->next_lease++; e.lease=a.lease; *out=e; return IAP2_OK;
}
void close_resource(void *context,uint64_t gen,uint64_t lease) {
    auto *s=static_cast<projection_video_services*>(context);
    if(!s||s->finalized||s->generation!=gen) return;
    if(auto *a=find(s,lease)) slot_close(s,*a);
    cleanup_wsa(s);
}
int start_resources(void *context,uint64_t gen,const uint64_t *leases,size_t count) {
    auto *s=static_cast<projection_video_services*>(context); int r=owner(s,gen); if(r) return r;
    if(!leases||!count||count>s->slots.size()) return IAP2_ARGUMENT;
    std::array<Slot*,PROJECTION_SESSION_STREAMS> list{};
    std::array<uint64_t,PROJECTION_SESSION_STREAMS> children{}; size_t n=0;
    for(size_t i=0;i<count;++i) {
        auto *a=find(s,leases[i]); if(!a||a->started||a->flushing) return IAP2_INVALID;
        for(size_t j=0;j<i;++j) if(leases[i]==leases[j]) return IAP2_INVALID;
        list[i]=a; if(!a->screen()) children[n++]=a->child;
    }
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    if(n) { r=s->config.other.start(s->config.other.context,gen,children.data(),n); if(r) return fail(s,r); if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED; }
    for(size_t i=0;i<count;++i) {
        auto &a=*list[i];
        if(a.screen()) {
            r=s->config.sink.start(s->config.sink.context,gen,a.child); if(r) return fail(s,r);
            if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
            r=projection_video_start(a.video,gen,s->now_ns/ns_ms); if(r<0) return fail(s,r);
        }
        a.started=true;
    }
    return IAP2_OK;
}
int accept_screen(projection_video_services *s,Slot &a) {
    if(a.client!=INVALID_SOCKET) return IAP2_OK;
    SOCKADDR_STORAGE addr{}; int n=sizeof(addr); SOCKET value=accept(a.listener,reinterpret_cast<SOCKADDR*>(&addr),&n);
    if(value==INVALID_SOCKET) { int r=WSAGetLastError(); return r==WSAEWOULDBLOCK?IAP2_MORE:fail(s,r); }
    if(!peer(s->config.peer,addr,n)) { closesocket(value); return IAP2_MORE; }
    a.client=value; socket_close(a.listener);
    if(!SetHandleInformation(reinterpret_cast<HANDLE>(value),HANDLE_FLAG_INHERIT,0)) return fail(s,static_cast<int>(GetLastError()));
    u_long nonblock=1; int one=1;
    if(ioctlsocket(value,FIONBIO,&nonblock) || setsockopt(value,IPPROTO_TCP,TCP_NODELAY,reinterpret_cast<const char*>(&one),sizeof(one))) return fail(s,WSAGetLastError());
    return refresh(s);
}
int deliver(projection_video_services *s,Slot &a) {
    if(!a.started) return IAP2_MORE;
    if(!a.held) {
        int r=projection_video_take(a.video,s->generation,&a.held,&a.metadata,s->now_ns/ns_ms);
        if(r==PROJECTION_VIDEO_MORE) return IAP2_MORE;
        if(r!=PROJECTION_VIDEO_FRAME) return fail(s,r);
    }
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    projection_h264_view view{};
    if(projection_h264_frame_view(a.held,&view)!=PROJECTION_H264_FRAME) return fail(s,IAP2_INVALID);
    int r=s->config.sink.submit(s->config.sink.context,s->generation,a.child,&view,&a.metadata);
    if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    if(r==IAP2_OK) { projection_h264_frame_destroy(a.held); a.held=nullptr; a.metadata={}; }
    return r;
}
int screen_poll(projection_video_services *s,Slot &a) {
    int r;
    if(a.started) {
        r=s->config.sink.poll(s->config.sink.context,s->generation,a.child,s->now_ns);
        if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);
        if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    }
    // Deliver at most once, before reading further input. Backpressure cannot
    // transfer a borrowed pointer or renew the held frame's absolute deadline.
    r=deliver(s,a); if(r<0) return r;
    if(a.held) return IAP2_OK;
    r=accept_screen(s,a); if(r==IAP2_MORE) return IAP2_OK; if(r) return r;
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    if(!a.used) {
        int n=recv(a.client,reinterpret_cast<char*>(a.network.data()),static_cast<int>(a.network.size()),0);
        if(n==SOCKET_ERROR) { r=WSAGetLastError(); return r==WSAEWOULDBLOCK?IAP2_OK:fail(s,r); }
        if(!n) return fail(s,IAP2_END); // No reconnect/nonce reset, no presentation of EOF tail.
        a.used=static_cast<size_t>(n); a.network_at=s->now_ns;
    }
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    size_t consumed=0;
    r=projection_video_feed(a.video,s->generation,a.network.data()+a.offset,a.used-a.offset,&consumed,s->now_ns/ns_ms);
    if(r<0) return fail(s,r);
    pair_crypto_wipe(a.network.data()+a.offset,consumed); a.offset+=consumed;
    if(a.offset==a.used) { a.offset=a.used=0; a.network_at=0; }
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    if(r==PROJECTION_VIDEO_CONFIG) {
        projection_video_configuration cfg{};
        if(projection_video_get_configuration(a.video,s->generation,&cfg)!=PROJECTION_VIDEO_CONFIG) return fail(s,IAP2_INVALID);
        r=s->config.sink.configure(s->config.sink.context,s->generation,a.child,&cfg); if(r) return fail(s,r);
        if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    }
    return IAP2_OK;
}
int poll_provider(void *s,uint64_t gen,uint64_t) { return projection_video_services_poll(static_cast<projection_video_services*>(s),gen); }
uint32_t delay_provider(const void *s,uint64_t gen) { return projection_video_services_next_delay(static_cast<const projection_video_services*>(s),gen); }
int playback(void *context,uint64_t gen,uint64_t lease,projection_playback_position *out) {
    if(out) *out={}; auto *s=static_cast<projection_video_services*>(context); int r=owner(s,gen); if(r) return r;
    if(!out) return IAP2_ARGUMENT;
    auto *a=find(s,lease); if(!a||a->type<100||a->type>102) return IAP2_INVALID;
    if(!s->config.other.playback) return IAP2_UNSUPPORTED;
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    r=s->config.other.playback(s->config.other.context,gen,a->child,out);
    if(r) { *out={}; return fail(s,r); }
    r=refresh(s); if(r) *out={}; return r;
}
int flush(void *context,uint64_t gen,uint64_t lease,const projection_audio_flush_request *q) {
    auto *s=static_cast<projection_video_services*>(context); int r=owner(s,gen); if(r) return r;
    auto *a=find(s,lease); if(!a||a->type<100||a->type>102||(q?(!a->started||a->flushing):!a->flushing)) return IAP2_INVALID;
    if(!s->config.other.flush) return IAP2_UNSUPPORTED;
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    r=s->config.other.flush(s->config.other.context,gen,a->child,q); if(r) return fail(s,r);
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    a->flushing=q!=nullptr; a->started=q==nullptr; return IAP2_OK;
}
}
extern "C" int projection_video_services_create(const projection_video_services_config *c,uint64_t gen,projection_video_services **out) {
    if(out) *out=nullptr;
    if(!out||!c||!gen||!ip_valid(c->local)||!ip_valid(c->peer)||c->local.family!=c->peer.family||!c->clock_ns||
       !c->accept_ms||c->accept_ms>60000||!c->poll_ms||c->poll_ms>1000||c->enabled_features>15||
       (c->enabled_features&PROJECTION_SESSION_HEVC)||!c->sink.open||!c->sink.start||!c->sink.configure||!c->sink.submit||!c->sink.poll||!c->sink.close)
        return IAP2_ARGUMENT;
    const auto &v=c->video; const auto &p=c->other;
    if(v.allow_clear_config!=1||v.queue_frames<2||v.queue_frames>8||!v.receive_ms||v.receive_ms>60000||!v.hold_ms||v.hold_ms>60000||
       v.max_width<16||v.max_height<16||v.max_width>PROJECTION_H264_MAX_WIDTH||v.max_height>PROJECTION_H264_MAX_HEIGHT||v.max_width%16||v.max_height%16||
       (bool(p.open)!=bool(p.start))||(bool(p.open)!=bool(p.close))||(bool(p.poll)!=bool(p.next_delay))||
       (!p.open&&(p.poll||p.playback||p.flush||p.clock))) return IAP2_ARGUMENT;
    auto *s=new(std::nothrow) projection_video_services;
    if(!s) return IAP2_NO_SPACE;
    s->config=*c; s->generation=gen; *out=s; return IAP2_OK;
}
extern "C" projection_session_provider projection_video_services_provider(projection_video_services *s) {
    projection_session_provider p{}; p.context=s; p.open=open_resource; p.start=start_resources; p.close=close_resource;
    p.poll=poll_provider; p.next_delay=delay_provider;
    p.playback=s&&s->config.other.playback?playback:nullptr; p.flush=s&&s->config.other.flush?flush:nullptr; return p;
}
extern "C" int projection_video_services_poll(projection_video_services *s,uint64_t gen) {
    int r=owner(s,gen); if(r) return r;
    bool active=false,other=false;
    for(const auto &a:s->slots) if(a.occupied) { active=true; if(!a.screen()) other=true; }
    if(!active) return IAP2_MORE;
    if(refresh(s)) return PROJECTION_VIDEO_SERVICES_CLOSED;
    for(auto &a:s->slots) if(a.occupied&&a.screen()) { r=screen_poll(s,a); if(r) return r; }
    if(other&&s->config.other.poll) {
        r=s->config.other.poll(s->config.other.context,gen,s->now_ns/ns_ms);
        if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);
    }
    return refresh(s);
}
extern "C" uint32_t projection_video_services_next_delay(const projection_video_services *s,uint64_t gen) {
    if(owner(s,gen)) return UINT32_MAX;
    uint32_t delay=UINT32_MAX; bool other=false;
    auto deadline=[&](uint64_t elapsed,uint32_t budget) { delay=std::min(delay,elapsed>=budget?0:budget-static_cast<uint32_t>(elapsed)); };
    for(const auto &a:s->slots) if(a.occupied) {
        delay=std::min(delay,s->config.poll_ms);
        if(!a.screen()) { other=true; continue; }
        if(a.client==INVALID_SOCKET) deadline((s->now_ns-a.opened_ns)/ns_ms,s->config.accept_ms);
        if(a.used) deadline((s->now_ns-a.network_at)/ns_ms,s->config.video.receive_ms);
        if(a.held) deadline(s->now_ns/ns_ms-a.metadata.received_ms,s->config.video.hold_ms);
        delay=std::min(delay,projection_video_next_delay(a.video));
    }
    if(other&&s->config.other.next_delay) delay=std::min(delay,s->config.other.next_delay(s->config.other.context,gen));
    return delay;
}
extern "C" int projection_video_services_error(const projection_video_services *s) { return s?s->last_error:IAP2_ARGUMENT; }
extern "C" void projection_video_services_close(projection_video_services *s) {
    if(!s||s->finalized) return;
    fail(s,IAP2_END); pair_crypto_wipe(&s->config,sizeof(s->config)); s->finalized=true;
}
extern "C" void projection_video_services_destroy(projection_video_services *s) { if(s) { projection_video_services_close(s); delete s; } }
