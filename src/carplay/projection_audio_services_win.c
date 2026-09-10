/* SPDX-License-Identifier: GPL-3.0-only */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "projection_audio_services.h"
#define BAD_SOCKET ((uintptr_t)INVALID_SOCKET)
static void copy(void *d,const void *p,size_t n) { size_t i; for(i=0;i<n;++i) ((uint8_t *)d)[i]=((const uint8_t *)p)[i]; }
static int same(const uint8_t *a,const uint8_t *b,size_t n) { size_t i; for(i=0;i<n;++i) if(a[i]!=b[i]) return 0; return 1; }
static int zero(const uint8_t *p,size_t n) { size_t i; for(i=0;i<n;++i) if(p[i]) return 0; return 1; }
static int ip_valid(const projection_ip *a) {
    if(a->family==4) return a->bytes[0]>0&&a->bytes[0]<224&&!a->scope&&zero(a->bytes+4,12);
    if(a->family!=6||zero(a->bytes,16)||a->bytes[0]==255||(zero(a->bytes,10)&&a->bytes[10]==255&&a->bytes[11]==255)) return 0;
    return (a->bytes[0]==0xfe&&(a->bytes[1]&0xc0)==0x80)?a->scope!=0:a->scope==0;
}
static int address(const projection_ip *ip,uint16_t port,SOCKADDR_STORAGE *out) {
    pair_crypto_wipe(out,sizeof(*out));
    if(ip->family==4) { SOCKADDR_IN *a=(SOCKADDR_IN *)out; a->sin_family=AF_INET; a->sin_port=htons(port); copy(&a->sin_addr,ip->bytes,4); return sizeof(*a); }
    { SOCKADDR_IN6 *a=(SOCKADDR_IN6 *)out; a->sin6_family=AF_INET6; a->sin6_port=htons(port); a->sin6_scope_id=ip->scope; copy(&a->sin6_addr,ip->bytes,16); return sizeof(*a); }
}
static int peer(const projection_ip *ip,const SOCKADDR_STORAGE *ss,int n,uint16_t *port) {
    if(ip->family==4&&ss->ss_family==AF_INET&&n==(int)sizeof(SOCKADDR_IN)) {
        const SOCKADDR_IN *a=(const SOCKADDR_IN *)ss; *port=ntohs(a->sin_port); return same((const uint8_t *)&a->sin_addr,ip->bytes,4);
    }
    if(ip->family==6&&ss->ss_family==AF_INET6&&n==(int)sizeof(SOCKADDR_IN6)) {
        const SOCKADDR_IN6 *a=(const SOCKADDR_IN6 *)ss; *port=ntohs(a->sin6_port); return a->sin6_scope_id==ip->scope&&same((const uint8_t *)&a->sin6_addr,ip->bytes,16);
    } return 0;
}
static int owner(const projection_audio_services *s,uint64_t gen) {
    if(!s||!s->ready||!gen) return IAP2_ARGUMENT; if(s->generation!=gen) return IAP2_INVALID; return s->failed?PROJECTION_AUDIO_CLOSED:IAP2_OK;
}
static void socket_close(uintptr_t *p) { if(*p!=BAD_SOCKET) { (void)closesocket((SOCKET)*p); *p=BAD_SOCKET; } }
static void slot_close(projection_audio_services *s,projection_audio_services_slot *slot) {
    if(!slot->occupied) return;
    socket_close(&slot->data_socket); socket_close(&slot->control_socket);
    projection_audio_close(&slot->audio);
    if(slot->child) s->config.sink.close(s->config.sink.context,s->generation,slot->child);
    pair_crypto_wipe(slot,sizeof(*slot)); slot->data_socket=slot->control_socket=BAD_SOCKET; --s->count;
    if(!s->count&&s->wsa) { (void)WSACleanup(); s->wsa=0; }
}
static int fail(projection_audio_services *s,int error) {
    size_t i; if(!s->failed) {
        s->failed=1; s->last_error=error; for(i=3;i>0;--i) slot_close(s,s->slots+i-1);
        pair_crypto_wipe(s->network,s->network_size);
    } return PROJECTION_AUDIO_CLOSED;
}
void projection_audio_services_close(projection_audio_services *s) {
    if(!s||!s->ready||s->finalized) return;
    (void)fail(s,IAP2_END); pair_crypto_wipe(s->storage,3*s->stream_bytes); pair_crypto_wipe(&s->config,sizeof(s->config)); s->finalized=1;
}
static int refresh(projection_audio_services *s) {
    size_t i; int r; uint64_t now=s->config.clock_ns(s->config.clock_context);
    if(now<s->now_ns) return fail(s,IAP2_INVALID); s->now_ns=now;
    for(i=0;i<3;++i) if(s->slots[i].occupied&&s->slots[i].audio.ready) {
        r=projection_audio_check(&s->slots[i].audio,s->generation,now); if(r) return fail(s,r);
    }
    return IAP2_OK;
}
int projection_audio_services_init(projection_audio_services *s,const projection_audio_services_config *c,uint8_t *storage,size_t capacity,uint8_t *network,size_t network_capacity,uint64_t gen) {
    size_t i,bytes; const projection_audio_sink *p;
    if(!s||!c||!storage||!network||!gen||!ip_valid(&c->local)||!ip_valid(&c->peer)||c->local.family!=c->peer.family||!c->clock_ns||!c->poll_ms||c->poll_ms>1000||
       !c->audio.slots||c->audio.slots>PROJECTION_AUDIO_SLOTS||!c->audio.payload_capacity||c->audio.payload_capacity>PROJECTION_AUDIO_PAYLOAD||
       c->audio.reorder_ms>1000||!c->audio.hold_ms||c->audio.hold_ms>60000) return IAP2_ARGUMENT;
    p=&c->sink; if(!p->open||!p->start||!p->submit||!p->poll||!p->playback||!p->close) return IAP2_ARGUMENT;
    bytes=c->audio.slots*c->audio.payload_capacity; if(capacity<3*bytes||network_capacity<c->audio.payload_capacity+36) return IAP2_NO_SPACE;
    pair_crypto_wipe(s,sizeof(*s)); s->config=*c; s->storage=storage; s->network=network; s->stream_bytes=bytes; s->network_size=c->audio.payload_capacity+36;
    s->generation=gen; s->next_lease=1; s->ready=1; for(i=0;i<3;++i) s->slots[i].data_socket=s->slots[i].control_socket=BAD_SOCKET; return IAP2_OK;
}
static int make_socket(projection_audio_services *s,uintptr_t *out,uint16_t *port) {
    SOCKET v; SOCKADDR_STORAGE a; int n,one=1; u_long nonblock=1; uint16_t actual=0;
    v=WSASocketW(s->config.local.family==4?AF_INET:AF_INET6,SOCK_DGRAM,0,0,0,WSA_FLAG_NO_HANDLE_INHERIT);
    if(v==INVALID_SOCKET) return WSAGetLastError(); *out=(uintptr_t)v;
    if(setsockopt(v,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char *)&one,sizeof(one))||
       (s->config.local.family==6&&setsockopt(v,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&one,sizeof(one)))||ioctlsocket(v,FIONBIO,&nonblock)) return WSAGetLastError();
    n=address(&s->config.local,0,&a); if(bind(v,(const SOCKADDR *)&a,n)||getsockname(v,(SOCKADDR *)&a,&n)) return WSAGetLastError();
    if(!peer(&s->config.local,&a,n,&actual)||!actual) return WSAEINVAL; *port=actual; return IAP2_OK;
}
static int open_resource(void *context,uint64_t gen,const projection_session_resource *q,uint8_t features,const projection_session_keys *key,projection_session_endpoint *out) {
    projection_audio_services *s=(projection_audio_services *)context; projection_audio_services_slot *slot; projection_audio_config cfg;
    projection_audio_format format; uint64_t child=0; size_t i,index; int r;
    if(out) pair_crypto_wipe(out,sizeof(*out)); r=owner(s,gen); if(r) return r;
    if(!q||!key||!out||features>15) return IAP2_ARGUMENT;
    if(q->type<100||q->type>102||q->peer_data_port||key->has_write) return IAP2_UNSUPPORTED;
    index=q->type-100; slot=s->slots+index; if(slot->occupied) return IAP2_INVALID; if(!s->next_lease) return IAP2_INVALID;
    r=projection_audio_format_get(q->audio_format,&format); if(r) return r;
    r=refresh(s); if(r) return r;
    slot->occupied=1; ++s->count; slot->type=q->type; slot->opened_ns=s->now_ns;
    cfg=s->config.audio; cfg.format=q->audio_format;
    r=projection_audio_init(&slot->audio,&cfg,s->storage+index*s->stream_bytes,s->stream_bytes,key->read,gen,s->now_ns); if(r) return fail(s,r);
    r=s->config.sink.open(s->config.sink.context,gen,q,&format,&child);
    if(child) {
        for(i=0;i<3;++i) if(s->slots[i].child==child) return fail(s,IAP2_INVALID);
        slot->child=child;
    }
    if(r||!child) return fail(s,r?r:IAP2_INVALID);
    r=refresh(s); if(r) return r;
    if(!s->wsa) { WSADATA d; r=WSAStartup(MAKEWORD(2,2),&d); if(r) return fail(s,r); s->wsa=1; }
    r=make_socket(s,&slot->data_socket,&out->data_port); if(!r) r=make_socket(s,&slot->control_socket,&out->control_port);
    if(r) { pair_crypto_wipe(out,sizeof(*out)); return fail(s,r); }
    slot->lease=s->next_lease++; out->lease=slot->lease; return IAP2_OK;
}
static projection_audio_services_slot *lease_slot(projection_audio_services *s,uint64_t lease) {
    size_t i; if(!lease) return 0; for(i=0;i<3;++i) if(s->slots[i].occupied&&s->slots[i].lease==lease) return s->slots+i; return 0;
}
static void close_resource(void *context,uint64_t gen,uint64_t lease) {
    projection_audio_services *s=(projection_audio_services *)context; projection_audio_services_slot *slot;
    if(!s||!s->ready||s->finalized||gen!=s->generation) return;
    slot=lease_slot(s,lease); if(slot) slot_close(s,slot);
}
static int start_resources(void *context,uint64_t gen,const uint64_t *leases,size_t count) {
    projection_audio_services *s=(projection_audio_services *)context; projection_audio_services_slot *slots[3]; size_t i,j; int r=owner(s,gen);
    if(r) return r; if(!leases||!count||count>3) return IAP2_ARGUMENT;
    for(i=0;i<count;++i) { slots[i]=lease_slot(s,leases[i]); if(!slots[i]||slots[i]->started||slots[i]->flushing) return IAP2_INVALID; for(j=0;j<i;++j) if(leases[j]==leases[i]) return IAP2_INVALID; }
    r=refresh(s); if(r) return r;
    for(i=0;i<count;++i) {
        slots[i]->started_ns=s->now_ns;
        r=s->config.sink.start(s->config.sink.context,gen,slots[i]->child); if(r) return fail(s,r);
        r=refresh(s); if(r) return r;
        r=projection_audio_start(&slots[i]->audio,gen,s->now_ns); if(r) return fail(s,r); slots[i]->started=1;
    } return IAP2_OK;
}
static int receive(projection_audio_services *s,projection_audio_services_slot *slot,int control) {
    SOCKADDR_STORAGE a; uint16_t port=0; int size=sizeof(a),n,r;
    if(!control&&slot->audio.count==slot->audio.config.slots) return IAP2_OK;
    n=recvfrom((SOCKET)(control?slot->control_socket:slot->data_socket),(char *)s->network,(int)s->network_size,0,(SOCKADDR *)&a,&size);
    if(n==SOCKET_ERROR) { r=WSAGetLastError(); pair_crypto_wipe(s->network,s->network_size); return r==WSAEWOULDBLOCK||r==WSAEMSGSIZE||r==WSAECONNRESET?IAP2_OK:fail(s,r); }
    if(peer(&s->config.peer,&a,size,&port)&&port) {
        if(control) { if(slot->control_received!=UINT32_MAX) ++slot->control_received; }
        else if(!slot->peer_port||slot->peer_port==port) {
            r=refresh(s); if(r) return r;
            r=projection_audio_feed(&slot->audio,s->generation,s->network,(size_t)n,s->now_ns);
            if(r==PROJECTION_AUDIO_PACKET) slot->peer_port=port;
            else if(r!=PROJECTION_AUDIO_DROPPED&&r!=PROJECTION_AUDIO_BUSY) return fail(s,r);
        }
    }
    pair_crypto_wipe(s->network,s->network_size); return IAP2_OK;
}
int projection_audio_services_poll(projection_audio_services *s,uint64_t gen) {
    size_t i; int r=owner(s,gen); if(r) return r; if(!s->count) return IAP2_MORE;
    r=refresh(s); if(r) return r;
    for(i=0;i<3;++i) if(s->slots[i].occupied) {
        projection_audio_services_slot *slot=s->slots+i; projection_audio_packet packet; projection_audio_key key;
        if(slot->started) { r=s->config.sink.poll(s->config.sink.context,gen,slot->child,s->now_ns); if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r); r=refresh(s); if(r) return r; }
        r=receive(s,slot,1); if(!r) r=receive(s,slot,0); if(r) return r;
        r=refresh(s); if(r) return r;
        r=projection_audio_peek(&slot->audio,gen,&packet,&key,s->now_ns);
        if(r==IAP2_MORE) continue; if(r!=PROJECTION_AUDIO_PACKET) return fail(s,r);
        r=s->config.sink.submit(s->config.sink.context,gen,slot->child,&slot->audio.format,&packet);
        if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);
        { int checked=refresh(s); if(checked) return checked; }
        if(r==IAP2_OK) { r=projection_audio_release(&slot->audio,key,s->now_ns); if(r) return fail(s,r); }
    }
    return IAP2_OK;
}
uint32_t projection_audio_services_next_delay(const projection_audio_services *s,uint64_t gen) {
    size_t i; uint32_t delay,n; if(owner(s,gen)||!s->count) return UINT32_MAX; delay=s->config.poll_ms;
    for(i=0;i<3;++i) if(s->slots[i].occupied) { n=projection_audio_next_delay(&s->slots[i].audio); if(n<delay) delay=n; } return delay;
}
static int poll_provider(void *s,uint64_t gen,uint64_t now) { (void)now; return projection_audio_services_poll((projection_audio_services *)s,gen); }
static uint32_t delay_provider(const void *s,uint64_t gen) { return projection_audio_services_next_delay((const projection_audio_services *)s,gen); }
static int playback_provider(void *context,uint64_t gen,uint64_t lease,projection_playback_position *out) {
    projection_audio_services *s=(projection_audio_services *)context; projection_audio_services_slot *slot; int r;
    if(out) pair_crypto_wipe(out,sizeof(*out)); if(!out) return IAP2_ARGUMENT; r=owner(s,gen); if(r) return r;
    slot=lease_slot(s,lease); if(!slot) return IAP2_INVALID; r=refresh(s); if(r) return r;
    r=s->config.sink.playback(s->config.sink.context,gen,slot->child,out); if(r) { pair_crypto_wipe(out,sizeof(*out)); return fail(s,r); }
    r=refresh(s);
    if(!r&&(out->sample_rate!=slot->audio.format.clock_rate||out->has_position>1||
       (!out->has_position&&(out->sample_time||out->raw_ns))||
       (out->has_position&&(!slot->started||out->raw_ns<slot->opened_ns||out->raw_ns<slot->started_ns||out->raw_ns>s->now_ns)))) r=fail(s,IAP2_INVALID);
    if(r) pair_crypto_wipe(out,sizeof(*out)); return r;
}
static int flush_provider(void *context,uint64_t gen,uint64_t lease,const projection_audio_flush_request *request) {
    projection_audio_services *s=(projection_audio_services *)context; projection_audio_services_slot *slot; int r=owner(s,gen);
    if(r) return r; if(!s->config.sink.flush) return IAP2_UNSUPPORTED;
    slot=lease_slot(s,lease); if(!slot||(request?(!slot->started||slot->flushing):!slot->flushing)) return IAP2_INVALID;
    r=refresh(s); if(r) return r;
    if(!request) slot->started_ns=s->now_ns;
    r=s->config.sink.flush(s->config.sink.context,gen,slot->child,request); if(r) return fail(s,r);
    r=refresh(s); if(r) return r;
    if(request) {
        r=projection_audio_flush(&slot->audio,gen,request->sample_time,s->now_ns); if(r) return fail(s,r);
        slot->started=0; slot->flushing=1;
    } else {
        r=projection_audio_start(&slot->audio,gen,s->now_ns); if(r) return fail(s,r);
        slot->started=1; slot->flushing=0;
    }
    return IAP2_OK;
}
projection_session_provider projection_audio_services_provider(projection_audio_services *s) {
    projection_session_provider p; p.context=s; p.open=open_resource; p.start=start_resources; p.close=close_resource;
    p.poll=poll_provider; p.next_delay=delay_provider; p.playback=playback_provider; p.clock=0;
    p.flush=s&&s->ready&&s->config.sink.flush?flush_provider:0; return p;
}
