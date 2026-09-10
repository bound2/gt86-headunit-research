/* SPDX-License-Identifier: GPL-3.0-only */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "projection_services.h"
#define BAD_SOCKET ((uintptr_t)INVALID_SOCKET)
static void copy(void *d,const void *p,size_t n) { size_t i; for(i=0;i<n;++i) ((uint8_t *)d)[i]=((const uint8_t *)p)[i]; }
static int same(const uint8_t *a,const uint8_t *b,size_t n) { size_t i; for(i=0;i<n;++i) if(a[i]!=b[i]) return 0; return 1; }
static int zero(const uint8_t *a,size_t n) { size_t i; for(i=0;i<n;++i) if(a[i]) return 0; return 1; }
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
static int peer(const projection_ip *ip,uint16_t port,const SOCKADDR_STORAGE *ss,int n) {
    if(ip->family==4&&ss->ss_family==AF_INET&&n==(int)sizeof(SOCKADDR_IN)) {
        const SOCKADDR_IN *a=(const SOCKADDR_IN *)ss; return (!port||ntohs(a->sin_port)==port)&&same((const uint8_t *)&a->sin_addr,ip->bytes,4);
    }
    if(ip->family==6&&ss->ss_family==AF_INET6&&n==(int)sizeof(SOCKADDR_IN6)) {
        const SOCKADDR_IN6 *a=(const SOCKADDR_IN6 *)ss; return (!port||ntohs(a->sin6_port)==port)&&a->sin6_scope_id==ip->scope&&same((const uint8_t *)&a->sin6_addr,ip->bytes,16);
    }
    return 0;
}
static void socket_close(uintptr_t *value) { if(*value!=BAD_SOCKET) { (void)shutdown((SOCKET)*value,SD_BOTH); (void)closesocket((SOCKET)*value); *value=BAD_SOCKET; } }
static void network_close(projection_services *s) {
    socket_close(&s->event_socket); socket_close(&s->listener); socket_close(&s->keep_socket); socket_close(&s->timing_socket);
    if(s->event.generation) control_cipher_close(&s->event);
    if(s->events_enabled) projection_events_close(&s->events);
    if(s->storage.network) pair_crypto_wipe(s->storage.network,s->storage.network_size);
    s->network_used=s->network_offset=0; s->connected=0;
    projection_timing_close(&s->timing);
    if(s->wsa&&!s->media_count) { (void)WSACleanup(); s->wsa=0; }
}
static int fail(projection_services *s,int error) { if(!s->failed) { s->last_error=error; s->failed=1; network_close(s); } return PROJECTION_SERVICES_CLOSED; }
static int owner(const projection_services *s,uint64_t gen) {
    if(!s||!s->ready||!gen) return IAP2_ARGUMENT;
    if(s->generation!=gen) return IAP2_INVALID; return s->failed?PROJECTION_SERVICES_CLOSED:IAP2_OK;
}
static int clock_check(projection_services *s,uint64_t now) {
    int r; if(now<s->now_ns) return fail(s,IAP2_INVALID); s->now_ns=now;
    if(!s->event_lease) return IAP2_OK;
    if(!s->connected&&now-s->opened_ns>=(uint64_t)s->config.accept_ms*1000000) return fail(s,IAP2_MORE);
    r=projection_timing_check(&s->timing,now); if(r!=IAP2_OK) return fail(s,r);
    r=control_cipher_check(&s->event,s->generation,now/1000000); if(r!=IAP2_OK) return fail(s,r);
    if(s->events_enabled) { r=projection_events_check(&s->events,s->generation,now/1000000); if(r) return fail(s,r); }
    return IAP2_OK;
}
static int refresh(projection_services *s) { return clock_check(s,s->config.clock_ns(s->config.clock_context)); }
static int make_socket(projection_services *s,int type,uintptr_t *out,uint16_t *port) {
    SOCKET socket_value; SOCKADDR_STORAGE a; int n,result,one=1; u_long nonblock=1;
    socket_value=WSASocketW(s->config.local.family==4?AF_INET:AF_INET6,type,0,0,0,WSA_FLAG_NO_HANDLE_INHERIT);
    if(socket_value==INVALID_SOCKET) return WSAGetLastError(); *out=(uintptr_t)socket_value;
    if(setsockopt(socket_value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char *)&one,sizeof(one))||
       (s->config.local.family==6&&setsockopt(socket_value,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&one,sizeof(one)))||
       ioctlsocket(socket_value,FIONBIO,&nonblock)) return WSAGetLastError();
    n=address(&s->config.local,0,&a); result=bind(socket_value,(const SOCKADDR *)&a,n);
    if(result||getsockname(socket_value,(SOCKADDR *)&a,&n)) return WSAGetLastError();
    if(!peer(&s->config.local,0,&a,n)) return WSAEINVAL;
    *port=ntohs(s->config.local.family==4?((SOCKADDR_IN *)&a)->sin_port:((SOCKADDR_IN6 *)&a)->sin6_port);
    if(!*port) return WSAEINVAL;
    if(type==SOCK_STREAM&&listen(socket_value,4)) return WSAGetLastError(); return IAP2_OK;
}
void projection_services_default_config(projection_services_config *c) {
    if(c) { pair_crypto_wipe(c,sizeof(*c)); projection_timing_default_config(&c->timing); control_cipher_default_config(&c->event); c->accept_ms=10000; c->poll_ms=5; }
}
int projection_services_init(projection_services *s,const projection_services_config *c,const projection_services_storage *b,uint64_t gen) {
    projection_timing timing; control_cipher cipher; int r;
    if(!s||!c||!b||!gen||!ip_valid(&c->local)||!ip_valid(&c->peer)||c->local.family!=c->peer.family||!c->clock_ns||
       !c->accept_ms||c->accept_ms>60000||!c->poll_ms||c->poll_ms>1000||c->enabled_features>15||!b->network||
       b->network_size<1||b->network_size>CONTROL_CIPHER_MAX_PAYLOAD+18||
       ((c->media.open!=0)!=(c->media.start!=0))||((c->media.open!=0)!=(c->media.close!=0))||
       ((c->media.poll!=0)!=(c->media.next_delay!=0))||(!c->media.open&&(c->enabled_features||c->media.poll))) return IAP2_ARGUMENT;
    r=projection_timing_init(&timing,&c->timing,c->mono_origin_ns,c->ntp_origin); if(r) return r;
    r=control_cipher_init(&cipher,&c->event,b->cipher_rx,b->cipher_rx_size,b->plain,b->plain_size,b->cipher_tx,b->cipher_tx_size,gen,c->mono_origin_ns/1000000);
    if(r) return r; pair_crypto_wipe(&cipher,sizeof(cipher));
    pair_crypto_wipe(s,sizeof(*s)); s->config=*c; s->storage=*b; s->generation=gen; s->next_lease=1; s->ready=1;
    s->timing_socket=s->keep_socket=s->listener=s->event_socket=BAD_SOCKET; s->now_ns=c->mono_origin_ns; return IAP2_OK;
}
int projection_services_enable_events(projection_services *s,uint64_t gen,const projection_events_config *c,const projection_events_storage *b) {
    projection_events e; int r=owner(s,gen); if(r) return r;
    if(s->opened||s->events_enabled) return RTSP_BUSY;
    r=projection_events_init(&e,c,b,gen,s->now_ns/1000000); if(r) return r; s->events=e; s->events_enabled=1; return IAP2_OK;
}
static int open_resource(void *context,uint64_t gen,const projection_session_resource *q,uint8_t features,const projection_session_keys *keys,projection_session_endpoint *out) {
    projection_services *s=(projection_services *)context; projection_session_endpoint e; uint64_t now; size_t i; int r=owner(s,gen);
    if(out) pair_crypto_wipe(out,sizeof(*out)); if(r) return r;
    if(!q||!keys||!out||features!=s->config.enabled_features||!s->next_lease) return IAP2_ARGUMENT;
    pair_crypto_wipe(&e,sizeof(e));
    if(q->type) {
        if(!s->event_lease||!s->config.media.open) return IAP2_UNSUPPORTED;
        if(s->media_count==PROJECTION_SESSION_STREAMS) return IAP2_NO_SPACE;
        r=refresh(s); if(r) return r;
        r=s->config.media.open(s->config.media.context,gen,q,features,keys,&e);
        if(e.lease) {
            for(i=0;i<s->media_count;++i) if(s->media[i].child==e.lease) return fail(s,IAP2_INVALID);
            s->media[s->media_count].child=e.lease; s->media[s->media_count].type=q->type;
            s->media[s->media_count++].lease=s->next_lease; e.lease=s->next_lease++;
        }
        *out=e; return r;
    }
    if(s->opened||!q->peer_timing_port||q->keep_alive_low_power>1||keys->has_write!=1) return IAP2_INVALID;
    s->opened=1; now=s->config.clock_ns(s->config.clock_context); if(now<s->now_ns) return fail(s,IAP2_INVALID);
    s->now_ns=s->opened_ns=now; s->peer_timing_port=q->peer_timing_port;
    r=projection_timing_init(&s->timing,&s->config.timing,s->config.mono_origin_ns,s->config.ntp_origin); if(r) return fail(s,r);
    s->timing.opened_ns=s->timing.now_ns=now; /* Explicit origin may predate socket open; sync budget starts here. */
    r=control_cipher_init(&s->event,&s->config.event,s->storage.cipher_rx,s->storage.cipher_rx_size,s->storage.plain,s->storage.plain_size,
        s->storage.cipher_tx,s->storage.cipher_tx_size,gen,now/1000000); if(r) return fail(s,r);
    r=control_cipher_start(&s->event,gen,keys->read,keys->write,now/1000000); if(r) return fail(s,r);
    { WSADATA data; r=WSAStartup(MAKEWORD(2,2),&data); if(r) return fail(s,r); s->wsa=1; }
    r=make_socket(s,SOCK_DGRAM,&s->timing_socket,&e.timing_port); if(r) return fail(s,r);
    r=make_socket(s,SOCK_STREAM,&s->listener,&e.event_port); if(r) return fail(s,r);
    if(q->keep_alive_low_power) { r=make_socket(s,SOCK_DGRAM,&s->keep_socket,&e.keep_alive_port); if(r) return fail(s,r); }
    s->event_lease=e.lease=s->next_lease++; *out=e; return IAP2_OK;
}
static void close_resource(void *context,uint64_t gen,uint64_t lease) {
    projection_services *s=(projection_services *)context; size_t i,j;
    if(!s||!s->ready||s->finalized||gen!=s->generation||!lease) return;
    for(i=0;i<s->media_count;++i) if(s->media[i].lease==lease) {
        s->config.media.close(s->config.media.context,gen,s->media[i].child);
        for(j=i+1;j<s->media_count;++j) s->media[j-1]=s->media[j]; --s->media_count; pair_crypto_wipe(s->media+s->media_count,sizeof(s->media[0]));
        if(s->failed&&s->wsa&&!s->media_count) { (void)WSACleanup(); s->wsa=0; } return;
    }
    if(lease==s->event_lease) { network_close(s); s->event_lease=0; s->failed=1; }
}
void projection_services_close(projection_services *s) {
    if(!s||!s->ready||s->finalized) return;
    while(s->media_count) close_resource(s,s->generation,s->media[s->media_count-1].lease);
    network_close(s); pair_crypto_wipe(&s->config,sizeof(s->config)); s->event_lease=0; s->failed=s->finalized=1;
}
static int start_resources(void *context,uint64_t gen,const uint64_t *leases,size_t count) {
    projection_services *s=(projection_services *)context; uint64_t children[PROJECTION_SESSION_STREAMS]; size_t i,j,k,n=0; int initial=0,r=owner(s,gen);
    if(r) return r; if(!leases||!count||count>PROJECTION_SESSION_STREAMS+1) return IAP2_ARGUMENT;
    for(i=0;i<count;++i) {
        for(k=0;k<i;++k) if(leases[k]==leases[i]) return IAP2_INVALID;
        if(leases[i]&&leases[i]==s->event_lease) { initial=1; continue; }
        for(j=0;j<s->media_count;++j) if(s->media[j].lease==leases[i]) break;
        if(j==s->media_count) return IAP2_INVALID; children[n++]=s->media[j].child;
    }
    r=refresh(s); if(r) return r;
    if(n) { r=s->config.media.start(s->config.media.context,gen,children,n); if(r) return fail(s,r); }
    if(initial) {
        if(s->events_enabled) { r=projection_events_start(&s->events,gen,s->now_ns/1000000); if(r) return fail(s,r); }
        s->started=1;
    } return IAP2_OK;
}
static int udp_send(projection_services *s,const uint8_t *p,size_t n) {
    SOCKADDR_STORAGE dest; int size=address(&s->config.peer,s->peer_timing_port,&dest);
    int sent=sendto((SOCKET)s->timing_socket,(const char *)p,(int)n,0,(const SOCKADDR *)&dest,size);
    if(sent==(int)n) return IAP2_OK;
    if(sent==SOCKET_ERROR) { int error=WSAGetLastError(); if(error==WSAEWOULDBLOCK||error==WSAENOBUFS||error==WSAECONNRESET) return IAP2_MORE; return fail(s,error); }
    return fail(s,IAP2_INVALID);
}
static int udp_poll(projection_services *s) {
    uint8_t p[32],reply[32]; SOCKADDR_STORAGE source; int n,size,r; unsigned i;
    for(i=0;i<4;++i) {
        if(refresh(s)) return PROJECTION_SERVICES_CLOSED;
        size=sizeof(source); n=recvfrom((SOCKET)s->timing_socket,(char *)p,sizeof(p),0,(SOCKADDR *)&source,&size);
        if(n==SOCKET_ERROR) { int error=WSAGetLastError(); if(error==WSAEWOULDBLOCK) break; if(error==WSAEMSGSIZE||error==WSAECONNRESET) continue; return fail(s,error); }
        if(!peer(&s->config.peer,s->peer_timing_port,&source,size)) continue;
        { uint64_t rx=s->config.clock_ns(s->config.clock_context),tx=s->config.clock_ns(s->config.clock_context);
          r=projection_timing_feed(&s->timing,p,(size_t)n,rx,tx,reply);
          if(r==PROJECTION_TIMING_CLOSED||r==IAP2_ARGUMENT) return fail(s,r);
          if(clock_check(s,tx)) return PROJECTION_SERVICES_CLOSED;
          if(r==PROJECTION_TIMING_REPLY) { r=udp_send(s,reply,32); if(r!=IAP2_OK&&r!=IAP2_MORE) return r; } }
    }
    if(refresh(s)) return PROJECTION_SERVICES_CLOSED;
    r=projection_timing_probe(&s->timing,s->now_ns,p);
    if(r==IAP2_OK) {
        r=udp_send(s,p,32); if(r==IAP2_OK) return projection_timing_sent(&s->timing,s->now_ns,projection_timing_now(&s->timing,s->now_ns));
        if(r!=IAP2_MORE) return r;
    } else if(r!=IAP2_MORE) return fail(s,r);
    return IAP2_OK;
}
static int event_poll(projection_services *s) {
    rtsp_slice output; control_cipher_key key; size_t used; int n,r;
    if(!s->connected) {
        SOCKADDR_STORAGE source; int size=sizeof(source); SOCKET accepted;
        if(refresh(s)) return PROJECTION_SERVICES_CLOSED;
        accepted=accept((SOCKET)s->listener,(SOCKADDR *)&source,&size);
        if(accepted==INVALID_SOCKET) { r=WSAGetLastError(); return r==WSAEWOULDBLOCK?IAP2_OK:fail(s,r); }
        if(!peer(&s->config.peer,0,&source,size)) { (void)closesocket(accepted); return IAP2_OK; }
        { u_long nonblock=1; int one=1;
          if(!SetHandleInformation((HANDLE)accepted,HANDLE_FLAG_INHERIT,0)) { r=(int)GetLastError(); (void)closesocket(accepted); return fail(s,r); }
          if(ioctlsocket(accepted,FIONBIO,&nonblock)||
             setsockopt(accepted,IPPROTO_TCP,TCP_NODELAY,(const char *)&one,sizeof(one))) { r=WSAGetLastError(); (void)closesocket(accepted); return fail(s,r); } }
        s->event_socket=(uintptr_t)accepted; s->connected=1; socket_close(&s->listener);
    }
    if(refresh(s)) return PROJECTION_SERVICES_CLOSED;
    r=control_cipher_output(&s->event,&output,&key);
    if(r==CONTROL_CIPHER_OUTPUT) {
        n=send((SOCKET)s->event_socket,(const char *)output.data,(int)output.size,0);
        if(n==SOCKET_ERROR) { r=WSAGetLastError(); if(r!=WSAEWOULDBLOCK&&r!=WSAENOBUFS) return fail(s,r); }
        else { if(n<=0) return fail(s,IAP2_END); r=control_cipher_consume_output(&s->event,key,(size_t)n,s->now_ns/1000000); if(r!=IAP2_OK&&r!=CONTROL_CIPHER_OUTPUT) return fail(s,r); }
    } else if(r!=IAP2_MORE) return fail(s,r);
    if(s->event.held) return IAP2_OK;
    if(refresh(s)) return PROJECTION_SERVICES_CLOSED;
    if(s->network_offset==s->network_used) {
        s->network_offset=s->network_used=0;
        n=recv((SOCKET)s->event_socket,(char *)s->storage.network,(int)s->storage.network_size,0);
        if(n==SOCKET_ERROR) { r=WSAGetLastError(); return r==WSAEWOULDBLOCK?IAP2_OK:fail(s,r); }
        if(!n) return fail(s,IAP2_END); s->network_used=(size_t)n;
    }
    r=control_cipher_feed(&s->event,s->generation,s->storage.network+s->network_offset,s->network_used-s->network_offset,&used,s->now_ns/1000000);
    pair_crypto_wipe(s->storage.network+s->network_offset,used); s->network_offset+=used;
    return r==IAP2_MORE||r==CONTROL_CIPHER_FRAME?IAP2_OK:fail(s,r);
}
static int messages_poll(projection_services *s) {
    rtsp_slice bytes; control_cipher_key cipher_key; rtsp_channel_key key; size_t used; int r,command;
    if(!s->events_enabled||!s->connected) return IAP2_OK;
    if(refresh(s)) return PROJECTION_SERVICES_CLOSED;
    /* A response can already be queued by the peer after the last socket send.
     * Publish that send's drain BEFORE consuming the incoming response. */
    if(s->events.active&&!s->event.tx_size) {
        r=projection_events_output(&s->events,s->generation,&bytes,&key,&command,s->now_ns/1000000);
        if(r==PROJECTION_EVENTS_DRAIN) { r=projection_events_drain(&s->events,key,s->now_ns/1000000); if(r) return fail(s,r); }
        else if(r!=PROJECTION_EVENTS_OUTPUT) return fail(s,r);
    }
    if(!s->events.held&&s->event.held) {
        r=control_cipher_plain(&s->event,&bytes,&cipher_key); if(r!=CONTROL_CIPHER_FRAME) return fail(s,r);
        r=projection_events_feed(&s->events,s->generation,bytes.data,bytes.size,&used,s->now_ns/1000000);
        if(r!=IAP2_MORE&&r!=PROJECTION_EVENTS_REQUEST&&r!=PROJECTION_EVENTS_RESPONSE) return fail(s,r);
        r=control_cipher_consume_plain(&s->event,cipher_key,used,s->now_ns/1000000);
        if(r!=IAP2_OK&&r!=CONTROL_CIPHER_FRAME) return fail(s,r);
    }
    if(!s->event.tx_size) {
        r=projection_events_output(&s->events,s->generation,&bytes,&key,&command,s->now_ns/1000000);
        if(r==IAP2_MORE) return IAP2_OK; if(r!=PROJECTION_EVENTS_OUTPUT) return fail(s,r);
        if(command&&!s->started) return fail(s,IAP2_INVALID);
        used=bytes.size>s->config.event.payload_limit?s->config.event.payload_limit:bytes.size;
        r=control_cipher_queue(&s->event,s->generation,bytes.data,used,s->now_ns/1000000); if(r!=CONTROL_CIPHER_OUTPUT) return fail(s,r);
        r=projection_events_consume(&s->events,key,used,s->now_ns/1000000);
        if(r!=PROJECTION_EVENTS_OUTPUT&&r!=PROJECTION_EVENTS_DRAIN) return fail(s,r);
    } return IAP2_OK;
}
int projection_services_poll(projection_services *s,uint64_t gen) {
    int r=owner(s,gen); if(r) return r; if(!s->event_lease) return IAP2_MORE;
    r=udp_poll(s); if(r) return r;
    if(s->keep_socket!=BAD_SOCKET) {
        uint8_t p[256]; SOCKADDR_STORAGE source; int size=sizeof(source),n;
        if(refresh(s)) return PROJECTION_SERVICES_CLOSED;
        n=recvfrom((SOCKET)s->keep_socket,(char *)p,sizeof(p),0,(SOCKADDR *)&source,&size);
        if(n==SOCKET_ERROR) { r=WSAGetLastError(); if(r!=WSAEWOULDBLOCK&&r!=WSAEMSGSIZE&&r!=WSAECONNRESET) return fail(s,r); }
        if(n>=0&&peer(&s->config.peer,0,&source,size)&&s->keep_received!=UINT32_MAX) ++s->keep_received;
        /* No reply or lifetime extension, even from the pinned peer. */
        pair_crypto_wipe(p,sizeof(p));
    }
    r=event_poll(s); if(r) return r;
    r=messages_poll(s); if(r) return r;
    if(s->media_count&&s->config.media.poll) { r=s->config.media.poll(s->config.media.context,gen,s->now_ns/1000000); if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r); }
    return IAP2_OK;
}
uint32_t projection_services_next_delay(const projection_services *s,uint64_t gen) {
    uint32_t delay,n; uint64_t elapsed;
    if(owner(s,gen)!=IAP2_OK||!s->event_lease) return UINT32_MAX;
    delay=s->config.poll_ms; n=projection_timing_next_delay(&s->timing); if(n<delay) delay=n;
    n=control_cipher_next_delay(&s->event); if(n<delay) delay=n;
    if(s->events_enabled) { n=projection_events_next_delay(&s->events); if(n<delay) delay=n; }
    if(!s->connected) { elapsed=(s->now_ns-s->opened_ns)/1000000; n=elapsed>=s->config.accept_ms?0:s->config.accept_ms-(uint32_t)elapsed; if(n<delay) delay=n; }
    if(s->media_count&&s->config.media.next_delay) { n=s->config.media.next_delay(s->config.media.context,gen); if(n<delay) delay=n; }
    return delay;
}
static int poll_provider(void *s,uint64_t gen,uint64_t now) { (void)now; return projection_services_poll((projection_services *)s,gen); }
static uint32_t delay_provider(const void *s,uint64_t gen) { return projection_services_next_delay((const projection_services *)s,gen); }
projection_session_provider projection_services_provider(projection_services *s) {
    projection_session_provider p; p.context=s; p.open=open_resource; p.start=start_resources; p.close=close_resource; p.poll=poll_provider; p.next_delay=delay_provider; return p;
}
int projection_services_event_peek(const projection_services *s,uint64_t gen,rtsp_slice *out,control_cipher_key *key) {
    int r; if(out) pair_crypto_wipe(out,sizeof(*out)); if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!out||!key) return IAP2_ARGUMENT; r=owner(s,gen); if(r) return r; if(s->events_enabled) return IAP2_UNSUPPORTED;
    return s->connected?control_cipher_plain(&s->event,out,key):IAP2_MORE;
}
int projection_services_event_consume(projection_services *s,control_cipher_key key,size_t n,uint64_t now) {
    rtsp_slice p; control_cipher_key current; int r=projection_services_event_peek(s,key.generation,&p,&current);
    if(r!=CONTROL_CIPHER_FRAME) return r;
    if(current.counter!=key.counter) return IAP2_INVALID;
    if(n>p.size||(!n&&p.size)||now<s->now_ns) return IAP2_ARGUMENT;
    r=clock_check(s,now); if(r) return r;
    r=control_cipher_consume_plain(&s->event,key,n,now/1000000); return r==IAP2_OK||r==CONTROL_CIPHER_FRAME?r:fail(s,r);
}
int projection_services_event_queue(projection_services *s,uint64_t gen,const uint8_t *p,size_t n,int unsolicited,uint64_t now) {
    int r=owner(s,gen); if(r) return r;
    if(s->events_enabled) return IAP2_UNSUPPORTED;
    if((!p&&n)||n>s->config.event.payload_limit||(unsolicited!=0&&unsolicited!=1)||now<s->now_ns) return IAP2_ARGUMENT;
    if(!s->connected||(unsolicited&&!s->started)||s->event.tx_size) return CONTROL_CIPHER_BUSY;
    r=clock_check(s,now); if(r) return r;
    r=control_cipher_queue(&s->event,gen,p,n,now/1000000); return r==CONTROL_CIPHER_OUTPUT?r:fail(s,r);
}
int projection_services_commands(projection_services *s,uint64_t gen,const rtsp_slice *bodies,size_t count,rtsp_channel_key *keys,uint64_t now) {
    int r; if(keys&&count<=PROJECTION_EVENTS_SLOTS) pair_crypto_wipe(keys,count*sizeof(*keys));
    r=owner(s,gen); if(r) return r; if(!s->events_enabled) return IAP2_UNSUPPORTED;
    if(now<s->now_ns) return IAP2_ARGUMENT; if(!s->connected) return RTSP_BUSY;
    r=projection_events_queue(&s->events,gen,bodies,count,keys,now/1000000);
    if(r==PROJECTION_EVENTS_CLOSED) return fail(s,r); if(r!=PROJECTION_EVENTS_OUTPUT) return r;
    if(clock_check(s,now)) { pair_crypto_wipe(keys,count*sizeof(*keys)); return PROJECTION_SERVICES_CLOSED; } return r;
}
int projection_services_message(const projection_services *s,uint64_t gen,rtsp_message *m,rtsp_channel_key *key) {
    int r; if(m) pair_crypto_wipe(m,sizeof(*m)); if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!m||!key) return IAP2_ARGUMENT; r=owner(s,gen); if(r) return r; if(!s->events_enabled) return IAP2_UNSUPPORTED;
    return projection_events_message(&s->events,gen,m,key);
}
int projection_services_respond(projection_services *s,rtsp_channel_key key,const rtsp_response *res,uint64_t now) {
    int r=owner(s,key.generation); if(r) return r; if(!s->events_enabled) return IAP2_UNSUPPORTED; if(now<s->now_ns) return IAP2_ARGUMENT;
    r=projection_events_respond(&s->events,key,res,now/1000000); if(r==PROJECTION_EVENTS_CLOSED) return fail(s,r);
    if(r!=PROJECTION_EVENTS_OUTPUT) return r; return clock_check(s,now)?PROJECTION_SERVICES_CLOSED:r;
}
int projection_services_release(projection_services *s,rtsp_channel_key key,uint64_t now) {
    int r=owner(s,key.generation); if(r) return r; if(!s->events_enabled) return IAP2_UNSUPPORTED; if(now<s->now_ns) return IAP2_ARGUMENT;
    r=projection_events_release(&s->events,key,now/1000000); if(r==PROJECTION_EVENTS_CLOSED) return fail(s,r);
    if(r!=IAP2_OK) return r; return clock_check(s,now);
}
