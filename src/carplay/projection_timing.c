/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_timing.h"
static void zero(void *p,size_t n) { size_t i; for(i=0;i<n;++i) ((uint8_t *)p)[i]=0; }
static uint64_t ticks(uint64_t ns) { return ((ns/UINT64_C(1000000000))<<32)+((ns%UINT64_C(1000000000))<<32)/UINT64_C(1000000000); }
static uint64_t ms(uint32_t n) { return (uint64_t)n*UINT64_C(1000000); }
static uint64_t read64(const uint8_t *p) { size_t i; uint64_t n=0; for(i=0;i<8;++i) n=(n<<8)|p[i]; return n; }
static void write64(uint8_t *p,uint64_t n) { size_t i; for(i=8;i>0;--i) { p[i-1]=(uint8_t)n; n>>=8; } }
static void packet(uint8_t *p,uint8_t type,uint64_t t1,uint64_t t2,uint64_t t3) {
    zero(p,32); p[0]=0x80; p[1]=type; p[3]=7; write64(p+8,t1); write64(p+16,t2); write64(p+24,t3);
}
void projection_timing_default_config(projection_timing_config *c) { if(c) { c->interval_ms=1000; c->response_ms=3000; c->sync_ms=30000; c->max_rtt_ms=500; } }
int projection_timing_init(projection_timing *s,const projection_timing_config *c,uint64_t now,uint64_t ntp) {
    if(!s||!c||!c->interval_ms||c->interval_ms>60000||!c->response_ms||c->response_ms>60000||
       !c->sync_ms||c->sync_ms>60000||!c->max_rtt_ms||c->max_rtt_ms>c->response_ms) return IAP2_ARGUMENT;
    zero(s,sizeof(*s)); s->config=*c; s->now_ns=s->opened_ns=s->mono_origin=now; s->ntp_origin=ntp; s->active=1; return IAP2_OK;
}
void projection_timing_close(projection_timing *s) { if(s) zero(s,sizeof(*s)); }
int projection_timing_check(projection_timing *s,uint64_t now) {
    if(!s) return IAP2_ARGUMENT; if(!s->active) return PROJECTION_TIMING_CLOSED;
    if(now<s->now_ns) return IAP2_ARGUMENT; s->now_ns=now;
    if(now-(s->synced?s->last_sync_ns:s->opened_ns)>=ms(s->config.sync_ms)) { projection_timing_close(s); return PROJECTION_TIMING_CLOSED; }
    if(s->pending&&now-s->pending_ns>=ms(s->config.response_ms)) { s->pending=0; if(s->timeouts!=UINT32_MAX) ++s->timeouts; }
    return IAP2_OK;
}
uint64_t projection_timing_now(const projection_timing *s,uint64_t now) {
    return s&&s->active&&now>=s->mono_origin?s->ntp_origin+ticks(now-s->mono_origin):0;
}
int projection_timing_probe(projection_timing *s,uint64_t now,uint8_t out[32]) {
    int r; if(!out) return IAP2_ARGUMENT; r=projection_timing_check(s,now); if(r) return r;
    if(s->pending||(s->sent&&now-s->last_sent_ns<ms(s->config.interval_ms))) return IAP2_MORE;
    packet(out,210,0,0,projection_timing_now(s,now)); return IAP2_OK;
}
int projection_timing_sent(projection_timing *s,uint64_t now,uint64_t t1) {
    int r;
    if(!s||!s->active||now<s->now_ns||t1!=projection_timing_now(s,now)) return IAP2_ARGUMENT;
    r=projection_timing_check(s,now); if(r) return r;
    if(s->pending||(s->sent&&now-s->last_sent_ns<ms(s->config.interval_ms))) return IAP2_MORE;
    s->pending=s->sent=1; s->pending_t1=t1; s->pending_ns=s->last_sent_ns=now; return IAP2_OK;
}
int projection_timing_feed(projection_timing *s,const uint8_t *p,size_t n,uint64_t rx,uint64_t tx,uint8_t out[32]) {
    uint64_t t1,t2,t3,elapsed,peer,rtt,offset,absolute,applied; size_t i; int r,use=1;
    if(!p||!out||tx<rx||!s||rx<s->now_ns) return IAP2_ARGUMENT;
    r=projection_timing_check(s,tx); if(r) return r;
    if(n!=32||p[0]!=0x80||(p[1]!=210&&p[1]!=211)||p[2]||p[3]!=7) return IAP2_INVALID;
    t1=read64(p+8); t2=read64(p+16); t3=read64(p+24);
    if(p[1]==210) { packet(out,211,t3,projection_timing_now(s,rx),projection_timing_now(s,tx)); return PROJECTION_TIMING_REPLY; }
    if(!s->pending||t1!=s->pending_t1) return IAP2_MORE;
    s->pending=0; elapsed=ticks(rx-s->pending_ns); peer=t3-t2;
    if(peer>elapsed) return IAP2_INVALID;
    rtt=elapsed-peer; if(rtt>ticks(ms(s->config.max_rtt_ms))) return IAP2_INVALID;
    offset=(t2+peer/2)-(t1+elapsed/2);
    if(offset==UINT64_C(0x8000000000000000)) return IAP2_INVALID; /* Ambiguous half era. */
    if(!s->picks||rtt<s->pick_rtt) { s->pick_rtt=rtt; s->pick_offset=offset; }
    if(++s->picks<2) return IAP2_OK;
    rtt=s->pick_rtt; offset=s->pick_offset; s->picks=0;
    for(i=0;i<s->delay_count;++i) if(rtt>s->delays[i]) use=0;
    s->delays[s->delay_index]=rtt; s->delay_index=(uint8_t)((s->delay_index+1)%8); if(s->delay_count<8) ++s->delay_count;
    if(!use) return IAP2_OK;
    absolute=(offset>>63)?UINT64_C(0)-offset:offset;
    if(!s->synced||absolute>UINT64_C(549755814)) { applied=offset; s->delay_count=s->delay_index=0; }
    else applied=(offset>>63)?UINT64_C(0)-(absolute/8):offset/8;
    s->ntp_origin+=applied; s->last_sync_ns=tx; s->synced=1; if(s->samples!=UINT32_MAX) ++s->samples;
    return PROJECTION_TIMING_SAMPLE;
}
static uint32_t left(uint64_t elapsed,uint64_t budget) { return elapsed>=budget?0:(uint32_t)((budget-elapsed+999999)/1000000); }
uint32_t projection_timing_next_delay(const projection_timing *s) {
    uint32_t a,b; if(!s||!s->active) return UINT32_MAX;
    a=left(s->now_ns-(s->synced?s->last_sync_ns:s->opened_ns),ms(s->config.sync_ms));
    b=s->pending?left(s->now_ns-s->pending_ns,ms(s->config.response_ms)):
        (s->sent?left(s->now_ns-s->last_sent_ns,ms(s->config.interval_ms)):0);
    return a<b?a:b;
}
