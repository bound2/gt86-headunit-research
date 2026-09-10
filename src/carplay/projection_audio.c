/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_audio.h"
static void copy(void *d,const void *p,size_t n) { size_t i; for(i=0;i<n;++i) ((uint8_t *)d)[i]=((const uint8_t *)p)[i]; }
static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static uint64_t le64(const uint8_t *p) { uint64_t n=0; unsigned i; for(i=0;i<8;++i) n|=(uint64_t)p[i]<<(8*i); return n; }
int projection_audio_sync_parse(const uint8_t *p,size_t n,projection_audio_sync *out) {
    projection_audio_sync value={0,0,0,0};
    if(!p||!out) return IAP2_ARGUMENT;
    if(n!=20||(p[0]!=0x80&&p[0]!=0x90)||p[1]!=0xd4||p[2]||p[3]!=4) return IAP2_INVALID;
    value.ntp=((uint64_t)be32(p+8)<<32)|be32(p+12);
    value.play_sample=be32(p+4); value.sender_sample=be32(p+16); value.initial=(uint8_t)(p[0]==0x90);
    *out=value; return IAP2_OK;
}
int projection_audio_format_get(uint32_t bit,projection_audio_format *out) {
    static const uint32_t bits[]={4,8,16,32,64,128,256,512,1024,2048,16384,32768};
    static const uint32_t rates[]={8000,16000,24000,32000,44100,48000};
    projection_audio_format f={0,0,0,0,0,0}; size_t i;
    if(!out) return IAP2_ARGUMENT;
    if(!bit||(bit&(bit-1))) return IAP2_INVALID;
    f.bit=bit;
    for(i=0;i<12;++i) if(bit==bits[i]) { f.codec=PROJECTION_AUDIO_PCM16; f.clock_rate=rates[i/2]; f.channels=(uint8_t)(i%2+1); break; }
    if(bit==0x400000u||bit==0x800000u) { f.codec=PROJECTION_AUDIO_AAC_LC; f.clock_rate=bit==0x400000u?44100:48000; f.channels=2; f.aac_config=(uint16_t)(bit==0x400000u?0x1210:0x1190); }
    if(bit==0x10000000u||bit==0x20000000u||bit==0x40000000u) {
        f.codec=PROJECTION_AUDIO_OPUS; f.clock_rate=48000; f.channels=1;
        f.input_rate=bit==0x10000000u?16000:bit==0x20000000u?24000:48000;
    }
    if(!f.codec) return IAP2_UNSUPPORTED;
    if(!f.input_rate) f.input_rate=f.clock_rate; *out=f; return IAP2_OK;
}
void projection_audio_default_config(projection_audio_config *c) {
    if(c) { pair_crypto_wipe(c,sizeof(*c)); c->reorder_ms=20; c->hold_ms=1000; c->slots=8; c->payload_capacity=2048; }
}
static int owner(const projection_audio *s,uint64_t gen) {
    if(!s||!s->ready||!gen) return IAP2_ARGUMENT;
    if(s->generation!=gen) return IAP2_INVALID; return s->dead?PROJECTION_AUDIO_CLOSED:IAP2_OK;
}
void projection_audio_close(projection_audio *s) {
    uint64_t gen; int error;
    if(!s||!s->ready||s->dead) return;
    gen=s->generation; error=s->last_error; pair_crypto_wipe(s->storage,s->storage_size); pair_crypto_wipe(s,sizeof(*s));
    s->generation=gen; s->last_error=error; s->ready=s->dead=1;
}
static int fail(projection_audio *s,int error) { s->last_error=error; projection_audio_close(s); return PROJECTION_AUDIO_CLOSED; }
int projection_audio_init(projection_audio *s,const projection_audio_config *c,uint8_t *storage,size_t capacity,const uint8_t *key,uint64_t gen,uint64_t now) {
    projection_audio_format f; int r;
    if(!s||!c||!storage||!key||!gen||!c->slots||c->slots>PROJECTION_AUDIO_SLOTS||!c->payload_capacity||c->payload_capacity>PROJECTION_AUDIO_PAYLOAD||
       c->reorder_ms>1000||!c->hold_ms||c->hold_ms>60000) return IAP2_ARGUMENT;
    if(capacity<c->slots*c->payload_capacity) return IAP2_NO_SPACE;
    r=projection_audio_format_get(c->format,&f); if(r) return r;
    if(f.codec==PROJECTION_AUDIO_PCM16&&c->payload_capacity<2u*f.channels) return IAP2_NO_SPACE;
    pair_crypto_wipe(s,sizeof(*s)); s->config=*c; s->format=f; s->storage=storage; s->storage_size=c->slots*c->payload_capacity;
    s->generation=gen; s->next_token=1; s->now_ns=now; s->ready=1; copy(s->key,key,32); return IAP2_OK;
}
int projection_audio_check(projection_audio *s,uint64_t gen,uint64_t now) {
    int r=owner(s,gen); if(r) return r; if(now<s->now_ns) return IAP2_ARGUMENT; s->now_ns=now;
    if(s->held&&now-s->held_ns>=(uint64_t)s->config.hold_ms*1000000) return fail(s,IAP2_MORE); return IAP2_OK;
}
int projection_audio_start(projection_audio *s,uint64_t gen,uint64_t now) {
    int r=owner(s,gen); if(r) return r; if(s->started) return IAP2_INVALID;
    r=projection_audio_check(s,gen,now); if(r) return r; s->started=1; return IAP2_OK;
}
int projection_audio_flush(projection_audio *s,uint64_t gen,uint32_t sample,uint64_t now) {
    int r=owner(s,gen); if(r) return r; if(!s->started) return IAP2_INVALID;
    r=projection_audio_check(s,gen,now); if(r) return r;
    pair_crypto_wipe(s->storage,s->storage_size); pair_crypto_wipe(s->slots,sizeof(s->slots));
    s->count=s->held=0; s->token=s->held_ns=0; s->started=0;
    if(s->received) { s->last=s->highest; s->delivered=1; }
    s->flush_sample=sample; s->fenced=1; return IAP2_OK;
}
int projection_audio_feed(projection_audio *s,uint64_t gen,const uint8_t *p,size_t n,uint64_t now) {
    uint64_t counter,delta; uint32_t ssrc; uint8_t nonce[12]={0}; size_t i,size,written=0; projection_audio_slot *slot; int r=owner(s,gen);
    if(r) return r; if(!p&&n) return IAP2_ARGUMENT;
    r=projection_audio_check(s,gen,now); if(r) return r;
    if(s->count==s->config.slots) return PROJECTION_AUDIO_BUSY;
    if(n<36||n-36>s->config.payload_capacity||p[0]!=0x80||(p[1]&0x7f)<96) return PROJECTION_AUDIO_DROPPED;
    size=n-36; counter=le64(p+n-8); ssrc=be32(p+8);
    if(s->delivered&&counter<=s->last) return PROJECTION_AUDIO_DROPPED;
    if(s->held&&counter<=s->slots[s->held-1].packet.counter) return PROJECTION_AUDIO_DROPPED;
    if(s->received&&counter<=s->highest) { delta=s->highest-counter; if(delta>=64||(s->seen&(UINT64_C(1)<<delta))) return PROJECTION_AUDIO_DROPPED; }
    if(s->received&&ssrc!=s->ssrc) return PROJECTION_AUDIO_DROPPED;
    if(s->format.codec==PROJECTION_AUDIO_PCM16&&size%(2u*s->format.channels)) return PROJECTION_AUDIO_DROPPED;
    for(i=0;i<s->config.slots;++i) if(!s->slots[i].occupied) break;
    if(i==s->config.slots) return fail(s,IAP2_INVALID);
    slot=s->slots+i; copy(nonce+4,p+n-8,8);
    r=pair_aead_open(s->key,nonce,p+4,8,p+12,n-20,s->storage+i*s->config.payload_capacity,s->config.payload_capacity,&written);
    pair_crypto_wipe(nonce,sizeof(nonce));
    if(r) return PROJECTION_AUDIO_DROPPED;
    if(written!=size) return fail(s,IAP2_INVALID);
    if(!s->received) { s->highest=counter; s->seen=1; s->ssrc=ssrc; s->received=1; }
    else if(counter>s->highest) { delta=counter-s->highest; s->seen=delta>=64?1:(s->seen<<delta)|1; s->highest=counter; }
    else s->seen|=UINT64_C(1)<<(s->highest-counter);
    if(s->fenced) {
        uint32_t forward=be32(p+4)-s->flush_sample;
        if(forward>=UINT32_C(0x80000000)) {
            pair_crypto_wipe(s->storage+i*s->config.payload_capacity,s->config.payload_capacity);
            return PROJECTION_AUDIO_DROPPED;
        }
    }
    slot->packet.data=s->storage+i*s->config.payload_capacity; slot->packet.size=size;
    slot->packet.counter=counter; slot->packet.received_ns=now; slot->packet.sample_time=be32(p+4); slot->packet.ssrc=ssrc;
    slot->packet.sequence=(uint16_t)(((uint16_t)p[2]<<8)|p[3]); slot->packet.payload_type=(uint8_t)(p[1]&0x7f); slot->packet.marker=(uint8_t)(p[1]>>7);
    slot->packet.frames=s->format.codec==PROJECTION_AUDIO_PCM16?(uint32_t)(size/(2u*s->format.channels)):0;
    slot->packet.presentation_ns=0; slot->packet.concealed=slot->packet.timed=0;
    slot->occupied=1; ++s->count; return PROJECTION_AUDIO_PACKET;
}
static size_t first(const projection_audio *s) {
    size_t i,best=PROJECTION_AUDIO_SLOTS;
    for(i=0;i<s->config.slots;++i) if(s->slots[i].occupied&&(best==PROJECTION_AUDIO_SLOTS||s->slots[i].packet.counter<s->slots[best].packet.counter)) best=i;
    return best;
}
static uint32_t delay(const projection_audio *s,const projection_audio_packet *p) {
    uint64_t elapsed=s->now_ns-p->received_ns,wait=(uint64_t)s->config.reorder_ms*1000000;
    if(s->delivered&&p->counter-s->last==1) return 0;
    return elapsed>=wait?0:(uint32_t)((wait-elapsed+999999)/1000000);
}
int projection_audio_peek(projection_audio *s,uint64_t gen,projection_audio_packet *out,projection_audio_key *key,uint64_t now) {
    size_t i; int r;
    if(out) pair_crypto_wipe(out,sizeof(*out)); if(key) pair_crypto_wipe(key,sizeof(*key)); if(!out||!key) return IAP2_ARGUMENT;
    r=projection_audio_check(s,gen,now); if(r) return r; if(!s->started||!s->count) return IAP2_MORE;
    if(!s->held) {
        i=first(s); if(i==PROJECTION_AUDIO_SLOTS) return fail(s,IAP2_INVALID);
        if(delay(s,&s->slots[i].packet)) return IAP2_MORE;
        if(!s->next_token) return fail(s,IAP2_INVALID);
        s->held=i+1; s->token=s->next_token++; s->held_ns=now;
        s->slots[i].packet.skipped_packets=s->delivered?s->slots[i].packet.counter-s->last-1:0;
    }
    *out=s->slots[s->held-1].packet; key->generation=s->generation; key->token=s->token; return PROJECTION_AUDIO_PACKET;
}
int projection_audio_release(projection_audio *s,projection_audio_key key,uint64_t now) {
    size_t i; int r=owner(s,key.generation); if(r) return r;
    if(!key.token||!s->held||key.token!=s->token) return IAP2_INVALID;
    r=projection_audio_check(s,key.generation,now); if(r) return r;
    i=s->held-1; s->last=s->slots[i].packet.counter; s->delivered=1;
    pair_crypto_wipe(s->storage+i*s->config.payload_capacity,s->config.payload_capacity); pair_crypto_wipe(s->slots+i,sizeof(s->slots[i]));
    s->held=0; s->token=0; s->held_ns=0; s->fenced=0; s->flush_sample=0; --s->count; return IAP2_OK;
}
uint32_t projection_audio_next_delay(const projection_audio *s) {
    size_t i; uint64_t elapsed,total;
    if(!s||!s->ready||s->dead||!s->started||!s->count) return UINT32_MAX;
    if(!s->held) { i=first(s); return i==PROJECTION_AUDIO_SLOTS?UINT32_MAX:delay(s,&s->slots[i].packet); }
    elapsed=s->now_ns-s->held_ns; total=(uint64_t)s->config.hold_ms*1000000;
    return elapsed>=total?0:(uint32_t)((total-elapsed+999999)/1000000);
}
int projection_audio_pcm16le(const projection_audio_format *f,const uint8_t *p,size_t n,uint8_t *out,size_t capacity,size_t *written) {
    projection_audio_format canonical; size_t i; int r;
    if(written) *written=0; if(!f||(!p&&n)||!out||!written) return IAP2_ARGUMENT;
    r=projection_audio_format_get(f->bit,&canonical); if(r) return r;
    if(canonical.codec!=PROJECTION_AUDIO_PCM16) return IAP2_UNSUPPORTED;
    if(f->codec!=canonical.codec||f->channels!=canonical.channels||f->clock_rate!=canonical.clock_rate||f->input_rate!=canonical.input_rate||f->aac_config) return IAP2_INVALID;
    if(n>PROJECTION_AUDIO_PAYLOAD||n%(2u*f->channels)) return IAP2_INVALID;
    if(capacity<n) return IAP2_NO_SPACE;
    for(i=0;i<n;i+=2) { out[i]=p[i+1]; out[i+1]=p[i]; } *written=n; return IAP2_OK;
}
