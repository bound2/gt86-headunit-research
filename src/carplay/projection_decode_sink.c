/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_decode_sink.h"
#include <stdlib.h>
#include <string.h>
typedef struct decode_slot {
    projection_decode *decoder;
    projection_audio_format original,pcm;
    projection_audio_packet packet;
    projection_decoded_audio decoded;
    uint64_t lease,child,held_ns,opened_ns,started_ns;
    uint32_t offset;
    uint8_t started;
} decode_slot;
struct projection_decode_sink {
    projection_decode_sink_config config;
    decode_slot slots[3]; uint8_t wire[PROJECTION_AUDIO_PAYLOAD];
    uint64_t generation,serial,now_ns; uint8_t failed;
};
static void clear(projection_decode_sink *s,decode_slot *slot) {
    if(slot->child) s->config.pcm.close(s->config.pcm.context,s->generation,slot->child);
    projection_decode_destroy(slot->decoder); pair_crypto_wipe(slot,sizeof(*slot));
}
static int fail(projection_decode_sink *s,int code) {
    size_t i; if(!s->failed) { s->failed=1; for(i=3;i>0;--i) clear(s,&s->slots[i-1]); pair_crypto_wipe(s->wire,sizeof(s->wire)); }
    return code;
}
static int refresh(projection_decode_sink *s) {
    size_t i; uint64_t now=s->config.clock_ns(s->config.clock_context);
    if(now==UINT64_MAX||now<s->now_ns) return fail(s,IAP2_PROVIDER_FAILED);
    s->now_ns=now;
    for(i=0;i<3;++i) if(s->slots[i].decoded.frames&&now-s->slots[i].held_ns>=(uint64_t)s->config.hold_ms*1000000)
        return fail(s,IAP2_PROVIDER_FAILED);
    return IAP2_OK;
}
static int valid(projection_decode_sink *s,uint64_t gen) { return s&&!s->failed&&gen&&gen==s->generation; }
static decode_slot *find(projection_decode_sink *s,uint64_t lease) {
    size_t i; for(i=0;i<3;++i) if(lease&&s->slots[i].lease==lease) return &s->slots[i]; return NULL;
}
static int same(const projection_audio_format *a,const projection_audio_format *b) {
    return a->bit==b->bit&&a->codec==b->codec&&a->clock_rate==b->clock_rate&&a->input_rate==b->input_rate&&a->channels==b->channels&&a->aac_config==b->aac_config;
}
static int open(void *ctx,uint64_t gen,const projection_session_resource *resource,const projection_audio_format *format,uint64_t *lease) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot;
    projection_session_resource mapped; projection_audio_format expected; int r; size_t i; uint64_t child=0;
    if(lease) *lease=0;
    if(!valid(s,gen)||!resource||!format||!lease) return IAP2_ARGUMENT;
    if(resource->type<100||resource->type>102||resource->peer_data_port||resource->audio_format!=format->bit||
       projection_audio_format_get(format->bit,&expected)!=IAP2_OK||!same(format,&expected)) return IAP2_UNSUPPORTED;
    slot=&s->slots[resource->type-100]; if(slot->decoder||s->serial==UINT64_MAX) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    slot->original=*format; slot->opened_ns=s->now_ns;
    r=projection_decode_pcm_format(format->bit,&slot->pcm); if(r) return fail(s,r);
    r=projection_decode_create(format->bit,gen,&slot->decoder); if(r) return fail(s,r);
    mapped=*resource; mapped.audio_format=slot->pcm.bit; mapped.frames_per_packet=0;
    r=s->config.pcm.open(s->config.pcm.context,gen,&mapped,&slot->pcm,&child);
    if(child) {
        for(i=0;i<3;++i) if(s->slots[i].child==child) return fail(s,IAP2_PROVIDER_FAILED);
        slot->child=child;
    }
    if(r||!child) return fail(s,r?r:IAP2_PROVIDER_FAILED);
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    slot->lease=++s->serial; *lease=slot->lease; return IAP2_OK;
}
static int start(void *ctx,uint64_t gen,uint64_t lease) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot; int r;
    if(!valid(s,gen)||(slot=find(s,lease))==NULL||slot->started) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    slot->started_ns=s->now_ns;
    r=s->config.pcm.start(s->config.pcm.context,gen,slot->child); if(r) return fail(s,r);
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    slot->started=1; return IAP2_OK;
}
static int submit(void *ctx,uint64_t gen,uint64_t lease,const projection_audio_format *format,const projection_audio_packet *packet) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot; int r;
    if(!valid(s,gen)||!format||!packet||(slot=find(s,lease))==NULL||!slot->started||!same(format,&slot->original)) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(slot->decoded.frames) return IAP2_MORE;
    slot->held_ns=s->now_ns;
    r=projection_decode_packet(slot->decoder,gen,packet,&slot->decoded); if(r) return fail(s,r);
    slot->packet=*packet; slot->packet.data=NULL; slot->packet.size=0; slot->offset=0;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    return IAP2_OK;
}
static int poll(void *ctx,uint64_t gen,uint64_t lease,uint64_t now) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot; projection_audio_packet packet;
    uint32_t frames; size_t samples,i; int r;
    if(!valid(s,gen)||(slot=find(s,lease))==NULL) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(now>s->now_ns) return fail(s,IAP2_PROVIDER_FAILED);
    if(!slot->started) return IAP2_OK;
    r=s->config.pcm.poll(s->config.pcm.context,gen,slot->child,s->now_ns);
    if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(!slot->decoded.frames) return IAP2_MORE;
    frames=slot->decoded.frames-slot->offset;
    if(frames>PROJECTION_AUDIO_PAYLOAD/(2u*slot->pcm.channels)) frames=PROJECTION_AUDIO_PAYLOAD/(2u*slot->pcm.channels);
    samples=(size_t)frames*slot->pcm.channels;
    for(i=0;i<samples;++i) {
        uint16_t n=(uint16_t)slot->decoded.samples[(size_t)slot->offset*slot->pcm.channels+i];
        s->wire[2*i]=(uint8_t)(n>>8); s->wire[2*i+1]=(uint8_t)n;
    }
    packet=slot->packet; packet.data=s->wire; packet.size=samples*2; packet.frames=frames;
    packet.sample_time=slot->decoded.sample_time+slot->offset;
    r=s->config.pcm.submit(s->config.pcm.context,gen,slot->child,&slot->pcm,&packet);
    pair_crypto_wipe(s->wire,sizeof(s->wire));
    if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(r==IAP2_MORE) return r;
    slot->offset+=frames;
    if(slot->offset==slot->decoded.frames) {
        r=projection_decode_discard(slot->decoder,gen); if(r) return fail(s,r);
        memset(&slot->decoded,0,sizeof(slot->decoded)); memset(&slot->packet,0,sizeof(slot->packet)); slot->offset=0;
    }
    return IAP2_OK;
}
static int playback(void *ctx,uint64_t gen,uint64_t lease,projection_playback_position *out) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot; int r;
    if(out) memset(out,0,sizeof(*out));
    if(!valid(s,gen)||!out||(slot=find(s,lease))==NULL) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    r=s->config.pcm.playback(s->config.pcm.context,gen,slot->child,out);
    if(r) { memset(out,0,sizeof(*out)); return fail(s,r); }
    if(refresh(s)) { memset(out,0,sizeof(*out)); return IAP2_PROVIDER_FAILED; }
    if(out->sample_rate!=slot->original.clock_rate||out->has_position>1||(!out->has_position&&(out->raw_ns||out->sample_time))||
       (out->has_position&&(!slot->started||out->raw_ns<slot->opened_ns||out->raw_ns<slot->started_ns||out->raw_ns>s->now_ns))) {
        memset(out,0,sizeof(*out)); return fail(s,IAP2_PROVIDER_FAILED);
    }
    return IAP2_OK;
}
static void close(void *ctx,uint64_t gen,uint64_t lease) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot;
    if(!s||gen!=s->generation) return;
    slot=find(s,lease); if(slot) clear(s,slot);
}
int projection_decode_sink_create(const projection_decode_sink_config *c,uint64_t gen,projection_decode_sink **out) {
    projection_decode_sink *s;
    if(out) *out=NULL;
    if(!out||!c||!gen||!c->clock_ns||!c->hold_ms||c->hold_ms>60000||!c->pcm.open||!c->pcm.start||!c->pcm.submit||!c->pcm.poll||!c->pcm.playback||!c->pcm.close) return IAP2_ARGUMENT;
    s=(projection_decode_sink *)calloc(1,sizeof(*s)); if(!s) return IAP2_NO_SPACE;
    s->config=*c; s->generation=gen; *out=s; return IAP2_OK;
}
projection_audio_sink projection_decode_sink_provider(projection_decode_sink *s) {
    projection_audio_sink out={s,open,start,submit,poll,playback,close};
    if(!s) memset(&out,0,sizeof(out)); return out;
}
void projection_decode_sink_destroy(projection_decode_sink *s) {
    if(s) { (void)fail(s,IAP2_END); pair_crypto_wipe(s,sizeof(*s)); free(s); }
}
