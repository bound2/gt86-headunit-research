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
    uint64_t deadline_ns,base_ns,timeline,decoded_at,last_counter;
    uint8_t encoded[PROJECTION_AUDIO_PAYLOAD]; size_t encoded_size;
    uint32_t offset,next_sample,gap_left,latency_ms;
    uint8_t started,flushing,pending,seen,anchored;
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
    for(i=0;i<3;++i) if((s->slots[i].decoded.frames||s->slots[i].pending)&&now>=s->slots[i].deadline_ns)
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
static int time_at(const decode_slot *slot,uint64_t frames,uint64_t *out) {
    uint64_t whole=frames/slot->original.clock_rate,part=frames%slot->original.clock_rate,ns;
    if(whole>UINT64_MAX/1000000000) return IAP2_INVALID;
    ns=whole*1000000000; part=part*1000000000/slot->original.clock_rate;
    if(ns>UINT64_MAX-part||slot->base_ns>=UINT64_MAX-(ns+part)) return IAP2_INVALID;
    *out=slot->base_ns+ns+part; return IAP2_OK;
}
static int advance(projection_decode_sink *s,decode_slot *slot,int received) {
    slot->decoded_at=slot->timeline;
    if(slot->timeline>UINT64_MAX-slot->decoded.duration) return fail(s,IAP2_INVALID);
    slot->timeline+=slot->decoded.duration;
    if(slot->decoded.duration) {
        slot->next_sample=slot->decoded.sample_time+slot->decoded.duration;
        if(received) { slot->seen=1; slot->last_counter=slot->packet.counter; }
    }
    return IAP2_OK;
}
static int prepare_pending(projection_decode_sink *s,decode_slot *slot) {
    int r;
    if(slot->gap_left) {
        uint32_t frames=slot->gap_left,maximum=slot->original.codec==PROJECTION_AUDIO_AAC_LC?5120:PROJECTION_DECODE_FRAMES;
        if(frames>maximum) frames=maximum;
        r=projection_decode_conceal(slot->decoder,s->generation,frames,&slot->decoded); if(r) return fail(s,r);
        slot->gap_left-=frames; return advance(s,slot,0);
    } else {
        projection_audio_packet packet=slot->packet; packet.data=slot->encoded; packet.size=slot->encoded_size;
        r=projection_decode_packet(slot->decoder,s->generation,&packet,&slot->decoded);
        pair_crypto_wipe(slot->encoded,sizeof(slot->encoded)); slot->encoded_size=0; slot->pending=0;
        if(r) return fail(s,r); return advance(s,slot,1);
    }
}
static int open(void *ctx,uint64_t gen,const projection_session_resource *resource,const projection_audio_format *format,uint64_t *lease) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot;
    projection_session_resource mapped; projection_audio_format expected; int r; size_t i; uint64_t child=0;
    if(lease) *lease=0;
    if(!valid(s,gen)||!resource||!format||!lease) return IAP2_ARGUMENT;
    if(resource->type<100||resource->type>102||resource->peer_data_port||resource->audio_format!=format->bit||
       resource->audio_latency_ms>60000||projection_audio_format_get(format->bit,&expected)!=IAP2_OK||!same(format,&expected)) return IAP2_UNSUPPORTED;
    slot=&s->slots[resource->type-100]; if(slot->decoder||s->serial==UINT64_MAX) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    slot->original=*format; slot->opened_ns=s->now_ns; slot->latency_ms=resource->audio_latency_ms;
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
    if(!valid(s,gen)||(slot=find(s,lease))==NULL||slot->started||slot->flushing) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    slot->started_ns=s->now_ns;
    r=s->config.pcm.start(s->config.pcm.context,gen,slot->child); if(r) return fail(s,r);
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    slot->started=1; return IAP2_OK;
}
static int submit(void *ctx,uint64_t gen,uint64_t lease,const projection_audio_format *format,const projection_audio_packet *packet) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot; uint32_t gap=0; uint64_t end; int r;
    if(!valid(s,gen)||!format||!packet||(slot=find(s,lease))==NULL||!slot->started||!same(format,&slot->original)) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(slot->decoded.frames||slot->pending) return IAP2_MORE;
    if((!packet->data&&packet->size)||packet->size>PROJECTION_AUDIO_PAYLOAD||packet->concealed||packet->timed||packet->presentation_ns) return IAP2_INVALID;
    if((format->codec==PROJECTION_AUDIO_PCM16&&(packet->size%(2u*format->channels)||packet->frames!=packet->size/(2u*format->channels)))||
       (format->codec!=PROJECTION_AUDIO_PCM16&&packet->frames)) return IAP2_INVALID;
    if(!packet->size) return IAP2_OK;
    if(slot->seen) {
        if(packet->counter<=slot->last_counter) return fail(s,IAP2_UNSUPPORTED);
        gap=packet->sample_time-slot->next_sample;
        if(gap&&(!s->config.max_gap_ms||packet->counter-slot->last_counter<=1||
           gap>(uint64_t)slot->original.clock_rate*s->config.max_gap_ms/1000||
           (format->codec==PROJECTION_AUDIO_OPUS&&gap%120)||(format->codec==PROJECTION_AUDIO_AAC_LC&&gap%1024))) return fail(s,IAP2_UNSUPPORTED);
    }
    slot->held_ns=s->now_ns;
    if(s->now_ns>=UINT64_MAX-(uint64_t)s->config.hold_ms*1000000) return fail(s,IAP2_INVALID);
    slot->deadline_ns=s->now_ns+(uint64_t)s->config.hold_ms*1000000;
    if(s->config.paced) {
        if(packet->received_ns>s->now_ns) return fail(s,IAP2_INVALID);
        if(!slot->anchored) {
            uint64_t base=packet->received_ns>slot->started_ns?packet->received_ns:slot->started_ns;
            if(base>=UINT64_MAX-(uint64_t)slot->latency_ms*1000000) return fail(s,IAP2_INVALID);
            slot->base_ns=base+(uint64_t)slot->latency_ms*1000000; slot->anchored=1;
        }
        if(slot->timeline>UINT64_MAX-gap-PROJECTION_DECODE_FRAMES||time_at(slot,slot->timeline+gap+PROJECTION_DECODE_FRAMES,&end)) return fail(s,IAP2_INVALID);
        if(end>s->now_ns) {
            if(end>=UINT64_MAX-(uint64_t)s->config.hold_ms*1000000) return fail(s,IAP2_INVALID);
            slot->deadline_ns=end+(uint64_t)s->config.hold_ms*1000000;
        }
    }
    slot->packet=*packet; slot->packet.data=NULL; slot->packet.size=0; slot->offset=0;
    if(gap) {
        memcpy(slot->encoded,packet->data,packet->size); slot->encoded_size=packet->size;
        slot->pending=1; slot->gap_left=gap;
    } else {
        r=projection_decode_packet(slot->decoder,gen,packet,&slot->decoded); if(r) return fail(s,r);
        r=advance(s,slot,1); if(r) return r;
    }
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    return IAP2_OK;
}
static int poll(void *ctx,uint64_t gen,uint64_t lease,uint64_t now) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot; projection_audio_packet packet;
    uint32_t frames; uint64_t due=0; size_t samples,i; int r;
    if(!valid(s,gen)||(slot=find(s,lease))==NULL) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(now>s->now_ns) return fail(s,IAP2_PROVIDER_FAILED);
    if(!slot->started) return IAP2_OK;
    r=s->config.pcm.poll(s->config.pcm.context,gen,slot->child,s->now_ns);
    if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(!slot->decoded.frames&&slot->pending) {
        r=prepare_pending(s,slot); if(r) return r;
        if(refresh(s)) return IAP2_PROVIDER_FAILED;
    }
    if(!slot->decoded.frames) return IAP2_MORE;
    if(s->config.paced) {
        if(time_at(slot,slot->decoded_at+slot->offset,&due)) return fail(s,IAP2_INVALID);
        if(due>s->now_ns&&due-s->now_ns>(uint64_t)s->config.ahead_ms*1000000) return IAP2_MORE;
    }
    frames=slot->decoded.frames-slot->offset;
    if(frames>PROJECTION_AUDIO_PAYLOAD/(2u*slot->pcm.channels)) frames=PROJECTION_AUDIO_PAYLOAD/(2u*slot->pcm.channels);
    samples=(size_t)frames*slot->pcm.channels;
    for(i=0;i<samples;++i) {
        uint16_t n=(uint16_t)slot->decoded.samples[(size_t)slot->offset*slot->pcm.channels+i];
        s->wire[2*i]=(uint8_t)(n>>8); s->wire[2*i+1]=(uint8_t)n;
    }
    packet=slot->packet; packet.data=s->wire; packet.size=samples*2; packet.frames=frames;
    packet.sample_time=slot->decoded.sample_time+slot->offset;
    packet.concealed=slot->decoded.concealed; packet.timed=s->config.paced; packet.presentation_ns=due;
    if(packet.concealed) { packet.counter=0; packet.skipped_packets=0; }
    r=s->config.pcm.submit(s->config.pcm.context,gen,slot->child,&slot->pcm,&packet);
    pair_crypto_wipe(s->wire,sizeof(s->wire));
    if(r!=IAP2_OK&&r!=IAP2_MORE) return fail(s,r);
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(r==IAP2_MORE) return r;
    slot->offset+=frames;
    if(slot->offset==slot->decoded.frames) {
        r=projection_decode_discard(slot->decoder,gen); if(r) return fail(s,r);
        memset(&slot->decoded,0,sizeof(slot->decoded)); if(!slot->pending) memset(&slot->packet,0,sizeof(slot->packet)); slot->offset=0;
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
static int flush(void *ctx,uint64_t gen,uint64_t lease,const projection_audio_flush_request *request) {
    projection_decode_sink *s=(projection_decode_sink *)ctx; decode_slot *slot; projection_decode *fresh=0; int r;
    if(!valid(s,gen)||!s->config.pcm.flush||(slot=find(s,lease))==NULL||
       (request?(!slot->started||slot->flushing):!slot->flushing)) return IAP2_INVALID;
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    if(!request) slot->started_ns=s->now_ns;
    r=s->config.pcm.flush(s->config.pcm.context,gen,slot->child,request); if(r) return fail(s,r);
    if(request) {
        /* Retire the published view/history before constructing a fresh codec.
         * Replay/key lifetime belongs to the outer audio owner, never this reset. */
        projection_decode_destroy(slot->decoder); slot->decoder=NULL;
        memset(&slot->decoded,0,sizeof(slot->decoded)); memset(&slot->packet,0,sizeof(slot->packet)); slot->offset=0;
        pair_crypto_wipe(slot->encoded,sizeof(slot->encoded)); slot->encoded_size=0;
        slot->pending=slot->seen=slot->anchored=0; slot->gap_left=slot->next_sample=0;
        slot->timeline=slot->decoded_at=slot->base_ns=slot->last_counter=slot->deadline_ns=0;
        slot->held_ns=0; slot->started=0; slot->flushing=1;
        r=projection_decode_create(slot->original.bit,gen,&fresh); if(r) return fail(s,r); slot->decoder=fresh;
    } else { slot->started=1; slot->flushing=0; }
    if(refresh(s)) return IAP2_PROVIDER_FAILED;
    return IAP2_OK;
}
int projection_decode_sink_create(const projection_decode_sink_config *c,uint64_t gen,projection_decode_sink **out) {
    projection_decode_sink *s;
    if(out) *out=NULL;
    if(!out||!c||!gen||!c->clock_ns||!c->hold_ms||c->hold_ms>60000||!c->pcm.open||!c->pcm.start||!c->pcm.submit||!c->pcm.poll||!c->pcm.playback||!c->pcm.close||
       c->paced>1||c->max_gap_ms>1000||c->ahead_ms>500||(!c->paced&&c->ahead_ms)||
       (c->paced&&!(c->pcm.features&PROJECTION_AUDIO_SINK_TIMED))||
       (c->max_gap_ms&&!(c->pcm.features&PROJECTION_AUDIO_SINK_CONCEALMENT))) return IAP2_ARGUMENT;
    s=(projection_decode_sink *)calloc(1,sizeof(*s)); if(!s) return IAP2_NO_SPACE;
    s->config=*c; s->generation=gen; *out=s; return IAP2_OK;
}
projection_audio_sink projection_decode_sink_provider(projection_decode_sink *s) {
    projection_audio_sink out={s,open,start,submit,poll,playback,close,s&&s->config.pcm.flush?flush:NULL,0};
    if(!s) memset(&out,0,sizeof(out)); return out;
}
void projection_decode_sink_destroy(projection_decode_sink *s) {
    if(s) { (void)fail(s,IAP2_END); pair_crypto_wipe(s,sizeof(*s)); free(s); }
}
