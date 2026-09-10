/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_decode.h"
#include <opus.h>
#include <neaacdec.h>
#include <stdlib.h>
#include <string.h>
struct projection_decode {
    projection_audio_format format;
    OpusDecoder *opus; NeAACDecHandle aac;
    int16_t pcm[PROJECTION_DECODE_SAMPLES];
    uint8_t wire[PROJECTION_AUDIO_PAYLOAD+32];
    uint64_t generation,last_counter;
    uint32_t next_sample;
    uint8_t received,dead,aac_prime,aac_recover;
};
static void clear(projection_decode *s) {
    if(s->opus) { int n=opus_decoder_get_size(s->format.channels); if(n>0) pair_crypto_wipe(s->opus,(size_t)n); opus_decoder_destroy(s->opus); s->opus=NULL; }
    if(s->aac) { NeAACDecClose(s->aac); s->aac=NULL; }
    pair_crypto_wipe(s->pcm,sizeof(s->pcm)); pair_crypto_wipe(s->wire,sizeof(s->wire)); s->dead=1;
}
static int fail(projection_decode *s,int result) { clear(s); return result; }
static int open_aac(projection_decode *s) {
    unsigned long rate=0; unsigned char channels=0,asc[2]; NeAACDecConfigurationPtr config;
    s->aac=NeAACDecOpen(); if(!s->aac) return IAP2_NO_SPACE;
    config=NeAACDecGetCurrentConfiguration(s->aac); if(!config) return IAP2_PROVIDER_FAILED;
    config->defObjectType=LC; config->defSampleRate=s->format.clock_rate; config->outputFormat=FAAD_FMT_16BIT;
    config->downMatrix=0; config->dontUpSampleImplicitSBR=1; config->useOldADTSFormat=0;
    asc[0]=(uint8_t)(s->format.aac_config>>8); asc[1]=(uint8_t)s->format.aac_config;
    if(!NeAACDecSetConfiguration(s->aac,config)||NeAACDecInit2(s->aac,asc,2,&rate,&channels)!=0||rate!=s->format.clock_rate||channels!=s->format.channels)
        return IAP2_UNSUPPORTED;
    s->aac_prime=1; return IAP2_OK;
}
int projection_decode_pcm_format(uint32_t bit,projection_audio_format *out) {
    projection_audio_format f; int r;
    if(!out) return IAP2_ARGUMENT;
    memset(out,0,sizeof(*out));
    r=projection_audio_format_get(bit,&f); if(r) return r;
    if(f.codec==PROJECTION_AUDIO_AAC_LC) bit=f.clock_rate==44100?2048u:32768u;
    if(f.codec==PROJECTION_AUDIO_OPUS) bit=16384u;
    return projection_audio_format_get(bit,out);
}
int projection_decode_create(uint32_t bit,uint64_t gen,projection_decode **out) {
    projection_audio_format format; projection_decode *s; int r;
    if(out) *out=NULL;
    if(!out||!gen) return IAP2_ARGUMENT;
    r=projection_audio_format_get(bit,&format); if(r) return r;
    s=(projection_decode *)calloc(1,sizeof(*s)); if(!s) return IAP2_NO_SPACE;
    s->format=format; s->generation=gen;
    if(format.codec==PROJECTION_AUDIO_OPUS) {
        int error=OPUS_OK; s->opus=opus_decoder_create(48000,1,&error);
        if(!s->opus||error!=OPUS_OK) { projection_decode_destroy(s); return IAP2_PROVIDER_FAILED; }
    } else if(format.codec==PROJECTION_AUDIO_AAC_LC) {
        r=open_aac(s); if(r) { projection_decode_destroy(s); return r; }
    }
    *out=s; return IAP2_OK;
}
int projection_decode_packet(projection_decode *s,uint64_t gen,const projection_audio_packet *p,projection_decoded_audio *out) {
    uint32_t frames=0,duration=0; size_t i; uint8_t priming=0,concealed=0;
    if(out) memset(out,0,sizeof(*out));
    if(!s||!p||!out||!gen||(!p->data&&p->size)||p->size>PROJECTION_AUDIO_PAYLOAD) return IAP2_ARGUMENT;
    if(gen!=s->generation||s->dead||p->concealed||p->timed||p->presentation_ns) return IAP2_INVALID;
    if((s->format.codec==PROJECTION_AUDIO_PCM16&&(p->size%(2u*s->format.channels)||p->frames!=p->size/(2u*s->format.channels)))||
       (s->format.codec!=PROJECTION_AUDIO_PCM16&&p->frames)) return IAP2_INVALID;
    if(p->size&&s->received&&(p->counter<=s->last_counter||p->sample_time!=s->next_sample)) return fail(s,IAP2_UNSUPPORTED);
    pair_crypto_wipe(s->pcm,sizeof(s->pcm)); pair_crypto_wipe(s->wire,sizeof(s->wire));
    if(!p->size) { out->channels=s->format.channels; out->sample_time=p->sample_time; return IAP2_OK; }
    memcpy(s->wire,p->data,p->size);
    if(s->format.codec==PROJECTION_AUDIO_PCM16) {
        frames=p->frames; duration=frames;
        for(i=0;i<p->size/2;++i) { int32_t n=((int32_t)s->wire[2*i]<<8)|s->wire[2*i+1]; if(n>=32768) n-=65536; s->pcm[i]=(int16_t)n; }
    } else if(s->format.codec==PROJECTION_AUDIO_OPUS) {
        int expected=opus_packet_get_nb_samples(s->wire,(opus_int32)p->size,48000),decoded;
        if(expected<=0||expected>(int)PROJECTION_DECODE_FRAMES||opus_packet_get_nb_channels(s->wire)!=1) return fail(s,IAP2_INVALID);
        decoded=opus_decode(s->opus,s->wire,(opus_int32)p->size,s->pcm,(int)PROJECTION_DECODE_FRAMES,0);
        if(decoded!=expected) return fail(s,IAP2_INVALID);
        frames=duration=(uint32_t)decoded;
    } else {
        NeAACDecFrameInfo info; void *buffer=s->pcm; void *decoded;
        memset(&info,0,sizeof(info));
        decoded=NeAACDecDecode2(s->aac,&info,s->wire,(unsigned long)p->size,&buffer,1024u*2u*sizeof(int16_t));
        if(info.error||decoded!=s->pcm||buffer!=s->pcm||info.bytesconsumed!=p->size||info.channels!=2||info.samplerate!=s->format.clock_rate||
           info.object_type!=LC||info.header_type!=RAW||info.sbr!=NO_SBR||info.ps||
           (info.samples!=2048&&(!s->aac_prime||info.samples!=0))) return fail(s,IAP2_INVALID);
        duration=1024; frames=(uint32_t)info.samples/2; priming=(uint8_t)(frames==0);
        if(priming&&s->aac_recover) { pair_crypto_wipe(s->pcm,sizeof(s->pcm)); frames=1024; concealed=1; }
        s->aac_prime=s->aac_recover=0;
    }
    pair_crypto_wipe(s->wire,sizeof(s->wire));
    if(!frames) pair_crypto_wipe(s->pcm,sizeof(s->pcm));
    s->received=1; s->last_counter=p->counter; s->next_sample=p->sample_time+duration;
    out->samples=frames?s->pcm:NULL; out->frames=frames; out->duration=duration; out->sample_time=p->sample_time;
    out->channels=s->format.channels; out->priming=priming; out->concealed=concealed; return IAP2_OK;
}
int projection_decode_conceal(projection_decode *s,uint64_t gen,uint32_t frames,projection_decoded_audio *out) {
    int r;
    if(out) memset(out,0,sizeof(*out));
    if(!s||!out||!gen||!frames||frames>PROJECTION_DECODE_FRAMES) return IAP2_ARGUMENT;
    if(gen!=s->generation||s->dead||!s->received) return IAP2_INVALID;
    if((s->format.codec==PROJECTION_AUDIO_OPUS&&frames%120)||(s->format.codec==PROJECTION_AUDIO_AAC_LC&&frames%1024)) return IAP2_ARGUMENT;
    pair_crypto_wipe(s->pcm,sizeof(s->pcm)); pair_crypto_wipe(s->wire,sizeof(s->wire));
    if(s->format.codec==PROJECTION_AUDIO_OPUS) {
        r=opus_decode(s->opus,NULL,0,s->pcm,(int)frames,0); if(r!=(int)frames) return fail(s,IAP2_INVALID);
    } else if(s->format.codec==PROJECTION_AUDIO_AAC_LC&&!s->aac_recover) {
        NeAACDecClose(s->aac); s->aac=NULL; r=open_aac(s); if(r) return fail(s,r); s->aac_recover=1;
    }
    out->samples=s->pcm; out->frames=out->duration=frames; out->sample_time=s->next_sample;
    out->channels=s->format.channels; out->concealed=1; s->next_sample+=frames; return IAP2_OK;
}
int projection_decode_discard(projection_decode *s,uint64_t gen) {
    if(!s||!gen) return IAP2_ARGUMENT;
    if(gen!=s->generation||s->dead) return IAP2_INVALID;
    pair_crypto_wipe(s->pcm,sizeof(s->pcm)); return IAP2_OK;
}
void projection_decode_destroy(projection_decode *s) {
    if(s) { clear(s); pair_crypto_wipe(s,sizeof(*s)); free(s); }
}
