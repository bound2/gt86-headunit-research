/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_tlv.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
int pair_tlv_decode(const uint8_t *p,size_t n,pair_tlv *items,size_t cap,uint8_t *arena,size_t acap,size_t *count) {
    size_t off=0,bytes=0,fields=0; unsigned last=256,len=0; int pass;
    if(count) *count=0;
    if(!count||(!p&&n)||(!items&&cap)||(!arena&&acap)||cap>PAIR_TLV_MAX_ITEMS) return IAP2_ARGUMENT;
    if(n>PAIR_TLV_MAX_WIRE) return IAP2_NO_SPACE;
    for(pass=0;pass<2;++pass) {
        off=bytes=fields=0;last=256;len=0;
        while(off<n) {
            unsigned type,take;int join;
            if(n-off<2) return IAP2_INVALID;
            type=p[off];take=p[off+1];off+=2;
            if(take>n-off) return IAP2_INVALID;
            if(type==255) { if(take) return IAP2_INVALID;last=256;len=0;continue; }
            join=type==last&&len==255;
            if(!join) { if(fields==cap) return IAP2_NO_SPACE;++fields; }
            if(take>acap-bytes) return IAP2_NO_SPACE;
            if(pass) {
                pair_tlv *v=&items[fields-1];
                if(!join) { v->type=(uint8_t)type;v->data=arena?arena+bytes:0;v->size=0; }
                if(take) copy(arena+bytes,p+off,take);
                v->size+=take;
            }
            bytes+=take;off+=take;last=type;len=take;
        }
    }
    *count=fields;return IAP2_OK;
}
int pair_tlv_get(const pair_tlv *items,size_t count,uint8_t type,pair_tlv *out) {
    size_t i;const pair_tlv *v=0;
    if(out) { out->type=0;out->data=0;out->size=0; }
    if(!out||(!items&&count)||count>PAIR_TLV_MAX_ITEMS||type==255) return IAP2_ARGUMENT;
    for(i=0;i<count;++i) if(items[i].type==type) { if(v) return IAP2_INVALID;v=&items[i]; }
    if(!v) return IAP2_END;
    *out=*v;return IAP2_OK;
}
int pair_tlv_encode(const pair_tlv *items,size_t count,uint8_t *out,size_t cap,size_t *written) {
    size_t i,n=0,off=0;
    if(written) *written=0;
    if(!written||(!items&&count)||count>PAIR_TLV_MAX_ITEMS||(!out&&cap)) return IAP2_ARGUMENT;
    for(i=0;i<count;++i) {
        size_t size=items[i].size,chunks;
        if(items[i].type==255||(!items[i].data&&size)) return IAP2_ARGUMENT;
        if(size>PAIR_TLV_MAX_WIRE) return IAP2_NO_SPACE;
        chunks=size?(size+254)/255:1;n+=size+chunks*2;
        if(i&&items[i].type==items[i-1].type) n+=2;
        if(n>PAIR_TLV_MAX_WIRE) return IAP2_NO_SPACE;
    }
    if(!out) { *written=n;return IAP2_OK; }
    if(n>cap) return IAP2_NO_SPACE;
    for(i=0;i<count;++i) {
        size_t used=0;
        if(i&&items[i].type==items[i-1].type) { out[off++]=255;out[off++]=0; }
        do {
            size_t take=items[i].size-used;if(take>255) take=255;
            out[off++]=items[i].type;out[off++]=(uint8_t)take;
            if(take) copy(out+off,items[i].data+used,take);
            off+=take;used+=take;
        } while(used<items[i].size);
    }
    *written=off;return IAP2_OK;
}
