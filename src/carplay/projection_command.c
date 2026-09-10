/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_command.h"
static void zero(void *p,size_t n) { uint8_t *q=(uint8_t *)p; while(n--) *q++=0; }
static rtsp_slice text(const char *p) { rtsp_slice s; s.data=(const uint8_t *)p; s.size=0; while(p[s.size]) ++s.size; return s; }
static int same(rtsp_slice a,rtsp_slice b) { size_t i; if(a.size!=b.size||(!a.data&&a.size)) return 0; for(i=0;i<a.size;++i) if(a.data[i]!=b.data[i]) return 0; return 1; }
typedef struct node { rtsp_slice bytes; uint8_t refs[6],count,kind,value; } node;
typedef struct writer { node nodes[12]; uint16_t offsets[12]; size_t count,at; uint8_t *out; int error; } writer;
static uint8_t add(writer *w,uint8_t parent,uint8_t kind,rtsp_slice data,uint8_t value) {
    uint8_t id; if(w->error) return 0;
    if(w->count==12||(parent!=255&&(parent>=w->count||w->nodes[parent].count==6))) { w->error=IAP2_NO_SPACE; return 0; }
    id=(uint8_t)w->count++; w->nodes[id].kind=kind; w->nodes[id].bytes=data; w->nodes[id].value=value;
    if(parent!=255) w->nodes[parent].refs[w->nodes[parent].count++]=id; return id;
}
static uint8_t field(writer *w,uint8_t parent,const char *name,uint8_t kind,rtsp_slice data,uint8_t value) {
    (void)add(w,parent,5,text(name),0); return add(w,parent,kind,data,value);
}
static void put(writer *w,uint8_t n) { if(w->error) return; if(w->at==PROJECTION_COMMAND_LIMIT) { w->error=IAP2_NO_SPACE; return; } if(w->out) w->out[w->at]=n; ++w->at; }
static void be(writer *w,uint64_t n,unsigned size) { while(size) { --size; put(w,(uint8_t)(n>>(size*8))); } }
static void marker(writer *w,uint8_t kind,size_t n) {
    put(w,(uint8_t)((kind<<4)|(n<15?n:15))); if(n>=15) { put(w,n<=255?0x10:0x11); be(w,n,n<=255?1:2); }
}
static int encode(writer *w) {
    size_t i,j,table; for(i=0;i<8;++i) put(w,(uint8_t)"bplist00"[i]);
    for(i=0;i<w->count;++i) { const node *n=w->nodes+i; w->offsets[i]=(uint16_t)w->at;
        if(n->kind==0) put(w,n->value?9:8);
        else if(n->kind==1) { put(w,0x10); put(w,n->value); }
        else if(n->kind==4||n->kind==5) { marker(w,n->kind,n->bytes.size); for(j=0;j<n->bytes.size;++j) put(w,n->bytes.data[j]); }
        else { marker(w,13,n->count/2); for(j=0;j<n->count;j+=2) put(w,n->refs[j]); for(j=1;j<n->count;j+=2) put(w,n->refs[j]); }
    }
    table=w->at; for(i=0;i<w->count;++i) be(w,w->offsets[i],2);
    be(w,0,6); put(w,2); put(w,1); be(w,w->count,8); be(w,0,8); be(w,table,8); return w->error;
}
int projection_command_encode(const projection_info_profile *p,uint8_t features,const projection_command *c,uint8_t *out,size_t cap,size_t *written) {
    writer w; rtsp_slice empty={0,0}; size_t measured,i; uint8_t params; const char *name; int r;
    if(written) *written=0;
    if(!written||!p||!c||features>15||(!out&&cap)||(!c->uuid.data&&c->uuid.size)||(!c->data.data&&c->data.size)) return IAP2_ARGUMENT;
    r=projection_info_encode(p,0,0,&measured); if(r) return r;
    if(c->kind==PROJECTION_COMMAND_HID) {
        if(c->value||!c->data.size||c->data.size>4096) return IAP2_ARGUMENT;
        for(i=0;i<p->hid_count;++i) if(same(c->uuid,p->hids[i].uuid)) break;
        if(i==p->hid_count) return IAP2_UNSUPPORTED; name="hidSendReport";
    } else if(c->kind==PROJECTION_COMMAND_KEYFRAME) {
        if(c->value||c->data.size) return IAP2_ARGUMENT;
        for(i=0;i<p->display_count;++i) if(same(c->uuid,p->displays[i].uuid)) break;
        if(i==p->display_count||(p->displays[i].type==111&&!(features&8))) return IAP2_UNSUPPORTED; name="forceKeyFrame";
    } else {
        if(c->uuid.size) return IAP2_ARGUMENT;
        if(c->kind==PROJECTION_COMMAND_NIGHT) { if(c->data.size||c->value>1) return IAP2_ARGUMENT; name="setNightMode"; }
        else if(c->kind==PROJECTION_COMMAND_SIRI) { if(c->data.size||(c->value!=2&&c->value!=3)) return IAP2_ARGUMENT; name="requestSiri"; }
        else if(c->kind==PROJECTION_COMMAND_IAP) { if(c->value||!c->data.size||c->data.size>16384) return IAP2_ARGUMENT; if(!(features&2)) return IAP2_UNSUPPORTED; name="iAPSendMessage"; }
        else return IAP2_UNSUPPORTED;
    }
    zero(&w,sizeof(w)); (void)add(&w,255,13,empty,0); (void)field(&w,0,"type",5,text(name),0);
    if(c->kind==PROJECTION_COMMAND_HID) { (void)field(&w,0,"uuid",5,c->uuid,0); (void)field(&w,0,"hidReport",4,c->data,0); }
    else { params=field(&w,0,"params",13,empty,0);
        if(c->kind==PROJECTION_COMMAND_NIGHT) (void)field(&w,params,"nightMode",0,empty,(uint8_t)c->value);
        if(c->kind==PROJECTION_COMMAND_SIRI) (void)field(&w,params,"siriAction",1,empty,(uint8_t)c->value);
        if(c->kind==PROJECTION_COMMAND_IAP) (void)field(&w,params,"data",4,c->data,0);
        if(c->kind==PROJECTION_COMMAND_KEYFRAME) (void)field(&w,params,"uuid",5,c->uuid,0);
    }
    r=encode(&w); if(r) return r; measured=w.at; if(!out) { *written=measured; return IAP2_OK; }
    if(cap<measured) return IAP2_NO_SPACE; w.at=0; w.out=out; r=encode(&w); if(!r) *written=w.at; return r;
}
