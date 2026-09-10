/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_info.h"
#define INFO_NODES 640u
#define NONE UINT16_MAX
enum kind { BOOL,UINT,MINUS_ONE_REAL,TEXT,DATA,ARRAY,DICT };
typedef struct node {
    rtsp_slice bytes; uint64_t value;
    uint16_t first,last,next,children; uint8_t kind;
} node;
typedef struct builder { node nodes[INFO_NODES]; size_t count; int error; } builder;
typedef struct writer { uint8_t *out; size_t at; } writer;
static void zero(void *p,size_t n) { uint8_t *b=(uint8_t *)p; while(n--) *b++=0; }
static size_t length(const char *p) { size_t n=0; while(p[n]) ++n; return n; }
static rtsp_slice text(const char *p) { rtsp_slice s; s.data=(const uint8_t *)p; s.size=length(p); return s; }
static int same(rtsp_slice a,rtsp_slice b) {
    size_t i; if(a.size!=b.size) return 0;
    for(i=0;i<a.size;++i) if(a.data[i]!=b.data[i]) return 0;
    return 1;
}
static int ascii(rtsp_slice s,size_t min,size_t max) {
    size_t i; if(s.size<min||s.size>max||(!s.data&&s.size)) return 0;
    for(i=0;i<s.size;++i) if(s.data[i]<32||s.data[i]>126) return 0;
    return 1;
}
static int hex(uint8_t c) { return (c>='0'&&c<='9')||(c>='a'&&c<='f'); }
static int uuid(rtsp_slice s) {
    size_t i; if(!ascii(s,36,36)) return 0;
    for(i=0;i<36;++i) if(i==8||i==13||i==18||i==23) { if(s.data[i]!='-') return 0; }
        else if(!hex(s.data[i])) return 0;
    return 1;
}
static int mac(rtsp_slice s) {
    size_t i; if(!ascii(s,17,17)) return 0;
    for(i=0;i<17;++i) if(i%3==2) { if(s.data[i]!=':') return 0; }
        else if(!hex(s.data[i])&&!(s.data[i]>='A'&&s.data[i]<='F')) return 0;
    return 1;
}
static int rect(projection_info_rect a,projection_info_rect outer) {
    return a.width&&a.height&&a.x>=outer.x&&a.y>=outer.y&&a.x-outer.x<=outer.width&&a.y-outer.y<=outer.height&&
        a.width<=outer.width-(a.x-outer.x)&&a.height<=outer.height-(a.y-outer.y);
}
static int validate(const projection_info_profile *p) {
    size_t i,j; int screen=0,audio=0;
    if(p->display_count>2||p->hid_count>4||p->audio_count>9||p->latency_count>9||p->resource_count>2||p->extension_count>8||p->icon_count>2||
       !ascii(p->source_version,1,64)||!ascii(p->model,1,64)||!ascii(p->manufacturer,1,64)||!mac(p->device_id)||
       (p->bluetooth_id.size&&!mac(p->bluetooth_id))||!ascii(p->name,1,64)||p->right_hand_drive>1||p->keep_alive_low_power>1||
       p->keep_alive_stats>1||p->hevc>1||p->call_active>1||p->turn_by_turn_active>1||p->speech_mode< -1) return IAP2_INVALID;
    for(i=0;i<p->display_count;++i) {
        const projection_info_display *d=p->displays+i; projection_info_rect full;
        if(!uuid(d->uuid)||d->type!=(i?111u:110u)||!d->width||d->width>16384||!d->height||d->height>16384||
           !d->width_mm||d->width_mm>10000||!d->height_mm||d->height_mm>10000||!d->max_fps||d->max_fps>240||
           d->has_view>1||d->has_safe>1||d->draw_outside_safe>1||(d->has_safe&&!d->has_view)||!ascii(d->initial_url,0,256)) return IAP2_INVALID;
        full.x=full.y=0; full.width=d->width; full.height=d->height;
        if((d->has_view&&!rect(d->view,full))||(d->has_safe&&!rect(d->safe,d->view))) return IAP2_INVALID;
        for(j=0;j<i;++j) if(same(d->uuid,p->displays[j].uuid)) return IAP2_INVALID;
    }
    for(i=0;i<p->hid_count;++i) {
        const projection_info_hid *h=p->hids+i; int found=0;
        if(!ascii(h->uuid,1,16)||!ascii(h->name,1,64)||!uuid(h->display_uuid)||!h->descriptor.data||!h->descriptor.size||h->descriptor.size>1024) return IAP2_INVALID;
        if(h->uuid.size>1&&h->uuid.data[0]=='0') return IAP2_INVALID;
        for(j=0;j<h->uuid.size;++j) if(!hex(h->uuid.data[j])) return IAP2_INVALID;
        for(j=0;j<i;++j) if(same(h->uuid,p->hids[j].uuid)) return IAP2_INVALID;
        for(j=0;j<p->display_count;++j) if(same(h->display_uuid,p->displays[j].uuid)) found=1;
        if(!found) return IAP2_INVALID;
    }
    for(i=0;i<p->audio_count;++i) {
        const projection_info_audio_format *a=p->audio+i;
        if(a->type<100||a->type>102||a->audio_type<1||a->audio_type>6||(!a->input_formats&&!a->output_formats)) return IAP2_INVALID;
        for(j=0;j<i;++j) if(a->type==p->audio[j].type&&a->audio_type==p->audio[j].audio_type) return IAP2_INVALID;
    }
    for(i=0;i<p->latency_count;++i) {
        const projection_info_latency *a=p->latencies+i; int found=0;
        if(a->type<100||a->type>102||a->audio_type<0||a->audio_type>6) return IAP2_INVALID;
        for(j=0;j<i;++j) if(a->type==p->latencies[j].type&&a->audio_type==p->latencies[j].audio_type) return IAP2_INVALID;
        for(j=0;j<p->audio_count;++j) if(a->type==p->audio[j].type) found=1;
        if(!found) return IAP2_INVALID;
    }
    for(i=0;i<p->resource_count;++i) {
        if(p->resources[i].id==1) { if(screen) return IAP2_INVALID; screen=1; }
        else if(p->resources[i].id==2) { if(audio) return IAP2_INVALID; audio=1; }
        else return IAP2_INVALID;
    }
    if(screen!=(p->display_count!=0)||audio!=(p->audio_count!=0)) return IAP2_INVALID;
    for(i=0;i<p->extension_count;++i) {
        if(!ascii(p->extensions[i],1,64)) return IAP2_INVALID;
        for(j=0;j<i;++j) if(same(p->extensions[i],p->extensions[j])) return IAP2_INVALID;
    }
    if(p->icon_count&&!ascii(p->oem_label,1,64)) return IAP2_INVALID;
    for(i=0;i<p->icon_count;++i) {
        const projection_info_icon *a=p->icons+i;
        if(!a->data.data||!a->data.size||a->data.size>8192||!a->width||a->width>4096||!a->height||a->height>4096||a->prerendered>1) return IAP2_INVALID;
    }
    return IAP2_OK;
}
static uint16_t add(builder *b,uint16_t parent,uint8_t kind) {
    uint16_t id; node *n,*p;
    if(b->error) return 0;
    if(b->count==INFO_NODES) { b->error=IAP2_NO_SPACE; return 0; }
    id=(uint16_t)b->count++; n=b->nodes+id; zero(n,sizeof(*n)); n->first=n->last=n->next=NONE; n->kind=kind;
    if(parent!=NONE) {
        p=b->nodes+parent;
        if(p->last==NONE) p->first=id; else b->nodes[p->last].next=id;
        p->last=id; ++p->children;
    }
    return id;
}
static void string(builder *b,uint16_t parent,rtsp_slice s,uint8_t kind) {
    uint16_t n=add(b,parent,kind); if(!b->error) b->nodes[n].bytes=s;
}
static uint16_t field(builder *b,uint16_t parent,const char *key,uint8_t kind) {
    if(key) string(b,parent,text(key),TEXT);
    return add(b,parent,kind);
}
static void str(builder *b,uint16_t parent,const char *key,rtsp_slice value,uint8_t kind) {
    uint16_t n=field(b,parent,key,kind); if(!b->error) b->nodes[n].bytes=value;
}
static void num(builder *b,uint16_t parent,const char *key,uint64_t value,uint8_t kind) {
    uint16_t n=field(b,parent,key,kind); if(!b->error) b->nodes[n].value=value;
}
static void rectangle(builder *b,uint16_t parent,projection_info_rect r) {
    num(b,parent,"widthPixels",r.width,UINT); num(b,parent,"heightPixels",r.height,UINT);
    num(b,parent,"originXPixels",r.x,UINT); num(b,parent,"originYPixels",r.y,UINT);
}
static const char *audio_name(enum projection_info_audio_type t) {
    static const char *names[]={"","compatibility","default","media","telephony","speechRecognition","alert"};
    return names[(unsigned)t];
}
static void build(builder *b,const projection_info_profile *p) {
    size_t i; uint16_t root=add(b,NONE,DICT),a,d,m,r;
    str(b,root,"sourceVersion",p->source_version,TEXT); num(b,root,"features",p->features,UINT); num(b,root,"statusFlags",p->status_flags,UINT);
    str(b,root,"model",p->model,TEXT); str(b,root,"manufacturer",p->manufacturer,TEXT); str(b,root,"deviceID",p->device_id,TEXT);
    a=field(b,root,"bluetoothIDs",ARRAY); if(p->bluetooth_id.size) string(b,a,p->bluetooth_id,TEXT);
    str(b,root,"name",p->name,TEXT); num(b,root,"rightHandDrive",p->right_hand_drive,BOOL);
    num(b,root,"keepAliveLowPower",p->keep_alive_low_power,BOOL); num(b,root,"keepAliveSendStatsAsBody",p->keep_alive_stats,BOOL);
    m=field(b,root,"modes",DICT); a=field(b,m,"resources",ARRAY);
    for(i=0;i<p->resource_count;++i) {
        const projection_info_resource *q=p->resources+i; r=add(b,a,DICT);
        num(b,r,"resourceID",q->id,UINT); num(b,r,"transferType",q->transfer_type,UINT); num(b,r,"transferPriority",q->priority,UINT);
        num(b,r,"takeConstraint",q->take_constraint,UINT); num(b,r,"borrowConstraint",q->borrow_constraint,UINT); num(b,r,"unborrowConstraint",q->unborrow_constraint,UINT);
    }
    a=field(b,m,"appStates",ARRAY); r=add(b,a,DICT); num(b,r,"appStateID",2,UINT); num(b,r,"state",p->call_active,BOOL);
    r=add(b,a,DICT); num(b,r,"appStateID",1,UINT); num(b,r,"speechMode",p->speech_mode<0?0:(uint32_t)p->speech_mode,p->speech_mode<0?MINUS_ONE_REAL:UINT);
    r=add(b,a,DICT); num(b,r,"appStateID",3,UINT); num(b,r,"state",p->turn_by_turn_active,BOOL);
    if(p->latency_count) {
        a=field(b,root,"audioLatencies",ARRAY);
        for(i=0;i<p->latency_count;++i) {
            const projection_info_latency *q=p->latencies+i; d=add(b,a,DICT); num(b,d,"type",q->type,UINT);
            num(b,d,"inputLatencyMicros",q->input_micros,UINT); num(b,d,"outputLatencyMicros",q->output_micros,UINT);
            if(q->audio_type) str(b,d,"audioType",text(audio_name(q->audio_type)),TEXT);
        }
    }
    if(p->audio_count) {
        a=field(b,root,"audioFormats",ARRAY);
        for(i=0;i<p->audio_count;++i) {
            const projection_info_audio_format *q=p->audio+i; d=add(b,a,DICT); num(b,d,"type",q->type,UINT);
            str(b,d,"audioType",text(audio_name(q->audio_type)),TEXT); num(b,d,"audioOutputFormats",q->output_formats,UINT);
            if(q->input_formats) num(b,d,"audioInputFormats",q->input_formats,UINT);
        }
    }
    a=field(b,root,"extendedFeatures",ARRAY); for(i=0;i<p->extension_count;++i) string(b,a,p->extensions[i],TEXT);
    a=field(b,root,"displays",ARRAY);
    for(i=0;i<p->display_count;++i) {
        const projection_info_display *q=p->displays+i; d=add(b,a,DICT);
        str(b,d,"uuid",q->uuid,TEXT); num(b,d,"type",q->type,UINT); num(b,d,"maxFPS",q->max_fps,UINT);
        num(b,d,"widthPixels",q->width,UINT); num(b,d,"heightPixels",q->height,UINT); num(b,d,"widthPhysical",q->width_mm,UINT);
        num(b,d,"heightPhysical",q->height_mm,UINT); num(b,d,"features",q->features,UINT); num(b,d,"primaryInputDevice",q->primary_input,UINT);
        if(q->has_view) {
            m=field(b,d,"viewAreas",ARRAY); r=add(b,m,DICT); rectangle(b,r,q->view);
            if(q->has_safe) { m=field(b,r,"safeArea",DICT); rectangle(b,m,q->safe); num(b,m,"drawUIOutsideSafeArea",q->draw_outside_safe,BOOL); }
            num(b,d,"initialViewArea",0,UINT);
        }
        if(q->initial_url.size) str(b,d,"initialURL",q->initial_url,TEXT);
    }
    a=field(b,root,"hidDevices",ARRAY);
    for(i=0;i<p->hid_count;++i) {
        const projection_info_hid *q=p->hids+i; d=add(b,a,DICT);
        num(b,d,"hidProductID",q->product_id,UINT); num(b,d,"hidVendorID",q->vendor_id,UINT); num(b,d,"hidCountryCode",q->country_code,UINT);
        str(b,d,"uuid",q->uuid,TEXT); str(b,d,"name",q->name,TEXT); str(b,d,"displayUUID",q->display_uuid,TEXT); str(b,d,"hidDescriptor",q->descriptor,DATA);
    }
    if(p->icon_count) {
        num(b,root,"oemIconVisible",1,BOOL); str(b,root,"oemIconLabel",p->oem_label,TEXT); a=field(b,root,"oemIcons",ARRAY);
        for(i=0;i<p->icon_count;++i) {
            const projection_info_icon *q=p->icons+i; d=add(b,a,DICT); str(b,d,"imageData",q->data,DATA);
            num(b,d,"widthPixels",q->width,UINT); num(b,d,"heightPixels",q->height,UINT); num(b,d,"prerendered",q->prerendered,BOOL);
        }
    }
    if(p->hevc) (void)field(b,root,"hevcInfo",DICT);
}
static unsigned width(uint64_t n) { return n<=255?1:(n<=65535?2:(n<=UINT32_MAX?4:8)); }
static void put(writer *w,uint8_t v) { if(w->out) w->out[w->at]=v; ++w->at; }
static void be(writer *w,uint64_t value,unsigned size) { while(size) { --size; put(w,(uint8_t)(value>>(size*8))); } }
static void integer(writer *w,uint64_t value) {
    unsigned n=width(value);
    if(value>>63) { put(w,0x14); be(w,0,8); be(w,value,8); }
    else { put(w,(uint8_t)(0x10|(n==8?3:(n==4?2:(n==2?1:0))))); be(w,value,n); }
}
static void marker(writer *w,uint8_t kind,size_t n) {
    put(w,(uint8_t)(kind|(n<15?n:15)));
    if(n>=15) integer(w,n);
}
static void object(writer *w,const builder *b,const node *n,unsigned refs) {
    size_t i; uint16_t child;
    if(n->kind==BOOL) put(w,(uint8_t)(n->value?9:8));
    else if(n->kind==UINT) integer(w,n->value);
    else if(n->kind==MINUS_ONE_REAL) { put(w,0x23); be(w,UINT64_C(0xbff0000000000000),8); }
    else if(n->kind==TEXT||n->kind==DATA) {
        marker(w,n->kind==TEXT?0x50:0x40,n->bytes.size);
        for(i=0;i<n->bytes.size;++i) put(w,n->bytes.data[i]);
    } else {
        marker(w,n->kind==ARRAY?0xa0:0xd0,n->kind==ARRAY?n->children:n->children/2u);
        child=n->first;
        while(child!=NONE) { be(w,child,refs); child=b->nodes[child].next; if(n->kind==DICT) child=b->nodes[child].next; }
        if(n->kind==DICT) {
            child=n->first==NONE?NONE:b->nodes[n->first].next;
            while(child!=NONE) { be(w,child,refs); child=b->nodes[child].next; if(child!=NONE) child=b->nodes[child].next; }
        }
    }
}
int projection_info_encode(const projection_info_profile *p,uint8_t *out,size_t capacity,size_t *written) {
    builder b; writer w; uint32_t offsets[INFO_NODES]; size_t i,table,total; unsigned refs,offset_width; int r;
    if(written) *written=0;
    if(!p||!written||(!out&&capacity)) return IAP2_ARGUMENT;
    r=validate(p); if(r!=IAP2_OK) return r;
    zero(&b,sizeof(b)); build(&b,p); if(b.error) return b.error;
    refs=b.count>256?2:1; w.out=0; w.at=8;
    for(i=0;i<b.count;++i) { offsets[i]=(uint32_t)w.at; object(&w,&b,b.nodes+i,refs); }
    table=w.at; offset_width=width(table); total=table+b.count*offset_width+32;
    if(total>PROJECTION_INFO_LIMIT) return IAP2_NO_SPACE;
    if(!out) { *written=total; return IAP2_OK; }
    if(capacity<total) return IAP2_NO_SPACE;
    w.out=out; w.at=0; for(i=0;i<8;++i) put(&w,(uint8_t)"bplist00"[i]);
    for(i=0;i<b.count;++i) object(&w,&b,b.nodes+i,refs);
    for(i=0;i<b.count;++i) be(&w,offsets[i],offset_width);
    be(&w,0,6); put(&w,(uint8_t)offset_width); put(&w,(uint8_t)refs);
    be(&w,b.count,8); be(&w,0,8); be(&w,table,8); *written=w.at; return IAP2_OK;
}
