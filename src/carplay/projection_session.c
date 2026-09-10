/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_session.h"
#include "service_plist.h"

static size_t len(const char *p) { size_t n=0; while(p[n]) ++n; return n; }
static int same(const uint8_t *a,size_t n,const char *b) {
    size_t i; if(n!=len(b)) return 0; for(i=0;i<n;++i) if(a[i]!=(uint8_t)b[i]) return 0; return 1;
}
static int slice(rtsp_slice a,const char *b) { return same(a.data,a.size,b); }
static void copy(void *d,const void *s,size_t n) { size_t i; for(i=0;i<n;++i) ((uint8_t *)d)[i]=((const uint8_t *)s)[i]; }
static const service_plist_node *find(const service_plist_document *d,const service_plist_node *p,const char *key) {
    const service_plist_node *v=0;
    return service_plist_find(d,p,(const uint8_t *)key,len(key),&v)==IAP2_OK?v:0;
}
static int uint_field(const service_plist_document *d,const service_plist_node *p,const char *key,uint64_t max,int required,uint64_t *out) {
    const service_plist_node *v=find(d,p,key); *out=0;
    if(!v) return required?IAP2_INVALID:IAP2_OK;
    if(v->type!=SERVICE_PLIST_INTEGER||v->negative||v->magnitude>max) return IAP2_INVALID;
    *out=v->magnitude; return IAP2_OK;
}
static int bool_field(const service_plist_document *d,const service_plist_node *p,const char *key,uint8_t *out) {
    const service_plist_node *v=find(d,p,key); *out=0; if(!v) return IAP2_OK;
    if(v->type!=SERVICE_PLIST_BOOL) return IAP2_INVALID; *out=(uint8_t)v->magnitude; return IAP2_OK;
}
static int text_is(const service_plist_node *v,const char *s) { return v&&v->type==SERVICE_PLIST_STRING&&same(v->data,v->size,s); }
static int iap_uuid(const service_plist_node *v) {
    static const char expected[]="e9459fd0-bcad-4c45-820f-1e72447ef2f2"; size_t i;
    if(!v||v->type!=SERVICE_PLIST_STRING||v->size!=36) return 0;
    for(i=0;i<36;++i) { uint8_t c=v->data[i]; if(c>='A'&&c<='F') c=(uint8_t)(c+32); if(c!=(uint8_t)expected[i]) return 0; }
    return 1;
}
static int encrypted_fields(const service_plist_document *d,const service_plist_node *p) {
    return find(d,p,"eiv")||find(d,p,"ekey")||find(d,p,"et");
}
static int audio_type(const service_plist_node *v) {
    static const char *names[]={"compatibility","default","media","telephony","speechRecognition","alert"};
    unsigned i; for(i=0;i<6;++i) if(text_is(v,names[i])) return (int)i+1; return 0;
}
static int advertised(const projection_session *s,const projection_session_resource *r) {
    size_t i; const projection_info_profile *p=s->profile;
    if(r->type==110||r->type==111) {
        if(r->type==111&&!(s->config.enabled_features&PROJECTION_SESSION_ALT_SCREEN)) return IAP2_UNSUPPORTED;
        for(i=0;i<p->display_count;++i) if(p->displays[i].type==r->type) return IAP2_OK;
    } else if(r->type>=100&&r->type<=102) {
        for(i=0;i<p->audio_count;++i) {
            const projection_info_audio_format *a=p->audio+i;
            if(a->type==r->type&&a->audio_type==r->audio_type&&(a->output_formats&r->audio_format)==r->audio_format&&
               (!r->peer_data_port||(a->input_formats&r->audio_format)==r->audio_format)) return IAP2_OK;
        }
    } else if(r->type==130&&(s->config.enabled_features&PROJECTION_SESSION_IAP)) return IAP2_OK;
    return IAP2_UNSUPPORTED;
}
static int parse_stream(const service_plist_document *d,const service_plist_node *p,projection_session_resource *r,int teardown) {
    uint64_t n; const service_plist_node *v;
    if(p->type!=SERVICE_PLIST_DICT||encrypted_fields(d,p)||uint_field(d,p,"type",UINT32_MAX,1,&n)) return IAP2_INVALID;
    r->type=(uint32_t)n;
    if(r->type!=100&&r->type!=101&&r->type!=102&&r->type!=110&&r->type!=111&&r->type!=130) return IAP2_UNSUPPORTED;
    if(teardown) return IAP2_OK;
    if(uint_field(d,p,r->type==130?"seed":"streamConnectionID",UINT64_MAX,1,&r->connection_id)) return IAP2_INVALID;
    if(r->type==130) {
        v=find(d,p,"clientTypeUUID");
        if(!iap_uuid(v)) return IAP2_UNSUPPORTED;
    } else if(r->type>=100&&r->type<=102) {
        r->audio_type=(uint8_t)audio_type(find(d,p,"audioType")); if(!r->audio_type) return IAP2_INVALID;
        if(uint_field(d,p,"audioFormat",UINT32_MAX,1,&n)||!n||(n&(n-1))) return IAP2_INVALID;
        r->audio_format=(uint32_t)n;
        if(uint_field(d,p,"dataPort",65535,0,&n)) return IAP2_INVALID; r->peer_data_port=(uint16_t)n;
        if(r->peer_data_port&&r->type!=100) return IAP2_UNSUPPORTED;
        if(uint_field(d,p,"framesPerPacket",65535,0,&n)||(r->peer_data_port&&!n)) return IAP2_INVALID; r->frames_per_packet=(uint32_t)n;
        if(uint_field(d,p,"audioLatencyMs",60000,0,&n)) return IAP2_INVALID; r->audio_latency_ms=(uint32_t)n;
    }
    return IAP2_OK;
}
typedef struct request { projection_session_resource resources[PROJECTION_SESSION_STREAMS]; size_t count; uint8_t kind; } request;
static int parse(const rtsp_message *req,request *out,uint8_t *scratch,size_t capacity) {
    service_plist_node nodes[SERVICE_PLIST_PROJECTION_NODES]; service_plist_storage storage;
    service_plist_document d; const service_plist_node *streams,*v; uint16_t child; uint64_t n; size_t i;
    rtsp_slice type; int status=rtsp_header_get(req,(rtsp_slice){(const uint8_t *)"Content-Type",12},&type);
    pair_crypto_wipe(out,sizeof(*out));
    if(status!=IAP2_END&&(status!=IAP2_OK||!slice(type,"application/x-apple-binary-plist"))) return IAP2_INVALID;
    if(slice(req->method,"RECORD")) { if(req->body.size) return IAP2_INVALID; out->kind=3; return IAP2_OK; }
    if(!slice(req->method,"SETUP")&&!slice(req->method,"TEARDOWN")) return IAP2_UNSUPPORTED;
    if(!req->body.size) { if(slice(req->method,"TEARDOWN")) { out->kind=5; return IAP2_OK; } return IAP2_INVALID; }
    if(status!=IAP2_OK||req->body.size>PROJECTION_INFO_LIMIT) return IAP2_INVALID;
    storage.nodes=nodes; storage.node_capacity=SERVICE_PLIST_PROJECTION_NODES; storage.bytes=scratch;
    storage.byte_capacity=capacity<PROJECTION_INFO_LIMIT?capacity:PROJECTION_INFO_LIMIT;
    status=service_plist_decode_projection(req->body.data,req->body.size,&storage,&d);
    if(status!=IAP2_OK) goto done;
    if(d.nodes[0].type!=SERVICE_PLIST_DICT||encrypted_fields(&d,d.nodes)) { status=IAP2_INVALID; goto done; }
    streams=find(&d,d.nodes,"streams");
    if(streams) {
        if(streams->type!=SERVICE_PLIST_ARRAY||!streams->children||streams->children>PROJECTION_SESSION_STREAMS) { status=IAP2_INVALID; goto done; }
        out->kind=slice(req->method,"TEARDOWN")?4:2;
        for(child=streams->first;child!=SERVICE_PLIST_NONE;child=d.nodes[child].next) {
            projection_session_resource *r=out->resources+out->count;
            status=parse_stream(&d,d.nodes+child,r,out->kind==4); if(status) goto done;
            for(i=0;i<out->count;++i) if(out->resources[i].type==r->type||
                (out->kind==2&&out->resources[i].connection_id==r->connection_id)) { status=IAP2_INVALID; goto done; }
            /* Optional teardown ID must still be a uint64, never ignored/coerced. */
            if(out->kind==4&&find(&d,d.nodes+child,"streamConnectionID")) {
                status=uint_field(&d,d.nodes+child,"streamConnectionID",UINT64_MAX,1,&r->connection_id); if(status) goto done;
                r->frames_per_packet=1; /* Internal presence marker for teardown only. */
            }
            ++out->count;
        }
    } else if(slice(req->method,"TEARDOWN")) out->kind=5;
    else {
        out->kind=1; out->count=1;
        status=uint_field(&d,d.nodes,"timingPort",65535,1,&n); if(status||!n) { status=IAP2_INVALID; goto done; }
        out->resources[0].peer_timing_port=(uint16_t)n;
        status=bool_field(&d,d.nodes,"keepAliveLowPower",&out->resources[0].keep_alive_low_power); if(status) goto done;
        v=find(&d,d.nodes,"timingProtocol"); if(v&&!text_is(v,"NTP")) { status=IAP2_UNSUPPORTED; goto done; }
        /* These are untrusted metadata, never trust identity or network destinations. */
        { static const char *names[]={"name","model","deviceID","macAddress","sessionUUID"};
          for(i=0;i<5;++i) { v=find(&d,d.nodes,names[i]); if(v&&(v->type!=SERVICE_PLIST_STRING||v->size>256)) { status=IAP2_INVALID; goto done; } } }
    }
done:
    pair_crypto_wipe(nodes,sizeof(nodes)); pair_crypto_wipe(scratch,storage.byte_capacity);
    if(status) pair_crypto_wipe(out,sizeof(*out)); return status;
}

/* Fixed reply schemas only: <=80 objects, uint64/ASCII/array/dict, no external
 * graphs, offset/ref widths or opaque successful reply supplied by a caller. */
typedef struct object { const char *text; uint64_t value; uint8_t refs[24],count,kind; } object;
typedef struct plist { object nodes[80]; size_t count; uint8_t *out; size_t at; int error; } plist;
static uint8_t add(plist *b,uint8_t parent,uint8_t kind) {
    uint8_t id; object *o;
    if(b->error) return 0;
    if(b->count==80||(parent!=255&&(parent>=b->count||b->nodes[parent].count==24))) { b->error=IAP2_NO_SPACE; return 0; }
    id=(uint8_t)b->count++; o=b->nodes+id; o->kind=kind;
    if(parent!=255) b->nodes[parent].refs[b->nodes[parent].count++]=id; return id;
}
static uint8_t field(plist *b,uint8_t parent,const char *key,uint8_t kind) {
    if(key) b->nodes[add(b,parent,5)].text=key; return add(b,parent,kind);
}
static void number(plist *b,uint8_t parent,const char *key,uint64_t value) { b->nodes[field(b,parent,key,1)].value=value; }
static void put(plist *b,uint8_t v) {
    if(b->error) return;
    if(b->at==PROJECTION_SESSION_REPLY) { b->error=IAP2_NO_SPACE; return; }
    b->out[b->at++]=v;
}
static void be(plist *b,uint64_t v,unsigned n) { while(n) { --n; put(b,(uint8_t)(v>>(8*n))); } }
static void integer(plist *b,uint64_t v) {
    unsigned n=v<=255?1:(v<=65535?2:(v<=UINT32_MAX?4:8));
    if(v>>63) { put(b,0x14); be(b,0,8); be(b,v,8); }
    else { put(b,(uint8_t)(0x10|(n==8?3:n==4?2:n==2?1:0))); be(b,v,n); }
}
static void marker(plist *b,uint8_t kind,size_t n) { put(b,(uint8_t)(kind|(n<15?n:15))); if(n>=15) integer(b,n); }
static int reply(projection_session *s,uint8_t kind,size_t first) {
    plist b; uint16_t offsets[80]; size_t i,j,table; uint8_t root,array,dict; int status;
    pair_crypto_wipe(&b,sizeof(b)); b.out=s->reply; s->reply_size=0;
    if(kind!=1&&kind!=2) return IAP2_OK;
    root=add(&b,255,13);
    if(kind==1) {
        const projection_session_endpoint *e=&s->slots[0].endpoint;
        number(&b,root,"timingPort",e->timing_port); number(&b,root,"eventPort",e->event_port);
        if(e->keep_alive_port) number(&b,root,"keepAlivePort",e->keep_alive_port);
        array=field(&b,root,"enabledFeatures",10);
        { static const char *names[]={"viewAreas","iAPChannel","hevc","altScreen"};
          for(i=0;i<4;++i) if(s->config.enabled_features&(1u<<i)) b.nodes[add(&b,array,5)].text=names[i]; }
    } else {
        array=field(&b,root,"streams",10);
        for(i=first;i<s->count;++i) {
            const projection_session_slot *slot=s->slots+i; uint32_t type=slot->request.type;
            dict=add(&b,array,13); number(&b,dict,"type",type); number(&b,dict,"dataPort",slot->endpoint.data_port);
            if(type>=100&&type<=102) { number(&b,dict,"controlPort",slot->endpoint.control_port); number(&b,dict,"streamConnectionID",slot->request.connection_id); }
            if(type==130) number(&b,dict,"streamID",slot->endpoint.stream_id);
        }
    }
    if(b.error) { status=b.error; pair_crypto_wipe(&b,sizeof(b)); return status; }
    for(i=0;i<8;++i) put(&b,(uint8_t)"bplist00"[i]);
    for(i=0;i<b.count;++i) {
        const object *o=b.nodes+i; offsets[i]=(uint16_t)b.at;
        if(o->kind==1) integer(&b,o->value);
        else if(o->kind==5) { size_t n=len(o->text); marker(&b,0x50,n); for(j=0;j<n;++j) put(&b,(uint8_t)o->text[j]); }
        else if(o->kind==10) { marker(&b,0xa0,o->count); for(j=0;j<o->count;++j) put(&b,o->refs[j]); }
        else { marker(&b,0xd0,o->count/2u); for(j=0;j<o->count;j+=2) put(&b,o->refs[j]); for(j=1;j<o->count;j+=2) put(&b,o->refs[j]); }
    }
    table=b.at; for(i=0;i<b.count;++i) be(&b,offsets[i],2);
    be(&b,0,6); put(&b,2); put(&b,1); be(&b,b.count,8); be(&b,0,8); be(&b,table,8);
    status=b.error; if(!status) s->reply_size=b.at;
    pair_crypto_wipe(&b,sizeof(b)); return status;
}
static int keys(const uint8_t *shared,const projection_session_resource *r,projection_session_keys *out) {
    uint8_t salt[40],digits[20]; size_t n=0,d=0,i; uint64_t id=r->connection_id; int status;
    const char *read,*write;
    pair_crypto_wipe(out,sizeof(*out));
    if(!r->type) {
        n=len("Events-Salt"); copy(salt,"Events-Salt",n); read="Events-Read-Encryption-Key"; write="Events-Write-Encryption-Key"; out->has_write=1;
    } else {
        n=len("DataStream-Salt"); copy(salt,"DataStream-Salt",n);
        do { digits[d++]=(uint8_t)('0'+id%10); id/=10; } while(id);
        for(i=0;i<d;++i) salt[n++]=digits[d-i-1]; read="DataStream-Output-Encryption-Key"; write="DataStream-Input-Encryption-Key";
        out->has_write=(uint8_t)(r->type==100&&r->peer_data_port!=0);
    }
    status=pair_hkdf_sha512(shared,32,salt,n,(const uint8_t *)read,len(read),out->read,32);
    if(!status&&out->has_write) status=pair_hkdf_sha512(shared,32,salt,n,(const uint8_t *)write,len(write),out->write,32);
    pair_crypto_wipe(salt,sizeof(salt)); pair_crypto_wipe(digits,sizeof(digits)); if(status) pair_crypto_wipe(out,sizeof(*out)); return status;
}
void projection_session_close(projection_session *s) {
    size_t i; if(!s||!s->enabled||s->state==PROJECTION_SESSION_DEAD) return;
    for(i=s->count;i>0;--i) s->config.provider.close(s->config.provider.context,s->generation,s->slots[i-1].endpoint.lease);
    pair_crypto_wipe(s,sizeof(*s)); s->state=PROJECTION_SESSION_DEAD;
}
static int fail(projection_session *s,int r) { projection_session_close(s); return r; }
int projection_session_init(projection_session *s,const projection_info_profile *p,
    int (*available)(void *,uint64_t,const projection_info_profile *),void *context,const projection_session_config *cfg,uint64_t gen) {
    size_t n; int status;
    if(!s||!p||!available||!cfg||!gen||!cfg->provider.open||!cfg->provider.start||!cfg->provider.close||cfg->enabled_features>15||
       ((cfg->provider.poll!=0)!=(cfg->provider.next_delay!=0))) return IAP2_ARGUMENT;
    if(((cfg->enabled_features&PROJECTION_SESSION_HEVC)&&!p->hevc)||
       ((cfg->enabled_features&PROJECTION_SESSION_ALT_SCREEN)&&p->display_count!=2)) return IAP2_INVALID;
    status=projection_info_encode(p,0,0,&n); if(status) return status;
    pair_crypto_wipe(s,sizeof(*s)); s->profile=p; s->available=available; s->available_context=context; s->config=*cfg; s->generation=gen; s->enabled=1;
    return IAP2_OK;
}
static int endpoint_valid(const projection_session_resource *r,const projection_session_endpoint *e) {
    if(!e->lease) return 0;
    if(!r->type) return e->timing_port&&e->event_port&&!e->data_port&&!e->control_port&&!e->stream_id&&
        ((e->keep_alive_port!=0)==(r->keep_alive_low_power!=0));
    if(!e->data_port||e->timing_port||e->event_port||e->keep_alive_port) return 0;
    if(r->type>=100&&r->type<=102) return e->control_port&&!e->stream_id;
    return !e->control_port&&((r->type==130)?e->stream_id!=0:e->stream_id==0);
}
int projection_session_request(projection_session *s,const rtsp_message *req,const uint8_t *shared,uint8_t *scratch,size_t capacity) {
    request q; size_t i,j,first; int status;
    if(!s||!s->enabled||!req||!shared||!scratch||!capacity) return IAP2_ARGUMENT;
    if(s->state==PROJECTION_SESSION_HELD) return RTSP_BUSY;
    if(req->kind!=RTSP_REQUEST||!req->target.data||!req->target.size||req->target.size>sizeof(s->target)) return fail(s,IAP2_INVALID);
    if(s->target_size&&(req->target.size!=s->target_size)) return fail(s,IAP2_INVALID);
    for(i=0;i<s->target_size;++i) if(req->target.data[i]!=s->target[i]) return fail(s,IAP2_INVALID);
    status=parse(req,&q,scratch,capacity); if(status) return fail(s,status);
    if((s->state==PROJECTION_SESSION_EMPTY)!=(q.kind==1)) return fail(s,IAP2_INVALID);
    if(q.kind==1&&q.resources[0].keep_alive_low_power&&!s->profile->keep_alive_low_power) return fail(s,IAP2_UNSUPPORTED);
    if(q.kind==3&&(s->recording||s->count<2)) return fail(s,IAP2_INVALID);
    if(q.kind==2) {
        if(s->count+q.count>PROJECTION_SESSION_STREAMS+1||s->used_count+q.count>PROJECTION_SESSION_IDS) return fail(s,IAP2_NO_SPACE);
        for(i=0;i<q.count;++i) {
            status=advertised(s,q.resources+i); if(status) return fail(s,status);
            for(j=0;j<s->count;++j) if(s->slots[j].request.type==q.resources[i].type) return fail(s,IAP2_INVALID);
            for(j=0;j<s->used_count;++j) if(s->used_ids[j]==q.resources[i].connection_id) return fail(s,IAP2_INVALID);
        }
    }
    if(q.kind==4) for(i=0;i<q.count;++i) {
        for(j=1;j<s->count;++j) if(s->slots[j].request.type==q.resources[i].type) break;
        if(j==s->count||(q.resources[i].frames_per_packet&&s->slots[j].request.connection_id!=q.resources[i].connection_id)) return fail(s,IAP2_INVALID);
    }
    /* No provider work for an invalid complete request. Teardown does not depend
     * on availability: resource loss must never prevent cancellation. */
    if(q.kind<=3) { status=s->available(s->available_context,s->generation,s->profile); if(status) return fail(s,status); }
    first=s->count;
    if(q.kind==1||q.kind==2) for(i=0;i<q.count;++i) {
        projection_session_keys derived; projection_session_endpoint endpoint;
        pair_crypto_wipe(&endpoint,sizeof(endpoint)); status=keys(shared,q.resources+i,&derived);
        if(!status) status=s->config.provider.open(s->config.provider.context,s->generation,q.resources+i,s->config.enabled_features,&derived,&endpoint);
        pair_crypto_wipe(&derived,sizeof(derived));
        if(endpoint.lease) {
            for(j=0;j<s->count;++j) if(s->slots[j].endpoint.lease==endpoint.lease) break;
            if(j!=s->count) return fail(s,IAP2_INVALID);
            s->slots[s->count].request=q.resources[i]; s->slots[s->count++].endpoint=endpoint;
        }
        if(status||!endpoint_valid(q.resources+i,&endpoint)) return fail(s,status?status:IAP2_INVALID);
        if(q.kind==2) s->used_ids[s->used_count++]=q.resources[i].connection_id;
    }
    if(q.kind==4||q.kind==5) for(i=s->count;i>0;--i) {
        size_t slot=i-1; int remove=q.kind==5;
        for(j=0;j<q.count;++j) if(s->slots[slot].request.type==q.resources[j].type) remove=1;
        if(remove) {
            s->config.provider.close(s->config.provider.context,s->generation,s->slots[slot].endpoint.lease);
            for(j=slot+1;j<s->count;++j) s->slots[j-1]=s->slots[j]; --s->count;
            pair_crypto_wipe(s->slots+s->count,sizeof(s->slots[0]));
        }
    }
    if(!s->target_size) { copy(s->target,req->target.data,req->target.size); s->target_size=req->target.size; }
    status=reply(s,q.kind,first); if(status) return fail(s,status);
    s->pending=q.kind; s->pending_first=first; s->state=PROJECTION_SESSION_HELD; return IAP2_OK;
}
int projection_session_release(projection_session *s) {
    size_t i,n=0,first; uint64_t leases[PROJECTION_SESSION_STREAMS+1]; int status;
    if(!s||!s->enabled) return IAP2_ARGUMENT; if(s->state!=PROJECTION_SESSION_HELD) return RTSP_BUSY;
    if(s->pending==3||(s->pending==2&&s->recording)) {
        first=s->pending==3?0:s->pending_first;
        for(i=first;i<s->count;++i) leases[n++]=s->slots[i].endpoint.lease;
        status=s->config.provider.start(s->config.provider.context,s->generation,leases,n);
        pair_crypto_wipe(leases,sizeof(leases)); if(status) return fail(s,status); s->recording=1;
    }
    if(s->pending==5) { projection_session_close(s); return IAP2_END; }
    pair_crypto_wipe(s->reply,sizeof(s->reply)); s->reply_size=0; s->pending=0; s->pending_first=0; s->state=PROJECTION_SESSION_READY; return IAP2_OK;
}
