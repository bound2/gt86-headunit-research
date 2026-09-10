/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_events.h"
static void zero(void *p,size_t n) { volatile uint8_t *b=(volatile uint8_t *)p; while(n--) *b++=0; }
static int valid_size(size_t n) { return n>=64&&n<=RTSP_MAX_MESSAGE_SIZE; }
static int valid_ms(uint32_t n) { return n&&n<=60000; }
static rtsp_slice text(const char *p) { rtsp_slice s; s.data=(const uint8_t *)p; s.size=0; while(p[s.size]) ++s.size; return s; }
void projection_events_default_config(projection_events_config *c) { if(c) { c->receive_ms=10000; c->hold_ms=c->output_ms=c->response_ms=5000; c->first_cseq=1; } }
int projection_events_init(projection_events *s,const projection_events_config *c,const projection_events_storage *b,uint64_t gen,uint64_t now) {
    if(!s||!c||!b||!gen||!c->first_cseq||!valid_ms(c->receive_ms)||!valid_ms(c->hold_ms)||!valid_ms(c->output_ms)||!valid_ms(c->response_ms)||
       !b->rx||!b->reply||!b->commands||!valid_size(b->rx_size)||!valid_size(b->reply_size)||!valid_size(b->command_size)||
       !b->slots||b->slots>PROJECTION_EVENTS_SLOTS||b->commands_size<b->slots*b->command_size) return IAP2_ARGUMENT;
    zero(s,sizeof(*s)); s->config=*c; s->storage=*b; s->generation=gen; s->next_token=1; s->next_cseq=c->first_cseq; s->now=now; s->ready=1;
    return rtsp_stream_init(&s->input,b->rx,b->rx_size);
}
static int owner(const projection_events *s,uint64_t gen) {
    if(!s||!s->ready||!gen) return IAP2_ARGUMENT; if(gen!=s->generation) return IAP2_INVALID;
    return s->dead?PROJECTION_EVENTS_CLOSED:IAP2_OK;
}
static int stop(projection_events *s,int error) {
    size_t i; if(!s->dead) {
        rtsp_stream_clear(&s->input); zero(s->storage.reply,s->reply.size);
        for(i=0;i<s->storage.slots;++i) zero(s->storage.commands+i*s->storage.command_size,s->slots[i].size);
        zero(s->slots,sizeof(s->slots)); zero(&s->reply,sizeof(s->reply)); s->held=s->active=s->started=0; s->held_token=0; s->dead=1; s->last_error=error;
    } return PROJECTION_EVENTS_CLOSED;
}
void projection_events_close(projection_events *s) { if(s&&s->ready) (void)stop(s,IAP2_END); }
int projection_events_check(projection_events *s,uint64_t gen,uint64_t now) {
    size_t i; int r=owner(s,gen); if(r) return r; if(now<s->now) return IAP2_ARGUMENT; s->now=now;
    if((s->held&&now-s->rx_at>=s->config.hold_ms)||(!s->held&&s->input.used&&now-s->rx_at>=s->config.receive_ms)||
       (s->reply.phase&&now-s->reply.at>=s->config.output_ms)) return stop(s,IAP2_MORE);
    for(i=0;i<s->storage.slots;++i) { const projection_events_slot *slot=s->slots+i;
        if(slot->phase&&slot->phase!=PROJECTION_EVENT_RESULT&&now-slot->at>=(slot->phase==PROJECTION_EVENT_WAITING?s->config.response_ms:s->config.output_ms)) return stop(s,IAP2_MORE); }
    return IAP2_OK;
}
int projection_events_start(projection_events *s,uint64_t gen,uint64_t now) { int r=projection_events_check(s,gen,now); if(!r) s->started=1; return r; }
static void command_request(rtsp_message *m,rtsp_slice body,uint32_t seq) {
    zero(m,sizeof(*m)); m->kind=RTSP_REQUEST; m->protocol=RTSP_10; m->method=text("POST"); m->target=text("/command"); m->body=body;
    m->has_cseq=1; m->cseq=seq; m->header_count=1; m->headers[0].name=text("Content-Type"); m->headers[0].value=text("application/x-apple-binary-plist");
}
int projection_events_queue(projection_events *s,uint64_t gen,const rtsp_slice *bodies,size_t count,rtsp_channel_key *keys,uint64_t now) {
    size_t i,n=0,ids[PROJECTION_EVENTS_SLOTS],sizes[PROJECTION_EVENTS_SLOTS]; rtsp_message req; int r;
    if(!keys||!count||count>PROJECTION_EVENTS_SLOTS) return IAP2_ARGUMENT; zero(keys,count*sizeof(*keys));
    r=owner(s,gen); if(r) return r; if(!bodies||now<s->now) return IAP2_ARGUMENT;
    for(i=0;i<count;++i) { if(!bodies[i].size) return IAP2_ARGUMENT; command_request(&req,bodies[i],UINT32_MAX);
        r=rtsp_request_encode(&req,0,0,sizes+i); if(r) return r; }
    if(!s->started) return RTSP_BUSY;
    for(i=0;i<s->storage.slots&&n<count;++i) if(!s->slots[i].phase) ids[n++]=i;
    if(n<count) return RTSP_BUSY;
    if(!s->next_cseq||(uint64_t)s->next_cseq+count-1>UINT32_MAX||!s->next_token||count-1>UINT64_MAX-s->next_token) return stop(s,IAP2_NO_SPACE);
    for(i=0;i<count;++i) { command_request(&req,bodies[i],s->next_cseq+(uint32_t)i); r=rtsp_request_encode(&req,0,0,sizes+i);
        if(r) return r; if(sizes[i]>s->storage.command_size) return IAP2_NO_SPACE; }
    r=projection_events_check(s,gen,now); if(r) return r;
    for(i=0;i<count;++i) { projection_events_slot *slot=s->slots+ids[i]; command_request(&req,bodies[i],s->next_cseq++);
        r=rtsp_request_encode(&req,s->storage.commands+ids[i]*s->storage.command_size,s->storage.command_size,&slot->size);
        if(r) { zero(keys,count*sizeof(*keys)); return stop(s,r); }
        slot->cseq=req.cseq; slot->token=s->next_token++; slot->at=now; slot->phase=PROJECTION_EVENT_QUEUED; keys[i].generation=gen; keys[i].token=slot->token;
    } return PROJECTION_EVENTS_OUTPUT;
}
int projection_events_feed(projection_events *s,uint64_t gen,const uint8_t *p,size_t n,size_t *used,uint64_t now) {
    rtsp_message m; size_t i; int r; if(used) *used=0; if(!used||(!p&&n)) return IAP2_ARGUMENT;
    r=projection_events_check(s,gen,now); if(r) return r; if(s->held) return RTSP_BUSY;
    if(!s->input.used&&n) s->rx_at=now; r=rtsp_stream_feed(&s->input,p,n,used); if(r==IAP2_MORE) return r; if(r) return stop(s,r);
    r=rtsp_stream_message(&s->input,&m); if(r) return stop(s,r);
    if(m.kind==RTSP_REQUEST) { if(!s->next_token) return stop(s,IAP2_NO_SPACE); s->held=1; s->held_token=s->next_token++; }
    else { if(!m.has_cseq||m.status<200) return stop(s,IAP2_INVALID);
        for(i=0;i<s->storage.slots;++i) if(s->slots[i].phase==PROJECTION_EVENT_WAITING&&s->slots[i].cseq==m.cseq) break;
        if(i==s->storage.slots) return stop(s,IAP2_INVALID);
        s->slots[i].phase=PROJECTION_EVENT_RESULT; s->held=2; s->held_slot=(uint8_t)i; s->held_token=s->slots[i].token;
    } s->rx_at=now; return s->held==1?PROJECTION_EVENTS_REQUEST:PROJECTION_EVENTS_RESPONSE;
}
int projection_events_message(const projection_events *s,uint64_t gen,rtsp_message *m,rtsp_channel_key *key) {
    int r; if(m) zero(m,sizeof(*m)); if(key) zero(key,sizeof(*key)); if(!m||!key) return IAP2_ARGUMENT;
    r=owner(s,gen); if(r) return r; if(!s->held) return IAP2_MORE; r=rtsp_stream_message(&s->input,m); if(r) return r;
    key->generation=gen; key->token=s->held_token; return s->held==1?PROJECTION_EVENTS_REQUEST:PROJECTION_EVENTS_RESPONSE;
}
static int held_key(const projection_events *s,rtsp_channel_key key) {
    int r=owner(s,key.generation); if(r) return r; return key.token&&key.token==s->held_token?IAP2_OK:IAP2_INVALID;
}
int projection_events_respond(projection_events *s,rtsp_channel_key key,const rtsp_response *res,uint64_t now) {
    rtsp_message req; size_t n=0; int r=held_key(s,key); if(r) return r; if(s->held!=1||s->reply.phase) return RTSP_BUSY;
    if(!res||res->status<200||now<s->now) return IAP2_ARGUMENT; r=rtsp_stream_message(&s->input,&req); if(r) return r;
    r=rtsp_response_encode(&req,res,0,0,&n); if(r) return r; if(n>s->storage.reply_size) return IAP2_NO_SPACE;
    r=projection_events_check(s,key.generation,now); if(r) return r;
    r=rtsp_response_encode(&req,res,s->storage.reply,s->storage.reply_size,&s->reply.size); if(r) return stop(s,r);
    s->reply.token=key.token; s->reply.phase=PROJECTION_EVENT_QUEUED; s->reply.at=now; s->held=0; s->held_token=0; rtsp_stream_clear(&s->input); return PROJECTION_EVENTS_OUTPUT;
}
int projection_events_release(projection_events *s,rtsp_channel_key key,uint64_t now) {
    int r=held_key(s,key); if(r) return r; if(s->held!=2) return RTSP_BUSY; r=projection_events_check(s,key.generation,now); if(r) return r;
    zero(s->slots+s->held_slot,sizeof(s->slots[0])); s->held=0; s->held_token=0; rtsp_stream_clear(&s->input); return IAP2_OK;
}
static projection_events_slot *active(projection_events *s) { return s->active==1?&s->reply:s->slots+(s->active-2); }
static uint8_t *buffer(projection_events *s) { return s->active==1?s->storage.reply:s->storage.commands+(s->active-2)*s->storage.command_size; }
int projection_events_output(projection_events *s,uint64_t gen,rtsp_slice *out,rtsp_channel_key *key,int *command,uint64_t now) {
    size_t i; projection_events_slot *slot; int r; if(out) zero(out,sizeof(*out)); if(key) zero(key,sizeof(*key)); if(command) *command=0;
    if(!out||!key||!command) return IAP2_ARGUMENT; r=projection_events_check(s,gen,now); if(r) return r;
    if(!s->active) { if(s->reply.phase) s->active=1;
        else for(i=0;i<s->storage.slots;++i) if(s->slots[i].phase==PROJECTION_EVENT_QUEUED&&(!s->active||s->slots[i].token<active(s)->token)) s->active=(uint8_t)(i+2);
        if(!s->active) return IAP2_MORE; active(s)->phase=PROJECTION_EVENT_SENDING;
    }
    slot=active(s); key->generation=gen; key->token=slot->token; *command=s->active!=1;
    if(slot->phase==PROJECTION_EVENT_DRAINING) return PROJECTION_EVENTS_DRAIN;
    out->data=buffer(s)+slot->offset; out->size=slot->size-slot->offset; return PROJECTION_EVENTS_OUTPUT;
}
static int output_key(projection_events *s,rtsp_channel_key key) {
    int r=owner(s,key.generation); if(r) return r; return s->active&&key.token&&key.token==active(s)->token?IAP2_OK:IAP2_INVALID;
}
int projection_events_consume(projection_events *s,rtsp_channel_key key,size_t n,uint64_t now) {
    projection_events_slot *slot; int r=output_key(s,key); if(r) return r; slot=active(s);
    if(slot->phase!=PROJECTION_EVENT_SENDING) return RTSP_BUSY; if(!n||n>slot->size-slot->offset) return IAP2_ARGUMENT;
    r=projection_events_check(s,key.generation,now); if(r) return r; zero(buffer(s)+slot->offset,n); slot->offset+=n;
    if(slot->offset==slot->size) { slot->phase=PROJECTION_EVENT_DRAINING; return PROJECTION_EVENTS_DRAIN; } return PROJECTION_EVENTS_OUTPUT;
}
int projection_events_drain(projection_events *s,rtsp_channel_key key,uint64_t now) {
    projection_events_slot *slot; int r=output_key(s,key); if(r) return r; slot=active(s); if(slot->phase!=PROJECTION_EVENT_DRAINING) return RTSP_BUSY;
    r=projection_events_check(s,key.generation,now); if(r) return r;
    if(s->active==1) zero(slot,sizeof(*slot)); else { slot->phase=PROJECTION_EVENT_WAITING; slot->at=now; }
    s->active=0; return IAP2_OK;
}
static uint32_t remaining(uint64_t elapsed,uint32_t budget) { return elapsed>=budget?0:budget-(uint32_t)elapsed; }
uint32_t projection_events_next_delay(const projection_events *s) {
    size_t i; uint32_t delay=UINT32_MAX,n; if(!s||!s->ready||s->dead) return delay;
    if(s->held||s->input.used) delay=remaining(s->now-s->rx_at,s->held?s->config.hold_ms:s->config.receive_ms);
    if(s->reply.phase) { n=remaining(s->now-s->reply.at,s->config.output_ms); if(n<delay) delay=n; }
    for(i=0;i<s->storage.slots;++i) { const projection_events_slot *slot=s->slots+i;
        if(slot->phase&&slot->phase!=PROJECTION_EVENT_RESULT) { n=remaining(s->now-slot->at,slot->phase==PROJECTION_EVENT_WAITING?s->config.response_ms:s->config.output_ms); if(n<delay) delay=n; } }
    return delay;
}
