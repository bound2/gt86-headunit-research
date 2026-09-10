/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_receiver.h"
#include "service_plist.h"

static void copy(void *d, const void *s, size_t n) {
    uint8_t *p=(uint8_t *)d; const uint8_t *q=(const uint8_t *)s;
    while(n--) *p++=*q++;
}
static rtsp_slice literal(const char *p) {
    rtsp_slice s; s.data=(const uint8_t *)p; s.size=0;
    while(p[s.size]) ++s.size;
    return s;
}
static int equals(rtsp_slice a, const char *b) {
    size_t i;
    for(i=0;i<a.size;++i) if(!b[i]||a.data[i]!=(uint8_t)b[i]) return 0;
    return !b[a.size];
}
void projection_receiver_default_config(projection_receiver_config *cfg) {
    if(cfg) {
        rtsp_channel_default_config(&cfg->initial);
        cfg->initial.reply_ms=30000;
        pair_setup_channel_default_config(&cfg->setup);
        projection_auth_default_config(&cfg->auth);
        cfg->enrollment_enabled=0;
    }
}
static int init_auth(projection_receiver *s, uint64_t now) {
    const projection_receiver_providers *p=&s->providers;
    return projection_auth_init(&s->auth,p->identity,p->random,p->random_context,
        p->lookup,p->lookup_context,&p->mfi,&s->config.auth,&s->storage.control,s->verify_generation,now);
}
static int init_setup(projection_receiver *s, uint64_t now) {
    const projection_receiver_providers *p=&s->providers;
    const projection_control_storage *b=&s->storage.control;
    return pair_setup_channel_init(&s->setup,p->identity,p->random,p->random_context,
        p->commit,p->commit_context,p->lookup,p->lookup_context,&s->config.setup,
        b->request,b->request_capacity,b->response,b->response_capacity,s->generation,now);
}
int projection_receiver_init(projection_receiver *s, const projection_receiver_providers *providers,
    const projection_receiver_config *cfg, const projection_receiver_storage *storage,
    uint64_t gen, uint64_t verify_gen, uint64_t now) {
    projection_receiver tmp; int r;
    if(!s||!providers||!cfg||!storage||!gen||!verify_gen||gen==verify_gen||
       cfg->enrollment_enabled>1||storage->initial_capacity>storage->control.request_capacity)
        return IAP2_ARGUMENT;
    pair_crypto_wipe(&tmp,sizeof(tmp));
    tmp.providers=*providers; tmp.config=*cfg; tmp.storage=*storage;
    tmp.generation=gen; tmp.verify_generation=verify_gen; tmp.now=tmp.started_at=now; tmp.next_token=1;
    /* Child init validates but neither allocates nor writes supplied buffers.
     * Discard validation-only owners by wiping, not close (cipher close wipes
     * its buffers). No active child exists before the initial route is chosen. */
    r=init_auth(&tmp,now); if(r!=IAP2_OK) goto done;
    pair_crypto_wipe(&tmp.auth,sizeof(tmp.auth));
    if(cfg->enrollment_enabled) {
        r=init_setup(&tmp,now); if(r!=IAP2_OK) goto done;
        pair_crypto_wipe(&tmp.setup,sizeof(tmp.setup));
    }
    r=rtsp_channel_init(&tmp.initial,&cfg->initial,storage->initial,storage->initial_capacity,
        storage->control.response,storage->control.response_capacity,gen,now);
    if(r==IAP2_OK) { tmp.state=PROJECTION_RECEIVER_ROUTING; copy(s,&tmp,sizeof(tmp)); }
done:
    pair_crypto_wipe(&tmp,sizeof(tmp)); return r;
}
static int owner(const projection_receiver *s, uint64_t gen) {
    if(!s||!s->generation||!gen) return IAP2_ARGUMENT;
    if(s->generation!=gen) return IAP2_INVALID;
    return s->state==PROJECTION_RECEIVER_DEAD?PROJECTION_RECEIVER_CLOSED:IAP2_OK;
}
static int keyed(const projection_receiver *s, rtsp_channel_key key) {
    int r=owner(s,key.generation); if(r!=IAP2_OK) return r;
    return key.token&&key.token==s->key.token?IAP2_OK:IAP2_INVALID;
}
static int stop(projection_receiver *s, enum projection_receiver_reason reason, int error) {
    if(s->state!=PROJECTION_RECEIVER_DEAD) {
        s->enrolled=s->setup.setup.committed;
        projection_session_close(&s->session);
        rtsp_channel_close(&s->initial);
        pair_setup_channel_close(&s->setup);
        projection_auth_close(&s->auth);
        if(s->info.buffer) pair_crypto_wipe(s->info.buffer,s->info_size);
        pair_crypto_wipe(&s->info,sizeof(s->info)); s->info_size=0; s->info_pending=0;
        pair_crypto_wipe(&s->providers,sizeof(s->providers));
        pair_crypto_wipe(&s->key,sizeof(s->key));
        pair_crypto_wipe(&s->child_key,sizeof(s->child_key));
        s->authorization=0; s->state=PROJECTION_RECEIVER_DEAD;
        s->reason=reason; s->last_error=error;
    }
    return PROJECTION_RECEIVER_CLOSED;
}
static int sync(projection_receiver *s, int r) {
    rtsp_channel_key key={0,0};
    if(s->state==PROJECTION_RECEIVER_SETUP) {
        s->now=s->setup.now; s->enrolled=s->setup.setup.committed;
        if(s->setup.state==PAIR_SETUP_CHANNEL_DEAD)
            return stop(s,PROJECTION_RECEIVER_REASON_SETUP,s->setup.last_error);
        key=s->setup.key;
    } else if(s->state==PROJECTION_RECEIVER_AUTH) {
        s->now=s->auth.now;
        if(s->auth.state==PROJECTION_AUTH_DEAD)
            return stop(s,PROJECTION_RECEIVER_REASON_AUTH,s->auth.last_error);
        key=s->auth.control.key;
    } else {
        s->now=s->initial.now;
        if(s->initial.state==RTSP_CHANNEL_DEAD)
            return stop(s,PROJECTION_RECEIVER_REASON_INITIAL,s->initial.last_error);
        key.generation=s->generation; key.token=s->initial.token;
    }
    if(r==RTSP_CHANNEL_OUTPUT||r==RTSP_CHANNEL_REQUEST||r==PAIR_SETUP_APPROVAL) {
        if(!key.token||!key.generation) return stop(s,PROJECTION_RECEIVER_REASON_TOKEN,IAP2_INVALID);
        if(!s->key.token) {
            if(!s->next_token) return stop(s,PROJECTION_RECEIVER_REASON_TOKEN,IAP2_INVALID);
            s->key.generation=s->generation; s->key.token=s->next_token++;
            s->child_key=key;
        } else if(key.generation!=s->child_key.generation||key.token!=s->child_key.token)
            return stop(s,PROJECTION_RECEIVER_REASON_TOKEN,IAP2_INVALID);
    }
    return r;
}
int projection_receiver_check(projection_receiver *s, uint64_t gen, uint64_t now) {
    int r=owner(s,gen); if(r!=IAP2_OK) return r;
    if(now<s->now) return IAP2_ARGUMENT;
    if(s->info.profile&&s->state!=PROJECTION_RECEIVER_SETUP&&s->state!=PROJECTION_RECEIVER_AUTH&&
       now-s->started_at>=s->info.initial_ms) {
        s->now=now; return stop(s,PROJECTION_RECEIVER_REASON_INITIAL,IAP2_MORE);
    }
    if(s->state==PROJECTION_RECEIVER_SETUP) r=pair_setup_channel_check(&s->setup,gen,now);
    else if(s->state==PROJECTION_RECEIVER_AUTH) r=projection_auth_check(&s->auth,s->verify_generation,now);
    else r=rtsp_channel_check(&s->initial,gen,now);
    return sync(s,r);
}
void projection_receiver_info_default_config(projection_receiver_info_config *cfg) {
    if(cfg) { pair_crypto_wipe(cfg,sizeof(*cfg)); cfg->initial_ms=60000; cfg->initial_limit=4; }
}
int projection_receiver_poll(projection_receiver *s,uint64_t gen,uint64_t now) {
    int r=projection_receiver_check(s,gen,now); if(r!=IAP2_OK) return r;
    if(!s->session.enabled||!s->session.count) return IAP2_MORE;
    if(!s->session.config.provider.poll) return IAP2_UNSUPPORTED;
    r=s->session.config.provider.poll(s->session.config.provider.context,gen,now);
    return r==IAP2_OK||r==IAP2_MORE?r:stop(s,PROJECTION_RECEIVER_REASON_SESSION,r);
}
int projection_receiver_enable_info(projection_receiver *s,uint64_t gen,const projection_receiver_info_config *cfg,uint64_t now) {
    size_t size=0; int r=owner(s,gen); if(r!=IAP2_OK) return r;
    if(!cfg||!cfg->profile||!cfg->available||!cfg->buffer||!cfg->initial_ms||cfg->initial_ms>60000||
       !cfg->initial_limit||cfg->initial_limit>16||cfg->allow_initial>1) return IAP2_ARGUMENT;
    if(s->info.profile||s->state!=PROJECTION_RECEIVER_ROUTING||s->initial.input.used) return RTSP_BUSY;
    r=projection_info_encode(cfg->profile,0,0,&size); if(r!=IAP2_OK) return r;
    if(cfg->capacity<size||s->storage.control.response_capacity<size+256u) return IAP2_NO_SPACE;
    if(now<s->now) return IAP2_ARGUMENT;
    if(now-s->started_at>=cfg->initial_ms) return IAP2_INVALID;
    r=projection_receiver_check(s,gen,now); if(r!=IAP2_OK) return r;
    s->info=*cfg; s->info_size=size; return IAP2_OK;
}
static int info_request(projection_receiver *s,const rtsp_message *req) {
    rtsp_slice type; int r=rtsp_header_get(req,literal("Content-Type"),&type);
    if(!equals(req->method,"GET")&&!equals(req->method,"POST")) return IAP2_UNSUPPORTED;
    if(r!=IAP2_END&&(r!=IAP2_OK||!equals(type,"application/x-apple-binary-plist"))) return IAP2_INVALID;
    if(!req->body.size) return IAP2_OK;
    if(!equals(req->method,"POST")||r!=IAP2_OK||req->body.size<8||req->body.size>PROJECTION_INFO_LIMIT) return IAP2_INVALID;
    { rtsp_slice magic=req->body; magic.size=8; if(!equals(magic,"bplist00")) return IAP2_INVALID; }
    {
        service_plist_node nodes[SERVICE_PLIST_PROJECTION_NODES];
        service_plist_storage storage; service_plist_document doc;
        storage.nodes=nodes; storage.node_capacity=SERVICE_PLIST_PROJECTION_NODES; storage.bytes=s->info.buffer;
        storage.byte_capacity=s->info.capacity<PROJECTION_INFO_LIMIT?s->info.capacity:PROJECTION_INFO_LIMIT;
        r=service_plist_decode_projection(req->body.data,req->body.size,&storage,&doc);
        if(r==IAP2_OK&&doc.nodes[0].type!=SERVICE_PLIST_DICT) r=IAP2_INVALID;
        pair_crypto_wipe(nodes,sizeof(nodes)); pair_crypto_wipe(storage.bytes,storage.byte_capacity); return r;
    }
}
int projection_receiver_enable_session(projection_receiver *s,uint64_t gen,const projection_session_config *cfg,uint64_t now) {
    projection_session tmp; int r=owner(s,gen); if(r!=IAP2_OK) return r;
    if(!s->info.profile||s->session.enabled||s->state!=PROJECTION_RECEIVER_ROUTING||s->initial.input.used||s->initial_info_count) return RTSP_BUSY;
    if(s->storage.control.response_capacity<PROJECTION_SESSION_REPLY+256u) return IAP2_NO_SPACE;
    r=projection_session_init(&tmp,s->info.profile,s->info.available,s->info.context,cfg,gen);
    if(r!=IAP2_OK) return r;
    r=projection_receiver_check(s,gen,now);
    if(r==IAP2_OK) s->session=tmp;
    pair_crypto_wipe(&tmp,sizeof(tmp)); return r;
}
static int session_reply(projection_receiver *s,const rtsp_message *req,rtsp_channel_key key,uint64_t now) {
    rtsp_response response; rtsp_header header; int r;
    if(s->auth.auth.state!=MFI_SAP_DONE) return stop(s,PROJECTION_RECEIVER_REASON_SESSION,IAP2_UNSUPPORTED);
    r=projection_session_request(&s->session,req,s->auth.control.shared_secret,s->info.buffer,s->info.capacity);
    if(r!=IAP2_OK) return stop(s,PROJECTION_RECEIVER_REASON_SESSION,r);
    pair_crypto_wipe(&response,sizeof(response)); response.status=200;
    if(s->session.reply_size) {
        header.name=literal("Content-Type"); header.value=literal("application/x-apple-binary-plist");
        response.headers=&header; response.header_count=1;
        response.body.data=s->session.reply; response.body.size=s->session.reply_size;
    }
    r=projection_auth_respond(&s->auth,key,&response,now);
    pair_crypto_wipe(s->session.reply,sizeof(s->session.reply)); s->session.reply_size=0;
    if(r!=RTSP_CHANNEL_OUTPUT) return stop(s,PROJECTION_RECEIVER_REASON_SESSION,r);
    return sync(s,r);
}
static int info_reply(projection_receiver *s,const rtsp_message *req,rtsp_channel_key key,int initial,uint64_t now) {
    size_t size=0; rtsp_header header; rtsp_response response; int r;
    if(!s->info.profile||(initial&&(!s->info.allow_initial||s->initial_info_count>=s->info.initial_limit)))
        return stop(s,PROJECTION_RECEIVER_REASON_INFO,IAP2_UNSUPPORTED);
    r=info_request(s,req); if(r!=IAP2_OK) return stop(s,PROJECTION_RECEIVER_REASON_INFO,r);
    r=projection_info_encode(s->info.profile,s->info.buffer,s->info.capacity,&size);
    if(r!=IAP2_OK||size!=s->info_size) return stop(s,PROJECTION_RECEIVER_REASON_INFO,r==IAP2_OK?IAP2_INVALID:r);
    r=s->info.available(s->info.context,s->generation,s->info.profile);
    if(r!=IAP2_OK) return stop(s,PROJECTION_RECEIVER_REASON_INFO,r);
    header.name=literal("Content-Type"); header.value=literal("application/x-apple-binary-plist"); pair_crypto_wipe(&response,sizeof(response));
    response.status=200; response.headers=&header; response.header_count=1; response.body.data=s->info.buffer; response.body.size=size;
    if(initial) { r=rtsp_channel_respond(&s->initial,key,&response,now); s->state=PROJECTION_RECEIVER_DISCOVERY; }
    else r=projection_auth_respond(&s->auth,key,&response,now);
    pair_crypto_wipe(s->info.buffer,size);
    if(r!=RTSP_CHANNEL_OUTPUT) return stop(s,PROJECTION_RECEIVER_REASON_INFO,r);
    s->info_pending=1; if(initial) ++s->initial_info_count;
    return sync(s,r);
}
static int select_route(projection_receiver *s, int setup, uint64_t now) {
    size_t used=0, n=s->initial.input.used; int r;
    if(setup) {
        r=init_setup(s,now); if(r!=IAP2_OK) return stop(s,PROJECTION_RECEIVER_REASON_SETUP,r);
        s->state=PROJECTION_RECEIVER_SETUP;
        r=pair_setup_channel_authorize(&s->setup,s->generation,s->authorization,now);
        if(r!=IAP2_OK) return stop(s,PROJECTION_RECEIVER_REASON_SETUP,r);
        r=pair_setup_channel_feed(&s->setup,s->generation,s->initial.input.buffer,n,&used,now);
    } else {
        r=init_auth(s,now); if(r!=IAP2_OK) return stop(s,PROJECTION_RECEIVER_REASON_AUTH,r);
        s->state=PROJECTION_RECEIVER_AUTH;
        pair_crypto_wipe(&s->providers,sizeof(s->providers)); s->authorization=0;
        r=projection_auth_feed(&s->auth,s->verify_generation,s->initial.input.buffer,n,&used,now);
    }
    rtsp_channel_close(&s->initial); /* Any earlier discovery TX has fully drained. */
    r=sync(s,r);
    if(s->state!=PROJECTION_RECEIVER_DEAD&&(used!=n||r!=RTSP_CHANNEL_OUTPUT))
        return stop(s,PROJECTION_RECEIVER_REASON_ROUTE,IAP2_INVALID);
    return r;
}
int projection_receiver_authorize(projection_receiver *s, uint64_t gen, uint64_t authorization, uint64_t now) {
    int r=owner(s,gen); if(r!=IAP2_OK) return r;
    if(!authorization) return IAP2_ARGUMENT;
    if(!s->config.enrollment_enabled) return IAP2_UNSUPPORTED;
    if(s->authorization||(s->state!=PROJECTION_RECEIVER_ROUTING&&s->state!=PROJECTION_RECEIVER_WAIT_AUTH)) return RTSP_BUSY;
    r=projection_receiver_check(s,gen,now); if(r!=IAP2_OK) return r;
    if(!s->next_token) return stop(s,PROJECTION_RECEIVER_REASON_TOKEN,IAP2_INVALID);
    s->authorization=authorization;
    return s->state==PROJECTION_RECEIVER_WAIT_AUTH?select_route(s,1,now):IAP2_OK;
}
int projection_receiver_feed(projection_receiver *s, uint64_t gen, const uint8_t *p, size_t n, size_t *used, uint64_t now) {
    rtsp_message req; rtsp_channel_key key; rtsp_slice type; int r, setup;
    if(used) *used=0;
    if(!used||(!p&&n)) return IAP2_ARGUMENT;
    r=projection_receiver_check(s,gen,now); if(r!=IAP2_OK) return r;
    if(!s->key.token&&!s->next_token) return stop(s,PROJECTION_RECEIVER_REASON_TOKEN,IAP2_INVALID);
    if(s->state==PROJECTION_RECEIVER_SETUP) return sync(s,pair_setup_channel_feed(&s->setup,gen,p,n,used,now));
    if(s->state==PROJECTION_RECEIVER_AUTH) {
        r=projection_auth_feed(&s->auth,s->verify_generation,p,n,used,now);
        if(r==RTSP_CHANNEL_REQUEST&&s->info.profile) {
            int got=projection_auth_request(&s->auth,&req,&key);
            if(got!=RTSP_CHANNEL_REQUEST) return stop(s,PROJECTION_RECEIVER_REASON_INFO,got);
            if(equals(req.target,"/info")) return info_reply(s,&req,key,0,now);
            if(s->session.enabled&&(equals(req.method,"SETUP")||equals(req.method,"RECORD")||equals(req.method,"TEARDOWN")))
                return session_reply(s,&req,key,now);
        }
        return sync(s,r);
    }
    if(s->state==PROJECTION_RECEIVER_WAIT_AUTH||s->state==PROJECTION_RECEIVER_DISCOVERY) return RTSP_BUSY;
    r=rtsp_channel_feed(&s->initial,gen,p,n,used,now);
    if(r!=RTSP_CHANNEL_REQUEST) return sync(s,r);
    s->now=s->initial.now;
    r=rtsp_channel_request(&s->initial,&req,&key);
    if(r!=RTSP_CHANNEL_REQUEST) return stop(s,PROJECTION_RECEIVER_REASON_INITIAL,r);
    if(equals(req.target,"/info")&&s->info.profile) return info_reply(s,&req,key,1,now);
    if(!equals(req.method,"POST")||rtsp_header_get(&req,literal("Content-Type"),&type)!=IAP2_OK||
       !equals(type,"application/pairing+tlv8")) return stop(s,PROJECTION_RECEIVER_REASON_ROUTE,IAP2_UNSUPPORTED);
    setup=equals(req.target,"/pair-setup");
    if((!setup&&!equals(req.target,"/pair-verify"))||(setup&&!s->config.enrollment_enabled))
        return stop(s,PROJECTION_RECEIVER_REASON_ROUTE,IAP2_UNSUPPORTED);
    if(setup&&!s->authorization) { s->state=PROJECTION_RECEIVER_WAIT_AUTH; return PROJECTION_RECEIVER_AUTHORIZE; }
    return select_route(s,setup,now);
}
int projection_receiver_pending(const projection_receiver *s, pair_setup_candidate *candidate, rtsp_channel_key *key) {
    rtsp_channel_key child; int r;
    if(candidate) pair_crypto_wipe(candidate,sizeof(*candidate));
    if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!candidate||!key) return IAP2_ARGUMENT;
    r=owner(s,s?s->generation:0); if(r!=IAP2_OK) return r;
    if(s->state!=PROJECTION_RECEIVER_SETUP) return IAP2_MORE;
    r=pair_setup_channel_pending(&s->setup,candidate,&child);
    if(r==PAIR_SETUP_APPROVAL) *key=s->key;
    return r;
}
int projection_receiver_decide(projection_receiver *s, rtsp_channel_key key, int approve, uint64_t now) {
    int r=keyed(s,key); if(r!=IAP2_OK) return r;
    if(s->state!=PROJECTION_RECEIVER_SETUP) return RTSP_BUSY;
    return sync(s,pair_setup_channel_decide(&s->setup,s->child_key,approve,now));
}
int projection_receiver_request(const projection_receiver *s, rtsp_message *req, rtsp_channel_key *key) {
    rtsp_channel_key child; int r;
    if(req) pair_crypto_wipe(req,sizeof(*req));
    if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!req||!key) return IAP2_ARGUMENT;
    r=owner(s,s?s->generation:0); if(r!=IAP2_OK) return r;
    if(s->state!=PROJECTION_RECEIVER_AUTH||s->info_pending||s->session.state==PROJECTION_SESSION_HELD) return IAP2_MORE;
    r=projection_auth_request(&s->auth,req,&child);
    if(r==RTSP_CHANNEL_REQUEST) *key=s->key;
    return r;
}
int projection_receiver_respond(projection_receiver *s, rtsp_channel_key key, const rtsp_response *response, uint64_t now) {
    int r=keyed(s,key); if(r!=IAP2_OK) return r;
    if(s->info_pending||s->session.state==PROJECTION_SESSION_HELD) return RTSP_BUSY;
    if(s->state!=PROJECTION_RECEIVER_AUTH) return RTSP_BUSY;
    return sync(s,projection_auth_respond(&s->auth,s->child_key,response,now));
}
int projection_receiver_output(projection_receiver *s, uint64_t gen, rtsp_slice *out, rtsp_channel_key *key, uint64_t now) {
    rtsp_channel_key child; int r;
    if(out) pair_crypto_wipe(out,sizeof(*out));
    if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!out||!key) return IAP2_ARGUMENT;
    r=projection_receiver_check(s,gen,now); if(r!=IAP2_OK) return r;
    if(s->state==PROJECTION_RECEIVER_SETUP) r=pair_setup_channel_output(&s->setup,gen,out,&child,now);
    else if(s->state==PROJECTION_RECEIVER_AUTH) r=projection_auth_output(&s->auth,s->verify_generation,out,&child,now);
    else if(s->state==PROJECTION_RECEIVER_DISCOVERY) r=rtsp_channel_output(&s->initial,s->child_key,out,now);
    else return RTSP_BUSY;
    r=sync(s,r);
    if(r==RTSP_CHANNEL_OUTPUT||r==RTSP_CHANNEL_OUTPUT_DONE) *key=s->key;
    else pair_crypto_wipe(out,sizeof(*out));
    return r;
}
int projection_receiver_consume(projection_receiver *s, rtsp_channel_key key, size_t n, uint64_t now) {
    int r=keyed(s,key); if(r!=IAP2_OK) return r;
    if(s->state==PROJECTION_RECEIVER_SETUP) r=pair_setup_channel_consume(&s->setup,s->child_key,n,now);
    else if(s->state==PROJECTION_RECEIVER_AUTH) r=projection_auth_consume(&s->auth,s->child_key,n,now);
    else if(s->state==PROJECTION_RECEIVER_DISCOVERY) {
        r=rtsp_channel_consume(&s->initial,s->child_key,n,now);
        if(r==RTSP_CHANNEL_OUTPUT||r==RTSP_CHANNEL_OUTPUT_DONE) {
            int check=projection_receiver_check(s,key.generation,now); if(check!=IAP2_OK) return check;
        }
    }
    else return RTSP_BUSY;
    return sync(s,r);
}
int projection_receiver_release(projection_receiver *s, rtsp_channel_key key, uint64_t now) {
    int r=keyed(s,key); if(r!=IAP2_OK) return r;
    if(s->state==PROJECTION_RECEIVER_SETUP) r=pair_setup_channel_release(&s->setup,s->child_key,now);
    else if(s->state==PROJECTION_RECEIVER_AUTH) r=projection_auth_release(&s->auth,s->child_key,now);
    else if(s->state==PROJECTION_RECEIVER_DISCOVERY) {
        if(s->initial.state!=RTSP_CHANNEL_SENT) return RTSP_BUSY;
        r=projection_receiver_check(s,key.generation,now); if(r!=IAP2_OK) return r;
        r=rtsp_channel_release(&s->initial,s->child_key,now);
        if(r==IAP2_OK) s->state=PROJECTION_RECEIVER_ROUTING;
    }
    else return RTSP_BUSY;
    r=sync(s,r);
    if(r==PAIR_SETUP_COMPLETE) {
        int take=pair_setup_channel_take_auth(&s->setup,s->child_key,&s->auth,&s->config.auth,
            &s->storage.control,&s->providers.mfi,s->verify_generation,now);
        if(take!=IAP2_OK) return stop(s,PROJECTION_RECEIVER_REASON_SETUP,take);
        s->state=PROJECTION_RECEIVER_AUTH;
        pair_crypto_wipe(&s->providers,sizeof(s->providers)); s->authorization=0;
    }
    if(r==IAP2_OK||r==PAIR_SETUP_COMPLETE||r==PROJECTION_CONTROL_SECURE||r==MFI_SAP_DRAINED) {
        if(s->session.state==PROJECTION_SESSION_HELD) {
            int released=projection_session_release(&s->session);
            if(released!=IAP2_OK) return stop(s,PROJECTION_RECEIVER_REASON_SESSION,released);
        }
        s->info_pending=0;
        pair_crypto_wipe(&s->key,sizeof(s->key)); pair_crypto_wipe(&s->child_key,sizeof(s->child_key));
    }
    return r;
}
int projection_receiver_eof(projection_receiver *s, uint64_t gen, uint64_t now) {
    int r=projection_receiver_check(s,gen,now);
    return r==IAP2_OK?stop(s,PROJECTION_RECEIVER_REASON_EOF,IAP2_END):r;
}
void projection_receiver_close(projection_receiver *s) {
    if(s&&s->generation) (void)stop(s,PROJECTION_RECEIVER_REASON_LOCAL,IAP2_END);
}
uint32_t projection_receiver_next_delay(const projection_receiver *s) {
    uint32_t delay,total;
    if(!s||!s->generation||s->state==PROJECTION_RECEIVER_DEAD) return UINT32_MAX;
    if(s->state==PROJECTION_RECEIVER_SETUP) return pair_setup_channel_next_delay(&s->setup);
    if(s->state==PROJECTION_RECEIVER_AUTH) {
        delay=projection_auth_next_delay(&s->auth);
        if(s->session.enabled&&s->session.count&&s->session.config.provider.next_delay) {
            total=s->session.config.provider.next_delay(s->session.config.provider.context,s->generation);
            if(total<delay) delay=total;
        }
        return delay;
    }
    delay=rtsp_channel_next_delay(&s->initial);
    if(s->info.profile) {
        total=s->now-s->started_at>=s->info.initial_ms?0:s->info.initial_ms-(uint32_t)(s->now-s->started_at);
        if(total<delay) delay=total;
    }
    return delay;
}
