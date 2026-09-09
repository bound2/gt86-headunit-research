/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_control.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
static rtsp_slice literal(const char *p) { rtsp_slice s;s.data=(const uint8_t *)p;s.size=0;while(p[s.size]) ++s.size;return s; }
static int equals(rtsp_slice a,const char *b) { size_t i;for(i=0;i<a.size;++i) if(!b[i]||a.data[i]!=(uint8_t)b[i]) return 0;return !b[a.size]; }
void projection_control_default_config(projection_control_config *c) {
    if(c) { pair_verify_default_config(&c->pairing);rtsp_channel_default_config(&c->rtsp);control_cipher_default_config(&c->cipher); }
}
int projection_control_init(projection_control *c,const pair_identity *id,pair_random_fn rng,void *rc,pair_lookup_fn lookup,void *lc,
                             const projection_control_config *cfg,const projection_control_storage *s,uint64_t gen,uint64_t now) {
    projection_control fresh;int r;
    if(!c||!cfg||!s) return IAP2_ARGUMENT;
    pair_crypto_wipe(&fresh,sizeof(fresh));
    r=pair_verify_init(&fresh.pairing,id,rng,rc,lookup,lc,&cfg->pairing,gen,now);if(r!=IAP2_OK) goto done;
    r=rtsp_channel_init(&fresh.rtsp,&cfg->rtsp,s->request,s->request_capacity,s->response,s->response_capacity,gen,now);if(r!=IAP2_OK) goto done;
    r=control_cipher_init(&fresh.cipher,&cfg->cipher,s->cipher_rx,s->cipher_rx_capacity,s->plain,s->plain_capacity,s->cipher_tx,s->cipher_tx_capacity,gen,now);
    if(r!=IAP2_OK) goto done;
    fresh.generation=gen;fresh.now=now;fresh.state=PROJECTION_CONTROL_PAIRING;
    copy((uint8_t *)c,(const uint8_t *)&fresh,sizeof(fresh));
done:
    pair_crypto_wipe(&fresh,sizeof(fresh));return r;
}
static int stop(projection_control *c,enum projection_control_reason reason,int error) {
    if(c->state!=PROJECTION_CONTROL_DEAD) {
        pair_verify_close(&c->pairing);rtsp_channel_close(&c->rtsp);control_cipher_close(&c->cipher);
        pair_crypto_wipe(c->shared_secret,32);pair_crypto_wipe(c->controller_id,PAIR_ID_MAX);c->controller_id_size=0;
        pair_crypto_wipe(&c->key,sizeof(c->key));c->pair_token=0;c->state=PROJECTION_CONTROL_DEAD;c->reason=reason;c->last_error=error;
    }
    return PROJECTION_CONTROL_CLOSED;
}
static int owner(const projection_control *c,uint64_t gen) {
    if(!c||!c->generation||!gen) return IAP2_ARGUMENT;
    if(c->generation!=gen) return IAP2_INVALID;
    return c->state==PROJECTION_CONTROL_DEAD?PROJECTION_CONTROL_CLOSED:IAP2_OK;
}
static int keyed(const projection_control *c,rtsp_channel_key key) {
    int r=owner(c,key.generation);if(r!=IAP2_OK) return r;
    return key.token&&key.token==c->key.token?IAP2_OK:IAP2_INVALID;
}
int projection_control_check(projection_control *c,uint64_t gen,uint64_t now) {
    int r=owner(c,gen);if(r!=IAP2_OK) return r;
    if(now<c->now) return IAP2_ARGUMENT;c->now=now;
    if(c->state==PROJECTION_CONTROL_PAIRING) {
        r=pair_verify_check(&c->pairing,gen,now);if(r!=IAP2_OK) return stop(c,PROJECTION_CONTROL_REASON_PAIRING,r);
    }
    r=rtsp_channel_check(&c->rtsp,gen,now);if(r!=IAP2_OK) return stop(c,PROJECTION_CONTROL_REASON_FRAMING,r);
    r=control_cipher_check(&c->cipher,gen,now);if(r!=IAP2_OK) return stop(c,PROJECTION_CONTROL_REASON_CIPHER,r);
    return IAP2_OK;
}
static int dispatch(projection_control *c,uint64_t now) {
    rtsp_message req;rtsp_slice content;rtsp_header header;rtsp_response res;
    const uint8_t *body;size_t size;int r;
    r=rtsp_channel_request(&c->rtsp,&req,&c->key);if(r!=RTSP_CHANNEL_REQUEST) return stop(c,PROJECTION_CONTROL_REASON_FRAMING,r);
    if(c->state==PROJECTION_CONTROL_ENCRYPTED) return RTSP_CHANNEL_REQUEST;
    r=rtsp_header_get(&req,literal("Content-Type"),&content);
    if(!equals(req.method,"POST")||!equals(req.target,"/pair-verify")||r!=IAP2_OK||!equals(content,"application/pairing+tlv8"))
        return stop(c,PROJECTION_CONTROL_REASON_ROUTE,IAP2_UNSUPPORTED);
    r=pair_verify_request(&c->pairing,c->generation,req.body.data,req.body.size,now);
    if(r!=PAIR_VERIFY_RESPONSE) return stop(c,PROJECTION_CONTROL_REASON_PAIRING,r);
    r=pair_verify_response(&c->pairing,&body,&size,&c->pair_token);
    if(r!=PAIR_VERIFY_RESPONSE) return stop(c,PROJECTION_CONTROL_REASON_PAIRING,r);
    header.name=literal("Content-Type");header.value=literal("application/pairing+tlv8");
    pair_crypto_wipe(&res,sizeof(res));res.status=200;res.headers=&header;res.header_count=1;res.body.data=body;res.body.size=size;
    r=rtsp_channel_respond(&c->rtsp,c->key,&res,now);
    return r==RTSP_CHANNEL_OUTPUT?r:stop(c,PROJECTION_CONTROL_REASON_FRAMING,r);
}
int projection_control_feed(projection_control *c,uint64_t gen,const uint8_t *p,size_t n,size_t *used,uint64_t now) {
    int r;rtsp_slice plain;control_cipher_key key;size_t retired=0;
    if(used) *used=0;if(!used||(!p&&n)) return IAP2_ARGUMENT;
    r=projection_control_check(c,gen,now);if(r!=IAP2_OK) return r;
    if(c->rtsp.state!=RTSP_CHANNEL_RECEIVING) return RTSP_BUSY;
    if(c->state==PROJECTION_CONTROL_PAIRING) r=rtsp_channel_feed(&c->rtsp,gen,p,n,used,now);
    else {
        if(!c->cipher.held) {
            r=control_cipher_feed(&c->cipher,gen,p,n,used,now);
            if(r==IAP2_MORE) return r;
            if(r!=CONTROL_CIPHER_FRAME) return stop(c,PROJECTION_CONTROL_REASON_CIPHER,r);
        }
        r=control_cipher_plain(&c->cipher,&plain,&key);
        if(r!=CONTROL_CIPHER_FRAME) return stop(c,PROJECTION_CONTROL_REASON_CIPHER,r);
        r=rtsp_channel_feed(&c->rtsp,gen,plain.data,plain.size,&retired,now);
        if(r==IAP2_MORE||r==RTSP_CHANNEL_REQUEST) {
            int consumed=control_cipher_consume_plain(&c->cipher,key,retired,now);
            if(consumed!=IAP2_OK&&consumed!=CONTROL_CIPHER_FRAME) return stop(c,PROJECTION_CONTROL_REASON_CIPHER,consumed);
        }
    }
    if(r==RTSP_CHANNEL_REQUEST) return dispatch(c,now);
    return r==IAP2_MORE?r:stop(c,PROJECTION_CONTROL_REASON_FRAMING,r);
}
int projection_control_request(const projection_control *c,rtsp_message *req,rtsp_channel_key *key) {
    if(req) pair_crypto_wipe(req,sizeof(*req));if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!c||!c->generation||!req||!key) return IAP2_ARGUMENT;
    if(c->state==PROJECTION_CONTROL_DEAD) return PROJECTION_CONTROL_CLOSED;
    return c->state==PROJECTION_CONTROL_ENCRYPTED?rtsp_channel_request(&c->rtsp,req,key):IAP2_MORE;
}
int projection_control_respond(projection_control *c,rtsp_channel_key key,const rtsp_response *res,uint64_t now) {
    rtsp_message req;size_t n;int r=keyed(c,key);if(r!=IAP2_OK) return r;
    if(c->state!=PROJECTION_CONTROL_ENCRYPTED||c->rtsp.state!=RTSP_CHANNEL_HELD) return RTSP_BUSY;
    if(!res||res->status<200) return IAP2_ARGUMENT;
    r=rtsp_stream_message(&c->rtsp.input,&req);if(r!=IAP2_OK) return r;
    r=rtsp_response_encode(&req,res,0,0,&n);if(r!=IAP2_OK) return r;
    if(n>c->rtsp.tx_capacity) return IAP2_NO_SPACE;
    r=projection_control_check(c,key.generation,now);if(r!=IAP2_OK) return r;
    r=rtsp_channel_respond(&c->rtsp,key,res,now);
    return r==RTSP_CHANNEL_OUTPUT?r:stop(c,PROJECTION_CONTROL_REASON_FRAMING,r);
}
int projection_control_output(projection_control *c,uint64_t gen,rtsp_slice *out,rtsp_channel_key *key,uint64_t now) {
    rtsp_slice plain;control_cipher_key ck;size_t n;int r;
    if(out) pair_crypto_wipe(out,sizeof(*out));if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!out||!key) return IAP2_ARGUMENT;
    r=projection_control_check(c,gen,now);if(r!=IAP2_OK) return r;
    if(c->rtsp.state!=RTSP_CHANNEL_SENDING&&c->rtsp.state!=RTSP_CHANNEL_SENT) return RTSP_BUSY;
    if(c->state==PROJECTION_CONTROL_PAIRING) {
        r=rtsp_channel_output(&c->rtsp,c->key,out,now);*key=c->key;return r;
    }
    if(!c->cipher.tx_size&&c->rtsp.state==RTSP_CHANNEL_SENDING) {
        r=rtsp_channel_output(&c->rtsp,c->key,&plain,now);
        if(r!=RTSP_CHANNEL_OUTPUT) return stop(c,PROJECTION_CONTROL_REASON_FRAMING,r);
        n=plain.size;if(n>c->cipher.config.payload_limit) n=c->cipher.config.payload_limit;
        r=control_cipher_queue(&c->cipher,gen,plain.data,n,now);
        if(r!=CONTROL_CIPHER_OUTPUT) return stop(c,PROJECTION_CONTROL_REASON_CIPHER,r);
        r=rtsp_channel_consume(&c->rtsp,c->key,n,now);
        if(r!=RTSP_CHANNEL_OUTPUT&&r!=RTSP_CHANNEL_OUTPUT_DONE) return stop(c,PROJECTION_CONTROL_REASON_FRAMING,r);
    }
    *key=c->key;
    if(!c->cipher.tx_size) return RTSP_CHANNEL_OUTPUT_DONE;
    r=control_cipher_output(&c->cipher,out,&ck);
    return r==CONTROL_CIPHER_OUTPUT?RTSP_CHANNEL_OUTPUT:stop(c,PROJECTION_CONTROL_REASON_CIPHER,r);
}
int projection_control_consume(projection_control *c,rtsp_channel_key key,size_t n,uint64_t now) {
    rtsp_slice out;control_cipher_key ck={0,0};int r=keyed(c,key);if(r!=IAP2_OK) return r;
    if(c->state==PROJECTION_CONTROL_PAIRING) {
        if(c->rtsp.state!=RTSP_CHANNEL_SENDING) return RTSP_BUSY;
        if(!n||n>c->rtsp.tx_size-c->rtsp.tx_offset) return IAP2_ARGUMENT;
    } else {
        r=control_cipher_output(&c->cipher,&out,&ck);if(r!=CONTROL_CIPHER_OUTPUT) return RTSP_BUSY;
        if(!n||n>out.size) return IAP2_ARGUMENT;
    }
    r=projection_control_check(c,key.generation,now);if(r!=IAP2_OK) return r;
    if(c->state==PROJECTION_CONTROL_PAIRING) return rtsp_channel_consume(&c->rtsp,key,n,now);
    r=control_cipher_consume_output(&c->cipher,ck,n,now);
    if(r!=IAP2_OK&&r!=CONTROL_CIPHER_OUTPUT) return stop(c,PROJECTION_CONTROL_REASON_CIPHER,r);
    return !c->cipher.tx_size&&c->rtsp.state==RTSP_CHANNEL_SENT?RTSP_CHANNEL_OUTPUT_DONE:RTSP_CHANNEL_OUTPUT;
}
int projection_control_release(projection_control *c,rtsp_channel_key key,uint64_t now) {
    pair_session_keys keys;int secure=0,r=keyed(c,key);if(r!=IAP2_OK) return r;
    if(c->rtsp.state!=RTSP_CHANNEL_SENT||c->cipher.tx_size) return RTSP_BUSY;
    r=projection_control_check(c,key.generation,now);if(r!=IAP2_OK) return r;
    if(c->state==PROJECTION_CONTROL_PAIRING) {
        r=pair_verify_release(&c->pairing,key.generation,c->pair_token,now);
        if(r==PAIR_VERIFY_KEYS) {
            pair_crypto_wipe(&keys,sizeof(keys));
            r=pair_verify_take(&c->pairing,key.generation,c->pair_token,&keys,now);
            if(r==IAP2_OK) r=control_cipher_start(&c->cipher,key.generation,keys.read_key,keys.write_key,now);
            if(r==IAP2_OK) {
                copy(c->shared_secret,keys.shared_secret,32);copy(c->controller_id,keys.controller_id,keys.controller_id_size);
                c->controller_id_size=keys.controller_id_size;secure=1;
            }
            pair_crypto_wipe(&keys,sizeof(keys));
        }
        if(r!=IAP2_OK) return stop(c,PROJECTION_CONTROL_REASON_PAIRING,r);
    }
    r=rtsp_channel_release(&c->rtsp,key,now);if(r!=IAP2_OK) return stop(c,PROJECTION_CONTROL_REASON_FRAMING,r);
    pair_crypto_wipe(&c->key,sizeof(c->key));c->pair_token=0;
    if(secure) c->state=PROJECTION_CONTROL_ENCRYPTED;
    return secure?PROJECTION_CONTROL_SECURE:IAP2_OK;
}
int projection_control_eof(projection_control *c,uint64_t gen,uint64_t now) {
    int r=projection_control_check(c,gen,now);return r==IAP2_OK?stop(c,PROJECTION_CONTROL_REASON_EOF,IAP2_END):r;
}
void projection_control_close(projection_control *c) { if(c&&c->generation) (void)stop(c,PROJECTION_CONTROL_REASON_LOCAL,IAP2_OK); }
uint32_t projection_control_next_delay(const projection_control *c) {
    uint32_t delay,n;if(!c||!c->generation||c->state==PROJECTION_CONTROL_DEAD) return UINT32_MAX;
    delay=rtsp_channel_next_delay(&c->rtsp);n=control_cipher_next_delay(&c->cipher);if(n<delay) delay=n;
    if(c->state==PROJECTION_CONTROL_PAIRING) { n=pair_verify_next_delay(&c->pairing);if(n<delay) delay=n; }
    return delay;
}
