/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_auth.h"
static void copy(void *d,const void *s,size_t n) { uint8_t *p=(uint8_t *)d;const uint8_t *q=(const uint8_t *)s;while(n--) *p++=*q++; }
static rtsp_slice literal(const char *p) { rtsp_slice s;s.data=(const uint8_t *)p;s.size=0;while(p[s.size]) ++s.size;return s; }
static int equals(rtsp_slice a,const char *b) { size_t i;for(i=0;i<a.size;++i) if(!b[i]||a.data[i]!=(uint8_t)b[i]) return 0;return !b[a.size]; }
void projection_auth_default_config(projection_auth_config *cfg) { if(cfg) { projection_control_default_config(&cfg->control);cfg->auth_hold_ms=5000; } }
int projection_auth_init(projection_auth *s,const pair_identity *id,pair_random_fn rng,void *rc,pair_lookup_fn lookup,void *lc,
                           const mfi_sap_provider *provider,const projection_auth_config *cfg,const projection_control_storage *storage,uint64_t gen,uint64_t now) {
    projection_auth tmp;int r;if(!s||!cfg||!storage||storage->response_capacity<MFI_SAP_REPLY_MAX+256u) return IAP2_ARGUMENT;
    pair_crypto_wipe(&tmp,sizeof(tmp));r=mfi_sap_init(&tmp.auth,rng,rc,provider,cfg->auth_hold_ms,gen,now);if(r!=IAP2_OK) goto done;
    r=projection_control_init(&tmp.control,id,rng,rc,lookup,lc,&cfg->control,storage,gen,now);if(r!=IAP2_OK) goto done;
    tmp.generation=gen;tmp.now=now;tmp.state=PROJECTION_AUTH_ACTIVE;copy(s,&tmp,sizeof(tmp));
done: pair_crypto_wipe(&tmp,sizeof(tmp));return r;
}
static int owner(const projection_auth *s,uint64_t gen) {
    if(!s||!s->generation||!gen) return IAP2_ARGUMENT;if(gen!=s->generation) return IAP2_INVALID;
    return s->state==PROJECTION_AUTH_DEAD?PROJECTION_AUTH_CLOSED:IAP2_OK;
}
static int keyed(const projection_auth *s,rtsp_channel_key key) {
    int r=owner(s,key.generation);if(r!=IAP2_OK) return r;return key.token&&key.token==s->control.key.token?IAP2_OK:IAP2_INVALID;
}
static int stop(projection_auth *s,enum projection_auth_reason reason,int error) {
    if(s->state!=PROJECTION_AUTH_DEAD) { projection_control_close(&s->control);mfi_sap_close(&s->auth);s->internal_reply=0;s->state=PROJECTION_AUTH_DEAD;s->reason=reason;s->last_error=error; }
    return PROJECTION_AUTH_CLOSED;
}
static int sync(projection_auth *s,int result) {
    s->now=s->control.now;
    return s->control.state==PROJECTION_CONTROL_DEAD?stop(s,PROJECTION_AUTH_REASON_CONTROL,s->control.last_error):result;
}
int projection_auth_check(projection_auth *s,uint64_t gen,uint64_t now) {
    int r=owner(s,gen);if(r!=IAP2_OK) return r;if(now<s->now) return IAP2_ARGUMENT;
    if(s->auth.state!=MFI_SAP_DONE) { r=mfi_sap_check(&s->auth,gen,now);if(r!=IAP2_OK) { s->now=now;return stop(s,PROJECTION_AUTH_REASON_MFI,s->auth.last_error); } }
    return sync(s,projection_control_check(&s->control,gen,now));
}
int projection_auth_feed(projection_auth *s,uint64_t gen,const uint8_t *p,size_t n,size_t *used,uint64_t now) {
    rtsp_message req;rtsp_channel_key key;rtsp_slice content;rtsp_header header;rtsp_response response;const uint8_t *body;size_t size;int r;
    if(used) *used=0;if(!used||(!p&&n)) return IAP2_ARGUMENT;r=projection_auth_check(s,gen,now);if(r!=IAP2_OK) return r;
    r=sync(s,projection_control_feed(&s->control,gen,p,n,used,now));if(r!=RTSP_CHANNEL_REQUEST) return r;
    r=projection_control_request(&s->control,&req,&key);if(r!=RTSP_CHANNEL_REQUEST) return stop(s,PROJECTION_AUTH_REASON_CONTROL,r);
    if(!equals(req.target,"/auth-setup")) return RTSP_CHANNEL_REQUEST;
    if(!equals(req.method,"POST")||rtsp_header_get(&req,literal("Content-Type"),&content)!=IAP2_OK||!equals(content,"application/octet-stream"))
        return stop(s,PROJECTION_AUTH_REASON_ROUTE,IAP2_UNSUPPORTED);
    if(s->auth.state!=MFI_SAP_WAIT) return stop(s,PROJECTION_AUTH_REASON_MFI,IAP2_INVALID);
    r=mfi_sap_request(&s->auth,gen,req.body.data,req.body.size,now);if(r!=MFI_SAP_RESPONSE) return stop(s,PROJECTION_AUTH_REASON_MFI,s->auth.last_error);
    r=mfi_sap_response(&s->auth,&body,&size);if(r!=MFI_SAP_RESPONSE) return stop(s,PROJECTION_AUTH_REASON_MFI,r);
    header.name=literal("Content-Type");header.value=literal("application/octet-stream");pair_crypto_wipe(&response,sizeof(response));
    response.status=200;response.headers=&header;response.header_count=1;response.body.data=body;response.body.size=size;
    r=projection_control_respond(&s->control,key,&response,now);if(r!=RTSP_CHANNEL_OUTPUT) return stop(s,PROJECTION_AUTH_REASON_CONTROL,r);
    s->internal_reply=1;return r;
}
int projection_auth_request(const projection_auth *s,rtsp_message *req,rtsp_channel_key *key) {
    if(req) pair_crypto_wipe(req,sizeof(*req));if(key) pair_crypto_wipe(key,sizeof(*key));if(!s||!s->generation||!req||!key) return IAP2_ARGUMENT;
    if(s->state==PROJECTION_AUTH_DEAD) return PROJECTION_AUTH_CLOSED;if(s->internal_reply) return IAP2_MORE;
    return projection_control_request(&s->control,req,key);
}
int projection_auth_respond(projection_auth *s,rtsp_channel_key key,const rtsp_response *response,uint64_t now) {
    int r=keyed(s,key);if(r!=IAP2_OK) return r;if(s->internal_reply) return RTSP_BUSY;
    return sync(s,projection_control_respond(&s->control,key,response,now));
}
int projection_auth_output(projection_auth *s,uint64_t gen,rtsp_slice *out,rtsp_channel_key *key,uint64_t now) {
    int r;if(out) pair_crypto_wipe(out,sizeof(*out));if(key) pair_crypto_wipe(key,sizeof(*key));if(!out||!key) return IAP2_ARGUMENT;
    r=projection_auth_check(s,gen,now);return r==IAP2_OK?sync(s,projection_control_output(&s->control,gen,out,key,now)):r;
}
int projection_auth_consume(projection_auth *s,rtsp_channel_key key,size_t n,uint64_t now) {
    int r=keyed(s,key);if(r!=IAP2_OK) return r;
    r=sync(s,projection_control_consume(&s->control,key,n,now));if(r!=RTSP_CHANNEL_OUTPUT&&r!=RTSP_CHANNEL_OUTPUT_DONE) return r;
    /* Child validates count/key/clock before changing time. Any applicable auth
     * deadline failure still closes/wipes all queues and suppresses completion. */
    if(s->internal_reply) { int check=projection_auth_check(s,key.generation,now);if(check!=IAP2_OK) return check; }return r;
}
int projection_auth_release(projection_auth *s,rtsp_channel_key key,uint64_t now) {
    int r=keyed(s,key);if(r!=IAP2_OK) return r;
    if(s->control.rtsp.state!=RTSP_CHANNEL_SENT||s->control.cipher.tx_size) return RTSP_BUSY;
    r=projection_auth_check(s,key.generation,now);if(r!=IAP2_OK) return r;
    r=sync(s,projection_control_release(&s->control,key,now));if(r!=IAP2_OK&&r!=PROJECTION_CONTROL_SECURE) return r;
    if(s->internal_reply) {
        r=mfi_sap_release(&s->auth,key.generation,now);if(r!=MFI_SAP_DRAINED) return stop(s,PROJECTION_AUTH_REASON_MFI,s->auth.last_error);
        s->internal_reply=0;
    }return r;
}
int projection_auth_eof(projection_auth *s,uint64_t gen,uint64_t now) { int r=projection_auth_check(s,gen,now);return r==IAP2_OK?stop(s,PROJECTION_AUTH_REASON_CONTROL,IAP2_END):r; }
void projection_auth_close(projection_auth *s) { if(s&&s->generation) (void)stop(s,PROJECTION_AUTH_REASON_LOCAL,IAP2_OK); }
uint32_t projection_auth_next_delay(const projection_auth *s) {
    uint32_t n,delay;if(!s||!s->generation||s->state==PROJECTION_AUTH_DEAD) return UINT32_MAX;
    delay=projection_control_next_delay(&s->control);n=mfi_sap_next_delay(&s->auth);return n<delay?n:delay;
}
