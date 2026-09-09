/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_setup_channel.h"
#include "projection_auth.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
static rtsp_slice literal(const char *p) { rtsp_slice s;s.data=(const uint8_t *)p;s.size=0;while(p[s.size]) ++s.size;return s; }
static int equals(rtsp_slice a,const char *b) { size_t i;for(i=0;i<a.size;++i) if(!b[i]||a.data[i]!=(uint8_t)b[i]) return 0;return !b[a.size]; }
void pair_setup_channel_default_config(pair_setup_channel_config *c) {
    if(c) { pair_setup_default_config(&c->setup);rtsp_channel_default_config(&c->rtsp);c->rtsp.reply_ms=30000;c->rtsp.output_ms=10000; }
}
int pair_setup_channel_init(pair_setup_channel *c,const pair_identity *id,pair_random_fn random,void *rc,pair_setup_commit_fn commit,void *cc,
    pair_lookup_fn lookup,void *lc,const pair_setup_channel_config *cfg,uint8_t *rx,size_t nr,uint8_t *tx,size_t nt,uint64_t gen,uint64_t now) {
    pair_setup_channel fresh;int r;if(!c||!cfg||!lookup) return IAP2_ARGUMENT;pair_crypto_wipe(&fresh,sizeof(fresh));
    r=pair_setup_init(&fresh.setup,id,random,rc,commit,cc,&cfg->setup,gen,now);if(r!=IAP2_OK) goto done;
    r=rtsp_channel_init(&fresh.rtsp,&cfg->rtsp,rx,nr,tx,nt,gen,now);if(r!=IAP2_OK) goto done;
    fresh.identity=id;fresh.random=random;fresh.random_context=rc;fresh.lookup=lookup;fresh.lookup_context=lc;
    fresh.generation=gen;fresh.now=now;fresh.state=PAIR_SETUP_CHANNEL_ACTIVE;copy((uint8_t *)c,(const uint8_t *)&fresh,sizeof(fresh));
done:
    pair_crypto_wipe(&fresh,sizeof(fresh));return r;
}
static void providers_clear(pair_setup_channel *c) { c->identity=0;c->random=0;c->random_context=0;c->lookup=0;c->lookup_context=0;c->pair_token=0;pair_crypto_wipe(&c->key,sizeof(c->key)); }
static int stop(pair_setup_channel *c,enum pair_setup_channel_reason reason,int error) {
    if(c->state!=PAIR_SETUP_CHANNEL_DEAD&&c->state!=PAIR_SETUP_CHANNEL_DETACHED) {
        pair_setup_close(&c->setup);rtsp_channel_close(&c->rtsp);providers_clear(c);c->state=PAIR_SETUP_CHANNEL_DEAD;c->reason=reason;c->last_error=error;
    }return PAIR_SETUP_CLOSED;
}
static int owner(const pair_setup_channel *c,uint64_t gen) {
    if(!c||!c->generation||!gen) return IAP2_ARGUMENT;if(gen!=c->generation) return IAP2_INVALID;
    return c->state==PAIR_SETUP_CHANNEL_DEAD||c->state==PAIR_SETUP_CHANNEL_DETACHED?PAIR_SETUP_CLOSED:IAP2_OK;
}
static int keyed(const pair_setup_channel *c,rtsp_channel_key key) { int r=owner(c,key.generation);if(r!=IAP2_OK) return r;return key.token&&key.token==c->key.token?IAP2_OK:IAP2_INVALID; }
int pair_setup_channel_check(pair_setup_channel *c,uint64_t gen,uint64_t now) {
    int r=owner(c,gen);if(r!=IAP2_OK) return r;if(now<c->now) return IAP2_ARGUMENT;c->now=now;
    if(c->state==PAIR_SETUP_CHANNEL_ACTIVE) { r=pair_setup_check(&c->setup,gen,now);if(r!=IAP2_OK) return stop(c,PAIR_SETUP_CHANNEL_REASON_SETUP,r); }
    r=rtsp_channel_check(&c->rtsp,gen,now);return r==IAP2_OK?r:stop(c,PAIR_SETUP_CHANNEL_REASON_RTSP,r);
}
int pair_setup_channel_authorize(pair_setup_channel *c,uint64_t gen,uint64_t authorization,uint64_t now) {
    int r=owner(c,gen);if(r!=IAP2_OK) return r;if(!authorization) return IAP2_ARGUMENT;
    if(c->setup.state!=PAIR_SETUP_WAIT_AUTH) return PAIR_SETUP_BUSY;
    r=pair_setup_channel_check(c,gen,now);if(r!=IAP2_OK) return r;return pair_setup_authorize(&c->setup,gen,authorization,now);
}
static int respond(pair_setup_channel *c,uint64_t now) {
    const uint8_t *body;size_t n;rtsp_header h;rtsp_response res;int r=pair_setup_response(&c->setup,&body,&n,&c->pair_token);
    if(r!=PAIR_SETUP_RESPONSE) return stop(c,PAIR_SETUP_CHANNEL_REASON_SETUP,r);
    h.name=literal("Content-Type");h.value=literal("application/pairing+tlv8");pair_crypto_wipe(&res,sizeof(res));
    res.status=200;res.headers=&h;res.header_count=1;res.body.data=body;res.body.size=n;
    r=rtsp_channel_respond(&c->rtsp,c->key,&res,now);return r==RTSP_CHANNEL_OUTPUT?r:stop(c,PAIR_SETUP_CHANNEL_REASON_RTSP,r);
}
int pair_setup_channel_feed(pair_setup_channel *c,uint64_t gen,const uint8_t *p,size_t n,size_t *used,uint64_t now) {
    rtsp_message req;rtsp_slice type;int r;if(used) *used=0;if(!used||(!p&&n)) return IAP2_ARGUMENT;
    r=pair_setup_channel_check(c,gen,now);if(r!=IAP2_OK) return r;
    if(c->state!=PAIR_SETUP_CHANNEL_ACTIVE||c->setup.state==PAIR_SETUP_WAIT_AUTH||c->rtsp.state!=RTSP_CHANNEL_RECEIVING) return PAIR_SETUP_BUSY;
    r=rtsp_channel_feed(&c->rtsp,gen,p,n,used,now);if(r==IAP2_MORE) return r;
    if(r!=RTSP_CHANNEL_REQUEST) return stop(c,PAIR_SETUP_CHANNEL_REASON_RTSP,r);
    r=rtsp_channel_request(&c->rtsp,&req,&c->key);if(r!=RTSP_CHANNEL_REQUEST) return stop(c,PAIR_SETUP_CHANNEL_REASON_RTSP,r);
    r=rtsp_header_get(&req,literal("Content-Type"),&type);
    if(!equals(req.method,"POST")||!equals(req.target,"/pair-setup")||r!=IAP2_OK||!equals(type,"application/pairing+tlv8")) return stop(c,PAIR_SETUP_CHANNEL_REASON_ROUTE,IAP2_UNSUPPORTED);
    r=pair_setup_request(&c->setup,gen,req.body.data,req.body.size,now);
    if(r==PAIR_SETUP_APPROVAL) { c->pair_token=c->setup.token;return r; }
    return r==PAIR_SETUP_RESPONSE?respond(c,now):stop(c,PAIR_SETUP_CHANNEL_REASON_SETUP,r);
}
int pair_setup_channel_pending(const pair_setup_channel *c,pair_setup_candidate *candidate,rtsp_channel_key *key) {
    uint64_t token;int r;if(candidate) pair_crypto_wipe(candidate,sizeof(*candidate));if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!c||!c->generation||!candidate||!key) return IAP2_ARGUMENT;
    if(c->state==PAIR_SETUP_CHANNEL_DEAD||c->state==PAIR_SETUP_CHANNEL_DETACHED) return PAIR_SETUP_CLOSED;
    if(c->state==PAIR_SETUP_CHANNEL_DRAINED) return IAP2_MORE;
    r=pair_setup_pending(&c->setup,candidate,&token);if(r==PAIR_SETUP_APPROVAL) *key=c->key;return r;
}
int pair_setup_channel_decide(pair_setup_channel *c,rtsp_channel_key key,int approve,uint64_t now) {
    int r=keyed(c,key);if(r!=IAP2_OK) return r;if(approve!=0&&approve!=1) return IAP2_ARGUMENT;
    if(c->setup.state!=PAIR_SETUP_PENDING) return PAIR_SETUP_BUSY;
    r=pair_setup_channel_check(c,key.generation,now);if(r!=IAP2_OK) return r;
    r=pair_setup_decide(&c->setup,key.generation,c->pair_token,approve,now);
    return r==PAIR_SETUP_RESPONSE?respond(c,now):stop(c,PAIR_SETUP_CHANNEL_REASON_SETUP,r);
}
int pair_setup_channel_output(pair_setup_channel *c,uint64_t gen,rtsp_slice *out,rtsp_channel_key *key,uint64_t now) {
    int r;if(out) pair_crypto_wipe(out,sizeof(*out));if(key) pair_crypto_wipe(key,sizeof(*key));if(!out||!key) return IAP2_ARGUMENT;
    r=pair_setup_channel_check(c,gen,now);if(r!=IAP2_OK) return r;
    if(c->state!=PAIR_SETUP_CHANNEL_ACTIVE||(c->rtsp.state!=RTSP_CHANNEL_SENDING&&c->rtsp.state!=RTSP_CHANNEL_SENT)) return PAIR_SETUP_BUSY;
    r=rtsp_channel_output(&c->rtsp,c->key,out,now);*key=c->key;return r;
}
int pair_setup_channel_consume(pair_setup_channel *c,rtsp_channel_key key,size_t n,uint64_t now) {
    int r=keyed(c,key);if(r!=IAP2_OK) return r;if(c->rtsp.state!=RTSP_CHANNEL_SENDING) return PAIR_SETUP_BUSY;
    if(!n||n>c->rtsp.tx_size-c->rtsp.tx_offset) return IAP2_ARGUMENT;
    r=pair_setup_channel_check(c,key.generation,now);if(r!=IAP2_OK) return r;return rtsp_channel_consume(&c->rtsp,key,n,now);
}
int pair_setup_channel_release(pair_setup_channel *c,rtsp_channel_key key,uint64_t now) {
    int r,complete;r=keyed(c,key);if(r!=IAP2_OK) return r;if(c->rtsp.state!=RTSP_CHANNEL_SENT) return PAIR_SETUP_BUSY;
    r=pair_setup_channel_check(c,key.generation,now);if(r!=IAP2_OK) return r;
    r=pair_setup_release(&c->setup,key.generation,c->pair_token,now);complete=r==PAIR_SETUP_COMPLETE;
    if(r!=IAP2_OK&&!complete) return stop(c,PAIR_SETUP_CHANNEL_REASON_SETUP,r);
    r=rtsp_channel_release(&c->rtsp,key,now);if(r!=IAP2_OK) return stop(c,PAIR_SETUP_CHANNEL_REASON_RTSP,r);
    c->pair_token=0;if(complete) { c->state=PAIR_SETUP_CHANNEL_DRAINED;return PAIR_SETUP_COMPLETE; }
    pair_crypto_wipe(&c->key,sizeof(c->key));return IAP2_OK;
}
int pair_setup_channel_take(pair_setup_channel *c,rtsp_channel_key key,projection_control *out,const projection_control_config *cfg,
                             const projection_control_storage *storage,uint64_t gen,uint64_t now) {
    projection_control fresh;int r=keyed(c,key);if(r!=IAP2_OK) return r;
    if(!out||!cfg||!storage||!gen||gen==c->generation) return IAP2_ARGUMENT;
    if(c->state!=PAIR_SETUP_CHANNEL_DRAINED) return PAIR_SETUP_BUSY;
    if(now<c->now) return IAP2_ARGUMENT;
    r=projection_control_init(&fresh,c->identity,c->random,c->random_context,c->lookup,c->lookup_context,cfg,storage,gen,now);
    if(r!=IAP2_OK) { pair_crypto_wipe(&fresh,sizeof(fresh));return r; }
    r=pair_setup_channel_check(c,key.generation,now);
    if(r==IAP2_OK) copy((uint8_t *)out,(const uint8_t *)&fresh,sizeof(fresh));
    pair_crypto_wipe(&fresh,sizeof(fresh));if(r!=IAP2_OK) return r;
    /* Source queues are empty; no downstream call or application can run until
     * this synchronous transfer returns. Future source close is inert. */
    rtsp_channel_close(&c->rtsp);providers_clear(c);c->state=PAIR_SETUP_CHANNEL_DETACHED;return IAP2_OK;
}
int pair_setup_channel_eof(pair_setup_channel *c,uint64_t gen,uint64_t now) {
    int r=pair_setup_channel_check(c,gen,now);return r==IAP2_OK?stop(c,PAIR_SETUP_CHANNEL_REASON_EOF,IAP2_END):r;
}
int pair_setup_channel_take_auth(pair_setup_channel *c,rtsp_channel_key key,projection_auth *out,const projection_auth_config *cfg,
                                  const projection_control_storage *storage,const mfi_sap_provider *provider,uint64_t gen,uint64_t now) {
    projection_auth fresh;int r=keyed(c,key);if(r!=IAP2_OK) return r;
    if(!out||!cfg||!storage||!provider||!gen||gen==c->generation) return IAP2_ARGUMENT;
    if(c->state!=PAIR_SETUP_CHANNEL_DRAINED) return PAIR_SETUP_BUSY;if(now<c->now) return IAP2_ARGUMENT;
    r=projection_auth_init(&fresh,c->identity,c->random,c->random_context,c->lookup,c->lookup_context,provider,cfg,storage,gen,now);
    if(r!=IAP2_OK) { pair_crypto_wipe(&fresh,sizeof(fresh));return r; }
    r=pair_setup_channel_check(c,key.generation,now);if(r==IAP2_OK) copy((uint8_t *)out,(const uint8_t *)&fresh,sizeof(fresh));
    pair_crypto_wipe(&fresh,sizeof(fresh));if(r!=IAP2_OK) return r;
    rtsp_channel_close(&c->rtsp);providers_clear(c);c->state=PAIR_SETUP_CHANNEL_DETACHED;return IAP2_OK;
}
void pair_setup_channel_close(pair_setup_channel *c) { if(c&&c->generation) (void)stop(c,PAIR_SETUP_CHANNEL_REASON_LOCAL,IAP2_OK); }
uint32_t pair_setup_channel_next_delay(const pair_setup_channel *c) {
    uint32_t n,delay;if(!c||!c->generation||c->state==PAIR_SETUP_CHANNEL_DEAD||c->state==PAIR_SETUP_CHANNEL_DETACHED) return UINT32_MAX;
    delay=rtsp_channel_next_delay(&c->rtsp);if(c->state==PAIR_SETUP_CHANNEL_ACTIVE) { n=pair_setup_next_delay(&c->setup);if(n<delay) delay=n; }return delay;
}
