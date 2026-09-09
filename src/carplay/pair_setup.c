/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_setup.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
static size_t length(const char *s) { size_t n=0;while(s[n]) ++n;return n; }
static int ms(uint32_t n) { return n&&n<=60000; }
static int identifier(const uint8_t *p,size_t n) { size_t i;if(!p||!n||n>PAIR_ID_MAX) return 0;for(i=0;i<n;++i) if(p[i]<33||p[i]>126) return 0;return 1; }
void pair_setup_default_config(pair_setup_config *c) { if(c) { c->exchange_ms=60000;c->hold_ms=10000;c->approval_ms=30000; } }
int pair_setup_init(pair_setup *s,const pair_identity *id,pair_random_fn random,void *rc,pair_setup_commit_fn commit,void *cc,
                      const pair_setup_config *cfg,uint64_t gen,uint64_t now) {
    if(!s||!id||!id->ready||!identifier(id->identifier,id->identifier_size)||!random||!commit||!cfg||!gen||
       !ms(cfg->exchange_ms)||!ms(cfg->hold_ms)||!ms(cfg->approval_ms)) return IAP2_ARGUMENT;
    pair_crypto_wipe(s,sizeof(*s));pair_srp_init(&s->srp);s->identity=id;s->random=random;s->random_context=rc;s->commit=commit;s->commit_context=cc;
    s->config=*cfg;s->generation=gen;s->now=s->started_at=now;s->state=PAIR_SETUP_WAIT_AUTH;return IAP2_OK;
}
static void clear(pair_setup *s) {
    pair_srp_clear(&s->srp);pair_crypto_wipe(s->session_key,64);pair_crypto_wipe(s->output,sizeof(s->output));
    pair_crypto_wipe(&s->candidate,sizeof(s->candidate));s->output_size=0;s->token=0;
    s->identity=0;s->random=0;s->random_context=0;s->commit=0;s->commit_context=0;
}
static int stop(pair_setup *s,enum pair_setup_reason reason,int error) {
    if(s->state!=PAIR_SETUP_DEAD&&s->state!=PAIR_SETUP_DONE) { clear(s);s->state=PAIR_SETUP_DEAD;s->reason=reason;s->last_error=error; }
    return PAIR_SETUP_CLOSED;
}
static int owner(const pair_setup *s,uint64_t gen) {
    if(!s||!s->generation||!gen) return IAP2_ARGUMENT;if(gen!=s->generation) return IAP2_INVALID;
    return s->state==PAIR_SETUP_DEAD||s->state==PAIR_SETUP_DONE?PAIR_SETUP_CLOSED:IAP2_OK;
}
static int held(const pair_setup *s) { return s->state==PAIR_SETUP_M2_HELD||s->state==PAIR_SETUP_M4_HELD||s->state==PAIR_SETUP_M6_HELD; }
int pair_setup_check(pair_setup *s,uint64_t gen,uint64_t now) {
    int r=owner(s,gen);if(r!=IAP2_OK) return r;if(now<s->now) return IAP2_ARGUMENT;s->now=now;
    if(now-s->started_at>=s->config.exchange_ms||(held(s)&&now-s->held_at>=s->config.hold_ms)||
       (s->state==PAIR_SETUP_PENDING&&now-s->held_at>=s->config.approval_ms)) return stop(s,PAIR_SETUP_REASON_DEADLINE,IAP2_MORE);
    return IAP2_OK;
}
int pair_setup_authorize(pair_setup *s,uint64_t gen,uint64_t authorization,uint64_t now) {
    int r=owner(s,gen);if(r!=IAP2_OK) return r;if(!authorization) return IAP2_ARGUMENT;
    if(s->state!=PAIR_SETUP_WAIT_AUTH) return PAIR_SETUP_BUSY;
    r=pair_setup_check(s,gen,now);if(r!=IAP2_OK) return r;s->authorization=authorization;s->state=PAIR_SETUP_M1;return IAP2_OK;
}
static int dictionary(const uint8_t *body,size_t n,pair_tlv *fields,uint8_t *arena,size_t *count) {
    size_t i,j,off=0;int r;
    while(off<n) { if(n-off<2||body[off+1]>n-off-2||body[off]==255) return IAP2_INVALID;off+=(size_t)body[off+1]+2; }
    r=pair_tlv_decode(body,n,fields,PAIR_TLV_MAX_ITEMS,arena,PAIR_SETUP_MAX_BODY,count);if(r!=IAP2_OK) return r;
    for(i=0;i<*count;++i) for(j=0;j<i;++j) if(fields[i].type==fields[j].type) return IAP2_INVALID;return IAP2_OK;
}
static const pair_tlv *get(const pair_tlv *f,size_t n,uint8_t type) { size_t i;for(i=0;i<n;++i) if(f[i].type==type) return f+i;return 0; }
static int exact(const pair_tlv *f,size_t n) { return f&&f->size==n; }
static int derive(const uint8_t k[64],const char *salt,const char *info,uint8_t out[32]) {
    return pair_hkdf_sha512(k,64,(const uint8_t *)salt,length(salt),(const uint8_t *)info,length(info),out,32);
}
static int m2(pair_setup *s,const pair_tlv *f,size_t count) {
    const pair_tlv *method=get(f,count,0),*flags=get(f,count,19);pair_tlv out[3];uint8_t state=2;int r;
    if(!exact(method,1)||method->data[0]!=0||(flags&&(!exact(flags,1)||flags->data[0]!=0))) return IAP2_UNSUPPORTED;
    r=pair_srp_start(&s->srp,s->random,s->random_context);if(r!=IAP2_OK) return r;
    out[0].type=6;out[0].data=&state;out[0].size=1;out[1].type=3;out[1].data=s->srp.public_key;out[1].size=384;
    out[2].type=2;out[2].data=s->srp.salt;out[2].size=16;
    return pair_tlv_encode(out,3,s->output,sizeof(s->output),&s->output_size);
}
static int m4(pair_setup *s,const pair_tlv *f,size_t count) {
    const pair_tlv *a=get(f,count,3),*proof=get(f,count,4);uint8_t server[64]={0},state=4;pair_tlv out[2];int r;
    if(!exact(a,384)||!exact(proof,64)) return IAP2_INVALID;
    r=pair_srp_verify(&s->srp,a->data,proof->data,s->session_key,server);
    if(r==IAP2_OK) {
        out[0].type=6;out[0].data=&state;out[0].size=1;out[1].type=4;out[1].data=server;out[1].size=64;
        r=pair_tlv_encode(out,2,s->output,sizeof(s->output),&s->output_size);
    }
    pair_crypto_wipe(server,64);return r;
}
static int m6(pair_setup *s,const pair_tlv *f,size_t count) {
    const pair_tlv *enc=get(f,count,5),*id,*pk,*sig;pair_tlv fields[PAIR_TLV_MAX_ITEMS],out[3];
    uint8_t plain[PAIR_SETUP_MAX_BODY],arena[PAIR_SETUP_MAX_BODY],key[32]={0},sign_key[32]={0},signed_data[128]={0};
    uint8_t signature[64]={0},sub[192]={0},sealed[208]={0},nonce[12]={0,0,0,0,'P','S','-','M','s','g','0','5'},state=6;
    size_t n=0,used=0,sealed_size=0;int r;
    if(!enc||enc->size<16) return IAP2_INVALID;
    r=derive(s->session_key,"Pair-Setup-Encrypt-Salt","Pair-Setup-Encrypt-Info",key);if(r!=IAP2_OK) goto done;
    r=pair_aead_open(key,nonce,0,0,enc->data,enc->size,plain,sizeof(plain),&n);if(r!=IAP2_OK) goto done;
    r=dictionary(plain,n,fields,arena,&used);if(r!=IAP2_OK) goto done;
    id=get(fields,used,1);pk=get(fields,used,3);sig=get(fields,used,10);
    if(!id||!identifier(id->data,id->size)||!exact(pk,32)||!exact(sig,64)) { r=IAP2_INVALID;goto done; }
    r=derive(s->session_key,"Pair-Setup-Controller-Sign-Salt","Pair-Setup-Controller-Sign-Info",sign_key);if(r!=IAP2_OK) goto done;
    copy(signed_data,sign_key,32);copy(signed_data+32,id->data,id->size);copy(signed_data+32+id->size,pk->data,32);
    r=pair_ed25519_verify(pk->data,signed_data,64+id->size,sig->data);if(r!=IAP2_OK) goto done;
    copy(s->candidate.identifier,id->data,id->size);s->candidate.identifier_size=id->size;copy(s->candidate.public_key,pk->data,32);
    r=derive(s->session_key,"Pair-Setup-Accessory-Sign-Salt","Pair-Setup-Accessory-Sign-Info",sign_key);if(r!=IAP2_OK) goto done;
    copy(signed_data,sign_key,32);copy(signed_data+32,s->identity->identifier,s->identity->identifier_size);
    copy(signed_data+32+s->identity->identifier_size,s->identity->public_key,32);
    r=pair_identity_sign(s->identity,signed_data,64+s->identity->identifier_size,signature);if(r!=IAP2_OK) goto done;
    out[0].type=1;out[0].data=s->identity->identifier;out[0].size=s->identity->identifier_size;
    out[1].type=3;out[1].data=s->identity->public_key;out[1].size=32;out[2].type=10;out[2].data=signature;out[2].size=64;
    r=pair_tlv_encode(out,3,sub,sizeof(sub),&n);if(r!=IAP2_OK) goto done;nonce[11]='6';
    r=pair_aead_seal(key,nonce,0,0,sub,n,sealed,sizeof(sealed),&sealed_size);if(r!=IAP2_OK) goto done;
    out[0].type=6;out[0].data=&state;out[0].size=1;out[1].type=5;out[1].data=sealed;out[1].size=sealed_size;
    r=pair_tlv_encode(out,2,s->output,sizeof(s->output),&s->output_size);
done:
    pair_crypto_wipe(plain,sizeof(plain));pair_crypto_wipe(arena,sizeof(arena));pair_crypto_wipe(fields,sizeof(fields));
    pair_crypto_wipe(key,32);pair_crypto_wipe(sign_key,32);pair_crypto_wipe(signed_data,sizeof(signed_data));pair_crypto_wipe(signature,64);
    pair_crypto_wipe(sub,sizeof(sub));pair_crypto_wipe(sealed,sizeof(sealed));pair_crypto_wipe(nonce,12);pair_crypto_wipe(s->session_key,64);return r;
}
int pair_setup_request(pair_setup *s,uint64_t gen,const uint8_t *body,size_t n,uint64_t now) {
    pair_tlv fields[PAIR_TLV_MAX_ITEMS];uint8_t arena[PAIR_SETUP_MAX_BODY];const pair_tlv *state;size_t count=0;uint8_t expected;int r;
    if(!body&&n) return IAP2_ARGUMENT;r=pair_setup_check(s,gen,now);if(r!=IAP2_OK) return r;
    if(s->state!=PAIR_SETUP_M1&&s->state!=PAIR_SETUP_M3&&s->state!=PAIR_SETUP_M5) return PAIR_SETUP_BUSY;
    if(n>PAIR_SETUP_MAX_BODY) return stop(s,PAIR_SETUP_REASON_PROTOCOL,IAP2_NO_SPACE);
    r=dictionary(body,n,fields,arena,&count);state=r==IAP2_OK?get(fields,count,6):0;
    expected=(uint8_t)(s->state==PAIR_SETUP_M1?1:(s->state==PAIR_SETUP_M3?3:5));
    if(!exact(state,1)||state->data[0]!=expected) r=IAP2_INVALID;
    else if(expected==1) r=m2(s,fields,count);else if(expected==3) r=m4(s,fields,count);else r=m6(s,fields,count);
    pair_crypto_wipe(arena,sizeof(arena));pair_crypto_wipe(fields,sizeof(fields));
    if(r!=IAP2_OK) return stop(s,r==IAP2_AUTH_FAILED?PAIR_SETUP_REASON_AUTH:
        (r==IAP2_PROVIDER_FAILED?PAIR_SETUP_REASON_PROVIDER:PAIR_SETUP_REASON_PROTOCOL),r);
    s->token=(uint64_t)(expected+1)/2;s->held_at=now;
    s->state=expected==1?PAIR_SETUP_M2_HELD:(expected==3?PAIR_SETUP_M4_HELD:PAIR_SETUP_PENDING);
    return expected==5?PAIR_SETUP_APPROVAL:PAIR_SETUP_RESPONSE;
}
int pair_setup_response(const pair_setup *s,const uint8_t **body,size_t *n,uint64_t *token) {
    if(body) *body=0;if(n) *n=0;if(token) *token=0;if(!s||!s->generation||!body||!n||!token) return IAP2_ARGUMENT;
    if(s->state==PAIR_SETUP_DEAD||s->state==PAIR_SETUP_DONE) return PAIR_SETUP_CLOSED;
    if(!held(s)) return IAP2_MORE;*body=s->output;*n=s->output_size;*token=s->token;return PAIR_SETUP_RESPONSE;
}
int pair_setup_pending(const pair_setup *s,pair_setup_candidate *out,uint64_t *token) {
    if(out) pair_crypto_wipe(out,sizeof(*out));if(token) *token=0;if(!s||!s->generation||!out||!token) return IAP2_ARGUMENT;
    if(s->state==PAIR_SETUP_DEAD||s->state==PAIR_SETUP_DONE) return PAIR_SETUP_CLOSED;
    if(s->state!=PAIR_SETUP_PENDING) return IAP2_MORE;copy((uint8_t *)out,(const uint8_t *)&s->candidate,sizeof(*out));*token=s->token;return PAIR_SETUP_APPROVAL;
}
static int keyed(const pair_setup *s,uint64_t gen,uint64_t token) { int r=owner(s,gen);if(r!=IAP2_OK) return r;return token&&token==s->token?IAP2_OK:IAP2_INVALID; }
int pair_setup_decide(pair_setup *s,uint64_t gen,uint64_t token,int approve,uint64_t now) {
    int r=keyed(s,gen,token);if(r!=IAP2_OK) return r;if(s->state!=PAIR_SETUP_PENDING) return PAIR_SETUP_BUSY;
    if(approve!=0&&approve!=1) return IAP2_ARGUMENT;r=pair_setup_check(s,gen,now);if(r!=IAP2_OK) return r;
    if(!approve) return stop(s,PAIR_SETUP_REASON_DENIED,IAP2_AUTH_FAILED);
    r=s->commit(s->commit_context,gen,s->authorization,s->candidate.identifier,s->candidate.identifier_size,s->candidate.public_key);
    if(r!=IAP2_OK) return stop(s,PAIR_SETUP_REASON_PROVIDER,r);
    s->committed=1;pair_crypto_wipe(&s->candidate,sizeof(s->candidate));s->state=PAIR_SETUP_M6_HELD;s->held_at=now;return PAIR_SETUP_RESPONSE;
}
int pair_setup_release(pair_setup *s,uint64_t gen,uint64_t token,uint64_t now) {
    int r=keyed(s,gen,token);if(r!=IAP2_OK) return r;if(!held(s)) return PAIR_SETUP_BUSY;
    r=pair_setup_check(s,gen,now);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(s->output,sizeof(s->output));s->output_size=0;s->token=0;
    if(s->state==PAIR_SETUP_M6_HELD) { clear(s);s->state=PAIR_SETUP_DONE;return PAIR_SETUP_COMPLETE; }
    s->state=s->state==PAIR_SETUP_M2_HELD?PAIR_SETUP_M3:PAIR_SETUP_M5;return IAP2_OK;
}
void pair_setup_close(pair_setup *s) { if(s&&s->generation) (void)stop(s,PAIR_SETUP_REASON_LOCAL,IAP2_OK); }
uint32_t pair_setup_next_delay(const pair_setup *s) {
    uint64_t elapsed;uint32_t delay,n,budget;if(!s||!s->generation||s->state==PAIR_SETUP_DEAD||s->state==PAIR_SETUP_DONE) return UINT32_MAX;
    elapsed=s->now-s->started_at;delay=elapsed>=s->config.exchange_ms?0:s->config.exchange_ms-(uint32_t)elapsed;
    if(held(s)||s->state==PAIR_SETUP_PENDING) {
        budget=s->state==PAIR_SETUP_PENDING?s->config.approval_ms:s->config.hold_ms;elapsed=s->now-s->held_at;
        n=elapsed>=budget?0:budget-(uint32_t)elapsed;if(n<delay) delay=n;
    }
    return delay;
}
