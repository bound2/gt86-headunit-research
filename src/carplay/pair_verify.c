/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_verify.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
static size_t length(const char *s) { size_t n=0;while(s[n]) ++n;return n; }
static int ms(uint32_t n) { return n&&n<=60000; }
static int identifier(const uint8_t *p,size_t n) {
    size_t i;if(!n||n>PAIR_ID_MAX) return 0;
    for(i=0;i<n;++i) if(p[i]<33||p[i]>126) return 0;
    return 1;
}
void pair_verify_default_config(pair_verify_config *c) { if(c) { c->exchange_ms=10000;c->hold_ms=5000; } }
int pair_verify_init(pair_verify *p,const pair_identity *id,pair_random_fn random,void *rc,pair_lookup_fn lookup,void *lc,
                      const pair_verify_config *cfg,uint64_t generation,uint64_t now) {
    if(!p||!id||!id->ready||!identifier(id->identifier,id->identifier_size)||!random||!lookup||!cfg||
       !ms(cfg->exchange_ms)||!ms(cfg->hold_ms)||!generation) return IAP2_ARGUMENT;
    pair_crypto_wipe(p,sizeof(*p));p->identity=id;p->random=random;p->random_context=rc;p->lookup=lookup;p->lookup_context=lc;
    p->config=*cfg;p->generation=generation;p->now=p->started_at=now;p->state=PAIR_VERIFY_M1;return IAP2_OK;
}
static void clear(pair_verify *p) {
    pair_crypto_wipe(p->our_ephemeral,32);pair_crypto_wipe(p->peer_ephemeral,32);pair_crypto_wipe(p->encrypt_key,32);
    pair_crypto_wipe(&p->keys,sizeof(p->keys));pair_crypto_wipe(p->output,sizeof(p->output));p->output_size=0;
    p->identity=0;p->random=0;p->random_context=0;p->lookup=0;p->lookup_context=0;p->token=0;
}
static int fail(pair_verify *p,enum pair_verify_reason reason,int error) {
    clear(p);p->state=PAIR_VERIFY_DEAD;p->reason=reason;p->last_error=error;return PAIR_VERIFY_CLOSED;
}
static int owner(const pair_verify *p,uint64_t gen) {
    if(!p||!p->generation||!gen) return IAP2_ARGUMENT;
    if(gen!=p->generation) return IAP2_INVALID;
    return p->state==PAIR_VERIFY_DEAD||p->state==PAIR_VERIFY_DETACHED?PAIR_VERIFY_CLOSED:IAP2_OK;
}
int pair_verify_check(pair_verify *p,uint64_t gen,uint64_t now) {
    int r=owner(p,gen);if(r!=IAP2_OK) return r;
    if(now<p->now) return IAP2_ARGUMENT;p->now=now;
    if(now-p->started_at>=p->config.exchange_ms||
       ((p->state==PAIR_VERIFY_M2_HELD||p->state==PAIR_VERIFY_M4_HELD||p->state==PAIR_VERIFY_KEYS_READY)&&
        now-p->held_at>=p->config.hold_ms)) return fail(p,PAIR_VERIFY_REASON_DEADLINE,IAP2_MORE);
    return IAP2_OK;
}
static int derive(const uint8_t secret[32],const char *salt,const char *info,uint8_t out[32]) {
    return pair_hkdf_sha512(secret,32,(const uint8_t *)salt,length(salt),(const uint8_t *)info,length(info),out,32);
}
static void label(uint8_t nonce[12],uint8_t n) {
    static const uint8_t prefix[11]={0,0,0,0,'P','V','-','M','s','g','0'};copy(nonce,prefix,11);nonce[11]=n;
}
/* Handshake-specific dictionary: reject separators and duplicate logical fields.
 * Fragments remain supported, including those in unknown forward-compatible fields.
 */
static int dictionary(const uint8_t *body,size_t size,pair_tlv *fields,uint8_t *arena,size_t *count) {
    size_t i,j,off=0;int r;
    while(off<size) {
        if(size-off<2||body[off+1]>size-off-2||body[off]==255) return IAP2_INVALID;
        off+=(size_t)body[off+1]+2;
    }
    r=pair_tlv_decode(body,size,fields,PAIR_TLV_MAX_ITEMS,arena,PAIR_VERIFY_MAX_BODY,count);if(r!=IAP2_OK) return r;
    for(i=0;i<*count;++i) for(j=0;j<i;++j) if(fields[i].type==fields[j].type) return IAP2_INVALID;
    return IAP2_OK;
}
static int m2(pair_verify *p,const pair_tlv *peer) {
    uint8_t sk[32]={0},sig[64]={0},signed_data[128]={0},sub[160]={0},sealed[176]={0},nonce[12];
    uint8_t state=2;pair_tlv fields[3];size_t n=0,sealed_size=0;int r;
    if(peer->size!=32) return IAP2_INVALID;
    copy(p->peer_ephemeral,peer->data,32);
    r=pair_x25519_generate(p->random,p->random_context,sk,p->our_ephemeral);if(r!=IAP2_OK) goto done;
    r=pair_x25519_shared(sk,p->peer_ephemeral,p->keys.shared_secret);if(r!=IAP2_OK) goto done;
    r=derive(p->keys.shared_secret,"Pair-Verify-Encrypt-Salt","Pair-Verify-Encrypt-Info",p->encrypt_key);if(r!=IAP2_OK) goto done;
    copy(signed_data,p->our_ephemeral,32);copy(signed_data+32,p->identity->identifier,p->identity->identifier_size);
    copy(signed_data+32+p->identity->identifier_size,p->peer_ephemeral,32);
    r=pair_identity_sign(p->identity,signed_data,64+p->identity->identifier_size,sig);if(r!=IAP2_OK) goto done;
    fields[0].type=1;fields[0].data=p->identity->identifier;fields[0].size=p->identity->identifier_size;
    fields[1].type=10;fields[1].data=sig;fields[1].size=64;
    r=pair_tlv_encode(fields,2,sub,sizeof(sub),&n);if(r!=IAP2_OK) goto done;
    label(nonce,'2');r=pair_aead_seal(p->encrypt_key,nonce,0,0,sub,n,sealed,sizeof(sealed),&sealed_size);if(r!=IAP2_OK) goto done;
    fields[0].type=6;fields[0].data=&state;fields[0].size=1;
    fields[1].type=3;fields[1].data=p->our_ephemeral;fields[1].size=32;
    fields[2].type=5;fields[2].data=sealed;fields[2].size=sealed_size;
    r=pair_tlv_encode(fields,3,p->output,sizeof(p->output),&p->output_size);
done:
    pair_crypto_wipe(sk,sizeof(sk));pair_crypto_wipe(sig,sizeof(sig));pair_crypto_wipe(signed_data,sizeof(signed_data));
    pair_crypto_wipe(sub,sizeof(sub));pair_crypto_wipe(sealed,sizeof(sealed));return r;
}
static int m4(pair_verify *p,const pair_tlv *enc) {
    uint8_t plain[PAIR_VERIFY_MAX_BODY]={0},arena[PAIR_VERIFY_MAX_BODY]={0},pk[32]={0},signed_data[128]={0},nonce[12];
    pair_tlv fields[PAIR_TLV_MAX_ITEMS],id,sig;size_t n=0,count=0;int r;
    label(nonce,'3');r=pair_aead_open(p->encrypt_key,nonce,0,0,enc->data,enc->size,plain,sizeof(plain),&n);if(r!=IAP2_OK) goto done;
    r=dictionary(plain,n,fields,arena,&count);if(r!=IAP2_OK) goto done;
    if(pair_tlv_get(fields,count,1,&id)!=IAP2_OK||!identifier(id.data,id.size)||
       pair_tlv_get(fields,count,10,&sig)!=IAP2_OK||sig.size!=64) { r=IAP2_INVALID;goto done; }
    r=p->lookup(p->lookup_context,id.data,id.size,pk);
    if(r!=IAP2_OK) { r=r==IAP2_END?IAP2_AUTH_FAILED:IAP2_PROVIDER_FAILED;goto done; }
    copy(signed_data,p->peer_ephemeral,32);copy(signed_data+32,id.data,id.size);copy(signed_data+32+id.size,p->our_ephemeral,32);
    r=pair_ed25519_verify(pk,signed_data,64+id.size,sig.data);if(r!=IAP2_OK) goto done;
    r=derive(p->keys.shared_secret,"Control-Salt","Control-Write-Encryption-Key",p->keys.read_key);if(r!=IAP2_OK) goto done;
    r=derive(p->keys.shared_secret,"Control-Salt","Control-Read-Encryption-Key",p->keys.write_key);if(r!=IAP2_OK) goto done;
    copy(p->keys.controller_id,id.data,id.size);p->keys.controller_id_size=id.size;
    p->output[0]=6;p->output[1]=1;p->output[2]=4;p->output_size=3;
    pair_crypto_wipe(p->encrypt_key,32);
done:
    pair_crypto_wipe(plain,sizeof(plain));pair_crypto_wipe(arena,sizeof(arena));pair_crypto_wipe(pk,sizeof(pk));
    pair_crypto_wipe(signed_data,sizeof(signed_data));return r;
}
int pair_verify_request(pair_verify *p,uint64_t gen,const uint8_t *body,size_t size,uint64_t now) {
    pair_tlv fields[PAIR_TLV_MAX_ITEMS],state,value;uint8_t arena[PAIR_VERIFY_MAX_BODY];size_t count=0;int r;
    if(!body&&size) return IAP2_ARGUMENT;
    r=pair_verify_check(p,gen,now);if(r!=IAP2_OK) return r;
    if(p->state!=PAIR_VERIFY_M1&&p->state!=PAIR_VERIFY_M3) return PAIR_VERIFY_BUSY;
    if(size>PAIR_VERIFY_MAX_BODY) return fail(p,PAIR_VERIFY_REASON_PROTOCOL,IAP2_NO_SPACE);
    r=dictionary(body,size,fields,arena,&count);
    if(r==IAP2_OK&&(pair_tlv_get(fields,count,6,&state)!=IAP2_OK||state.size!=1||
       state.data[0]!=(p->state==PAIR_VERIFY_M1?1:3))) r=IAP2_INVALID;
    if(r==IAP2_OK&&pair_tlv_get(fields,count,p->state==PAIR_VERIFY_M1?3:5,&value)!=IAP2_OK) r=IAP2_INVALID;
    if(r==IAP2_OK) r=p->state==PAIR_VERIFY_M1?m2(p,&value):m4(p,&value);
    pair_crypto_wipe(arena,sizeof(arena));
    if(r!=IAP2_OK) return fail(p,r==IAP2_AUTH_FAILED?PAIR_VERIFY_REASON_AUTH:
        (r==IAP2_PROVIDER_FAILED?PAIR_VERIFY_REASON_PROVIDER:PAIR_VERIFY_REASON_PROTOCOL),r);
    p->token=p->state==PAIR_VERIFY_M1?1:2;p->state=p->state==PAIR_VERIFY_M1?PAIR_VERIFY_M2_HELD:PAIR_VERIFY_M4_HELD;
    p->held_at=now;return PAIR_VERIFY_RESPONSE;
}
int pair_verify_response(const pair_verify *p,const uint8_t **body,size_t *size,uint64_t *token) {
    if(body) *body=0;if(size) *size=0;if(token) *token=0;
    if(!p||!p->generation||!body||!size||!token) return IAP2_ARGUMENT;
    if(p->state==PAIR_VERIFY_DEAD||p->state==PAIR_VERIFY_DETACHED) return PAIR_VERIFY_CLOSED;
    if(p->state!=PAIR_VERIFY_M2_HELD&&p->state!=PAIR_VERIFY_M4_HELD) return IAP2_MORE;
    *body=p->output;*size=p->output_size;*token=p->token;return PAIR_VERIFY_RESPONSE;
}
static int keyed(pair_verify *p,uint64_t gen,uint64_t token) {
    int r=owner(p,gen);if(r!=IAP2_OK) return r;
    return token&&token==p->token?IAP2_OK:IAP2_INVALID;
}
int pair_verify_release(pair_verify *p,uint64_t gen,uint64_t token,uint64_t now) {
    int r=keyed(p,gen,token);if(r!=IAP2_OK) return r;
    if(p->state!=PAIR_VERIFY_M2_HELD&&p->state!=PAIR_VERIFY_M4_HELD) return PAIR_VERIFY_BUSY;
    r=pair_verify_check(p,gen,now);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(p->output,sizeof(p->output));p->output_size=0;
    if(p->state==PAIR_VERIFY_M2_HELD) { p->state=PAIR_VERIFY_M3;p->token=0;return IAP2_OK; }
    p->state=PAIR_VERIFY_KEYS_READY;return PAIR_VERIFY_KEYS;
}
int pair_verify_take(pair_verify *p,uint64_t gen,uint64_t token,pair_session_keys *keys,uint64_t now) {
    int r=keyed(p,gen,token);if(r!=IAP2_OK) return r;
    if(!keys) return IAP2_ARGUMENT;if(p->state!=PAIR_VERIFY_KEYS_READY) return PAIR_VERIFY_BUSY;
    r=pair_verify_check(p,gen,now);if(r!=IAP2_OK) return r;
    copy((uint8_t *)keys,(const uint8_t *)&p->keys,sizeof(*keys));clear(p);p->state=PAIR_VERIFY_DETACHED;return IAP2_OK;
}
void pair_verify_close(pair_verify *p) {
    if(p&&p->generation&&p->state!=PAIR_VERIFY_DEAD&&p->state!=PAIR_VERIFY_DETACHED) (void)fail(p,PAIR_VERIFY_REASON_LOCAL,IAP2_END);
}
uint32_t pair_verify_next_delay(const pair_verify *p) {
    uint64_t elapsed;uint32_t delay,hold;
    if(!p||!p->generation||p->state==PAIR_VERIFY_DEAD||p->state==PAIR_VERIFY_DETACHED) return UINT32_MAX;
    elapsed=p->now-p->started_at;delay=elapsed>=p->config.exchange_ms?0:p->config.exchange_ms-(uint32_t)elapsed;
    if(p->state==PAIR_VERIFY_M2_HELD||p->state==PAIR_VERIFY_M4_HELD||p->state==PAIR_VERIFY_KEYS_READY) {
        elapsed=p->now-p->held_at;hold=elapsed>=p->config.hold_ms?0:p->config.hold_ms-(uint32_t)elapsed;
        if(hold<delay) delay=hold;
    }
    return delay;
}
