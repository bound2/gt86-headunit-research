/* SPDX-License-Identifier: GPL-3.0-only */
#include "mfi_sap.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
static void be32(uint8_t *p,size_t n) { p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n; }
static void clear(mfi_sap *s) {
    pair_crypto_wipe(s->output,sizeof(s->output));s->output_size=0;s->random=0;s->random_context=0;pair_crypto_wipe(&s->provider,sizeof(s->provider));
}
static int stop(mfi_sap *s,enum mfi_sap_reason reason,int error) {
    if(s->state!=MFI_SAP_DEAD&&s->state!=MFI_SAP_DONE) { clear(s);s->state=MFI_SAP_DEAD;s->reason=reason;s->last_error=error; }return MFI_SAP_CLOSED;
}
static int owner(const mfi_sap *s,uint64_t gen) {
    if(!s||!s->generation||!gen) return IAP2_ARGUMENT;if(gen!=s->generation) return IAP2_INVALID;
    return s->state==MFI_SAP_DEAD||s->state==MFI_SAP_DONE?MFI_SAP_CLOSED:IAP2_OK;
}
int mfi_sap_init(mfi_sap *s,pair_random_fn rng,void *rc,const mfi_sap_provider *provider,uint32_t hold,uint64_t gen,uint64_t now) {
    if(!s||!rng||!provider||!provider->identity||!provider->sign||!hold||hold>60000||!gen) return IAP2_ARGUMENT;
    pair_crypto_wipe(s,sizeof(*s));s->random=rng;s->random_context=rc;s->provider=*provider;s->hold_ms=hold;s->generation=gen;s->now=now;s->state=MFI_SAP_WAIT;return IAP2_OK;
}
int mfi_sap_check(mfi_sap *s,uint64_t gen,uint64_t now) {
    int r=owner(s,gen);if(r!=IAP2_OK) return r;if(now<s->now) return IAP2_ARGUMENT;s->now=now;
    return s->state==MFI_SAP_HELD&&now-s->held_at>=s->hold_ms?stop(s,MFI_SAP_REASON_DEADLINE,IAP2_MORE):IAP2_OK;
}
int mfi_sap_request(mfi_sap *s,uint64_t gen,const uint8_t *p,size_t n,uint64_t now) {
    uint8_t secret[32]={0},pub[32]={0},shared[32]={0},material[64]={0},key[20]={0},iv_hash[20]={0},digest[32]={0};
    uint8_t signature[MFI_SAP_SIGNATURE_MAX]={0},counter[16]={0},stream[16]={0},major=0;
    size_t cert_size=0,sig_size=0,offset=0;mbedtls_aes_context aes;int r=owner(s,gen);enum mfi_sap_reason reason=MFI_SAP_REASON_CRYPTO;
    if(r!=IAP2_OK) return r;if(!p&&n) return IAP2_ARGUMENT;if(s->state!=MFI_SAP_WAIT) return IAP2_INVALID;
    r=mfi_sap_check(s,gen,now);if(r!=IAP2_OK) return r;
    if(n!=33||p[0]!=1) return stop(s,MFI_SAP_REASON_PROTOCOL,IAP2_INVALID);
    mbedtls_aes_init(&aes);
    r=pair_x25519_generate(s->random,s->random_context,secret,pub);if(r!=IAP2_OK) goto done;
    r=pair_x25519_shared(secret,p+1,shared);if(r!=IAP2_OK) goto done;
    copy(material,(const uint8_t *)"AES-KEY",7);copy(material+7,shared,32);
    r=mbedtls_sha1(material,39,key);if(r) goto done;
    copy(material,(const uint8_t *)"AES-IV",6);copy(material+6,shared,32);
    r=mbedtls_sha1(material,38,iv_hash);if(r) goto done;
    reason=MFI_SAP_REASON_PROVIDER;
    r=s->provider.identity(s->provider.context,gen,s->output+36,MFI_SAP_CERT_MAX,&cert_size,&major);if(r!=IAP2_OK) goto done;
    if(!cert_size||cert_size>MFI_SAP_CERT_MAX) { r=IAP2_INVALID;goto done; }
    if(major!=2&&major!=3) { r=IAP2_UNSUPPORTED;goto done; }
    reason=MFI_SAP_REASON_CRYPTO;copy(material,pub,32);copy(material+32,p+1,32);
    r=major==2?mbedtls_sha1(material,64,digest):mbedtls_sha256(material,64,digest,0);if(r) goto done;
    reason=MFI_SAP_REASON_PROVIDER;
    r=s->provider.sign(s->provider.context,gen,digest,major==2?20u:32u,signature,sizeof(signature),&sig_size);if(r!=IAP2_OK) goto done;
    if(!sig_size||sig_size>sizeof(signature)) { r=IAP2_INVALID;goto done; }
    reason=MFI_SAP_REASON_CRYPTO;copy(counter,iv_hash,16);r=mbedtls_aes_setkey_enc(&aes,key,128);if(r) goto done;
    r=mbedtls_aes_crypt_ctr(&aes,sig_size,&offset,counter,stream,signature,s->output+40+cert_size);if(r) goto done;
    copy(s->output,pub,32);be32(s->output+32,cert_size);be32(s->output+36+cert_size,sig_size);
    s->output_size=40+cert_size+sig_size;s->protocol_major=major;s->held_at=now;s->state=MFI_SAP_HELD;
    s->random=0;s->random_context=0;pair_crypto_wipe(&s->provider,sizeof(s->provider));
done:
    mbedtls_aes_free(&aes);pair_crypto_wipe(secret,sizeof(secret));pair_crypto_wipe(pub,sizeof(pub));pair_crypto_wipe(shared,sizeof(shared));
    pair_crypto_wipe(material,sizeof(material));pair_crypto_wipe(key,sizeof(key));pair_crypto_wipe(iv_hash,sizeof(iv_hash));pair_crypto_wipe(digest,sizeof(digest));
    pair_crypto_wipe(signature,sizeof(signature));pair_crypto_wipe(counter,sizeof(counter));pair_crypto_wipe(stream,sizeof(stream));
    return r==IAP2_OK?MFI_SAP_RESPONSE:stop(s,reason,r);
}
int mfi_sap_response(const mfi_sap *s,const uint8_t **p,size_t *n) {
    if(p) *p=0;if(n) *n=0;if(!s||!s->generation||!p||!n) return IAP2_ARGUMENT;
    if(s->state==MFI_SAP_HELD) { *p=s->output;*n=s->output_size;return MFI_SAP_RESPONSE; }
    return s->state==MFI_SAP_WAIT?IAP2_MORE:MFI_SAP_CLOSED;
}
int mfi_sap_release(mfi_sap *s,uint64_t gen,uint64_t now) {
    int r=owner(s,gen);if(r!=IAP2_OK) return r;if(s->state!=MFI_SAP_HELD) return IAP2_INVALID;
    r=mfi_sap_check(s,gen,now);if(r!=IAP2_OK) return r;clear(s);s->state=MFI_SAP_DONE;return MFI_SAP_DRAINED;
}
void mfi_sap_close(mfi_sap *s) { if(s&&s->generation) (void)stop(s,MFI_SAP_REASON_LOCAL,IAP2_OK); }
uint32_t mfi_sap_next_delay(const mfi_sap *s) {
    if(!s||!s->generation||s->state!=MFI_SAP_HELD) return UINT32_MAX;
    return s->now-s->held_at>=s->hold_ms?0:s->hold_ms-(uint32_t)(s->now-s->held_at);
}
