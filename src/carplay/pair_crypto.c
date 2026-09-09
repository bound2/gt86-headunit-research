/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_crypto.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
void pair_crypto_wipe(void *p,size_t n) { if(p) crypto_wipe(p,n); }
static int id_valid(const uint8_t *p,size_t n) {
    size_t i;if(!p||!n||n>PAIR_ID_MAX) return 0;
    for(i=0;i<n;++i) if(p[i]<33||p[i]>126) return 0;
    return 1;
}
int pair_identity_import(pair_identity *id,const uint8_t seed[32],const uint8_t *expected,const uint8_t *name,size_t n) {
    pair_identity tmp;uint8_t fresh[32];int r=IAP2_OK;
    if(!id||!seed||!id_valid(name,n)) return IAP2_ARGUMENT;
    crypto_wipe(&tmp,sizeof(tmp));copy(fresh,seed,32);
    crypto_ed25519_key_pair(tmp.secret,tmp.public_key,fresh); /* wipes fresh */
    if(expected&&crypto_verify32(expected,tmp.public_key)) r=IAP2_AUTH_FAILED;
    else { copy(tmp.identifier,name,n);tmp.identifier_size=n;tmp.ready=1;copy((uint8_t *)id,(const uint8_t *)&tmp,sizeof(tmp)); }
    crypto_wipe(&tmp,sizeof(tmp));crypto_wipe(fresh,sizeof(fresh));return r;
}
int pair_identity_generate(pair_identity *id,pair_random_fn rng,void *ctx,const uint8_t *name,size_t n) {
    uint8_t seed[32]={0};int r;
    if(!id||!rng||!id_valid(name,n)) return IAP2_ARGUMENT;
    r=rng(ctx,seed,sizeof(seed))?IAP2_PROVIDER_FAILED:pair_identity_import(id,seed,0,name,n);
    crypto_wipe(seed,sizeof(seed));return r;
}
void pair_identity_clear(pair_identity *id) { if(id) crypto_wipe(id,sizeof(*id)); }
int pair_identity_sign(const pair_identity *id,const uint8_t *m,size_t n,uint8_t sig[64]) {
    if(!id||!id->ready||!sig||(!m&&n)||n>PAIR_CRYPTO_MAX_DATA) return IAP2_ARGUMENT;
    crypto_ed25519_sign(sig,id->secret,m,n);return IAP2_OK;
}
/* Public-only validation. y must be canonical (<2^255-19). With R=identity,
 * s=0, h=1 the documented cofactored equation holds exactly for on-curve
 * low-order A. Reject those points; actual signature verification below also
 * rejects points not on the curve. No secret data reaches this variable-time
 * equation check. This does not claim a full prime-subgroup membership test.
 */
static int point_allowed(const uint8_t p[32]) {
    static const uint8_t rs[64]={1},unit[32]={1};int i,less=0;
    for(i=31;i>=0;--i) {
        unsigned a=i==31?(p[i]&127u):p[i],b=i==31?127u:(i==0?237u:255u);
        if(a<b) { less=1;break; } if(a>b) return 0;
    }
    return less&&crypto_eddsa_check_equation(rs,p,unit)!=0;
}
int pair_ed25519_verify(const uint8_t pk[32],const uint8_t *m,size_t n,const uint8_t sig[64]) {
    if(!pk||!sig||(!m&&n)||n>PAIR_CRYPTO_MAX_DATA) return IAP2_ARGUMENT;
    if(!point_allowed(pk)||!point_allowed(sig)||crypto_ed25519_check(sig,pk,m,n)) return IAP2_AUTH_FAILED;
    return IAP2_OK;
}
int pair_x25519_generate(pair_random_fn rng,void *ctx,uint8_t sk[32],uint8_t pk[32]) {
    uint8_t tmp[32]={0};int r;
    if(!rng||!sk||!pk) return IAP2_ARGUMENT;
    r=rng(ctx,tmp,sizeof(tmp));
    if(r) { crypto_wipe(sk,32);crypto_wipe(pk,32); }
    else { copy(sk,tmp,32);crypto_x25519_public_key(pk,tmp); }
    crypto_wipe(tmp,sizeof(tmp));return r?IAP2_PROVIDER_FAILED:IAP2_OK;
}
int pair_x25519_shared(const uint8_t sk[32],const uint8_t pk[32],uint8_t shared[32]) {
    static const uint8_t zero[32]={0};
    if(!sk||!pk||!shared) return IAP2_ARGUMENT;
    crypto_x25519(shared,sk,pk);
    return crypto_verify32(shared,zero)?IAP2_OK:IAP2_AUTH_FAILED;
}
int pair_hkdf_sha512(const uint8_t *ikm,size_t ni,const uint8_t *salt,size_t ns,const uint8_t *info,size_t nf,uint8_t *out,size_t no) {
    if((!ikm&&ni)||(!salt&&ns)||(!info&&nf)||!out||!no||no>PAIR_CRYPTO_MAX_KDF_OUTPUT||
       ni>PAIR_CRYPTO_MAX_KDF_INPUT||ns>PAIR_CRYPTO_MAX_KDF_INPUT||nf>PAIR_CRYPTO_MAX_KDF_INPUT) return IAP2_ARGUMENT;
    crypto_sha512_hkdf(out,no,ikm,ni,salt,ns,info,nf);return IAP2_OK;
}
int pair_aead_seal(const uint8_t key[32],const uint8_t nonce[12],const uint8_t *aad,size_t na,const uint8_t *p,size_t n,uint8_t *out,size_t cap,size_t *written) {
    crypto_aead_ctx ctx;
    if(written) *written=0;
    if(!written||!key||!nonce||(!aad&&na)||(!p&&n)||!out||n>PAIR_CRYPTO_MAX_DATA||na>PAIR_CRYPTO_MAX_KDF_INPUT) return IAP2_ARGUMENT;
    if(cap<n+16) return IAP2_NO_SPACE;
    crypto_aead_init_ietf(&ctx,key,nonce);crypto_aead_write(&ctx,out,out+n,aad,na,p,n);
    crypto_wipe(&ctx,sizeof(ctx));*written=n+16;return IAP2_OK;
}
int pair_aead_open(const uint8_t key[32],const uint8_t nonce[12],const uint8_t *aad,size_t na,const uint8_t *p,size_t n,uint8_t *out,size_t cap,size_t *written) {
    crypto_aead_ctx ctx;int r;
    if(written) *written=0;
    if(!written||!key||!nonce||(!aad&&na)||!p||n<16||n>PAIR_CRYPTO_MAX_DATA+16||!out||na>PAIR_CRYPTO_MAX_KDF_INPUT) return IAP2_ARGUMENT;
    if(cap<n-16) return IAP2_NO_SPACE;
    crypto_aead_init_ietf(&ctx,key,nonce);r=crypto_aead_read(&ctx,out,p+n-16,aad,na,p,n-16);
    crypto_wipe(&ctx,sizeof(ctx));
    if(r) { crypto_wipe(out,n-16);return IAP2_AUTH_FAILED; }
    *written=n-16;return IAP2_OK;
}
