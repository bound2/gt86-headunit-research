/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_store.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
static void copy(void *dst,const void *src,size_t n) { uint8_t *d=(uint8_t *)dst;const uint8_t *s=(const uint8_t *)src;while(n--) *d++=*s++; }
static int same(const uint8_t *a,const uint8_t *b,size_t n) { while(n--) if(*a++!=*b++) return 0;return 1; }
static int zero(const uint8_t *p,size_t n) { while(n--) if(*p++) return 0;return 1; }
static int identifier(const uint8_t *p,size_t n) { size_t i;if(!p||!n||n>PAIR_ID_MAX) return 0;for(i=0;i<n;++i) if(p[i]<33||p[i]>126) return 0;return 1; }
static void le(uint8_t *p,uint64_t v,size_t n) { while(n--) { *p++=(uint8_t)v;v>>=8; } }
static uint64_t read_le(const uint8_t *p,size_t n) { uint64_t v=0;size_t i;for(i=0;i<n;++i) v|=(uint64_t)p[i]<<(8*i);return v; }
static int valid(const pair_store_data *s) {
    uint32_t i,j;
    if(!s||s->ready!=1||s->identity.ready!=1||s->count>PAIR_STORE_MAX_CONTROLLERS||s->revision!=s->count+1u||
       !identifier(s->identity.identifier,s->identity.identifier_size)) return 0;
    for(i=0;i<s->count;++i) {
        const pair_store_entry *e=&s->controllers[i];if(!identifier(e->identifier,e->identifier_size)) return 0;
        for(j=0;j<i;++j) if(e->identifier_size==s->controllers[j].identifier_size&&same(e->identifier,s->controllers[j].identifier,e->identifier_size)) return 0;
    }
    return 1;
}
int pair_store_init(pair_store_data *s,const uint8_t seed[32],const uint8_t *pk,const uint8_t *id,size_t n) {
    pair_store_data tmp;int r;
    if(!s||!seed||!identifier(id,n)) return IAP2_ARGUMENT;
    pair_crypto_wipe(&tmp,sizeof(tmp));r=pair_identity_import(&tmp.identity,seed,pk,id,n);
    if(r==IAP2_OK) { copy(tmp.seed,seed,32);tmp.count=0;tmp.revision=1;tmp.ready=1;copy(s,&tmp,sizeof(tmp)); }
    pair_store_clear(&tmp);return r;
}
int pair_store_generate(pair_store_data *s,pair_random_fn rng,void *ctx,const uint8_t *id,size_t n) {
    uint8_t seed[32]={0};int r;
    if(!s||!rng||!identifier(id,n)) return IAP2_ARGUMENT;
    r=rng(ctx,seed,sizeof(seed))?IAP2_PROVIDER_FAILED:pair_store_init(s,seed,0,id,n);
    pair_crypto_wipe(seed,sizeof(seed));return r;
}
void pair_store_clear(pair_store_data *s) { if(s) pair_crypto_wipe(s,sizeof(*s)); }
int pair_store_lookup(const pair_store_data *s,const uint8_t *id,size_t n,uint8_t pk[32]) {
    uint32_t i;if(pk) pair_crypto_wipe(pk,32);
    if(!pk||!identifier(id,n)) return IAP2_ARGUMENT;if(!valid(s)) return PAIR_STORE_CLOSED;
    for(i=0;i<s->count;++i) if(n==s->controllers[i].identifier_size&&same(id,s->controllers[i].identifier,n)) {
        copy(pk,s->controllers[i].public_key,32);return IAP2_OK;
    }
    return IAP2_END;
}
int pair_store_add(pair_store_data *s,const uint8_t *id,size_t n,const uint8_t pk[32]) {
    uint8_t found[32];pair_store_entry *e;int r;
    if(!pk||!identifier(id,n)) return IAP2_ARGUMENT;r=pair_store_lookup(s,id,n,found);
    if(r==IAP2_OK) return crypto_verify32(found,pk)?PAIR_STORE_CONFLICT:IAP2_END;
    if(r!=IAP2_END) return r;if(s->count==PAIR_STORE_MAX_CONTROLLERS) return IAP2_NO_SPACE;
    e=&s->controllers[s->count];pair_crypto_wipe(e,sizeof(*e));copy(e->identifier,id,n);copy(e->public_key,pk,32);e->identifier_size=(uint8_t)n;
    ++s->count;++s->revision;return IAP2_OK;
}
int pair_store_encode(const pair_store_data *s,uint8_t *out,size_t cap) {
    uint8_t image[PAIR_STORE_IMAGE_SIZE];pair_identity check;uint32_t i;int r;
    if(!out||!valid(s)) return IAP2_ARGUMENT;if(cap<sizeof(image)) return IAP2_NO_SPACE;
    /* Do not serialize inconsistent seed/public/secret halves, even if the
     * caller violated the read-only snapshot contract. */
    pair_crypto_wipe(&check,sizeof(check));r=pair_identity_import(&check,s->seed,s->identity.public_key,s->identity.identifier,s->identity.identifier_size);
    if(r==IAP2_OK&&crypto_verify64(check.secret,s->identity.secret)) r=IAP2_AUTH_FAILED;
    pair_identity_clear(&check);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(image,sizeof(image));copy(image,"GT86PS01",8);le(image+8,s->revision,8);image[16]=(uint8_t)s->identity.identifier_size;
    copy(image+24,s->seed,32);copy(image+56,s->identity.public_key,32);copy(image+88,s->identity.identifier,s->identity.identifier_size);le(image+152,s->count,4);
    for(i=0;i<s->count;++i) { uint8_t *p=image+160+104*i;const pair_store_entry *e=&s->controllers[i];
        p[0]=e->identifier_size;copy(p+8,e->identifier,e->identifier_size);copy(p+72,e->public_key,32); }
    crypto_sha512(image+PAIR_STORE_HASH_OFFSET,image,PAIR_STORE_HASH_OFFSET);copy(out,image,sizeof(image));pair_crypto_wipe(image,sizeof(image));return IAP2_OK;
}
int pair_store_decode(pair_store_data *out,const uint8_t *p,size_t n) {
    pair_store_data tmp;uint8_t hash[64];uint32_t count,i;int r=PAIR_STORE_CORRUPT;
    if(!out||(!p&&n)) return IAP2_ARGUMENT;if(n!=PAIR_STORE_IMAGE_SIZE) return PAIR_STORE_CORRUPT;
    crypto_sha512(hash,p,PAIR_STORE_HASH_OFFSET);
    if(crypto_verify64(hash,p+PAIR_STORE_HASH_OFFSET)) { pair_crypto_wipe(hash,sizeof(hash));return PAIR_STORE_CORRUPT; }
    pair_crypto_wipe(hash,sizeof(hash));count=(uint32_t)read_le(p+152,4);
    if(!same(p,(const uint8_t *)"GT86PS01",8)||count>PAIR_STORE_MAX_CONTROLLERS||read_le(p+8,8)!=count+1u||
       !identifier(p+88,p[16])||!zero(p+17,7)||!zero(p+88+p[16],PAIR_ID_MAX-p[16])||!zero(p+156,4)) return PAIR_STORE_CORRUPT;
    pair_crypto_wipe(&tmp,sizeof(tmp));
    if(pair_store_init(&tmp,p+24,p+56,p+88,p[16])!=IAP2_OK) goto done;
    for(i=0;i<PAIR_STORE_MAX_CONTROLLERS;++i) {
        const uint8_t *e=p+160+104*i;
        if(i>=count) { if(!zero(e,104)) goto done; }
        else if(!identifier(e+8,e[0])||!zero(e+1,7)||!zero(e+8+e[0],PAIR_ID_MAX-e[0])||pair_store_add(&tmp,e+8,e[0],e+72)!=IAP2_OK) goto done;
    }
    copy(out,&tmp,sizeof(tmp));r=IAP2_OK;
done: pair_store_clear(&tmp);return r;
}
int pair_store_successor(const pair_store_data *a,const pair_store_data *b) {
    uint32_t i;if(!valid(a)||!valid(b)) return IAP2_ARGUMENT;
    if(b->count!=a->count+1u||b->revision!=a->revision+1u||crypto_verify32(a->seed,b->seed)||
       crypto_verify32(a->identity.public_key,b->identity.public_key)||a->identity.identifier_size!=b->identity.identifier_size||
       !same(a->identity.identifier,b->identity.identifier,a->identity.identifier_size)) return PAIR_STORE_CORRUPT;
    for(i=0;i<a->count;++i) { const pair_store_entry *x=&a->controllers[i],*y=&b->controllers[i];
        if(x->identifier_size!=y->identifier_size||!same(x->identifier,y->identifier,x->identifier_size)||crypto_verify32(x->public_key,y->public_key)) return PAIR_STORE_CORRUPT; }
    return IAP2_OK;
}
