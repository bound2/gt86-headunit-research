/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_srp.h"
#include "mbedtls/bignum.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
static const char modulus[]=
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183"
    "995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A"
    "85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7AB"
    "F5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8"
    "7602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208"
    "E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
static void hash2(uint8_t out[64],const uint8_t *a,size_t na,const uint8_t *b,size_t nb) {
    crypto_sha512_ctx ctx;crypto_sha512_init(&ctx);crypto_sha512_update(&ctx,a,na);crypto_sha512_update(&ctx,b,nb);
    crypto_sha512_final(&ctx,out);pair_crypto_wipe(&ctx,sizeof(ctx));
}
void pair_srp_init(pair_srp *s) { if(s) pair_crypto_wipe(s,sizeof(*s)); }
void pair_srp_clear(pair_srp *s) { if(s) { pair_crypto_wipe(s->secret,32);pair_crypto_wipe(s->verifier,384);
    pair_crypto_wipe(s->public_key,384);pair_crypto_wipe(s->salt,16);s->state=PAIR_SRP_DEAD; } }
#define MPI(call) do { backend=(call);if(backend) { r=IAP2_PROVIDER_FAILED;goto done; } } while(0)
int pair_srp_start(pair_srp *s,pair_random_fn rng,void *context) {
    mbedtls_mpi n,g,x,v,b,k,t,pub,rr;uint8_t npad[384],gpad[384]={0},h[64],salt[16],secret[32];
    static const uint8_t zero[32]={0};int r=IAP2_OK,backend=0;
    if(!s||!rng) return IAP2_ARGUMENT;if(s->state!=PAIR_SRP_NEW) return IAP2_INVALID;
    mbedtls_mpi_init(&n);mbedtls_mpi_init(&g);mbedtls_mpi_init(&x);mbedtls_mpi_init(&v);mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&k);mbedtls_mpi_init(&t);mbedtls_mpi_init(&pub);mbedtls_mpi_init(&rr);
    pair_crypto_wipe(salt,16);pair_crypto_wipe(secret,32);
    if(rng(context,salt,16)||rng(context,secret,32)||!crypto_verify32(secret,zero)) { r=IAP2_PROVIDER_FAILED;goto done; }
    MPI(mbedtls_mpi_read_string(&n,16,modulus));MPI(mbedtls_mpi_lset(&g,5));gpad[383]=5;
    MPI(mbedtls_mpi_write_binary(&n,npad,384));hash2(h,npad,384,gpad,384);MPI(mbedtls_mpi_read_binary(&k,h,64));
    crypto_sha512(h,(const uint8_t *)"Pair-Setup:3939",15);hash2(h,salt,16,h,64);
    MPI(mbedtls_mpi_read_binary(&x,h,64));MPI(mbedtls_mpi_read_binary(&b,secret,32));
    MPI(mbedtls_mpi_exp_mod(&v,&g,&x,&n,&rr));MPI(mbedtls_mpi_exp_mod(&t,&g,&b,&n,&rr));
    MPI(mbedtls_mpi_mul_mpi(&pub,&k,&v));MPI(mbedtls_mpi_add_mpi(&pub,&pub,&t));MPI(mbedtls_mpi_mod_mpi(&pub,&pub,&n));
    if(mbedtls_mpi_cmp_int(&pub,0)==0) { r=IAP2_AUTH_FAILED;goto done; }
    MPI(mbedtls_mpi_write_binary(&v,s->verifier,384));MPI(mbedtls_mpi_write_binary(&pub,s->public_key,384));
    copy(s->secret,secret,32);copy(s->salt,salt,16);s->state=PAIR_SRP_WAIT_PROOF;
done:
    mbedtls_mpi_free(&n);mbedtls_mpi_free(&g);mbedtls_mpi_free(&x);mbedtls_mpi_free(&v);mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&k);mbedtls_mpi_free(&t);mbedtls_mpi_free(&pub);mbedtls_mpi_free(&rr);
    pair_crypto_wipe(npad,sizeof(npad));pair_crypto_wipe(gpad,sizeof(gpad));pair_crypto_wipe(h,64);
    pair_crypto_wipe(salt,16);pair_crypto_wipe(secret,32);s->last_error=backend?backend:r;
    if(r!=IAP2_OK) pair_srp_clear(s);return r;
}
int pair_srp_verify(pair_srp *s,const uint8_t a[384],const uint8_t proof[64],uint8_t key[64],uint8_t server_proof[64]) {
    mbedtls_mpi n,v,b,client,u,t,shared,rr,upper;crypto_sha512_ctx ctx;
    uint8_t h[64],hn[64],hg[64],hi[64],expected[64],k[64],spad[384],npad[384];
    const uint8_t generator=5;size_t i,size;int r=IAP2_OK,backend=0;
    if(!s||!a||!proof||!key||!server_proof) return IAP2_ARGUMENT;
    if(s->state!=PAIR_SRP_WAIT_PROOF) return IAP2_INVALID;
    mbedtls_mpi_init(&n);mbedtls_mpi_init(&v);mbedtls_mpi_init(&b);mbedtls_mpi_init(&client);mbedtls_mpi_init(&u);
    mbedtls_mpi_init(&t);mbedtls_mpi_init(&shared);mbedtls_mpi_init(&rr);mbedtls_mpi_init(&upper);
    MPI(mbedtls_mpi_read_string(&n,16,modulus));MPI(mbedtls_mpi_read_binary(&client,a,384));MPI(mbedtls_mpi_sub_int(&upper,&n,1));
    if(mbedtls_mpi_cmp_int(&client,1)<=0||mbedtls_mpi_cmp_mpi(&client,&upper)>=0) { r=IAP2_AUTH_FAILED;goto done; }
    hash2(h,a,384,s->public_key,384);MPI(mbedtls_mpi_read_binary(&u,h,64));
    if(mbedtls_mpi_cmp_int(&u,0)==0) { r=IAP2_AUTH_FAILED;goto done; }
    MPI(mbedtls_mpi_read_binary(&v,s->verifier,384));MPI(mbedtls_mpi_read_binary(&b,s->secret,32));
    MPI(mbedtls_mpi_exp_mod(&t,&v,&u,&n,&rr));MPI(mbedtls_mpi_mul_mpi(&t,&t,&client));MPI(mbedtls_mpi_mod_mpi(&t,&t,&n));
    if(mbedtls_mpi_cmp_int(&t,1)<=0||mbedtls_mpi_cmp_mpi(&t,&upper)>=0) { r=IAP2_AUTH_FAILED;goto done; }
    MPI(mbedtls_mpi_exp_mod(&shared,&t,&b,&n,&rr));
    if(mbedtls_mpi_cmp_int(&shared,1)<=0||mbedtls_mpi_cmp_mpi(&shared,&upper)>=0) { r=IAP2_AUTH_FAILED;goto done; }
    size=mbedtls_mpi_size(&shared);if(!size||size>384) { r=IAP2_AUTH_FAILED;goto done; }
    MPI(mbedtls_mpi_write_binary(&shared,spad,size));crypto_sha512(k,spad,size);
    MPI(mbedtls_mpi_write_binary(&n,npad,384));crypto_sha512(hn,npad,384);crypto_sha512(hg,&generator,1);
    crypto_sha512(hi,(const uint8_t *)"Pair-Setup",10);for(i=0;i<64;++i) h[i]=hn[i]^hg[i];
    crypto_sha512_init(&ctx);crypto_sha512_update(&ctx,h,64);crypto_sha512_update(&ctx,hi,64);crypto_sha512_update(&ctx,s->salt,16);
    crypto_sha512_update(&ctx,a,384);crypto_sha512_update(&ctx,s->public_key,384);crypto_sha512_update(&ctx,k,64);crypto_sha512_final(&ctx,expected);
    if(crypto_verify64(expected,proof)) { r=IAP2_AUTH_FAILED;goto done; }
    crypto_sha512_init(&ctx);crypto_sha512_update(&ctx,a,384);crypto_sha512_update(&ctx,proof,64);crypto_sha512_update(&ctx,k,64);
    crypto_sha512_final(&ctx,server_proof);copy(key,k,64);
done:
    mbedtls_mpi_free(&n);mbedtls_mpi_free(&v);mbedtls_mpi_free(&b);mbedtls_mpi_free(&client);mbedtls_mpi_free(&u);
    mbedtls_mpi_free(&t);mbedtls_mpi_free(&shared);mbedtls_mpi_free(&rr);mbedtls_mpi_free(&upper);
    pair_crypto_wipe(&ctx,sizeof(ctx));pair_crypto_wipe(h,64);pair_crypto_wipe(hn,64);pair_crypto_wipe(hg,64);pair_crypto_wipe(hi,64);
    pair_crypto_wipe(expected,64);pair_crypto_wipe(k,64);pair_crypto_wipe(spad,384);pair_crypto_wipe(npad,384);
    pair_srp_clear(s);s->last_error=backend?backend:r;
    if(r!=IAP2_OK) { pair_crypto_wipe(key,64);pair_crypto_wipe(server_proof,64); }return r;
}
