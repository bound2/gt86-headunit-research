/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_iap.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
static int ms(uint32_t n) { return n&&n<=60000; }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
void projection_iap_default_config(projection_iap_config *c) {
    if(c) { control_cipher_default_config(&c->records);c->package_limit=65536;c->package_ms=10000;c->hold_ms=5000; }
}
int projection_iap_init(projection_iap *s,const projection_iap_config *c,const projection_iap_storage *b,
                        const uint8_t key[32],uint64_t gen,uint64_t now) {
    uint8_t unused[32]={0}; int r;
    if(!s||!c||!b||!key||!gen||c->package_limit<32||c->package_limit>PROJECTION_IAP_MAX_PACKAGE||
       !ms(c->package_ms)||!ms(c->hold_ms)||!b->package||b->package_size<c->package_limit)
        return IAP2_ARGUMENT;
    /* Child validation precedes any mutation; it performs no external action. */
    r=control_cipher_init(&s->cipher,&c->records,b->cipher_rx,b->cipher_rx_size,b->plain,b->plain_size,
                          b->unused_tx,b->unused_tx_size,gen,now);
    if(r!=IAP2_OK) return r;
    s->config=*c;s->storage=*b;s->generation=gen;s->now=now;s->package_at=s->held_at=0;
    s->next_token=1;s->held_token=0;s->used=s->expected=s->offset=0;s->held=s->dead=0;
    s->reason=PROJECTION_IAP_REASON_NONE;s->last_error=IAP2_OK;
    return control_cipher_start(&s->cipher,gen,key,unused,now);
}
static int owner(const projection_iap *s,uint64_t gen) {
    if(!s||!s->generation||!gen) return IAP2_ARGUMENT;
    if(gen!=s->generation) return IAP2_INVALID;
    return s->dead?PROJECTION_IAP_CLOSED:IAP2_OK;
}
static int stop(projection_iap *s,enum projection_iap_reason reason,int error) {
    if(!s->dead) {
        control_cipher_close(&s->cipher);pair_crypto_wipe(s->storage.package,s->config.package_limit);
        s->used=s->expected=s->offset=0;s->held=0;s->held_token=0;s->dead=1;s->reason=reason;s->last_error=error;
    }
    return PROJECTION_IAP_CLOSED;
}
int projection_iap_check(projection_iap *s,uint64_t gen,uint64_t now) {
    int r=owner(s,gen);if(r!=IAP2_OK) return r;
    if(now<s->now) return IAP2_ARGUMENT;s->now=now;
    r=control_cipher_check(&s->cipher,gen,now);
    if(r!=IAP2_OK) return stop(s,PROJECTION_IAP_REASON_CIPHER,s->cipher.last_error);
    if((s->held&&now-s->held_at>=s->config.hold_ms)||
       (!s->held&&s->used&&now-s->package_at>=s->config.package_ms))
        return stop(s,PROJECTION_IAP_REASON_DEADLINE,IAP2_MORE);
    return IAP2_OK;
}
/* Consume only a bounded prefix of ONE authenticated record, ending at the
 * first package boundary. Further packages stay in cipher-owned plaintext. */
static int drain(projection_iap *s) {
    rtsp_slice p;control_cipher_key key;size_t n,at=0;int r;
    r=control_cipher_plain(&s->cipher,&p,&key);if(r!=CONTROL_CIPHER_FRAME) return r;
    if(!p.size) return control_cipher_consume_plain(&s->cipher,key,0,s->now)==IAP2_OK?IAP2_MORE:
        stop(s,PROJECTION_IAP_REASON_CIPHER,s->cipher.last_error);
    if(!s->used) s->package_at=s->now;
    if(s->used<32) {
        n=32-s->used;if(n>p.size) n=p.size;
        copy(s->storage.package+s->used,p.data,n);s->used+=n;at+=n;
        if(s->used==32) {
            s->expected=be32(s->storage.package);
            if(s->expected<32||s->expected>s->config.package_limit)
                return stop(s,PROJECTION_IAP_REASON_SIZE,IAP2_NO_SPACE);
        }
    }
    if(s->used>=32) {
        n=s->expected-s->used;if(n>p.size-at) n=p.size-at;
        copy(s->storage.package+s->used,p.data+at,n);s->used+=n;at+=n;
    }
    r=control_cipher_consume_plain(&s->cipher,key,at,s->now);
    if(r!=IAP2_OK&&r!=CONTROL_CIPHER_FRAME) return stop(s,PROJECTION_IAP_REASON_CIPHER,s->cipher.last_error);
    if(s->used<32||s->used!=s->expected) return IAP2_MORE;
    if(be32(s->storage.package+16)!=PROJECTION_IAP_COMM) {
        pair_crypto_wipe(s->storage.package,s->used);s->used=s->expected=0;
        return PROJECTION_IAP_IGNORED;
    }
    if(!s->next_token) return stop(s,PROJECTION_IAP_REASON_EXHAUSTED,IAP2_UNSUPPORTED);
    s->held_token=s->next_token;s->next_token=s->next_token==UINT64_MAX?0:s->next_token+1;
    s->held=1;s->held_at=s->now;s->offset=32;return PROJECTION_IAP_PACKAGE;
}
int projection_iap_feed(projection_iap *s,uint64_t gen,const uint8_t *p,size_t n,size_t *used,uint64_t now) {
    int r;if(used) *used=0;if(!used||(!p&&n)) return IAP2_ARGUMENT;
    r=projection_iap_check(s,gen,now);if(r!=IAP2_OK) return r;
    if(s->held) return PROJECTION_IAP_BUSY;
    if(s->cipher.held) return drain(s);
    r=control_cipher_feed(&s->cipher,gen,p,n,used,now);
    if(r==CONTROL_CIPHER_FRAME) return drain(s);
    if(r==CONTROL_CIPHER_CLOSED) return stop(s,PROJECTION_IAP_REASON_CIPHER,s->cipher.last_error);
    return r;
}
int projection_iap_peek(const projection_iap *s,uint64_t gen,projection_iap_view *v,projection_iap_key *key) {
    int r;if(v) pair_crypto_wipe(v,sizeof(*v));if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!v||!key) return IAP2_ARGUMENT;r=owner(s,gen);if(r!=IAP2_OK) return r;
    if(!s->held) return IAP2_MORE;
    v->header.data=s->storage.package;v->header.size=32;
    v->body.data=s->storage.package+s->offset;v->body.size=s->expected-s->offset;
    key->generation=gen;key->token=s->held_token;return PROJECTION_IAP_PACKAGE;
}
int projection_iap_consume(projection_iap *s,projection_iap_key key,size_t n,uint64_t now) {
    int r=owner(s,key.generation);if(r!=IAP2_OK) return r;
    if(!s->held||key.token!=s->held_token) return IAP2_INVALID;
    if(n>s->expected-s->offset||(!n&&s->offset!=s->expected)) return IAP2_ARGUMENT;
    r=projection_iap_check(s,key.generation,now);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(s->storage.package+s->offset,n);s->offset+=n;
    if(s->offset!=s->expected) return PROJECTION_IAP_PACKAGE;
    pair_crypto_wipe(s->storage.package,32);s->used=s->expected=s->offset=0;s->held=0;s->held_token=0;return IAP2_OK;
}
int projection_iap_eof(projection_iap *s,uint64_t gen,uint64_t now) {
    int r=projection_iap_check(s,gen,now);return r==IAP2_OK?stop(s,PROJECTION_IAP_REASON_EOF,IAP2_END):r;
}
void projection_iap_close(projection_iap *s) { if(s&&s->generation) (void)stop(s,PROJECTION_IAP_REASON_LOCAL,IAP2_OK); }
static uint32_t remaining(uint64_t now,uint64_t at,uint32_t budget) { return now-at>=budget?0:budget-(uint32_t)(now-at); }
uint32_t projection_iap_next_delay(const projection_iap *s) {
    uint32_t delay,n;if(!s||!s->generation||s->dead) return UINT32_MAX;
    delay=control_cipher_next_delay(&s->cipher);
    if(s->held||s->used) {
        n=remaining(s->now,s->held?s->held_at:s->package_at,s->held?s->config.hold_ms:s->config.package_ms);
        if(n<delay) delay=n;
    }
    if(!s->held&&s->cipher.held) return 0;
    return delay;
}
