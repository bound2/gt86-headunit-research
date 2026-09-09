/* SPDX-License-Identifier: GPL-3.0-only */
#include "control_cipher.h"
static void copy(uint8_t *d,const uint8_t *s,size_t n) { while(n--) *d++=*s++; }
static int ms(uint32_t n) { return n&&n<=60000; }
void control_cipher_default_config(control_cipher_config *c) {
    if(c) { c->payload_limit=CONTROL_CIPHER_MAX_PAYLOAD;c->receive_ms=10000;c->hold_ms=c->output_ms=5000; }
}
int control_cipher_init(control_cipher *c,const control_cipher_config *cfg,uint8_t *rx,size_t nr,
                         uint8_t *plain,size_t np,uint8_t *tx,size_t nt,uint64_t gen,uint64_t now) {
    if(!c||!cfg||!cfg->payload_limit||cfg->payload_limit>CONTROL_CIPHER_MAX_PAYLOAD||
       !ms(cfg->receive_ms)||!ms(cfg->hold_ms)||!ms(cfg->output_ms)||!rx||!plain||!tx||!gen||
       nr<cfg->payload_limit+18u||np<cfg->payload_limit||nt<cfg->payload_limit+18u) return IAP2_ARGUMENT;
    pair_crypto_wipe(c,sizeof(*c));c->rx=rx;c->plain=plain;c->tx=tx;c->config=*cfg;
    c->generation=gen;c->now=now;c->state=CONTROL_CIPHER_DORMANT;return IAP2_OK;
}
static int stop(control_cipher *c,enum control_cipher_reason reason,int error) {
    if(c->state!=CONTROL_CIPHER_DEAD) {
        pair_crypto_wipe(c->rx,c->config.payload_limit+18u);pair_crypto_wipe(c->plain,c->config.payload_limit);
        pair_crypto_wipe(c->tx,c->config.payload_limit+18u);pair_crypto_wipe(c->read_key,32);pair_crypto_wipe(c->write_key,32);
        c->rx_used=c->rx_expected=c->plain_size=c->plain_offset=c->tx_size=c->tx_offset=0;c->held=0;
        c->state=CONTROL_CIPHER_DEAD;c->reason=reason;c->last_error=error;
    }
    return CONTROL_CIPHER_CLOSED;
}
static int owner(const control_cipher *c,uint64_t gen) {
    if(!c||!c->generation||!gen) return IAP2_ARGUMENT;
    if(gen!=c->generation) return IAP2_INVALID;
    return c->state==CONTROL_CIPHER_DEAD?CONTROL_CIPHER_CLOSED:IAP2_OK;
}
int control_cipher_check(control_cipher *c,uint64_t gen,uint64_t now) {
    int r=owner(c,gen);if(r!=IAP2_OK) return r;
    if(now<c->now) return IAP2_ARGUMENT;c->now=now;
    if((c->rx_used&&now-c->rx_at>=c->config.receive_ms)||
       (c->held&&now-c->held_at>=c->config.hold_ms)||
       (c->tx_size&&now-c->tx_at>=c->config.output_ms))
        return stop(c,CONTROL_CIPHER_REASON_DEADLINE,IAP2_MORE);
    return IAP2_OK;
}
int control_cipher_start(control_cipher *c,uint64_t gen,const uint8_t read[32],const uint8_t write[32],uint64_t now) {
    int r=owner(c,gen);if(r!=IAP2_OK) return r;
    if(!read||!write) return IAP2_ARGUMENT;
    if(c->state!=CONTROL_CIPHER_DORMANT) return CONTROL_CIPHER_BUSY;
    r=control_cipher_check(c,gen,now);if(r!=IAP2_OK) return r;
    copy(c->read_key,read,32);copy(c->write_key,write,32);c->state=CONTROL_CIPHER_ACTIVE;return IAP2_OK;
}
static void nonce64(uint8_t out[12],uint64_t n) {
    size_t i;pair_crypto_wipe(out,12);for(i=0;i<8;++i) { out[i+4]=(uint8_t)n;n>>=8; }
}
static void advance(uint64_t *counter,uint8_t *exhausted) { if(*counter==UINT64_MAX) *exhausted=1;else ++*counter; }
int control_cipher_feed(control_cipher *c,uint64_t gen,const uint8_t *p,size_t n,size_t *used,uint64_t now) {
    size_t take,written=0;uint8_t nonce[12];int r;
    if(used) *used=0;if(!used||(!p&&n)) return IAP2_ARGUMENT;
    r=control_cipher_check(c,gen,now);if(r!=IAP2_OK) return r;
    if(c->state!=CONTROL_CIPHER_ACTIVE||c->held) return CONTROL_CIPHER_BUSY;
    if(!n) return IAP2_MORE;
    if(c->read_exhausted) return stop(c,CONTROL_CIPHER_REASON_EXHAUSTED,IAP2_UNSUPPORTED);
    if(!c->rx_used) c->rx_at=now;
    if(c->rx_used<2) {
        take=2-c->rx_used;if(take>n) take=n;copy(c->rx+c->rx_used,p,take);c->rx_used+=take;*used+=take;p+=take;n-=take;
        if(c->rx_used<2) return IAP2_MORE;
        take=(size_t)c->rx[0]+((size_t)c->rx[1]<<8);
        if(take>c->config.payload_limit) return stop(c,CONTROL_CIPHER_REASON_PROTOCOL,IAP2_NO_SPACE);
        c->rx_expected=take+18;
    }
    take=c->rx_expected-c->rx_used;if(take>n) take=n;copy(c->rx+c->rx_used,p,take);c->rx_used+=take;*used+=take;
    if(c->rx_used<c->rx_expected) return IAP2_MORE;
    nonce64(nonce,c->read_counter);
    r=pair_aead_open(c->read_key,nonce,c->rx,2,c->rx+2,c->rx_expected-2,c->plain,c->config.payload_limit,&written);
    pair_crypto_wipe(nonce,sizeof(nonce));
    if(r!=IAP2_OK) return stop(c,CONTROL_CIPHER_REASON_AUTH,r);
    c->plain_size=written;c->plain_offset=0;c->held=1;c->held_at=now;c->held_counter=c->read_counter;
    advance(&c->read_counter,&c->read_exhausted);pair_crypto_wipe(c->rx,c->rx_used);c->rx_used=c->rx_expected=0;
    return CONTROL_CIPHER_FRAME;
}
int control_cipher_plain(const control_cipher *c,rtsp_slice *out,control_cipher_key *key) {
    if(out) pair_crypto_wipe(out,sizeof(*out));if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!c||!c->generation||!out||!key) return IAP2_ARGUMENT;
    if(c->state==CONTROL_CIPHER_DEAD) return CONTROL_CIPHER_CLOSED;
    if(!c->held) return IAP2_MORE;
    out->data=c->plain+c->plain_offset;out->size=c->plain_size-c->plain_offset;
    key->generation=c->generation;key->counter=c->held_counter;return CONTROL_CIPHER_FRAME;
}
int control_cipher_consume_plain(control_cipher *c,control_cipher_key key,size_t n,uint64_t now) {
    int r=owner(c,key.generation);if(r!=IAP2_OK) return r;
    if(!c->held||key.counter!=c->held_counter) return IAP2_INVALID;
    if(n>c->plain_size-c->plain_offset||(!n&&c->plain_size!=c->plain_offset)) return IAP2_ARGUMENT;
    r=control_cipher_check(c,key.generation,now);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(c->plain+c->plain_offset,n);c->plain_offset+=n;
    if(c->plain_offset!=c->plain_size) return CONTROL_CIPHER_FRAME;
    c->held=0;c->plain_size=c->plain_offset=0;return IAP2_OK;
}
int control_cipher_queue(control_cipher *c,uint64_t gen,const uint8_t *p,size_t n,uint64_t now) {
    uint8_t nonce[12];size_t written=0;int r=owner(c,gen);if(r!=IAP2_OK) return r;
    if((!p&&n)||n>c->config.payload_limit) return IAP2_ARGUMENT;
    if(c->state!=CONTROL_CIPHER_ACTIVE||c->tx_size) return CONTROL_CIPHER_BUSY;
    r=control_cipher_check(c,gen,now);if(r!=IAP2_OK) return r;
    if(c->write_exhausted) return stop(c,CONTROL_CIPHER_REASON_EXHAUSTED,IAP2_UNSUPPORTED);
    c->tx[0]=(uint8_t)n;c->tx[1]=(uint8_t)(n>>8);nonce64(nonce,c->write_counter);
    r=pair_aead_seal(c->write_key,nonce,c->tx,2,p,n,c->tx+2,c->config.payload_limit+16u,&written);
    pair_crypto_wipe(nonce,sizeof(nonce));
    if(r!=IAP2_OK) return stop(c,CONTROL_CIPHER_REASON_PROTOCOL,r);
    c->tx_size=written+2;c->tx_offset=0;c->tx_at=now;c->output_counter=c->write_counter;
    advance(&c->write_counter,&c->write_exhausted);return CONTROL_CIPHER_OUTPUT;
}
int control_cipher_output(const control_cipher *c,rtsp_slice *out,control_cipher_key *key) {
    if(out) pair_crypto_wipe(out,sizeof(*out));if(key) pair_crypto_wipe(key,sizeof(*key));
    if(!c||!c->generation||!out||!key) return IAP2_ARGUMENT;
    if(c->state==CONTROL_CIPHER_DEAD) return CONTROL_CIPHER_CLOSED;
    if(!c->tx_size) return IAP2_MORE;
    out->data=c->tx+c->tx_offset;out->size=c->tx_size-c->tx_offset;
    key->generation=c->generation;key->counter=c->output_counter;return CONTROL_CIPHER_OUTPUT;
}
int control_cipher_consume_output(control_cipher *c,control_cipher_key key,size_t n,uint64_t now) {
    int r=owner(c,key.generation);if(r!=IAP2_OK) return r;
    if(!c->tx_size||key.counter!=c->output_counter) return IAP2_INVALID;
    if(!n||n>c->tx_size-c->tx_offset) return IAP2_ARGUMENT;
    r=control_cipher_check(c,key.generation,now);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(c->tx+c->tx_offset,n);c->tx_offset+=n;
    if(c->tx_offset<c->tx_size) return CONTROL_CIPHER_OUTPUT;
    c->tx_size=c->tx_offset=0;return IAP2_OK;
}
int control_cipher_eof(control_cipher *c,uint64_t gen,uint64_t now) {
    int r=control_cipher_check(c,gen,now);return r==IAP2_OK?stop(c,CONTROL_CIPHER_REASON_EOF,IAP2_END):r;
}
void control_cipher_close(control_cipher *c) { if(c&&c->generation) (void)stop(c,CONTROL_CIPHER_REASON_LOCAL,IAP2_OK); }
static uint32_t remaining(uint64_t now,uint64_t at,uint32_t budget) { return now-at>=budget?0:budget-(uint32_t)(now-at); }
uint32_t control_cipher_next_delay(const control_cipher *c) {
    uint32_t delay=UINT32_MAX,n;if(!c||!c->generation||c->state!=CONTROL_CIPHER_ACTIVE) return delay;
    if(c->rx_used) delay=remaining(c->now,c->rx_at,c->config.receive_ms);
    if(c->held) { n=remaining(c->now,c->held_at,c->config.hold_ms);if(n<delay) delay=n; }
    if(c->tx_size) { n=remaining(c->now,c->tx_at,c->config.output_ms);if(n<delay) delay=n; }
    return delay;
}
