/* SPDX-License-Identifier: GPL-3.0-only */
#include "rtsp_channel.h"
static void zero(void *p, size_t n) { volatile uint8_t *q=(volatile uint8_t *)p; while(n--) *q++=0; }
static int valid_ms(uint32_t n) { return n&&n<=60000; }
static int valid_config(const rtsp_channel_config *c) {
    return c&&valid_ms(c->idle_ms)&&valid_ms(c->receive_ms)&&valid_ms(c->reply_ms)&&valid_ms(c->output_ms);
}
void rtsp_channel_default_config(rtsp_channel_config *c) {
    if(c) { c->idle_ms=30000; c->receive_ms=10000; c->reply_ms=c->output_ms=5000; }
}
int rtsp_channel_init(rtsp_channel *c, const rtsp_channel_config *cfg, uint8_t *rx, size_t nr,
                       uint8_t *tx, size_t nt, uint64_t generation, uint64_t now) {
    if(!c||!valid_config(cfg)||!rx||!tx||nr<64||nr>RTSP_MAX_MESSAGE_SIZE||nt<64||
       nt>RTSP_MAX_MESSAGE_SIZE||!generation) return IAP2_ARGUMENT;
    zero(c,sizeof(*c));
    (void)rtsp_stream_init(&c->input,rx,nr); c->tx=tx; c->tx_capacity=nt; c->config=*cfg;
    c->generation=generation; c->next_token=1; c->now=c->phase_at=now;
    c->state=RTSP_CHANNEL_RECEIVING; return IAP2_OK;
}
static int stop(rtsp_channel *c, enum rtsp_channel_reason why, int error) {
    if(c->state!=RTSP_CHANNEL_DEAD) {
        rtsp_stream_clear(&c->input); zero(c->tx,c->tx_size);
        c->tx_size=c->tx_offset=0; c->token=0;
        c->reason=why; c->last_error=error; c->state=RTSP_CHANNEL_DEAD;
    }
    return RTSP_CHANNEL_CLOSED;
}
static int owner(const rtsp_channel *c, uint64_t generation) {
    if(!c||!c->generation||!generation) return IAP2_ARGUMENT;
    if(generation!=c->generation) return IAP2_INVALID;
    return c->state==RTSP_CHANNEL_DEAD?RTSP_CHANNEL_CLOSED:IAP2_OK;
}
static int key_check(const rtsp_channel *c, rtsp_channel_key key) {
    int r=owner(c,key.generation); if(r!=IAP2_OK) return r;
    return key.token&&key.token==c->token?IAP2_OK:IAP2_INVALID;
}
static uint32_t budget(const rtsp_channel *c) {
    switch(c->state) {
        case RTSP_CHANNEL_RECEIVING:return c->input.used?c->config.receive_ms:c->config.idle_ms;
        case RTSP_CHANNEL_HELD:return c->config.reply_ms;
        default:return c->config.output_ms;
    }
}
int rtsp_channel_check(rtsp_channel *c, uint64_t generation, uint64_t now) {
    int r=owner(c,generation); if(r!=IAP2_OK) return r;
    if(now<c->now) return IAP2_ARGUMENT;
    c->now=now;
    if(now-c->phase_at>=budget(c)) return stop(c,RTSP_CHANNEL_REASON_DEADLINE,IAP2_MORE);
    return IAP2_OK;
}
int rtsp_channel_feed(rtsp_channel *c, uint64_t generation, const uint8_t *p, size_t n,
                      size_t *used, uint64_t now) {
    int r; rtsp_message m;
    if(used) *used=0;
    if(!used||(!p&&n)) return IAP2_ARGUMENT;
    r=rtsp_channel_check(c,generation,now); if(r!=IAP2_OK) return r;
    if(c->state!=RTSP_CHANNEL_RECEIVING) return RTSP_BUSY;
    if(!c->input.used&&n) c->phase_at=now;
    r=rtsp_stream_feed(&c->input,p,n,used);
    if(r==IAP2_MORE) return r;
    if(r!=IAP2_OK) return stop(c,RTSP_CHANNEL_REASON_PROTOCOL,r);
    r=rtsp_stream_message(&c->input,&m);
    if(r!=IAP2_OK||m.kind!=RTSP_REQUEST||!c->next_token)
        return stop(c,RTSP_CHANNEL_REASON_PROTOCOL,r!=IAP2_OK?r:IAP2_UNSUPPORTED);
    c->token=c->next_token++; c->phase_at=now; c->state=RTSP_CHANNEL_HELD;
    return RTSP_CHANNEL_REQUEST;
}
int rtsp_channel_request(const rtsp_channel *c, rtsp_message *m, rtsp_channel_key *key) {
    int r;
    if(m) zero(m,sizeof(*m)); if(key) zero(key,sizeof(*key));
    if(!c||!m||!key||!c->generation) return IAP2_ARGUMENT;
    if(c->state==RTSP_CHANNEL_DEAD) return RTSP_CHANNEL_CLOSED;
    if(c->state!=RTSP_CHANNEL_HELD) return IAP2_MORE;
    r=rtsp_stream_message(&c->input,m); if(r!=IAP2_OK) return r;
    key->generation=c->generation; key->token=c->token; return RTSP_CHANNEL_REQUEST;
}
int rtsp_channel_respond(rtsp_channel *c, rtsp_channel_key key, const rtsp_response *res, uint64_t now) {
    rtsp_message req; size_t n=0; int r=key_check(c,key); if(r!=IAP2_OK) return r;
    if(c->state!=RTSP_CHANNEL_HELD) return RTSP_BUSY;
    if(!res||res->status<200) return IAP2_ARGUMENT;
    r=rtsp_stream_message(&c->input,&req); if(r!=IAP2_OK) return r;
    r=rtsp_response_encode(&req,res,0,0,&n); if(r!=IAP2_OK) return r;
    if(n>c->tx_capacity) return IAP2_NO_SPACE;
    r=rtsp_channel_check(c,key.generation,now); if(r!=IAP2_OK) return r;
    r=rtsp_response_encode(&req,res,c->tx,c->tx_capacity,&n);
    if(r!=IAP2_OK) return stop(c,RTSP_CHANNEL_REASON_PROTOCOL,r);
    c->tx_size=n; c->tx_offset=0; c->phase_at=now; c->state=RTSP_CHANNEL_SENDING;
    return RTSP_CHANNEL_OUTPUT;
}
int rtsp_channel_output(rtsp_channel *c, rtsp_channel_key key, rtsp_slice *out, uint64_t now) {
    int r; if(out) zero(out,sizeof(*out)); if(!out) return IAP2_ARGUMENT;
    r=key_check(c,key); if(r!=IAP2_OK) return r;
    r=rtsp_channel_check(c,key.generation,now); if(r!=IAP2_OK) return r;
    if(c->state==RTSP_CHANNEL_SENT) return RTSP_CHANNEL_OUTPUT_DONE;
    if(c->state!=RTSP_CHANNEL_SENDING) return RTSP_BUSY;
    out->data=c->tx+c->tx_offset; out->size=c->tx_size-c->tx_offset;
    return RTSP_CHANNEL_OUTPUT;
}
int rtsp_channel_consume(rtsp_channel *c, rtsp_channel_key key, size_t n, uint64_t now) {
    int r=key_check(c,key); if(r!=IAP2_OK) return r;
    if(c->state!=RTSP_CHANNEL_SENDING) return RTSP_BUSY;
    if(!n||n>c->tx_size-c->tx_offset) return IAP2_ARGUMENT;
    r=rtsp_channel_check(c,key.generation,now); if(r!=IAP2_OK) return r;
    zero(c->tx+c->tx_offset,n); c->tx_offset+=n;
    if(c->tx_offset!=c->tx_size) return RTSP_CHANNEL_OUTPUT;
    c->state=RTSP_CHANNEL_SENT; return RTSP_CHANNEL_OUTPUT_DONE;
}
int rtsp_channel_release(rtsp_channel *c, rtsp_channel_key key, uint64_t now) {
    int r=key_check(c,key); if(r!=IAP2_OK) return r;
    if(c->state!=RTSP_CHANNEL_SENT) return RTSP_BUSY;
    r=rtsp_channel_check(c,key.generation,now); if(r!=IAP2_OK) return r;
    rtsp_stream_clear(&c->input); c->tx_size=c->tx_offset=0; c->token=0;
    c->state=RTSP_CHANNEL_RECEIVING; c->phase_at=now; return IAP2_OK;
}
int rtsp_channel_eof(rtsp_channel *c, uint64_t generation, uint64_t now) {
    int r=rtsp_channel_check(c,generation,now); if(r!=IAP2_OK) return r;
    return stop(c,RTSP_CHANNEL_REASON_EOF,IAP2_END);
}
void rtsp_channel_close(rtsp_channel *c) {
    if(c&&c->generation) (void)stop(c,RTSP_CHANNEL_REASON_LOCAL,IAP2_END);
}
uint32_t rtsp_channel_next_delay(const rtsp_channel *c) {
    uint64_t elapsed; uint32_t ms;
    if(!c||!c->generation||c->state==RTSP_CHANNEL_DEAD) return UINT32_MAX;
    ms=budget(c); elapsed=c->now-c->phase_at;
    return elapsed>=ms?0:ms-(uint32_t)elapsed;
}
