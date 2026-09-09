/* SPDX-License-Identifier: GPL-3.0-only */
#include "lockdown_bootstrap.h"
static void zero(void *p,size_t n) { size_t i; for(i=0;i<n;++i) ((uint8_t *)p)[i]=0; }
static void copy(uint8_t *d,const uint8_t *s,size_t n) { size_t i; for(i=0;i<n;++i) d[i]=s[i]; }
static int initialized(const lockdown_bootstrap *b) { return b && b->channel && b->request && b->storage.nodes && b->storage.bytes; }
static int active(const lockdown_bootstrap *b) { return b->state<LOCKDOWN_BOOTSTRAP_DETACHED; }
static int held(const lockdown_bootstrap *b) { return b->state>=LOCKDOWN_BOOTSTRAP_VALUE_HELD && b->state<=LOCKDOWN_BOOTSTRAP_TLS_HELD; }
static int event_status(const lockdown_bootstrap *b) {
    return b->state==LOCKDOWN_BOOTSTRAP_TLS_HELD ? LOCKDOWN_BOOTSTRAP_TLS :
           b->state==LOCKDOWN_BOOTSTRAP_ERROR_HELD ? LOCKDOWN_REPLY_REMOTE_ERROR : LOCKDOWN_BOOTSTRAP_VALUE;
}
static void discard(lockdown_bootstrap *b) {
    zero(&b->document,sizeof b->document); zero(&b->reply,sizeof b->reply); b->token=0;
}
static int stop(lockdown_bootstrap *b,enum lockdown_bootstrap_reason reason,int error) {
    if(active(b)) {
        b->state=LOCKDOWN_BOOTSTRAP_DEAD; b->reason=reason; b->last_error=error;
        lockdown_channel_close(b->channel); discard(b);
    }
    return LOCKDOWN_BOOTSTRAP_CLOSED;
}
static int current(lockdown_bootstrap *b,uint64_t now) {
    enum usbmux_connection_state state; int status;
    if(!initialized(b)) return IAP2_ARGUMENT;
    if(!active(b)) return LOCKDOWN_BOOTSTRAP_CLOSED;
    status=usbmux_dispatcher_state(b->channel->dispatcher,&b->channel->handle,&state);
    if(status) return stop(b,status==USBMUX_DISPATCHER_STALE ? LOCKDOWN_BOOTSTRAP_REASON_STALE : LOCKDOWN_BOOTSTRAP_REASON_CHANNEL,status);
    if(now<b->now || now<b->channel->now || now<b->channel->dispatcher->now) return IAP2_ARGUMENT;
    return IAP2_OK;
}
static int writable(lockdown_bootstrap *b,uint64_t now) {
    const usbmux_connection *connection; int status=current(b,now); if(status) return status;
    if(b->state!=LOCKDOWN_BOOTSTRAP_IDLE) return LOCKDOWN_BOOTSTRAP_BUSY;
    if(b->channel->state!=LOCKDOWN_CHANNEL_IDLE) return stop(b,LOCKDOWN_BOOTSTRAP_REASON_STATE,IAP2_INVALID);
    connection=b->channel->dispatcher->connections[b->channel->handle.slot];
    if(connection->state!=USBMUX_CONNECTION_OPEN || connection->peer_fin || connection->fin_requested || connection->fin_sent)
        return stop(b,LOCKDOWN_BOOTSTRAP_REASON_CHANNEL,IAP2_END);
    return IAP2_OK;
}
int lockdown_bootstrap_init(lockdown_bootstrap *b,lockdown_channel *c,const lockdown_body *label,
                            uint8_t *request,size_t capacity,const service_plist_storage *storage,uint64_t now) {
    enum usbmux_connection_state state; const usbmux_connection *connection; size_t i; int status;
    if(!b || !c || !c->dispatcher || !c->rx || !c->tx || !label || !label->data || !label->size || label->size>64 ||
       !request || !capacity || capacity>LOCKDOWN_BOOTSTRAP_REQUEST_LIMIT || !storage || !storage->nodes || !storage->bytes ||
       !storage->node_capacity || storage->node_capacity>SERVICE_PLIST_NODES || !storage->byte_capacity || storage->byte_capacity>SERVICE_PLIST_LIMIT)
        return IAP2_ARGUMENT;
    for(i=0;i<label->size;++i) if(label->data[i]<32 || label->data[i]>126) return IAP2_ARGUMENT;
    status=usbmux_dispatcher_state(c->dispatcher,&c->handle,&state); if(status) return status;
    connection=c->dispatcher->connections[c->handle.slot];
    if(state!=USBMUX_CONNECTION_OPEN || c->state!=LOCKDOWN_CHANNEL_IDLE || c->next_token || connection->tx_size || connection->flight_count ||
       connection->rx_used || connection->peer_fin || connection->fin_requested || connection->fin_sent ||
       connection->tx_next!=connection->initial_sequence+1u || connection->rx_next!=connection->peer_initial+1u) return LOCKDOWN_BOOTSTRAP_BUSY;
    if(connection->remote_port!=62078) return IAP2_UNSUPPORTED;
    if(now<c->now || now<c->dispatcher->now || now<connection->now) return IAP2_ARGUMENT;
    zero(b,sizeof *b); b->channel=c; b->request=request; b->request_capacity=capacity;
    b->storage.nodes=storage->nodes; b->storage.node_capacity=storage->node_capacity;
    b->storage.bytes=storage->bytes; b->storage.byte_capacity=storage->byte_capacity;
    copy(b->label,label->data,label->size); b->label_size=label->size; b->now=now; return IAP2_OK;
}
static int queue(lockdown_bootstrap *b,size_t size,enum lockdown_reply_command command,enum service_plist_type expected,uint64_t now) {
    int status=lockdown_channel_request(b->channel,b->request,size,now);
    if(status) {
        if(status==LOCKDOWN_CHANNEL_CLOSED || status==IAP2_END) return stop(b,LOCKDOWN_BOOTSTRAP_REASON_CHANNEL,status);
        return status;
    }
    discard(b); b->command=command; b->expected=expected; b->state=LOCKDOWN_BOOTSTRAP_PENDING; b->now=now; return IAP2_OK;
}
int lockdown_bootstrap_get_value(lockdown_bootstrap *b,const lockdown_body *key,const lockdown_body *domain,
                                 enum service_plist_type expected,uint64_t now) {
    size_t written; lockdown_body label; int status;
    if(expected<SERVICE_PLIST_NULL || expected>=SERVICE_PLIST_KEY) return IAP2_ARGUMENT;
    status=writable(b,now); if(status) return status;
    label.data=b->label; label.size=b->label_size;
    status=lockdown_get_value_encode(&label,key,domain,b->request,b->request_capacity,&written); if(status) return status;
    return queue(b,written,LOCKDOWN_REPLY_GET_VALUE,expected,now);
}
int lockdown_bootstrap_start_session(lockdown_bootstrap *b,const lockdown_body *host,const lockdown_body *buid,uint64_t now) {
    size_t written; lockdown_body label; int status=writable(b,now); if(status) return status;
    label.data=b->label; label.size=b->label_size;
    status=lockdown_start_session_encode(&label,host,buid,b->request,b->request_capacity,&written); if(status) return status;
    return queue(b,written,LOCKDOWN_REPLY_START_SESSION,SERVICE_PLIST_NULL,now);
}
int lockdown_bootstrap_poll(lockdown_bootstrap *b,uint64_t now) {
    int status=current(b,now); if(status) return status;
    if((b->state==LOCKDOWN_BOOTSTRAP_IDLE && b->channel->state!=LOCKDOWN_CHANNEL_IDLE) ||
       (b->state==LOCKDOWN_BOOTSTRAP_PENDING && b->channel->state!=LOCKDOWN_CHANNEL_EXCHANGE) ||
       (held(b) && (b->channel->state!=LOCKDOWN_CHANNEL_HELD || b->channel->token!=b->token)))
        return stop(b,LOCKDOWN_BOOTSTRAP_REASON_STATE,IAP2_INVALID);
    status=lockdown_channel_poll(b->channel,now); b->now=now;
    if(status!=IAP2_OK && status!=IAP2_MORE && status!=USBMUX_DISPATCHER_CONTROL && status!=LOCKDOWN_CHANNEL_RESPONSE)
        return stop(b,LOCKDOWN_BOOTSTRAP_REASON_CHANNEL,status);
    if(held(b)) return event_status(b);
    if(status!=LOCKDOWN_CHANNEL_RESPONSE) return status;
    if(b->state!=LOCKDOWN_BOOTSTRAP_PENDING) return stop(b,LOCKDOWN_BOOTSTRAP_REASON_STATE,IAP2_INVALID);
    status=lockdown_reply_read(b->channel,&b->storage,b->command,b->expected,&b->document,&b->reply,&b->token);
    if(status==LOCKDOWN_REPLY_REMOTE_ERROR) b->state=LOCKDOWN_BOOTSTRAP_ERROR_HELD;
    else if(status) return stop(b,LOCKDOWN_BOOTSTRAP_REASON_RESPONSE,status);
    else b->state=b->command==LOCKDOWN_REPLY_START_SESSION ? LOCKDOWN_BOOTSTRAP_TLS_HELD : LOCKDOWN_BOOTSTRAP_VALUE_HELD;
    return event_status(b);
}
int lockdown_bootstrap_event(const lockdown_bootstrap *b,const lockdown_reply **reply,uint64_t *token) {
    enum usbmux_connection_state state;
    if(reply) *reply=NULL; if(token) *token=0;
    if(!initialized(b) || !reply || !token) return IAP2_ARGUMENT;
    if(!active(b) || usbmux_dispatcher_state(b->channel->dispatcher,&b->channel->handle,&state)!=IAP2_OK) return LOCKDOWN_BOOTSTRAP_CLOSED;
    if(!held(b)) return IAP2_MORE;
    if(b->channel->state!=LOCKDOWN_CHANNEL_HELD || b->channel->token!=b->token) return LOCKDOWN_BOOTSTRAP_CLOSED;
    *reply=&b->reply; *token=b->token; return event_status(b);
}
int lockdown_bootstrap_release(lockdown_bootstrap *b,uint64_t token,uint64_t now) {
    int status;
    if(!initialized(b)) return IAP2_ARGUMENT;
    if(!held(b) || !token || token!=b->token) return USBMUX_DISPATCHER_STALE;
    if(b->state==LOCKDOWN_BOOTSTRAP_TLS_HELD) return IAP2_UNSUPPORTED;
    status=current(b,now); if(status) return status;
    status=lockdown_channel_release(b->channel,token,now);
    if(status) return status==IAP2_ARGUMENT ? status : stop(b,LOCKDOWN_BOOTSTRAP_REASON_CHANNEL,status);
    discard(b); b->state=LOCKDOWN_BOOTSTRAP_IDLE; b->now=now; return IAP2_OK;
}
int lockdown_bootstrap_take_tls(lockdown_bootstrap *b,uint64_t token,lockdown_tls_handoff *out,uint64_t now) {
    lockdown_tls_handoff handoff; const usbmux_connection *connection; const service_plist_node *session; int status;
    if(out) zero(out,sizeof *out);
    if(!initialized(b) || !out) return IAP2_ARGUMENT;
    if(b->state!=LOCKDOWN_BOOTSTRAP_TLS_HELD || !token || token!=b->token) return USBMUX_DISPATCHER_STALE;
    status=current(b,now); if(status) return status;
    connection=b->channel->dispatcher->connections[b->channel->handle.slot];
    if(connection->state!=USBMUX_CONNECTION_OPEN || connection->peer_fin || connection->fin_requested || connection->fin_sent)
        return stop(b,LOCKDOWN_BOOTSTRAP_REASON_CHANNEL,IAP2_END);
    zero(&handoff,sizeof handoff); session=b->reply.session_id;
    if(!session || !session->size || session->size>sizeof handoff.session_id || !b->reply.tls_required)
        return stop(b,LOCKDOWN_BOOTSTRAP_REASON_STATE,IAP2_INVALID);
    handoff.dispatcher=b->channel->dispatcher; handoff.session_id_size=session->size; copy(handoff.session_id,session->data,session->size);
    status=lockdown_channel_release(b->channel,token,now);
    if(!status) status=lockdown_channel_detach(b->channel,&handoff.handle,now);
    if(status) return status==IAP2_ARGUMENT ? status : stop(b,LOCKDOWN_BOOTSTRAP_REASON_CHANNEL,status);
    out->dispatcher=handoff.dispatcher; out->handle.physical=handoff.handle.physical;
    out->handle.connection=handoff.handle.connection; out->handle.slot=handoff.handle.slot;
    out->session_id_size=handoff.session_id_size; copy(out->session_id,handoff.session_id,handoff.session_id_size);
    discard(b); b->state=LOCKDOWN_BOOTSTRAP_DETACHED; b->now=now; return IAP2_OK;
}
void lockdown_bootstrap_close(lockdown_bootstrap *b) { if(initialized(b)) (void)stop(b,LOCKDOWN_BOOTSTRAP_REASON_LOCAL,LOCKDOWN_BOOTSTRAP_CLOSED); }
uint32_t lockdown_bootstrap_next_delay(const lockdown_bootstrap *b) {
    if(!initialized(b) || !active(b)) return UINT32_MAX;
    return lockdown_channel_next_delay(b->channel);
}
