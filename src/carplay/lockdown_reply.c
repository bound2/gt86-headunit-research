/* SPDX-License-Identifier: GPL-3.0-only */
#include "lockdown_reply.h"
static void zero(void *p,size_t n) { size_t i; for(i=0;i<n;++i) ((uint8_t *)p)[i]=0; }
static size_t length(const char *s) { size_t n=0; while(s[n]) ++n; return n; }
static int text_is(const service_plist_node *v,const char *s) {
    size_t i,n=length(s); if(!v || v->type!=SERVICE_PLIST_STRING || v->size!=n) return 0;
    for(i=0;i<n;++i) if(v->data[i]!=(uint8_t)s[i]) return 0; return 1;
}
static const service_plist_node *field(const service_plist_document *d,const char *key) {
    const service_plist_node *v=NULL;
    (void)service_plist_find(d,&d->nodes[0],(const uint8_t *)key,length(key),&v); return v;
}
static int string(const service_plist_node *v,size_t maximum,int ascii) {
    size_t i;
    if(!v || v->type!=SERVICE_PLIST_STRING || !v->size || v->size>maximum) return 0;
    if(ascii) for(i=0;i<v->size;++i) if(v->data[i]<32 || v->data[i]>126) return 0;
    return 1;
}
int lockdown_reply_validate(const service_plist_document *doc,enum lockdown_reply_command command,
                            enum service_plist_type expected,lockdown_reply *out) {
    static const char *const names[]={"GetValue","StartSession","StartService","Pair"};
    const service_plist_node *error,*message,*description,*value,*ssl; lockdown_reply result;
    if(out) zero(out,sizeof *out);
    if(!out || !doc || !doc->nodes || !doc->count || command<LOCKDOWN_REPLY_GET_VALUE || command>LOCKDOWN_REPLY_PAIR ||
       expected<SERVICE_PLIST_NULL || expected>=SERVICE_PLIST_KEY || (command!=LOCKDOWN_REPLY_GET_VALUE && expected!=SERVICE_PLIST_NULL)) return IAP2_ARGUMENT;
    if(doc->nodes[0].type!=SERVICE_PLIST_DICT || !text_is(field(doc,"Request"),names[command])) return IAP2_INVALID;
    zero(&result,sizeof result); error=field(doc,"Error"); message=field(doc,"ErrorString"); description=field(doc,"ErrorDescription");
    if(error) {
        if((error->type!=SERVICE_PLIST_INTEGER && !string(error,256,0)) ||
           (message && !string(message,512,0)) || (description && !string(description,1024,0))) return IAP2_INVALID;
        out->error=error; out->error_string=message; out->error_description=description; return LOCKDOWN_REPLY_REMOTE_ERROR;
    }
    if(message || description) return IAP2_INVALID; /* Error metadata without Error is ambiguous. */
    if(command==LOCKDOWN_REPLY_GET_VALUE) {
        value=field(doc,"Value"); if(!value || value->type!=(uint8_t)expected) return IAP2_INVALID; result.value=value;
    } else if(command==LOCKDOWN_REPLY_START_SESSION) {
        value=field(doc,"SessionID"); ssl=field(doc,"EnableSessionSSL");
        if(!string(value,256,1) || !ssl || ssl->type!=SERVICE_PLIST_BOOL) return IAP2_INVALID;
        if(!ssl->magnitude) return IAP2_AUTH_FAILED;
        result.session_id=value; result.tls_required=result.tls_flag_present=1;
    } else if(command==LOCKDOWN_REPLY_START_SERVICE) {
        value=field(doc,"Port"); ssl=field(doc,"EnableServiceSSL");
        if(!value || value->type!=SERVICE_PLIST_INTEGER || value->negative || !value->magnitude || value->magnitude>65535 ||
           (ssl && ssl->type!=SERVICE_PLIST_BOOL)) return IAP2_INVALID;
        result.port=(uint16_t)value->magnitude; result.tls_flag_present=(uint8_t)(ssl!=NULL);
        result.tls_required=(uint8_t)(ssl && ssl->magnitude);
    } else {
        value=field(doc,"EscrowBag"); if(value && value->type!=SERVICE_PLIST_DATA) return IAP2_INVALID; result.escrow_bag=value;
    }
    out->value=result.value; out->session_id=result.session_id; out->escrow_bag=result.escrow_bag;
    out->port=result.port; out->tls_required=result.tls_required; out->tls_flag_present=result.tls_flag_present;
    return IAP2_OK;
}
int lockdown_reply_read(const lockdown_channel *channel,const service_plist_storage *storage,
                        enum lockdown_reply_command command,enum service_plist_type expected,
                        service_plist_document *doc,lockdown_reply *reply,uint64_t *token) {
    lockdown_body body; uint64_t current; int status;
    if(doc) zero(doc,sizeof *doc); if(reply) zero(reply,sizeof *reply); if(token) *token=0;
    if(!doc || !reply || !token) return IAP2_ARGUMENT;
    status=lockdown_channel_response(channel,&body,&current); if(status!=LOCKDOWN_CHANNEL_RESPONSE) return status;
    status=service_plist_decode(body.data,body.size,storage,doc); if(status) return status;
    status=lockdown_reply_validate(doc,command,expected,reply);
    if(status==IAP2_OK || status==LOCKDOWN_REPLY_REMOTE_ERROR) *token=current;
    else zero(doc,sizeof *doc);
    return status;
}
