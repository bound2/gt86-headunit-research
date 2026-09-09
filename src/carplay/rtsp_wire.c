/* SPDX-License-Identifier: GPL-3.0-only */
#include "rtsp_wire.h"

static void zero(void *p, size_t n) { volatile uint8_t *q=(volatile uint8_t *)p; while(n--) *q++=0; }
static void copy(uint8_t *d, const uint8_t *s, size_t n) { while(n--) *d++=*s++; }
static uint8_t lower(uint8_t c) { return c>='A'&&c<='Z'?(uint8_t)(c+32):c; }
static rtsp_slice slice(const uint8_t *p, size_t n) { rtsp_slice s; s.data=p; s.size=n; return s; }
static size_t length(const char *s) { size_t n=0; while(s[n]) ++n; return n; }
static int eq(rtsp_slice a, const char *b) {
    size_t i,n=length(b); if(a.size!=n) return 0;
    for(i=0;i<n;++i) if(a.data[i]!=(uint8_t)b[i]) return 0;
    return 1;
}
static int same(rtsp_slice a, rtsp_slice b) {
    size_t i; if(a.size!=b.size) return 0;
    for(i=0;i<a.size;++i) if(lower(a.data[i])!=lower(b.data[i])) return 0;
    return 1;
}
static int named(rtsp_slice a, const char *b) { return same(a,slice((const uint8_t *)b,length(b))); }
static int token_byte(uint8_t c) {
    if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')) return 1;
    switch(c) { case '!':case '#':case '$':case '%':case '&':case '\'':case '*':case '+':
        case '-':case '.':case '^':case '_':case '`':case '|':case '~': return 1; default:return 0; }
}
static int token(rtsp_slice s) {
    size_t i; if(!s.data||!s.size) return 0;
    for(i=0;i<s.size;++i) if(!token_byte(s.data[i])) return 0;
    return 1;
}
static int printable(rtsp_slice s, int whitespace) {
    size_t i; if(!s.data&&s.size) return 0;
    for(i=0;i<s.size;++i) {
        uint8_t c=s.data[i]; if(whitespace&&c=='\t') continue;
        if(c<(whitespace?32:33)||c>126) return 0;
    }
    return 1;
}
static int decimal(rtsp_slice s, uint32_t max, uint32_t *out) {
    size_t i; uint32_t n=0; if(!s.size) return IAP2_INVALID;
    for(i=0;i<s.size;++i) {
        uint32_t d=(uint32_t)s.data[i]-'0';
        if(d>9||n>max/10u||(n==max/10u&&d>max%10u)) return IAP2_INVALID;
        n=n*10u+d;
    }
    *out=n; return IAP2_OK;
}
static int protocol(rtsp_slice s, enum rtsp_protocol *p) {
    if(eq(s,"RTSP/1.0")) *p=RTSP_10;
    else if(eq(s,"HTTP/1.0")) *p=RTSP_HTTP_10;
    else if(eq(s,"HTTP/1.1")) *p=RTSP_HTTP_11;
    else return IAP2_UNSUPPORTED;
    return IAP2_OK;
}
static const char *protocol_text(enum rtsp_protocol p) {
    switch(p) { case RTSP_10:return "RTSP/1.0";case RTSP_HTTP_10:return "HTTP/1.0";
        case RTSP_HTTP_11:return "HTTP/1.1";default:return 0; }
}
/* Stop scanning at the header delimiter; arbitrary binary body bytes follow. */
static int header_end(const uint8_t *p, size_t n, size_t *end) {
    size_t i; if(n&&p[0]=='$') return IAP2_UNSUPPORTED;
    for(i=0;i<n&&i<RTSP_MAX_HEADER_SIZE;++i) {
        uint8_t c=p[i];
        if(i&&p[i-1]=='\r'&&c!='\n') return IAP2_INVALID;
        if(c=='\n'&&(!i||p[i-1]!='\r')) return IAP2_INVALID;
        if(c!='\r'&&c!='\n'&&c!='\t'&&(c<32||c>126)) return IAP2_INVALID;
        if(i>=3&&p[i-3]=='\r'&&p[i-2]=='\n'&&p[i-1]=='\r'&&c=='\n') { *end=i+1; return IAP2_OK; }
    }
    return n>=RTSP_MAX_HEADER_SIZE?IAP2_NO_SPACE:IAP2_MORE;
}
static int parse_header(const uint8_t *p, size_t end, rtsp_message *m, size_t *body) {
    size_t line=0,a,b,pos,count=0; uint32_t v=0; int r,cl=0;
    zero(m,sizeof(*m)); *body=0;
    while(line+1<end&&p[line]!='\r') ++line;
    if(line+1>=end||!line) return IAP2_INVALID;
    for(a=0;a<line&&p[a]!=' ';++a) {}
    if(!a||a==line) return IAP2_INVALID;
    for(b=a+1;b<line&&p[b]!=' ';++b) {}
    if(b==a+1||b==line) return IAP2_INVALID;
    if((a>=5&&p[0]=='R'&&p[1]=='T'&&p[2]=='S'&&p[3]=='P'&&p[4]=='/')||
       (a>=5&&p[0]=='H'&&p[1]=='T'&&p[2]=='T'&&p[3]=='P'&&p[4]=='/')) {
        m->kind=RTSP_RESPONSE;
        r=protocol(slice(p,a),&m->protocol); if(r!=IAP2_OK) return r;
        if(b-a-1!=3||decimal(slice(p+a+1,3),599,&v)!=IAP2_OK||v<100) return IAP2_INVALID;
        m->status=(uint16_t)v; m->reason=slice(p+b+1,line-b-1);
        if(!printable(m->reason,1)) return IAP2_INVALID;
    } else {
        m->kind=RTSP_REQUEST; m->method=slice(p,a); m->target=slice(p+a+1,b-a-1);
        if(a>32||!token(m->method)||!printable(m->target,0)) return IAP2_INVALID;
        r=protocol(slice(p+b+1,line-b-1),&m->protocol); if(r!=IAP2_OK) return r;
    }
    pos=line+2;
    while(pos+2<end) {
        rtsp_header *h; size_t colon,start,stop;
        line=pos; while(line+1<end&&p[line]!='\r') ++line;
        if(count==RTSP_MAX_HEADERS) return IAP2_NO_SPACE;
        colon=pos; while(colon<line&&p[colon]!=':') ++colon;
        if(colon==line) return IAP2_INVALID;
        h=&m->headers[count++]; h->name=slice(p+pos,colon-pos);
        if(!token(h->name)) return IAP2_INVALID;
        start=colon+1; stop=line;
        while(start<stop&&(p[start]==' '||p[start]=='\t')) ++start;
        while(stop>start&&(p[stop-1]==' '||p[stop-1]=='\t')) --stop;
        h->value=slice(p+start,stop-start);
        if(!printable(h->value,1)) return IAP2_INVALID;
        if(named(h->name,"Content-Length")) {
            if(cl++) return IAP2_INVALID;
            r=decimal(h->value,UINT32_MAX,&v); if(r!=IAP2_OK) return r;
            if(v>RTSP_MAX_BODY_SIZE) return IAP2_NO_SPACE;
            *body=v;
        } else if(named(h->name,"CSeq")) {
            if(m->has_cseq) return IAP2_INVALID;
            r=decimal(h->value,UINT32_MAX,&m->cseq); if(r!=IAP2_OK) return r;
            m->has_cseq=1;
        } else if(named(h->name,"Transfer-Encoding")) return IAP2_UNSUPPORTED;
        pos=line+2;
    }
    m->header_count=count;
    return m->protocol==RTSP_10&&!m->has_cseq?IAP2_INVALID:IAP2_OK;
}
int rtsp_message_decode(const uint8_t *p, size_t n, rtsp_message *m, size_t *used) {
    size_t end=0,body=0; int r;
    if(used) *used=0; if(m) zero(m,sizeof(*m));
    if(!used||!m||(!p&&n)) return IAP2_ARGUMENT;
    r=header_end(p,n,&end); if(r!=IAP2_OK) return r;
    r=parse_header(p,end,m,&body);
    if(r==IAP2_OK&&body>n-end) r=IAP2_MORE;
    if(r!=IAP2_OK) { zero(m,sizeof(*m)); return r; }
    m->body=slice(p+end,body); *used=end+body; return IAP2_OK;
}
int rtsp_header_get(const rtsp_message *m, rtsp_slice name, rtsp_slice *value) {
    size_t i; int found=0; rtsp_slice v=slice(0,0);
    if(value) *value=v;
    if(!m||!value||!token(name)||m->header_count>RTSP_MAX_HEADERS) return IAP2_ARGUMENT;
    for(i=0;i<m->header_count;++i) if(same(m->headers[i].name,name)) {
        if(found) return IAP2_INVALID;
        v=m->headers[i].value; found=1;
    }
    if(!found) return IAP2_END;
    *value=v; return IAP2_OK;
}
static const char *phrase(uint16_t status) {
    switch(status) { case 200:return "OK";case 400:return "Bad Request";case 401:return "Unauthorized";
        case 403:return "Forbidden";case 404:return "Not Found";case 405:return "Method Not Allowed";
        case 413:return "Payload Too Large";case 455:return "Method Not Valid in This State";
        case 461:return "Unsupported Transport";case 500:return "Internal Server Error";
        case 501:return "Not Implemented";case 503:return "Service Unavailable";default:return 0; }
}
static size_t number(uint32_t v, uint8_t out[10]) {
    uint8_t rev[10]; size_t n=0,i;
    do { rev[n++]=(uint8_t)('0'+v%10u); v/=10u; } while(v);
    for(i=0;i<n;++i) out[i]=rev[n-i-1];
    return n;
}
int rtsp_response_encode(const rtsp_message *req, const rtsp_response *res, uint8_t *out,
                         size_t capacity, size_t *written) {
    const char *p,*s; rtsp_slice why; uint8_t seq[10],len[10],code[10];
    size_t ns=0,nl,nc,head,total,i,j,off=0;
    if(written) *written=0;
    if(!written||!req||!res||(!out&&capacity)||req->kind!=RTSP_REQUEST||
       res->header_count>RTSP_MAX_HEADERS||(!res->headers&&res->header_count)||
       (!res->body.data&&res->body.size)||res->body.size>RTSP_MAX_BODY_SIZE||
       res->status<100||res->status>599||req->has_cseq>1) return IAP2_ARGUMENT;
    p=protocol_text(req->protocol);
    if(!p||(req->protocol==RTSP_10&&!req->has_cseq)) return IAP2_ARGUMENT;
    why=res->reason;
    if(!why.size) { s=phrase(res->status); if(!s) return IAP2_ARGUMENT; why=slice((const uint8_t *)s,length(s)); }
    if(why.size>RTSP_MAX_HEADER_SIZE||!printable(why,1)) return IAP2_ARGUMENT;
    if(req->has_cseq) ns=number(req->cseq,seq);
    nl=number((uint32_t)res->body.size,len); nc=number(res->status,code);
    head=8+1+nc+1+why.size+2+16+nl+2+2; /* Content-Length: + CRLF + final CRLF */
    if(req->has_cseq) head+=6+ns+2;
    if(res->header_count+1u+req->has_cseq>RTSP_MAX_HEADERS) return IAP2_NO_SPACE;
    for(i=0;i<res->header_count;++i) {
        const rtsp_header *h=&res->headers[i];
        if(h->name.size>RTSP_MAX_HEADER_SIZE||h->value.size>RTSP_MAX_HEADER_SIZE||
           !token(h->name)||!printable(h->value,1)||named(h->name,"Content-Length")||
           named(h->name,"CSeq")||named(h->name,"Transfer-Encoding")) return IAP2_ARGUMENT;
        for(j=0;j<i;++j) if(same(h->name,res->headers[j].name)) return IAP2_ARGUMENT;
        head+=h->name.size+2+h->value.size+2;
        if(head>RTSP_MAX_HEADER_SIZE) return IAP2_NO_SPACE;
    }
    if(head>RTSP_MAX_HEADER_SIZE) return IAP2_NO_SPACE;
    total=head+res->body.size;
    if(!out) { *written=total; return IAP2_OK; }
    if(capacity<total) return IAP2_NO_SPACE;
#define PUT_BYTES(d,n) do { size_t k_=(n); copy(out+off,(d),k_); off+=k_; } while(0)
#define PUT_TEXT(t) PUT_BYTES((const uint8_t *)(t),length(t))
    PUT_TEXT(p); PUT_TEXT(" "); PUT_BYTES(code,nc); PUT_TEXT(" "); PUT_BYTES(why.data,why.size); PUT_TEXT("\r\n");
    if(req->has_cseq) { PUT_TEXT("CSeq: "); PUT_BYTES(seq,ns); PUT_TEXT("\r\n"); }
    for(i=0;i<res->header_count;++i) {
        PUT_BYTES(res->headers[i].name.data,res->headers[i].name.size); PUT_TEXT(": ");
        PUT_BYTES(res->headers[i].value.data,res->headers[i].value.size); PUT_TEXT("\r\n");
    }
    PUT_TEXT("Content-Length: "); PUT_BYTES(len,nl); PUT_TEXT("\r\n\r\n"); PUT_BYTES(res->body.data,res->body.size);
#undef PUT_TEXT
#undef PUT_BYTES
    *written=off; return IAP2_OK;
}
int rtsp_stream_init(rtsp_stream *s, uint8_t *buffer, size_t capacity) {
    if(!s||!buffer||capacity<64||capacity>RTSP_MAX_MESSAGE_SIZE) return IAP2_ARGUMENT;
    zero(s,sizeof(*s)); s->buffer=buffer; s->capacity=capacity; return IAP2_OK;
}
static int stream_fail(rtsp_stream *s, int r) { zero(s->buffer,s->used); s->used=0; s->error=r; return r; }
int rtsp_stream_feed(rtsp_stream *s, const uint8_t *p, size_t n, size_t *used) {
    size_t count=0;
    if(used) *used=0;
    if(!s||!used||(!p&&n)||!s->buffer) return IAP2_ARGUMENT;
    if(s->error) return s->error;
    if(s->complete) return RTSP_BUSY;
    while(count<n) {
        if(!s->expected) {
            uint8_t c=p[count++]; size_t k=s->used;
            if(k==s->capacity||k==RTSP_MAX_HEADER_SIZE) { *used=count-1; return stream_fail(s,IAP2_NO_SPACE); }
            s->buffer[s->used++]=c; *used=count;
            if(!k&&c=='$') return stream_fail(s,IAP2_UNSUPPORTED);
            if((k&&s->buffer[k-1]=='\r'&&c!='\n')||(c=='\n'&&(!k||s->buffer[k-1]!='\r'))||
               (c!='\r'&&c!='\n'&&c!='\t'&&(c<32||c>126))) return stream_fail(s,IAP2_INVALID);
            if(k>=3&&s->buffer[k-3]=='\r'&&s->buffer[k-2]=='\n'&&s->buffer[k-1]=='\r'&&c=='\n') {
                rtsp_message m; size_t body; int r=parse_header(s->buffer,s->used,&m,&body);
                if(r!=IAP2_OK) return stream_fail(s,r);
                if(body>s->capacity-s->used) return stream_fail(s,IAP2_NO_SPACE);
                s->header_size=s->used; s->expected=s->used+body;
            } else if(s->used==s->capacity||s->used==RTSP_MAX_HEADER_SIZE) return stream_fail(s,IAP2_NO_SPACE);
        } else {
            size_t take=s->expected-s->used;
            if(take>n-count) take=n-count;
            copy(s->buffer+s->used,p+count,take); s->used+=take; count+=take; *used=count;
        }
        if(s->expected&&s->used==s->expected) { s->complete=1; return IAP2_OK; }
    }
    return IAP2_MORE;
}
int rtsp_stream_message(const rtsp_stream *s, rtsp_message *m) {
    size_t used;
    if(m) zero(m,sizeof(*m));
    if(!s||!m||!s->buffer) return IAP2_ARGUMENT;
    if(s->error) return s->error;
    if(!s->complete) return IAP2_MORE;
    return rtsp_message_decode(s->buffer,s->used,m,&used);
}
void rtsp_stream_clear(rtsp_stream *s) {
    if(!s||!s->buffer) return;
    zero(s->buffer,s->used); s->used=s->expected=s->header_size=0; s->error=0; s->complete=0;
}
