/* SPDX-License-Identifier: GPL-3.0-only */
#include "service_plist.h"
typedef struct parser {
    const uint8_t *in; size_t size, at;
    service_plist_storage out; size_t count, used;
    uint32_t *offsets, *ends; size_t object_limit; uint8_t projection;
    uint16_t path[SERVICE_PLIST_DEPTH]; size_t objects, refs;
} parser;
static void zero(void *p, size_t n) { size_t i; for (i=0;i<n;++i) ((uint8_t *)p)[i]=0; }
static int same(const uint8_t *a,const uint8_t *b,size_t n) { size_t i; for(i=0;i<n;++i) if(a[i]!=b[i]) return 0; return 1; }
static size_t length(const char *s) { size_t n=0; while(s[n]) ++n; return n; }
static int equal(const uint8_t *a,size_t n,const char *s) { return n==length(s) && same(a,(const uint8_t *)s,n); }
static int space(uint8_t c) { return c==' ' || c=='\t' || c=='\r' || c=='\n'; }
static int starts(const parser *p,const char *s) { size_t n=length(s); return n<=p->size-p->at && same(p->in+p->at,(const uint8_t *)s,n); }
static int take(parser *p,const char *s) { if(!starts(p,s)) return 0; p->at+=length(s); return 1; }
static void ws(parser *p) { while(p->at<p->size && space(p->in[p->at])) ++p->at; }
static int xml_char(uint32_t c) { return c==9 || c==10 || c==13 || (c>=32 && c<=0xd7ff) || (c>=0xe000 && c<=0xfffd) || (c>=0x10000 && c<=0x10ffff); }
static int utf8(const uint8_t *s,size_t n,size_t *at,uint32_t *cp) {
    uint32_t c; unsigned more,i; uint8_t first;
    if(*at>=n) return IAP2_INVALID;
    first=s[(*at)++];
    if(first<0x80) { *cp=first; return xml_char(first) ? IAP2_OK : IAP2_INVALID; }
    if(first>=0xc2 && first<=0xdf) { c=first&31; more=1; }
    else if(first>=0xe0 && first<=0xef) { c=first&15; more=2; }
    else if(first>=0xf0 && first<=0xf4) { c=first&7; more=3; }
    else return IAP2_INVALID;
    if(more>n-*at) return IAP2_INVALID;
    for(i=0;i<more;++i) { uint8_t b=s[(*at)++]; if((b&0xc0)!=0x80) return IAP2_INVALID; c=(c<<6)|(b&63); }
    if((more==1 && c<0x80) || (more==2 && c<0x800) || (more==3 && c<0x10000) || !xml_char(c)) return IAP2_INVALID;
    *cp=c; return IAP2_OK;
}
static int append(parser *p,uint8_t b) {
    if(p->used==p->out.byte_capacity) return IAP2_NO_SPACE;
    p->out.bytes[p->used++]=b; return IAP2_OK;
}
static int emit(parser *p,uint32_t c) {
    unsigned n,i; uint8_t b[4]; int status;
    if(!xml_char(c)) return IAP2_INVALID;
    if(c<128) { n=1; b[0]=(uint8_t)c; }
    else if(c<2048) { n=2; b[0]=(uint8_t)(0xc0|(c>>6)); b[1]=(uint8_t)(0x80|(c&63)); }
    else if(c<65536) { n=3; b[0]=(uint8_t)(0xe0|(c>>12)); b[1]=(uint8_t)(0x80|((c>>6)&63)); b[2]=(uint8_t)(0x80|(c&63)); }
    else { n=4; b[0]=(uint8_t)(0xf0|(c>>18)); b[1]=(uint8_t)(0x80|((c>>12)&63)); b[2]=(uint8_t)(0x80|((c>>6)&63)); b[3]=(uint8_t)(0x80|(c&63)); }
    for(i=0;i<n;++i) { status=append(p,b[i]); if(status) return status; } return IAP2_OK;
}
static int node(parser *p,uint8_t type,uint16_t *id) {
    service_plist_node *v;
    if(p->count==p->out.node_capacity) return IAP2_NO_SPACE;
    *id=(uint16_t)p->count++; v=&p->out.nodes[*id]; zero(v,sizeof *v);
    v->first=v->next=SERVICE_PLIST_NONE; v->type=type; return IAP2_OK;
}
static void link(parser *p,uint16_t parent,uint16_t child,uint16_t *last) {
    service_plist_node *v=&p->out.nodes[parent];
    if(*last==SERVICE_PLIST_NONE) v->first=child; else p->out.nodes[*last].next=child;
    *last=child; ++v->children;
}
static int duplicate(const parser *p,uint16_t parent,uint16_t key) {
    uint16_t i=p->out.nodes[parent].first; const service_plist_node *k=&p->out.nodes[key];
    while(i!=SERVICE_PLIST_NONE) {
        const service_plist_node *old=&p->out.nodes[i];
        if(old->size==k->size && same(old->data,k->data,k->size)) return 1;
        if(old->next==SERVICE_PLIST_NONE) break;
        i=p->out.nodes[old->next].next;
    }
    return 0;
}
static int comment(parser *p) {
    if(!take(p,"<!--")) return IAP2_INVALID;
    while(p->at<p->size) {
        if(take(p,"-->")) return IAP2_OK;
        if(starts(p,"--")) return IAP2_INVALID;
        ++p->at;
    }
    return IAP2_INVALID;
}
static int misc(parser *p) {
    int status;
    for(;;) { ws(p); if(!starts(p,"<!--")) return IAP2_OK; status=comment(p); if(status) return status; }
}
static int quoted(parser *p,const uint8_t **data,size_t *size) {
    size_t start; uint8_t quote;
    if(p->at==p->size || (p->in[p->at]!='\'' && p->in[p->at]!='"')) return IAP2_INVALID;
    quote=p->in[p->at++]; start=p->at;
    while(p->at<p->size && p->in[p->at]!=quote) {
        if(p->in[p->at]=='<' || p->in[p->at]=='&') return IAP2_INVALID;
        ++p->at;
    }
    if(p->at==p->size) return IAP2_INVALID;
    *data=p->in+start; *size=p->at-start; ++p->at; return IAP2_OK;
}
static int attr(parser *p,const char *name,const uint8_t **data,size_t *size) {
    if(!take(p,name)) return IAP2_INVALID;
    ws(p); if(!take(p,"=")) return IAP2_INVALID; ws(p); return quoted(p,data,size);
}
static int prolog(parser *p) {
    const uint8_t *v; size_t n; int status;
    if(starts(p,"\xef\xbb\xbf")) p->at+=3;
    if(take(p,"<?xml")) {
        if(p->at==p->size || !space(p->in[p->at])) return IAP2_INVALID;
        ws(p); status=attr(p,"version",&v,&n); if(status || !equal(v,n,"1.0")) return IAP2_INVALID;
        if(p->at<p->size && space(p->in[p->at])) {
            ws(p);
            if(starts(p,"encoding")) {
                status=attr(p,"encoding",&v,&n); if(status || (!equal(v,n,"UTF-8") && !equal(v,n,"utf-8"))) return IAP2_UNSUPPORTED;
                if(p->at<p->size && space(p->in[p->at])) ws(p);
                else if(!starts(p,"?>")) return IAP2_INVALID;
            }
            if(starts(p,"standalone")) { status=attr(p,"standalone",&v,&n); if(status || (!equal(v,n,"yes") && !equal(v,n,"no"))) return IAP2_INVALID; }
        }
        ws(p); if(!take(p,"?>")) return IAP2_INVALID;
    }
    status=misc(p); if(status) return status;
    if(take(p,"<!DOCTYPE")) {
        if(p->at==p->size || !space(p->in[p->at])) return IAP2_INVALID;
        ws(p); if(!take(p,"plist") || p->at==p->size || !space(p->in[p->at])) return IAP2_INVALID;
        ws(p); if(!take(p,"PUBLIC") || p->at==p->size || !space(p->in[p->at])) return IAP2_UNSUPPORTED;
        ws(p); status=quoted(p,&v,&n); if(status || !equal(v,n,"-//Apple//DTD PLIST 1.0//EN")) return IAP2_UNSUPPORTED;
        if(p->at==p->size || !space(p->in[p->at])) return IAP2_INVALID;
        ws(p); status=quoted(p,&v,&n);
        if(status || (!equal(v,n,"http://www.apple.com/DTDs/PropertyList-1.0.dtd") &&
                      !equal(v,n,"https://www.apple.com/DTDs/PropertyList-1.0.dtd"))) return IAP2_UNSUPPORTED;
        ws(p); if(!take(p,">")) return IAP2_UNSUPPORTED; /* Never accept internal declarations or fetch anything. */
        status=misc(p); if(status) return status;
    }
    if(!take(p,"<plist")) return IAP2_INVALID;
    if(p->at<p->size && space(p->in[p->at])) {
        ws(p);
        if(starts(p,"version")) { status=attr(p,"version",&v,&n); if(status || !equal(v,n,"1.0")) return IAP2_INVALID; ws(p); }
    }
    return take(p,">") ? IAP2_OK : IAP2_INVALID;
}
static int digit(uint8_t c) { if(c>='0' && c<='9') return c-'0'; if(c>='a' && c<='f') return c-'a'+10; if(c>='A' && c<='F') return c-'A'+10; return -1; }
static int entity(parser *p) {
    size_t start; uint32_t value=0,base=10; unsigned digits=0; int d;
    if(!take(p,"&")) return IAP2_INVALID;
    if(take(p,"#")) {
        if(take(p,"x")) base=16;
        while(p->at<p->size && p->in[p->at]!=';') {
            d=digit(p->in[p->at++]); if(d<0 || (uint32_t)d>=base || ++digits>8) return IAP2_INVALID;
            value=value*base+(uint32_t)d; if(value>0x10ffff) return IAP2_INVALID;
        }
        if(!digits || !take(p,";")) return IAP2_INVALID; return emit(p,value);
    }
    start=p->at; while(p->at<p->size && p->at-start<5 && p->in[p->at]!=';') ++p->at;
    if(!take(p,";")) return IAP2_INVALID;
    if(equal(p->in+start,p->at-start-1,"amp")) return emit(p,'&');
    if(equal(p->in+start,p->at-start-1,"lt")) return emit(p,'<');
    if(equal(p->in+start,p->at-start-1,"gt")) return emit(p,'>');
    if(equal(p->in+start,p->at-start-1,"quot")) return emit(p,'"');
    if(equal(p->in+start,p->at-start-1,"apos")) return emit(p,'\'');
    return IAP2_INVALID;
}
static int text_value(parser *p) {
    int status; uint32_t cp;
    while(p->at<p->size && p->in[p->at]!='<') {
        if(starts(p,"]]>")) return IAP2_INVALID;
        if(p->in[p->at]=='&') status=entity(p);
        else {
            status=utf8(p->in,p->size,&p->at,&cp); if(status) return status;
            if(cp==13) { cp=10; if(p->at<p->size && p->in[p->at]==10) ++p->at; }
            status=emit(p,cp);
        }
        if(status) return status;
    }
    return IAP2_OK;
}
static int integer(service_plist_node *v,const uint8_t *s,size_t n) {
    size_t i=0,end=n; uint64_t value=0; unsigned base=10; int d; int negative=0;
    while(i<end && space(s[i])) ++i; while(end>i && space(s[end-1])) --end;
    if(i<end && (s[i]=='-' || s[i]=='+')) negative=s[i++]=='-';
    if(end-i>=2 && s[i]=='0' && (s[i+1]=='x' || s[i+1]=='X')) { base=16; i+=2; }
    if(i==end) return IAP2_INVALID;
    for(;i<end;++i) {
        d=digit(s[i]); if(d<0 || (unsigned)d>=base) return IAP2_INVALID;
        if(base==10) {
            if(value>UINT64_C(1844674407370955161) || (value==UINT64_C(1844674407370955161) && d>5)) return IAP2_INVALID;
            value=value*10+(unsigned)d;
        } else { if(value>UINT64_C(0x0fffffffffffffff)) return IAP2_INVALID; value=(value<<4)|(unsigned)d; }
    }
    if(negative && value>UINT64_C(0x8000000000000000)) return IAP2_INVALID;
    v->magnitude=value; v->negative=(uint8_t)(negative && value); return IAP2_OK;
}
static int b64(uint8_t c) {
    if(c>='A' && c<='Z') return c-'A'; if(c>='a' && c<='z') return c-'a'+26;
    if(c>='0' && c<='9') return c-'0'+52; if(c=='+') return 62; if(c=='/') return 63; if(c=='=') return 64; return -1;
}
static int data_value(parser *p) {
    int q[4],status; unsigned n=0; int padded=0;
    while(p->at<p->size && p->in[p->at]!='<') {
        uint8_t c=p->in[p->at++]; if(space(c)) continue;
        if(padded || (q[n]=b64(c))<0) return IAP2_INVALID;
        if(++n!=4) continue; n=0;
        if(q[0]==64 || q[1]==64 || (q[2]==64 && q[3]!=64) ||
           (q[2]==64 && (q[1]&15)) || (q[3]==64 && q[2]!=64 && (q[2]&3))) return IAP2_INVALID;
        status=append(p,(uint8_t)((q[0]<<2)|(q[1]>>4))); if(status) return status;
        if(q[2]!=64) { status=append(p,(uint8_t)((q[1]<<4)|(q[2]>>2))); if(status) return status; }
        if(q[3]!=64) { status=append(p,(uint8_t)((q[2]<<6)|q[3])); if(status) return status; }
        padded=q[3]==64;
    }
    return n ? IAP2_INVALID : IAP2_OK;
}
static int xml_node(parser *p,unsigned depth,int key,uint16_t *id) {
    size_t start,n,saved; uint8_t type; int empty,status; uint16_t last=SERVICE_PLIST_NONE,child; service_plist_node *v;
    if(depth>=SERVICE_PLIST_DEPTH) return IAP2_NO_SPACE;
    status=misc(p); if(status) return status;
    if(!take(p,"<")) return IAP2_INVALID; start=p->at;
    while(p->at<p->size && p->in[p->at]>='a' && p->in[p->at]<='z') ++p->at; n=p->at-start;
    if(equal(p->in+start,n,"key")) type=SERVICE_PLIST_KEY;
    else if(equal(p->in+start,n,"string")) type=SERVICE_PLIST_STRING;
    else if(equal(p->in+start,n,"data")) type=SERVICE_PLIST_DATA;
    else if(equal(p->in+start,n,"integer")) type=SERVICE_PLIST_INTEGER;
    else if(equal(p->in+start,n,"true") || equal(p->in+start,n,"false")) type=SERVICE_PLIST_BOOL;
    else if(equal(p->in+start,n,"dict")) type=SERVICE_PLIST_DICT;
    else if(equal(p->in+start,n,"array")) type=SERVICE_PLIST_ARRAY;
    else return IAP2_UNSUPPORTED;
    if((type==SERVICE_PLIST_KEY)!=key) return IAP2_INVALID;
    ws(p); empty=take(p,"/>"); if(!empty && !take(p,">")) return IAP2_INVALID;
    status=node(p,type,id); if(status) return status; v=&p->out.nodes[*id]; saved=p->used;
    if(type==SERVICE_PLIST_DICT || type==SERVICE_PLIST_ARRAY) {
        if(!empty) for(;;) {
            status=misc(p); if(status) return status; if(starts(p,"</")) break;
            status=xml_node(p,depth+1,type==SERVICE_PLIST_DICT,&child); if(status) return status;
            if(type==SERVICE_PLIST_DICT && duplicate(p,*id,child)) return IAP2_INVALID;
            link(p,*id,child,&last);
            if(type==SERVICE_PLIST_DICT) { status=xml_node(p,depth+1,0,&child); if(status) return status; link(p,*id,child,&last); }
        }
    } else if(type==SERVICE_PLIST_BOOL) {
        v->magnitude=equal(p->in+start,n,"true");
        if(!empty) ws(p);
    } else {
        if(!empty) { status=type==SERVICE_PLIST_DATA ? data_value(p) : text_value(p); if(status) return status; }
        if(type==SERVICE_PLIST_INTEGER) {
            status=integer(v,p->out.bytes+saved,p->used-saved); if(status) return status; p->used=saved;
        } else { v->data=p->out.bytes+saved; v->size=p->used-saved; }
    }
    if(!empty) {
        if(!take(p,"</") || n>p->size-p->at || !same(p->in+p->at,p->in+start,n)) return IAP2_INVALID;
        p->at+=n; ws(p); if(!take(p,">")) return IAP2_INVALID;
    }
    return IAP2_OK;
}
static uint64_t be(const uint8_t *s,size_t n) { uint64_t v=0; size_t i; for(i=0;i<n;++i) v=(v<<8)|s[i]; return v; }
static int binary_setup(parser *p,uint16_t *root) {
    const uint8_t *t; uint64_t count,top,table; size_t os,i,j;
    if(p->size<40 || !same(p->in,(const uint8_t *)"bplist00",8)) return IAP2_INVALID;
    t=p->in+p->size-32; os=t[6]; p->refs=t[7]; count=be(t+8,8); top=be(t+16,8); table=be(t+24,8);
    if(!os || os>8 || !p->refs || p->refs>8 || !count || top>=count || table<8 || table>p->size-32) return IAP2_INVALID;
    if(count>p->object_limit) return IAP2_NO_SPACE;
    if(count*os!=(p->size-32)-table) return IAP2_INVALID;
    p->objects=(size_t)count; *root=(uint16_t)top;
    for(i=0;i<p->objects;++i) {
        uint64_t offset=be(p->in+(size_t)table+i*os,os);
        if(offset<8 || offset>=table) return IAP2_INVALID;
        p->offsets[i]=(uint32_t)offset; p->ends[i]=(uint32_t)table;
    }
    for(i=0;i<p->objects;++i) for(j=0;j<p->objects;++j) if(i!=j) {
        if(p->offsets[i]==p->offsets[j]) return IAP2_INVALID;
        if(p->offsets[j]>p->offsets[i] && p->offsets[j]<p->ends[i]) p->ends[i]=p->offsets[j];
    }
    return IAP2_OK;
}
static int binary_count(parser *p,size_t *at,size_t end,unsigned low,size_t *count) {
    uint64_t n=low; size_t width;
    if(low==15) {
        uint8_t tag;
        if(*at==end) return IAP2_INVALID; tag=p->in[(*at)++];
        if((tag&0xf0)!=0x10 || (tag&15)>3) return IAP2_INVALID;
        width=(size_t)1<<(tag&15); if(width>end-*at) return IAP2_INVALID;
        n=be(p->in+*at,width); *at+=width;
    }
    if(n>SERVICE_PLIST_LIMIT) return IAP2_NO_SPACE;
    *count=(size_t)n; return IAP2_OK;
}
static int binary_node(parser *p,uint16_t ref,unsigned depth,int key,uint16_t *id) {
    size_t at,end,n=0,i,saved; uint8_t tag,type; int status; uint16_t child,last=SERVICE_PLIST_NONE; service_plist_node *v;
    if(ref>=p->objects) return IAP2_INVALID;
    if(depth>=SERVICE_PLIST_DEPTH) return IAP2_NO_SPACE;
    for(i=0;i<depth;++i) if(p->path[i]==ref) return IAP2_INVALID;
    p->path[depth]=ref; at=p->offsets[ref]; end=p->ends[ref]; tag=p->in[at++];
    if(tag==0) type=SERVICE_PLIST_NULL;
    else if(tag==8 || tag==9) type=SERVICE_PLIST_BOOL;
    else if((tag&0xf0)==0x10) type=SERVICE_PLIST_INTEGER;
    else if((tag&0xf0)==0x20 && p->projection) type=SERVICE_PLIST_REAL;
    else if((tag&0xf0)==0x40) type=SERVICE_PLIST_DATA;
    else if((tag&0xf0)==0x50 || (tag&0xf0)==0x60) type=key ? SERVICE_PLIST_KEY : SERVICE_PLIST_STRING;
    else if((tag&0xf0)==0xa0) type=SERVICE_PLIST_ARRAY;
    else if((tag&0xf0)==0xd0) type=SERVICE_PLIST_DICT;
    else return IAP2_UNSUPPORTED;
    if(key && type!=SERVICE_PLIST_KEY) return IAP2_INVALID;
    status=node(p,type,id); if(status) return status; v=&p->out.nodes[*id]; saved=p->used;
    if(type==SERVICE_PLIST_BOOL) v->magnitude=tag==9;
    else if(type==SERVICE_PLIST_INTEGER) {
        unsigned low=tag&15; uint64_t value;
        if(low>4) return IAP2_UNSUPPORTED; n=(size_t)1<<low; if(n>end-at) return IAP2_INVALID;
        if(n==16) {
            uint64_t high=be(p->in+at,8); value=be(p->in+at+8,8);
            if(high && (high!=UINT64_MAX || !(value>>63))) return IAP2_UNSUPPORTED;
            v->negative=(uint8_t)(high!=0);
        } else { value=be(p->in+at,n); v->negative=(uint8_t)(n==8 && (value>>63)); }
        v->magnitude=v->negative ? UINT64_C(0)-value : value;
    } else if(type==SERVICE_PLIST_REAL) {
        uint64_t mask;
        if(tag!=0x22 && tag!=0x23) return IAP2_UNSUPPORTED;
        n=tag==0x22?4u:8u; if(n>end-at) return IAP2_INVALID;
        v->magnitude=be(p->in+at,n); v->size=n;
        mask=n==4?UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000);
        if((v->magnitude&mask)==mask) return IAP2_INVALID; /* NaN/infinity. No FP operations. */
    } else if(type==SERVICE_PLIST_DATA || type==SERVICE_PLIST_STRING || type==SERVICE_PLIST_KEY) {
        status=binary_count(p,&at,end,tag&15,&n); if(status) return status;
        if(n>(end-at)/((tag&0xf0)==0x60 ? 2u : 1u)) return IAP2_INVALID;
        if((tag&0xf0)==0x60) {
            for(i=0;i<n;++i) {
                uint32_t cp=(uint32_t)be(p->in+at+2*i,2);
                if(cp>=0xd800 && cp<=0xdbff) {
                    uint32_t low; if(++i==n) return IAP2_INVALID; low=(uint32_t)be(p->in+at+2*i,2);
                    if(low<0xdc00 || low>0xdfff) return IAP2_INVALID;
                    cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00);
                }
                status=emit(p,cp); if(status) return status;
            }
        } else for(i=0;i<n;++i) {
            uint8_t b=p->in[at+i];
            if(type!=SERVICE_PLIST_DATA && (b>=128 || !xml_char(b))) return IAP2_INVALID;
            status=append(p,b); if(status) return status;
        }
        v->data=p->out.bytes+saved; v->size=p->used-saved;
    } else if(type==SERVICE_PLIST_ARRAY || type==SERVICE_PLIST_DICT) {
        size_t total;
        status=binary_count(p,&at,end,tag&15,&n); if(status) return status;
        total=n*(type==SERVICE_PLIST_DICT ? 2u : 1u);
        if(total*p->refs>end-at) return IAP2_INVALID; /* Both factors are bounded above. */
        if(total>p->out.node_capacity-p->count) return IAP2_NO_SPACE;
        for(i=0;i<n;++i) {
            uint64_t reference=be(p->in+at+i*p->refs,p->refs);
            if(reference>=p->objects) return IAP2_INVALID;
            status=binary_node(p,(uint16_t)reference,depth+1,type==SERVICE_PLIST_DICT,&child); if(status) return status;
            if(type==SERVICE_PLIST_DICT && duplicate(p,*id,child)) return IAP2_INVALID;
            link(p,*id,child,&last);
            if(type==SERVICE_PLIST_DICT) {
                reference=be(p->in+at+(n+i)*p->refs,p->refs); if(reference>=p->objects) return IAP2_INVALID;
                status=binary_node(p,(uint16_t)reference,depth+1,0,&child); if(status) return status; link(p,*id,child,&last);
            }
        }
    }
    return IAP2_OK;
}
static int decode(const uint8_t *data,size_t size,const service_plist_storage *storage,service_plist_document *out,
                  uint32_t *offsets,uint32_t *ends,size_t limit,uint8_t projection) {
    parser p; int status; uint16_t root,id; size_t at=0; uint32_t cp;
    if(out) zero(out,sizeof *out);
    if(!out || !storage || !storage->nodes || !storage->bytes || !storage->node_capacity || storage->node_capacity>limit ||
       !storage->byte_capacity || storage->byte_capacity>SERVICE_PLIST_LIMIT || (!data && size)) return IAP2_ARGUMENT;
    if(!size) return IAP2_INVALID; if(size>SERVICE_PLIST_LIMIT) return IAP2_NO_SPACE;
    zero(&p,sizeof p); p.in=data; p.size=size; p.out.nodes=storage->nodes; p.out.node_capacity=storage->node_capacity;
    p.offsets=offsets; p.ends=ends; p.object_limit=limit; p.projection=projection;
    p.out.bytes=storage->bytes; p.out.byte_capacity=storage->byte_capacity;
    if(size>=8 && same(data,(const uint8_t *)"bplist00",8)) {
        status=binary_setup(&p,&root); if(status) return status; status=binary_node(&p,root,0,0,&id);
    } else {
        if(projection) return IAP2_UNSUPPORTED;
        while(at<size) { status=utf8(data,size,&at,&cp); if(status) return status; }
        status=prolog(&p); if(status) return status; status=xml_node(&p,0,0,&id);
        if(!status) { status=misc(&p); if(!status && !take(&p,"</plist>")) status=IAP2_INVALID; }
        if(!status) { status=misc(&p); if(!status && p.at!=p.size) status=IAP2_INVALID; }
    }
    if(status) return status;
    out->nodes=p.out.nodes; out->count=p.count; out->bytes_used=p.used; return IAP2_OK;
}
int service_plist_decode(const uint8_t *data,size_t size,const service_plist_storage *storage,service_plist_document *out) {
    uint32_t offsets[SERVICE_PLIST_NODES],ends[SERVICE_PLIST_NODES];
    return decode(data,size,storage,out,offsets,ends,SERVICE_PLIST_NODES,0);
}
int service_plist_decode_projection(const uint8_t *data,size_t size,const service_plist_storage *storage,service_plist_document *out) {
    uint32_t offsets[SERVICE_PLIST_PROJECTION_NODES],ends[SERVICE_PLIST_PROJECTION_NODES];
    return decode(data,size,storage,out,offsets,ends,SERVICE_PLIST_PROJECTION_NODES,1);
}
int service_plist_find(const service_plist_document *doc,const service_plist_node *dict,
                       const uint8_t *key,size_t size,const service_plist_node **value) {
    uint16_t i;
    if(value) *value=NULL;
    if(!doc || !doc->nodes || !doc->count || !dict || !value || (!key && size)) return IAP2_ARGUMENT;
    if(dict->type!=SERVICE_PLIST_DICT) return IAP2_INVALID;
    i=dict->first;
    while(i!=SERVICE_PLIST_NONE) {
        const service_plist_node *k;
        if(i>=doc->count) return IAP2_INVALID; k=&doc->nodes[i];
        if(k->type!=SERVICE_PLIST_KEY || k->next>=doc->count) return IAP2_INVALID;
        if(k->size==size && same(k->data,key,size)) { *value=&doc->nodes[k->next]; return IAP2_OK; }
        i=doc->nodes[k->next].next;
    }
    return IAP2_END;
}
