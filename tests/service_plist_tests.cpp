// SPDX-License-Identifier: GPL-3.0-only
#include "lockdown_reply.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using Bytes=std::vector<uint8_t>;
static void check(bool ok,const char *why) { if(!ok) throw std::runtime_error(why); }
static Bytes bytes(const std::string& s) { return Bytes(s.begin(),s.end()); }
static Bytes xml(const std::string& value) { return bytes("<plist version=\"1.0\">"+value+"</plist>"); }
static Bytes reply(const char *request,const std::string& fields) {
    return xml("<dict><key>Request</key><string>"+std::string(request)+"</string>"+fields+"</dict>");
}
static std::map<std::string,Bytes> vectors;
struct Parsed {
    std::array<service_plist_node,258> nodes{};
    Bytes arena=Bytes(65538,0xa5);
    service_plist_storage storage{nodes.data()+1,256,arena.data()+1,65536};
    service_plist_document doc{};
    Parsed() { std::memset(&nodes.front(),0xa5,sizeof nodes.front()); std::memset(&nodes.back(),0xa5,sizeof nodes.back()); }
    int parse(const Bytes& b) { return service_plist_decode(b.data(),b.size(),&storage,&doc); }
    void good(const Bytes& b) { check(parse(b)==0,"valid supported plist"); bounds(); }
    void bounds() const {
        check(arena.front()==0xa5 && arena.back()==0xa5,"arena canaries");
        for(const auto *v : {&nodes.front(),&nodes.back()}) {
            const auto *p=reinterpret_cast<const uint8_t *>(v);
            check(std::all_of(p,p+sizeof *v,[](uint8_t c) { return c==0xa5; }),"node canaries");
        }
        if(!doc.count) { check(!doc.nodes && !doc.bytes_used,"failure publishes no partial document"); return; }
        check(doc.nodes==storage.nodes && doc.count<=storage.node_capacity && doc.bytes_used<=storage.byte_capacity,"document storage bounds");
        for(size_t i=0;i<doc.count;++i) {
            const auto& v=doc.nodes[i];
            check(v.type<=SERVICE_PLIST_KEY && (v.next==SERVICE_PLIST_NONE || (v.next>i && v.next<doc.count)) &&
                  (v.first==SERVICE_PLIST_NONE || (v.first>i && v.first<doc.count)),"acyclic expanded tree");
            if(v.data) check(v.data>=storage.bytes && v.data<=storage.bytes+doc.bytes_used &&
                             v.size<=size_t(storage.bytes+doc.bytes_used-v.data),"decoded value stays in owned arena");
        }
    }
    const service_plist_node *find(const char *key) {
        const service_plist_node *v=nullptr;
        check(service_plist_find(&doc,doc.nodes,reinterpret_cast<const uint8_t *>(key),std::strlen(key),&v)==0,"dictionary field exists"); return v;
    }
    void bad(const Bytes& b) { check(parse(b)!=0,"malformed/unsupported input refused"); bounds(); }
};
static void load(const std::filesystem::path& root) {
    std::ifstream in(root/"plist-binary-vectors.txt"); check(bool(in),"binary fixture open"); std::string line;
    while(std::getline(in,line)) {
        if(line.empty() || line[0]=='#') continue;
        std::istringstream row(line); std::string name,hex; row>>name>>hex; check(!name.empty() && hex.size()%2==0,"fixture syntax");
        Bytes b; for(size_t i=0;i<hex.size();i+=2) b.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i,2),nullptr,16)));
        check(vectors.emplace(name,b).second,"unique vector name");
    }
    check(vectors.size()==7,"seven independent binary fixtures");
}
static void u64(Bytes& b,uint64_t n) { for(unsigned i=0;i<8;++i) b.push_back(static_cast<uint8_t>(n>>(56-8*i))); }
// Independent object table builder for boundary/malformed cases, not a decoder roundtrip.
static Bytes binary(const std::vector<Bytes>& objects,uint64_t root=0,uint8_t refs=1,uint8_t offset_width=0) {
    Bytes out=bytes("bplist00"); std::vector<size_t> offsets;
    for(const auto& o:objects) { offsets.push_back(out.size()); out.insert(out.end(),o.begin(),o.end()); }
    const size_t table=out.size(); const uint8_t os=offset_width?offset_width:table>255?2:1;
    for(auto offset:offsets) for(unsigned i=0;i<os;++i) out.push_back(static_cast<uint8_t>(uint64_t(offset)>>(8*(os-i-1))));
    out.insert(out.end(),6,0); out.push_back(os); out.push_back(refs); u64(out,objects.size()); u64(out,root); u64(out,table); return out;
}
static bool text(const service_plist_node *v,const std::string& s) { return v && v->size==s.size() && std::equal(s.begin(),s.end(),v->data,[](char a,uint8_t b){return static_cast<uint8_t>(a)==b;}); }
static void binary_fixture_semantics() {
    for(const auto& [name,b]:vectors) { Parsed p; p.good(b); check(p.doc.nodes[0].type==SERVICE_PLIST_DICT,"binary dictionary root"); }
    Parsed p; p.good(vectors.at("mixed")); auto v=p.find("Value"); check(v->type==SERVICE_PLIST_ARRAY && v->children==12,"expanded mixed array");
    std::vector<const service_plist_node *> a;
    for(auto i=v->first;i!=SERVICE_PLIST_NONE;i=p.doc.nodes[i].next) a.push_back(&p.doc.nodes[i]);
    check(text(a[0],"same") && text(a[1],"same") && a[0]!=a[1],"shared binary references expanded independently");
    check(a[2]->type==SERVICE_PLIST_INTEGER && !a[2]->magnitude && a[3]->negative && a[3]->magnitude==1 &&
          a[4]->negative && a[4]->magnitude==(uint64_t(1)<<63) && !a[5]->negative && a[5]->magnitude==(uint64_t(1)<<63) &&
          !a[6]->negative && a[6]->magnitude==UINT64_MAX,"signed 64-bit and unsigned 128-bit-encoded boundaries");
    check(a[7]->type==SERVICE_PLIST_BOOL && a[7]->magnitude==1 && a[8]->type==SERVICE_PLIST_BOOL && a[8]->magnitude==0 &&
          a[9]->type==SERVICE_PLIST_DATA && a[9]->size==2 && a[9]->data[0]==0 && a[9]->data[1]==255,"bool is not integer and data stays binary");
    check(text(a[10],"\xc3\x84\xf0\x9f\x98\x80") && a[11]->type==SERVICE_PLIST_DICT,"UTF-16 surrogate pair decoded as UTF-8 with nested dictionary");
}
static void xml_entities_unicode_and_ownership() {
    Parsed p;
    auto input=reply("GetValue","<key>Value</key><string>&amp;&lt;&gt;&quot;&apos;&#65;&#x1f600;\r\nx\ry</string>");
    p.good(input); const auto *v=p.find("Value"); const std::string expected="&<>\"'A\xf0\x9f\x98\x80\nx\ny";
    check(text(v,expected),"predefined/numeric entities and XML line ending normalization");
    std::fill(input.begin(),input.end(),0); check(text(v,expected),"decoded storage independent of source body");
    p.good(xml("<dict><key>&#65;</key><string>\xc3\x84\xf0\x9f\x98\x80</string></dict>"));
    check(text(p.find("A"),"\xc3\x84\xf0\x9f\x98\x80"),"UTF-8 values and decoded lookup key");
    const service_plist_node *missing=reinterpret_cast<const service_plist_node *>(1);
    check(service_plist_find(&p.doc,p.doc.nodes,reinterpret_cast<const uint8_t *>("Z"),1,&missing)==IAP2_END && !missing,"missing field explicit");
}
static void xml_prolog_and_container_grammar() {
    Parsed p; const auto body=xml("<dict><key>a</key><array><true/><false></false><dict/><array/><string/><data/></array></dict>");
    for(const auto& prefix: {std::string(""),std::string("<?xml version='1.0'?>"),
        std::string("<?xml version='1.0' standalone='no'?>"),
        std::string("\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
        std::string("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"),
        std::string("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")}) {
        auto b=bytes(prefix+"<!-- synthetic -->\n"); b.insert(b.end(),body.begin(),body.end()); p.good(b);
        check(p.find("a")->children==6,"empty/nested elements");
    }
    for(const auto& inner: {"<dict><key>x</key></dict>","<dict><string>x</string><true/></dict>","<array><key>x</key></array>",
        "<dict><key>x</key><true/><key>x</key><false/></dict>","<dict><key>x</key><true/><key>&#120;</key><false/></dict>",
        "<string></data>","<string a='b'>x</string>","<true>false</true>","<integer/>","<dict/><dict/>"}) p.bad(xml(inner));
    p.bad(bytes("<plist version='1.0'><dict/></plist>garbage")); p.bad(bytes("<plist version='2.0'><dict/></plist>"));
}
static void xml_security_and_bad_unicode() {
    Parsed p;
    for(const auto& s : {"<!DOCTYPE plist [<!ENTITY x 'expanded'>]><plist><string>&x;</string></plist>",
        "<!DOCTYPE plist SYSTEM 'file:///synthetic-denied'><plist><dict/></plist>",
        "<?xml version='1.0' encoding='UTF-16'?><plist><dict/></plist>",
        "<plist><string><![CDATA[not supported]]></string></plist>","<plist><?other x?><dict/></plist>",
        "<plist><!-- bad -- comment --><dict/></plist>","<plist><string>raw]]>text</string></plist>"}) p.bad(bytes(s));
    for(const auto& s: {"&unknown;","&amp","&#;","&#x;","&#0;","&#xD800;","&#x110000;","&#99999999999999;","&#xFFFFFFFF;","&AMP;"}) p.bad(xml("<string>"+std::string(s)+"</string>"));
    for(const auto& bad: {Bytes{0},Bytes{0xc0,0x80},Bytes{0xc2},Bytes{0xed,0xa0,0x80},Bytes{0xf4,0x90,0x80,0x80},Bytes{0xff},Bytes{0xe2,0x28,0xa1}}) {
        auto b=bytes("<plist><string>"); b.insert(b.end(),bad.begin(),bad.end()); const auto tail=bytes("</string></plist>"); b.insert(b.end(),tail.begin(),tail.end()); p.bad(b);
    }
}
static void integer_and_base64_boundaries() {
    Parsed p;
    for(const auto& s: {"0","+1"," -1 ","9223372036854775807","-9223372036854775808","18446744073709551615","0xFFFFFFFFFFFFFFFF"}) p.good(xml("<integer>"+std::string(s)+"</integer>"));
    check(p.doc.nodes[0].magnitude==UINT64_MAX && !p.doc.nodes[0].negative,"hex u64 maximum");
    for(const auto& s: {"","-","+","0x","1 2","1.0","18446744073709551616","-9223372036854775809","0x10000000000000000"}) p.bad(xml("<integer>"+std::string(s)+"</integer>"));
    for(const auto& [encoded,decoded]:std::vector<std::pair<std::string,Bytes>>{{"",{}},{"AA==",{0}},{"AP8=",{0,255}},{"AAECAw==",{0,1,2,3}},{" A A E C \r\n",{0,1,2}}}) {
        p.good(xml("<data>"+encoded+"</data>")); const auto& v=p.doc.nodes[0];
        check(v.type==SERVICE_PLIST_DATA && Bytes(v.data,v.data+v.size)==decoded,"strict base64 with XML whitespace");
    }
    for(const auto& s: {"A","AAA","AA=","=AAA","A=AA","AA=A","AB==","AAB=","AA==AA==","AA_A","AA-A","AA==!","&#65;A=="}) p.bad(xml("<data>"+std::string(s)+"</data>"));
}
static void depth_node_and_arena_limits() {
    Parsed p; std::string nested="<true/>";
    for(unsigned i=1;i<16;++i) nested="<array>"+nested+"</array>";
    p.good(xml(nested)); p.bad(xml("<array>"+nested+"</array>"));
    std::string many="<array>"; for(unsigned i=0;i<255;++i) many+="<string/>"; many+="</array>";
    p.good(xml(many)); check(p.doc.count==256,"maximum expanded nodes");
    p.bad(xml(many.substr(0,many.size()-8)+"<string/></array>"));
    const auto input=reply("GetValue","<key>Value</key><string>abc</string>"); p.good(input);
    const auto count=p.doc.count, used=p.doc.bytes_used;
    for(size_t n=1;n<count;++n) { p.storage.node_capacity=n; check(p.parse(input)==IAP2_NO_SPACE,"insufficient nodes"); p.bounds(); }
    p.storage.node_capacity=count;
    for(size_t n=1;n<used;++n) { p.storage.byte_capacity=n; check(p.parse(input)==IAP2_NO_SPACE,"insufficient owned bytes"); p.bounds(); }
    p.storage.byte_capacity=used; p.good(input); check(p.doc.bytes_used==used,"exact owned storage");
    p.storage={p.nodes.data()+1,256,p.arena.data()+1,65536};
    const std::string prefix="<plist><string>",suffix="</string></plist>";
    auto maximum=bytes(prefix+std::string(65536-prefix.size()-suffix.size(),'x')+suffix); p.good(maximum);
    maximum.push_back(' '); check(p.parse(maximum)==IAP2_NO_SPACE,"input cap before parse"); p.bounds();
}
static void binary_offsets_references_and_cycles() {
    Parsed p; p.good(binary({{0x51,'x'},{0x51,'y'}},1)); check(text(p.doc.nodes,"y"),"nonzero root object");
    p.good(binary({{0xa2,1,1},{0x51,'x'}})); check(p.doc.count==3,"shared scalar expanded twice");
    for(const auto& b: {binary({{0xa1,0}}),binary({{0xa1,1},{0xa1,0}}),binary({{0xa1,2},{0x51,'x'}}),
        binary({{0xd1,1,2},{0x10,1},{0x51,'v'}}),binary({{0xd2,1,1,2,2},{0x51,'x'},{0x09}}),
        binary({{0x5f,0x20,1,'x'}}),binary({{0x5f,0x13,255,255,255,255,255,255,255,255}}),binary({{0x54,'x'},{0x09}})}) p.bad(b);
    auto valid=binary({{0x51,'x'}});
    for(auto index:{size_t(6),size_t(7)}) for(uint8_t value:{uint8_t(0),uint8_t(9)}) {
        auto b=valid; b[b.size()-32+index]=value; p.bad(b);
    }
    for(uint64_t root:{uint64_t(1),UINT64_MAX}) p.bad(binary({{0x09}},root));
    auto overlap=binary({{0x09},{0x08}}); overlap[11]=overlap[10]; p.bad(overlap);
    auto trailer=valid; trailer[trailer.size()-1]=7; p.bad(trailer);
    trailer=valid; trailer[trailer.size()-24]=255; p.bad(trailer);
    auto into_header=valid; into_header[10]=7; p.bad(into_header);
    for(const auto& object: {Bytes{0x61,0xd8,0x00},Bytes{0x61,0xdc,0x00},Bytes{0x62,0xd8,0x00,0,65},Bytes{0x51,0x80}}) p.bad(binary({object}));
}
static void binary_long_lengths_and_expansion_limits() {
    Parsed p; Bytes data{0x4f,0x11,1,0}; data.insert(data.end(),256,0xff); p.good(binary({data}));
    check(p.doc.nodes[0].size==256 && p.doc.bytes_used==256,"extended length and two-byte object offsets");
    for(uint8_t width=1;width<=8;++width) {
        Bytes ref{0xa1}; ref.insert(ref.end(),width-1,0); ref.push_back(1);
        p.good(binary({ref,{0x09}},0,width,width));
        check(p.doc.count==2,"all bounded offset/reference widths");
        ref[1]=255; p.bad(binary({ref,{0x09}},0,width,width));
    }
    std::vector<Bytes> nested(16); for(unsigned i=0;i<15;++i) nested[i]={0xa1,static_cast<uint8_t>(i+1)}; nested[15]={0x09};
    p.good(binary(nested)); nested[15]={0xa1,16}; nested.push_back({0x09}); p.bad(binary(nested));
    Bytes array{0xaf,0x10,255}; array.insert(array.end(),255,1); p.good(binary({array,{0x09}})); check(p.doc.count==256,"maximum expanded shared references");
    array={0xaf,0x11,1,0}; array.insert(array.end(),256,1); p.bad(binary({array,{0x09}}));
    for(const auto& obj: {Bytes{0x22,0,0,0,0},Bytes{0x33,0,0,0,0,0,0,0,0},Bytes{0x80,0},Bytes{0xc0},Bytes{0x0f}}) {
        check(p.parse(binary({obj}))==IAP2_UNSUPPORTED,"unsupported binary type explicit"); p.bounds();
    }
    p.good(binary({{0x00}})); check(p.doc.nodes[0].type==SERVICE_PLIST_NULL,"binary null distinct from false");
}
static void complete_input_and_failure_publication() {
    Parsed p; const auto x=reply("GetValue","<key>Value</key><string>x</string>");
    for(size_t i=0;i<x.size();++i) p.bad(Bytes(x.begin(),x.begin()+i));
    for(const auto& [name,b]:vectors) for(size_t i=0;i<b.size();++i) p.bad(Bytes(b.begin(),b.begin()+i));
    p.good(x); auto too_many=bytes("<plist><dict/></plist><plist><dict/></plist>"); p.bad(too_many);
    auto invalid=p.storage; invalid.node_capacity=0;
    check(service_plist_decode(x.data(),x.size(),&invalid,&p.doc)==IAP2_ARGUMENT && !p.doc.nodes,"invalid storage clears old document");
    invalid=p.storage; invalid.byte_capacity=65537; check(service_plist_decode(x.data(),x.size(),&invalid,&p.doc)==IAP2_ARGUMENT,"excessive capacity rejected");
    check(service_plist_decode(nullptr,1,&p.storage,&p.doc)==IAP2_ARGUMENT &&
          service_plist_decode(x.data(),x.size(),&p.storage,nullptr)==IAP2_ARGUMENT,"null arguments"); p.bounds();
}
static int validate(Parsed& p,const Bytes& b,lockdown_reply_command cmd,service_plist_type type,lockdown_reply& out) {
    p.good(b); return lockdown_reply_validate(&p.doc,cmd,type,&out);
}
static void typed_positive_and_error_fixtures() {
    Parsed p; lockdown_reply out{};
    check(validate(p,vectors.at("product"),LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,out)==0 && text(out.value,"iPhone17,1"),"typed ProductType");
    check(validate(p,vectors.at("session"),LOCKDOWN_REPLY_START_SESSION,SERVICE_PLIST_NULL,out)==0 &&
          text(out.session_id,"synthetic-session") && out.tls_required && out.tls_flag_present,"session metadata requires explicit future TLS");
    check(validate(p,vectors.at("service_tls"),LOCKDOWN_REPLY_START_SERVICE,SERVICE_PLIST_NULL,out)==0 && out.port==62079 && out.tls_required,"typed service with TLS flag");
    check(validate(p,vectors.at("service_plain"),LOCKDOWN_REPLY_START_SERVICE,SERVICE_PLIST_NULL,out)==0 && out.port==1 && !out.tls_required && !out.tls_flag_present,"absent service TLS flag explicit default");
    check(validate(p,vectors.at("pair"),LOCKDOWN_REPLY_PAIR,SERVICE_PLIST_NULL,out)==0 && out.escrow_bag->size==4,"opaque pairing response data, no storage action");
    check(validate(p,vectors.at("error"),LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,out)==LOCKDOWN_REPLY_REMOTE_ERROR &&
          out.error->negative && out.error->magnitude==7 && text(out.error_string,"InvalidHostID") &&
          text(out.error_description,"synthetic refusal") && !out.value && !out.port && !out.tls_required,"numeric remote error cannot masquerade as success");
    check(validate(p,reply("Pair",""),LOCKDOWN_REPLY_PAIR,SERVICE_PLIST_NULL,out)==0 && !out.escrow_bag,"Pair may omit escrow bag");
}
static bool cleared(const lockdown_reply& out) {
    const auto *p=reinterpret_cast<const uint8_t *>(&out); return std::all_of(p,p+sizeof out,[](uint8_t b){return b==0;});
}
static void typed_mismatch_and_error_policy() {
    Parsed p; lockdown_reply out{};
    for(const auto& b: {reply("Other","<key>Value</key><string>x</string>"),xml("<dict><key>Value</key><string>x</string></dict>"),
        reply("GetValue",""),reply("GetValue","<key>Value</key><integer>1</integer>"),
        reply("GetValue","<key>Error</key><true/>"),reply("GetValue","<key>Error</key><string/>"),
        reply("GetValue","<key>Error</key><integer>1</integer><key>ErrorString</key><data/>"),
        reply("GetValue","<key>ErrorString</key><string>orphan</string><key>Value</key><string>x</string>")}) {
        std::memset(&out,0xa5,sizeof out); check(validate(p,b,LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,out)==IAP2_INVALID && cleared(out),"mismatch/malformed metadata clears result");
    }
    check(validate(p,reply("GetValue","<key>Value</key><string>x</string><key>Error</key><string>PairingDialogResponsePending</string>"),
          LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,out)==LOCKDOWN_REPLY_REMOTE_ERROR && !out.value,"Error presence overrides apparent Value");
    for(const auto& key: {"Error","ErrorString","ErrorDescription"}) {
        const auto limit=std::string(key)=="Error"?256u:std::string(key)=="ErrorString"?512u:1024u;
        std::string fields=std::string(key)=="Error"?"":"<key>Error</key><integer>0</integer>";
        fields+="<key>"+std::string(key)+"</key><string>"+std::string(limit,'x')+"</string>";
        check(validate(p,reply("GetValue",fields),LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,out)==LOCKDOWN_REPLY_REMOTE_ERROR,"bounded error metadata maximum");
        fields.insert(fields.size()-9,1,'x');
        check(validate(p,reply("GetValue",fields),LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_STRING,out)==IAP2_INVALID && cleared(out),"oversized error metadata refused");
    }
}
static void typed_service_security_boundaries() {
    Parsed p; lockdown_reply out{};
    for(const auto& port: {"0","-1","65536","18446744073709551615"}) {
        check(validate(p,reply("StartService","<key>Port</key><integer>"+std::string(port)+"</integer>"),
              LOCKDOWN_REPLY_START_SERVICE,SERVICE_PLIST_NULL,out)==IAP2_INVALID && cleared(out),"port checked before narrowing");
    }
    for(const auto& v: {"<string>62078</string>","<true/>","<data/>"}) check(validate(p,reply("StartService","<key>Port</key>"+std::string(v)),
        LOCKDOWN_REPLY_START_SERVICE,SERVICE_PLIST_NULL,out)==IAP2_INVALID,"port type strict");
    for(const auto& v: {"<string>true</string>","<integer>1</integer>","<data/>"}) check(validate(p,reply("StartService","<key>Port</key><integer>65535</integer><key>EnableServiceSSL</key>"+std::string(v)),
        LOCKDOWN_REPLY_START_SERVICE,SERVICE_PLIST_NULL,out)==IAP2_INVALID && cleared(out),"malformed present TLS flag is never default false");
    check(validate(p,reply("StartService","<key>Port</key><integer>65535</integer><key>EnableServiceSSL</key><false/>"),
        LOCKDOWN_REPLY_START_SERVICE,SERVICE_PLIST_NULL,out)==0 && out.port==65535 && out.tls_flag_present && !out.tls_required,"explicit false service TLS metadata");
    const std::string session="<key>SessionID</key><string>x</string>";
    check(validate(p,reply("StartSession",session+"<key>EnableSessionSSL</key><false/>"),
        LOCKDOWN_REPLY_START_SESSION,SERVICE_PLIST_NULL,out)==IAP2_AUTH_FAILED && cleared(out),"session plaintext downgrade refused");
    for(const auto& fields: {session,session+"<key>EnableSessionSSL</key><integer>1</integer>",
         std::string("<key>SessionID</key><string/><key>EnableSessionSSL</key><true/>"),
         "<key>SessionID</key><string>"+std::string(257,'x')+"</string><key>EnableSessionSSL</key><true/>"}) {
        check(validate(p,reply("StartSession",fields),LOCKDOWN_REPLY_START_SESSION,SERVICE_PLIST_NULL,out)==IAP2_INVALID && cleared(out),"invalid session security metadata");
    }
    check(validate(p,reply("Pair","<key>EscrowBag</key><string>not data</string>"),LOCKDOWN_REPLY_PAIR,SERVICE_PLIST_NULL,out)==IAP2_INVALID,"escrow data type strict");
    check(lockdown_reply_validate(&p.doc,LOCKDOWN_REPLY_PAIR,SERVICE_PLIST_DATA,&out)==IAP2_ARGUMENT && cleared(out),"unused expected type cannot be ambiguous");
}
static void deterministic_mutation_safety() {
    Parsed p; uint32_t state=0x12345678;
    for(const auto& seed:{vectors.at("mixed"),reply("GetValue","<key>Value</key><array><string>&amp;test</string><integer>65535</integer><data>AP8=</data></array>")})
    for(unsigned i=0;i<12000;++i) {
        state=state*1664525u+1013904223u;
        Bytes b=seed; const auto index=state%b.size(); b[index]^=static_cast<uint8_t>(1u<<(state>>29));
        if(i%3==0) b.resize(state%b.size());
        const int status=p.parse(b); check(status==0 || status==IAP2_INVALID || status==IAP2_NO_SPACE || status==IAP2_UNSUPPORTED,"bounded malformed-input statuses");
        p.bounds();
        if(!status) { lockdown_reply out{}; (void)lockdown_reply_validate(&p.doc,LOCKDOWN_REPLY_GET_VALUE,SERVICE_PLIST_ARRAY,&out); }
    }
}
int main(int argc,char **argv) {
    try {
        check(argc==2,"fixture directory required"); load(argv[1]);
        binary_fixture_semantics(); xml_entities_unicode_and_ownership(); xml_prolog_and_container_grammar();
        xml_security_and_bad_unicode(); integer_and_base64_boundaries(); depth_node_and_arena_limits();
        binary_offsets_references_and_cycles(); binary_long_lengths_and_expansion_limits(); complete_input_and_failure_publication();
        typed_positive_and_error_fixtures(); typed_mismatch_and_error_policy(); typed_service_security_boundaries(); deterministic_mutation_safety();
        std::cout<<"PASS: 13 service plist/reply groups; XML/binary synthetic inputs. Node bytes="<<sizeof(service_plist_node)<<'\n'; return 0;
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
