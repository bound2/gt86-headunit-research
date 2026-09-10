/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_info_fixture.h"
#include "service_plist.h"
#include <iomanip>
static uint64_t be(const uint8_t* p,size_t n) { uint64_t v=0; while(n--) v=(v<<8)|*p++; return v; }
static void profiles() {
    for(unsigned variant:{0u,1u,2u}) {
        auto p=info_fixture(variant); auto b=info_encode(p); CHECK(std::equal(b.begin(),b.begin()+8,bytes("bplist00").begin()));
        auto t=b.data()+b.size()-32; size_t count=static_cast<size_t>(be(t+8,8)),table=static_cast<size_t>(be(t+24,8));
        CHECK(count>1&&count<=640&&be(t+16,8)==0&&table+count*t[6]+32==b.size());
        CHECK(t[7]==(variant?2:1));
        size_t last=7;
        for(size_t i=0;i<count;++i) { auto offset=be(b.data()+table+i*t[6],t[6]); CHECK(offset>last&&offset<table); last=static_cast<size_t>(offset); }
        CHECK(info_encode(p)==b);
        {
            std::array<service_plist_node,SERVICE_PLIST_PROJECTION_NODES> nodes{}; Bytes scratch(32768); service_plist_document doc{};
            service_plist_storage storage={nodes.data(),nodes.size(),scratch.data(),scratch.size()};
            CHECK(service_plist_decode_projection(b.data(),b.size(),&storage,&doc)==IAP2_OK&&doc.count==count);
        }
        if(!variant) {
            std::array<service_plist_node,SERVICE_PLIST_NODES> nodes{}; Bytes scratch(4096); service_plist_document doc{};
            service_plist_storage storage={nodes.data(),nodes.size(),scratch.data(),scratch.size()};
            CHECK(service_plist_decode(b.data(),b.size(),&storage,&doc)==IAP2_OK);
            const service_plist_node* value=nullptr; auto name=info_text("name");
            CHECK(service_plist_find(&doc,doc.nodes,name.data,name.size,&value)==IAP2_OK&&Bytes(value->data,value->data+value->size)==bytes("Public capability fixture"));
        }
        std::cout<<"Profile "<<variant<<": "<<b.size()<<" bytes, "<<count<<" objects\n";
    }
}
static void invalid_profiles() {
    for(unsigned mode=0;mode<42;++mode) {
        auto p=info_fixture(2);
        switch(mode) {
        case 0:p.display_count=3;break; case 1:p.hid_count=5;break; case 2:p.audio_count=10;break;
        case 3:p.latency_count=10;break; case 4:p.resource_count=3;break; case 5:p.extension_count=9;break; case 6:p.icon_count=3;break;
        case 7:p.name={nullptr,1};break; case 8:p.name=info_text("bad\nname");break; case 9:p.model={nullptr,65};break;
        case 10:p.device_id=info_text("unknown");break; case 11:p.bluetooth_id=info_text("02:00:00:00:00:GG");break;
        case 12:p.right_hand_drive=2;break; case 13:p.speech_mode=-2;break;
        case 14:p.displays[0].width=0;break; case 15:p.displays[0].height_mm=0;break; case 16:p.displays[0].max_fps=241;break;
        case 17:p.displays[0].type=111;break; case 18:p.displays[1].uuid=p.displays[0].uuid;break;
        case 19:p.displays[0].uuid=info_text("00000000-1111-4000-8000-00000000000A");break;
        case 20:p.displays[0].has_view=0;break; case 21:p.displays[0].view.width=UINT32_MAX;break;
        case 22:p.displays[0].safe.x=0;break; case 23:p.displays[0].safe.height=0;break;
        case 24:p.hids[0].uuid=info_text("nothex");break; case 25:p.hids[1].uuid=p.hids[0].uuid;break;
        case 26:p.hids[0].display_uuid=info_text("ffffffff-1111-4000-8000-000000000001");break;
        case 27:p.hids[0].descriptor={nullptr,1};break; case 28:p.hids[0].descriptor.size=1025;break;
        case 29:p.audio[0].type=99;break; case 30:p.audio[0].audio_type=PROJECTION_AUDIO_ANY;break;
        case 31:p.audio[0].input_formats=p.audio[0].output_formats=0;break; case 32:p.audio[1]=p.audio[0];break;
        case 33:p.latencies[1]=p.latencies[0];break; case 34:p.audio_count=1;p.resources[1].id=2;break;
        case 35:p.resources[1].id=1;break; case 36:p.resource_count=1;break;
        case 37:p.extensions[1]=p.extensions[0];break; case 38:p.icons[0].data.size=8193;break;
        case 39:p.icons[0].width=0;break; case 40:p.oem_label={};break;
        case 41:p.hids[0].uuid=info_text("01234000");break;
        }
        Bytes output(PROJECTION_INFO_LIMIT,0xa5); auto saved=output; size_t written=99;
        CHECK(projection_info_encode(&p,output.data(),output.size(),&written)==IAP2_INVALID&&written==0&&output==saved);
    }
}
static void boundaries() {
    auto p=info_fixture(0); auto expected=info_encode(p);
    for(size_t cap=0;cap<expected.size();++cap) {
        Bytes b(expected.size()+10,0xcc); auto saved=b; size_t n=99;
        CHECK(projection_info_encode(&p,b.data(),cap,&n)==IAP2_NO_SPACE&&n==0&&b==saved);
    }
    size_t n=99; CHECK(projection_info_encode(nullptr,nullptr,0,&n)==IAP2_ARGUMENT&&n==0);
    CHECK(projection_info_encode(&p,nullptr,1,&n)==IAP2_ARGUMENT&&n==0);
    CHECK(projection_info_encode(&p,nullptr,0,nullptr)==IAP2_ARGUMENT);
    for(uint64_t value:{UINT64_C(0),UINT64_C(255),UINT64_C(256),UINT64_C(65535),UINT64_C(65536),UINT64_C(4294967295),UINT64_C(4294967296),UINT64_C(0x7fffffffffffffff),UINT64_C(0x8000000000000000),UINT64_MAX}) {
        p.features=value; auto b=info_encode(p);
        std::array<service_plist_node,SERVICE_PLIST_NODES> nodes{}; Bytes scratch(4096); service_plist_document doc{};
        service_plist_storage storage={nodes.data(),nodes.size(),scratch.data(),scratch.size()};
        CHECK(service_plist_decode(b.data(),b.size(),&storage,&doc)==IAP2_OK);
        auto field=info_text("features"); const service_plist_node* result=nullptr;
        CHECK(service_plist_find(&doc,doc.nodes,field.data,field.size,&result)==IAP2_OK&&!result->negative&&result->magnitude==value);
    }
    p=info_fixture(2); auto b=info_encode(p); Bytes output(b.size()+32,0x5a); n=0;
    CHECK(projection_info_encode(&p,output.data(),b.size(),&n)==IAP2_OK&&n==b.size()&&std::equal(b.begin(),b.end(),output.begin()));
    CHECK(std::all_of(output.begin()+n,output.end(),[](uint8_t v){return v==0x5a;}));
}
static void append_be(Bytes& out,uint64_t value,unsigned width) {
    while(width) { --width; out.push_back(static_cast<uint8_t>(value>>(width*8))); }
}
static Bytes binary(const std::vector<Bytes>& objects) {
    Bytes out=bytes("bplist00"); std::vector<size_t> offsets;
    for(const auto& object:objects) { offsets.push_back(out.size()); out.insert(out.end(),object.begin(),object.end()); }
    size_t table=out.size(); unsigned width=table<=255?1:2;
    for(size_t offset:offsets) append_be(out,offset,width);
    append_be(out,0,6); out.push_back(static_cast<uint8_t>(width)); out.push_back(objects.size()>256?2:1);
    append_be(out,objects.size(),8); append_be(out,0,8); append_be(out,table,8); return out;
}
static void projection_decoding() {
    std::array<service_plist_node,SERVICE_PLIST_PROJECTION_NODES+2> nodes{}; Bytes arena(32770,0xa5); service_plist_document doc{};
    std::memset(&nodes.front(),0xa5,sizeof(nodes.front())); std::memset(&nodes.back(),0xa5,sizeof(nodes.back()));
    const auto first=nodes.front(),last=nodes.back();
    service_plist_storage storage={nodes.data()+1,SERVICE_PLIST_PROJECTION_NODES,arena.data()+1,32768};
    auto decode=[&](const Bytes& b,bool projection=true) {
        auto selected=storage; if(!projection) selected.node_capacity=256;
        int r=projection?service_plist_decode_projection(b.data(),b.size(),&selected,&doc):service_plist_decode(b.data(),b.size(),&selected,&doc);
        CHECK(std::memcmp(&first,&nodes.front(),sizeof(first))==0&&std::memcmp(&last,&nodes.back(),sizeof(last))==0&&arena.front()==0xa5&&arena.back()==0xa5);
        if(r!=IAP2_OK) CHECK(doc.nodes==nullptr&&doc.count==0&&doc.bytes_used==0);
        return r;
    };
    for(unsigned width:{4u,8u}) {
        const std::vector<uint64_t> values=width==4?std::vector<uint64_t>{0,0x80000000,0xbf800000,1,0x7f7fffff}:
            std::vector<uint64_t>{0,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),1,UINT64_C(0x7fefffffffffffff)};
        for(uint64_t value:values) {
            Bytes object{static_cast<uint8_t>(width==4?0x22:0x23)}; append_be(object,value,width); auto b=binary({object});
            CHECK(decode(b)==IAP2_OK&&doc.nodes[0].type==SERVICE_PLIST_REAL&&doc.nodes[0].size==width&&doc.nodes[0].magnitude==value);
            CHECK(!doc.nodes[0].data&&!doc.nodes[0].negative&&decode(b,false)==IAP2_UNSUPPORTED);
            for(size_t size=0;size<b.size();++size) CHECK(decode(Bytes(b.begin(),b.begin()+size))!=IAP2_OK);
        }
        const std::vector<uint64_t> invalid=width==4?std::vector<uint64_t>{0x7f800000,0xff800000,0x7fc00000,0x7f800001}:
            std::vector<uint64_t>{UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8000000000000),UINT64_C(0x7ff0000000000001)};
        for(uint64_t value:invalid) {
            Bytes object{static_cast<uint8_t>(width==4?0x22:0x23)}; append_be(object,value,width); CHECK(decode(binary({object}))==IAP2_INVALID);
        }
    }
    CHECK(decode(binary({Bytes{0x21,0,0}}))==IAP2_UNSUPPORTED);
    CHECK(decode(bytes("<plist><dict/></plist>"))==IAP2_UNSUPPORTED);
    for(unsigned count:{639u,640u}) {
        Bytes array{0xaf,0x11,static_cast<uint8_t>(count>>8),static_cast<uint8_t>(count)}; array.insert(array.end(),count,1);
        CHECK(decode(binary({array,Bytes{9}}))==(count==639?IAP2_OK:IAP2_NO_SPACE));
        if(count==639) CHECK(doc.count==640);
        array={0xaf,0x11,static_cast<uint8_t>(count>>8),static_cast<uint8_t>(count)};
        for(unsigned i=1;i<=count;++i) append_be(array,i,2);
        std::vector<Bytes> objects(count+1,Bytes{9}); objects[0]=array;
        CHECK(decode(binary(objects))==(count==639?IAP2_OK:IAP2_NO_SPACE));
        if(count==639) CHECK(doc.count==640);
        CHECK(decode(binary(objects),false)==IAP2_NO_SPACE);
    }
    const auto seed=info_encode(info_fixture(1)); uint32_t state=0x120f80b3;
    for(unsigned i=0;i<600;++i) {
        state=state*1664525u+1013904223u; auto b=seed; b[state%b.size()]^=static_cast<uint8_t>(1u<<(state>>29));
        if(i%3==0) b.resize(state%b.size()); int r=decode(b);
        CHECK(r==IAP2_OK||r==IAP2_INVALID||r==IAP2_NO_SPACE||r==IAP2_UNSUPPORTED);
    }
    auto invalid=storage; invalid.node_capacity=641;
    CHECK(service_plist_decode_projection(seed.data(),seed.size(),&invalid,&doc)==IAP2_ARGUMENT&&!doc.nodes);
}
int main(int argc,char** argv) {
    try {
        if(argc==2&&std::string(argv[1])=="--emit") {
            for(unsigned variant:{0u,1u,2u}) {
                auto b=info_encode(info_fixture(variant)); std::cout<<variant<<'='<<std::hex<<std::setfill('0');
                for(uint8_t v:b) std::cout<<std::setw(2)<<unsigned(v);
                std::cout<<std::dec<<'\n';
            }
            return 0;
        }
        CHECK(argc==1); profiles(); invalid_profiles(); boundaries(); projection_decoding();
        std::cout<<"PASS: 4 capability-codec groups; typed profiles, exact capacities, integer boundaries and isolated projection plist/real decoding\n";
        std::cout<<"x64 profile bytes: "<<sizeof(projection_info_profile)<<"; borrowed data, output and stack additional\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
