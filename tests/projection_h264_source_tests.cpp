/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_h264.h"
#include "projection_h264_source_fixture.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <cstring>
#define CHECK(x) do { if(!(x)) { std::cerr<<#x<<" line "<<__LINE__<<'\n'; std::abort(); } } while(0)
using namespace source_fixture;
using Decoder=std::unique_ptr<projection_h264,decltype(&projection_h264_destroy)>;
using Frame=std::unique_ptr<projection_h264_frame,decltype(&projection_h264_frame_destroy)>;
static Decoder create() { projection_h264 *p=nullptr; CHECK(projection_h264_create(17,1920,1088,&p)==PROJECTION_H264_MORE); return {p,projection_h264_destroy}; }
static std::vector<Bytes> load(const std::filesystem::path &root) {
    std::ifstream f(root/"Static.264",std::ios::binary); CHECK(f.good()); Bytes b(std::istreambuf_iterator<char>(f),{});
    std::vector<Bytes> nals; size_t begin=0;
    for(size_t i=0;i+3<b.size();) {
        unsigned n=!b[i]&&!b[i+1]?(b[i+2]==1?3:(!b[i+2]&&b[i+3]==1?4:0)):0;
        if(n) { if(begin) nals.emplace_back(b.begin()+begin,b.begin()+i); begin=i+n; i=begin; } else ++i;
    }
    nals.emplace_back(b.begin()+begin,b.end()); CHECK(nals.size()==12); return nals;
}
static void push(projection_h264 *d,const Bytes &raw,uint64_t ts=0) {
    auto nal=annex(raw); projection_h264_frame *f=nullptr;
    CHECK(projection_h264_push(d,17,nal.data(),nal.size(),ts,&f)==PROJECTION_H264_MORE&&!f);
}
static Frame picture(projection_h264 *d,const Bytes &slice,uint64_t ts=0) {
    push(d,slice,ts); projection_h264_frame *f=nullptr;
    CHECK(projection_h264_end_access_unit(d,17,&f)==PROJECTION_H264_FRAME&&f); return {f,projection_h264_frame_destroy};
}
static projection_h264_view view(const Frame &f) { projection_h264_view v{}; CHECK(projection_h264_frame_view(f.get(),&v)==PROJECTION_H264_FRAME); return v; }
static void expected(const projection_h264_source &s,const Spec &e) {
    CHECK(s.vui_present==e.vui);
    if(!e.vui) { CHECK(!s.aspect_present&&!s.signal_present&&!s.timing_present&&!s.full_range&&s.matrix==2&&!s.sar_width); return; }
    CHECK(s.aspect_present==e.aspect&&s.signal_present==e.signal&&s.timing_present==e.timing);
    if(e.aspect&&e.aspect_idc==255) CHECK(s.sar_width==(e.sw&&e.sh?e.sw:0)&&s.sar_height==(e.sw&&e.sh?e.sh:0));
    CHECK(s.video_format==(e.signal?e.format:5)&&s.full_range==(e.signal?e.full:0));
    CHECK(s.colour_present==(e.signal?e.colour:0));
    CHECK(s.matrix==(e.signal&&e.colour?e.matrix:2)&&s.primaries==(e.signal&&e.colour?e.primaries:2)&&s.transfer==(e.signal&&e.colour?e.transfer:2));
    if(e.timing) CHECK(s.num_units_in_tick==e.tick&&s.time_scale==e.scale&&s.fixed_frame_rate==1);
    CHECK(s.chroma_present==e.chroma); if(e.chroma) CHECK(s.chroma_top==e.top&&s.chroma_bottom==e.bottom);
}
static void variants(const std::vector<Bytes> &nals) {
    for(unsigned i=0;i<30;++i) {
        Spec s;
        if(i<17) s.aspect_idc=i;
        if(i==17) { s.sw=65535; s.sh=1; }
        if(i==18) { s.sw=0; s.sh=1; }
        if(i==19) s.aspect=0;
        if(i==20) s.signal=0;
        if(i==21) s.colour=0;
        if(i==22) s.vui=0;
        if(i==23) s.timing=0;
        if(i==24) s.chroma=0;
        if(i==25) { s.full=1; s.primaries=6; s.transfer=6; s.matrix=6; s.top=5; s.bottom=5; }
        if(i==26) { s.primaries=9; s.transfer=16; s.matrix=9; }
        if(i==27) { s.tick=UINT32_MAX; s.scale=UINT32_MAX; }
        if(i==28) { s.nal_hrd=1; s.vcl_hrd=1; }
        if(i==29) { s.nal_hrd=1; s.cpb=31; }
        auto d=create(); push(d.get(),sps(s)); push(d.get(),nals[1]); auto f=picture(d.get(),nals[2],UINT64_MAX);
        auto v=view(f); CHECK(v.timestamp==UINT64_MAX&&v.width==152&&v.height==100); expected(v.source,s);
        if(i<17) { static const unsigned ratios[][2]={{0,0},{1,1},{12,11},{10,11},{16,11},{40,33},{24,11},{20,11},{32,11},{80,33},{18,11},{15,11},{64,33},{160,99},{4,3},{3,2},{2,1}};
            CHECK(v.source.sar_width==ratios[i][0]&&v.source.sar_height==ratios[i][1]); }
        d.reset(); expected(view(f).source,s);
    }
}
static void associations(const std::vector<Bytes> &nals) {
    auto d=create(); Spec first,other; other.id=1; other.full=1; other.matrix=6; other.sw=1; other.sh=2;
    push(d.get(),sps(first)); push(d.get(),sps(other)); push(d.get(),pps(0,0));
    auto a=picture(d.get(),nals[2],77); expected(view(a).source,first); // NOT last submitted SPS
    // Same PPS switches to another SPS; same external timestamp remains legal.
    push(d.get(),pps(0,1)); auto b=picture(d.get(),nals[2],77); expected(view(b).source,other); expected(view(a).source,first);
    first.full=1; push(d.get(),sps(first)); push(d.get(),pps(255,0));
    auto c=picture(d.get(),slice_pps(nals[2],255),77); expected(view(c).source,first);
    CHECK(view(a).timestamp==77&&view(b).timestamp==77&&view(c).timestamp==77);
    auto bytes=Bytes(view(a).plane[0],view(a).plane[0]+view(a).bytes);
    CHECK(bytes==Bytes(view(b).plane[0],view(b).plane[0]+view(b).bytes));
    // Replacing the original ID must not change an already transferred frame.
    first.full=0; first.matrix=5; push(d.get(),sps(first));
    d.reset(); CHECK(view(a).source.full_range==0&&view(a).source.matrix==1&&view(b).source.matrix==6&&view(c).source.full_range==1);
}
static void rejected(const Bytes &raw) {
    auto d=create(); auto nal=annex(raw); projection_h264_frame *f=nullptr;
    CHECK(projection_h264_push(d.get(),17,nal.data(),nal.size(),0,&f)==PROJECTION_H264_BITSTREAM&&!f);
    CHECK(projection_h264_drain(d.get(),17,&f)==PROJECTION_H264_STATE);
}
static void malformed(const std::vector<Bytes> &nals) {
    for(unsigned i=0;i<9;++i) { Spec s; if(i==0) s.aspect_idc=17; if(i==1) s.format=6; if(i==2) s.top=6;
        if(i==3) s.bottom=6; if(i==4) s.tick=0; if(i==5) s.scale=0; if(i==6) s.buffer=17;
        if(i==7) s.reorder=3; if(i==8) { s.nal_hrd=1; s.cpb=32; } rejected(sps(s)); }
    auto raw=sps(Spec{}); for(size_t n=1;n<raw.size();++n) rejected(Bytes(raw.begin(),raw.begin()+n));
    auto w=sps_bits(Spec{}); w.put(0,1); rejected(w.nal(0x67)); // missing stop bit
    auto tail=raw; tail.push_back(0x80); rejected(tail);
    for(unsigned mode=0;mode<3;++mode) {
        auto d=create(); push(d.get(),sps(Spec{})); if(mode!=0) push(d.get(),pps(0,0));
        auto bad=annex(mode==2?pps(0,1):slice_pps(nals[2],mode==0?0:1)); projection_h264_frame *f=nullptr;
        CHECK(projection_h264_push(d.get(),17,bad.data(),bad.size(),0,&f)==PROJECTION_H264_BITSTREAM&&!f);
    }
}
int main(int argc,char **argv) {
    CHECK(argc==2); auto nals=load(argv[1]); variants(nals); associations(nals); malformed(nals);
    std::cout<<"PASS: source VUI variants, selected SPS/PPS, repeated timestamps, owned snapshots and malformed syntax\n";
}
