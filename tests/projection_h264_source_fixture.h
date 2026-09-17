/* SPDX-License-Identifier: GPL-3.0-only; locally generated metadata for Static.264. */
#ifndef GT86_PROJECTION_H264_SOURCE_FIXTURE_H
#define GT86_PROJECTION_H264_SOURCE_FIXTURE_H
#include <cstdint>
#include <vector>
#include <cstdlib>
namespace source_fixture {
using Bytes=std::vector<uint8_t>;
struct Writer {
    std::vector<uint8_t> bits;
    void put(uint32_t v,unsigned n) { for(unsigned i=n;i;--i) bits.push_back(uint8_t((v>>(i-1))&1)); }
    void ue(uint32_t v) { uint32_t code=v+1; unsigned n=0; for(auto x=code;x;x>>=1) ++n; put(0,n-1); put(code,n); }
    Bytes nal(uint8_t header,bool stop=true) {
        if(stop) put(1,1); while(bits.size()%8) put(0,1);
        Bytes out{header}; unsigned zeros=0;
        for(size_t i=0;i<bits.size();i+=8) {
            uint8_t v=0; for(unsigned j=0;j<8;++j) v=uint8_t((v<<1)|bits[i+j]);
            if(zeros==2&&v<=3) { out.push_back(3); zeros=0; }
            out.push_back(v); zeros=v==0?zeros+1:0;
        }
        return out;
    }
};
struct Spec {
    unsigned id=0,vui=1,aspect=1,aspect_idc=255,sw=2,sh=1,signal=1,format=5,full=0,colour=1;
    unsigned primaries=1,transfer=1,matrix=1,chroma=1,top=0,bottom=0,timing=1,tick=1001,scale=60000;
    unsigned nal_hrd=0,vcl_hrd=0,cpb=0,restriction=1,reorder=0,buffer=2;
};
inline Writer sps_bits(const Spec &s) {
    Writer w; w.put(66,8); w.put(0,8); w.put(13,8); w.ue(s.id);
    // Original Static.264 coding syntax: 160x112 coded, cropped to 152x100.
    w.ue(11); w.ue(0); w.ue(12); w.ue(2); w.put(1,1); w.ue(9); w.ue(6);
    w.put(1,1); w.put(0,1); w.put(1,1); w.ue(0); w.ue(4); w.ue(0); w.ue(6);
    w.put(s.vui,1);
    if(!s.vui) return w;
    w.put(s.aspect,1); if(s.aspect) { w.put(s.aspect_idc,8); if(s.aspect_idc==255) { w.put(s.sw,16); w.put(s.sh,16); } }
    w.put(1,1); w.put(0,1); // explicitly no overscan
    w.put(s.signal,1); if(s.signal) { w.put(s.format,3); w.put(s.full,1); w.put(s.colour,1);
        if(s.colour) { w.put(s.primaries,8); w.put(s.transfer,8); w.put(s.matrix,8); } }
    w.put(s.chroma,1); if(s.chroma) { w.ue(s.top); w.ue(s.bottom); }
    w.put(s.timing,1); if(s.timing) { w.put(s.tick,32); w.put(s.scale,32); w.put(1,1); }
    auto hrd=[&] { w.ue(s.cpb); w.put(0,8); for(unsigned i=0;i<=s.cpb;++i) { w.ue(0); w.ue(0); w.put(1,1); } w.put(0,20); };
    w.put(s.nal_hrd,1); if(s.nal_hrd) hrd(); w.put(s.vcl_hrd,1); if(s.vcl_hrd) hrd();
    if(s.nal_hrd||s.vcl_hrd) w.put(0,1);
    w.put(0,1); w.put(s.restriction,1); if(s.restriction) { w.put(1,1); w.ue(2); w.ue(1); w.ue(16); w.ue(16); w.ue(s.reorder); w.ue(s.buffer); }
    return w;
}
inline Bytes sps(const Spec &s) { return sps_bits(s).nal(0x67); }
inline Bytes annex(const Bytes &raw) { Bytes out{0,0,0,1}; out.insert(out.end(),raw.begin(),raw.end()); return out; }
inline std::vector<uint8_t> rbsp_bits(const Bytes &nal) {
    std::vector<uint8_t> bits; unsigned zeros=0;
    for(size_t i=1;i<nal.size();++i) {
        if(zeros==2&&nal[i]==3) { zeros=0; continue; }
        for(unsigned j=8;j;--j) bits.push_back(uint8_t((nal[i]>>(j-1))&1));
        zeros=nal[i]==0?zeros+1:0;
    }
    while(!bits.empty()&&!bits.back()) bits.pop_back(); // retain rbsp_stop_one_bit
    return bits;
}
inline Bytes pps(unsigned pps_id,unsigned sps_id) {
    Writer w; w.ue(pps_id); w.ue(sps_id);
    auto bits=rbsp_bits({0x68,0xce,0x3c,0x80}); w.bits.insert(w.bits.end(),bits.begin()+2,bits.end());
    return w.nal(0x68,false);
}
inline Bytes slice_pps(const Bytes &slice,unsigned id) {
    auto bits=rbsp_bits(slice); size_t at=0;
    auto ue=[&]() { unsigned z=0; while(at<bits.size()&&!bits[at++]) ++z;
        if(z>30||at+z>bits.size()) std::abort(); uint32_t v=1; while(z--) v=(v<<1)|bits[at++]; return v-1; };
    Writer w; auto mb=ue(),type=ue(); ue(); w.ue(mb); w.ue(type); w.ue(id);
    w.bits.insert(w.bits.end(),bits.begin()+at,bits.end()); return w.nal(slice[0],false);
}
}
#endif
