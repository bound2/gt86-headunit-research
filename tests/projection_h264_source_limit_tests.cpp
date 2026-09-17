/* SPDX-License-Identifier: GPL-3.0-only */
/* White-box only: inject delayed codec output/limits without production hooks.
 * The public-API source and golden tests separately link carplay_h264. */
#include "../src/carplay/projection_h264.cpp"
#include <memory>
#include <iostream>
#define CHECK(x) do { if(!(x)) { std::cerr<<#x<<" line "<<__LINE__<<'\n'; std::abort(); } } while(0)
using Decoder=std::unique_ptr<projection_h264,decltype(&projection_h264_destroy)>;
static Decoder create() {
    projection_h264 *d=nullptr; CHECK(projection_h264_create(17,1920,1088,&d)==PROJECTION_H264_MORE);
    d->sps=true; d->sources[0].valid=true; d->sources[0].width=d->sources[0].height=2; d->pps[0]={0,true};
    return {d,projection_h264_destroy};
}
static const uint8_t slice[]={0,0,1,0x65,0xb8}; // first_mb=0, I, PPS 0; prefix inspection only
static int prepare(projection_h264 *d,uint64_t stamp) {
    bool sps=false,vcl=false; int r=inspect_nal(slice,sizeof(slice),d,stamp,sps,vcl);
    CHECK(r!=PROJECTION_H264_MORE||vcl); return r;
}
static int output(projection_h264 *d,uint64_t token,projection_h264_frame **out) {
    uint8_t pixels[6]={16,16,16,16,128,128}; uint8_t *planes[]={pixels,pixels+4,pixels+5};
    SBufferInfo b{}; b.iBufferStatus=1; b.uiOutYuvTimeStamp=token;
    auto &s=b.UsrData.sSystemBuffer; s.iWidth=s.iHeight=2; s.iFormat=videoFormatI420; s.iStride[0]=2; s.iStride[1]=1;
    return copy_frame(d,dsErrorFree,planes,b,out);
}
int main() {
    { auto d=create();
      for(unsigned i=0;i<32;++i) { d->sources[0].source.matrix=uint8_t(i); CHECK(prepare(d.get(),77)==PROJECTION_H264_MORE); }
      CHECK(prepare(d.get(),77)==PROJECTION_H264_LIMIT&&d->next_token==33);
      for(unsigned i=32;i;--i) { projection_h264_frame *f=nullptr; CHECK(output(d.get(),i,&f)==PROJECTION_H264_FRAME);
          projection_h264_view v{}; CHECK(projection_h264_frame_view(f,&v)==PROJECTION_H264_FRAME);
          CHECK(v.timestamp==77&&v.source.matrix==i-1); projection_h264_frame_destroy(f); }
      CHECK(prepare(d.get(),99)==PROJECTION_H264_MORE&&d->au_token==33);
    }
    { auto d=create(); d->next_token=UINT64_MAX; CHECK(prepare(d.get(),7)==PROJECTION_H264_MORE&&d->au_token==UINT64_MAX&&!d->next_token);
      projection_h264_frame *f=nullptr; CHECK(output(d.get(),UINT64_MAX,&f)==PROJECTION_H264_FRAME); projection_h264_frame_destroy(f); f=nullptr;
      CHECK(projection_h264_push(d.get(),17,slice,sizeof(slice),7,&f)==PROJECTION_H264_LIMIT&&!f&&!d->codec);
    }
    { auto d=create(); CHECK(prepare(d.get(),7)==PROJECTION_H264_MORE); projection_h264_frame *f=nullptr;
      CHECK(output(d.get(),0,&f)==PROJECTION_H264_BACKEND&&!d->codec&&!f); }
    { auto d=create(); d->sources[0].width=4; CHECK(prepare(d.get(),7)==PROJECTION_H264_MORE); projection_h264_frame *f=nullptr;
      CHECK(output(d.get(),1,&f)==PROJECTION_H264_BACKEND&&!d->codec&&!f); }
    { auto d=create(); CHECK(prepare(d.get(),7)==PROJECTION_H264_MORE); projection_h264_frame *f=nullptr;
      CHECK(output(d.get(),1,&f)==PROJECTION_H264_FRAME); projection_h264_frame_destroy(f); f=nullptr;
      CHECK(output(d.get(),1,&f)==PROJECTION_H264_BACKEND&&!d->codec&&!f); }
    { auto d=create(); CHECK(prepare(d.get(),7)==PROJECTION_H264_MORE); projection_h264_frame *f=nullptr;
      CHECK(projection_h264_drain(d.get(),17,&f)==PROJECTION_H264_BACKEND&&!d->codec&&!f); }
    { auto d=create(); for(unsigned i=0;i<32;++i) CHECK(prepare(d.get(),i)==PROJECTION_H264_MORE);
      projection_h264_frame *f=nullptr; CHECK(projection_h264_push(d.get(),18,slice,sizeof(slice),0,&f)==PROJECTION_H264_STALE&&d->codec&&d->next_token==33);
      CHECK(projection_h264_push(d.get(),17,slice,sizeof(slice),0,&f)==PROJECTION_H264_LIMIT&&!d->codec&&!f); }
    std::cout<<"PASS: injected delayed/reordered metadata, duplicate external stamps, 32-slot bound, token exhaustion and missing output associations\n";
}
