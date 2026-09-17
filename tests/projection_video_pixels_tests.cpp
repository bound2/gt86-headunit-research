/* SPDX-License-Identifier: GPL-3.0-only; independent floating-point colour oracle. */
#include "projection_video_pixels.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <vector>
#define CHECK(x) do { if(!(x)) { std::cerr<<#x<<" line "<<__LINE__<<'\n'; std::abort(); } } while(0)
extern "C" int projection_video_pixels_c_api_test(void);
using Bytes=std::vector<uint8_t>;
static projection_h264_view view(Bytes &pixels,uint32_t w,uint32_t h) {
    size_t n=size_t(w)*h; CHECK(pixels.size()==n+n/2);
    return {{pixels.data(),pixels.data()+n,pixels.data()+n+n/4},w,h,{w,w/2,w/2},91,0,pixels.size()};
}
static std::array<int,3> reference(unsigned y,unsigned u,unsigned v,unsigned color) {
    double kr=color<=2?0.299:0.2126,kb=color<=2?0.114:0.0722,kg=1-kr-kb;
    bool limited=color==1||color==3;
    double luma=(double(y)-(limited?16:0))*(limited?255.0/219:1),
        blue=(double(u)-128)*(limited?255.0/224:1),red=(double(v)-128)*(limited?255.0/224:1);
    auto round=[](double n){return int(std::clamp(std::lround(n),0L,255L));};
    return {round(luma+2*(1-kb)*blue),round(luma-2*kb*(1-kb)/kg*blue-2*kr*(1-kr)/kg*red),round(luma+2*(1-kr)*red)};
}
static void colors() {
    constexpr unsigned chroma[]={0,16,32,64,96,112,127,128,129,144,160,192,224,240,255};
    Bytes pixels(6),output(16); auto v=view(pixels,2,2); size_t checked=0;
    for(unsigned color=1;color<=4;++color) for(unsigned y=0;y<256;++y) for(auto u:chroma) for(auto vv:chroma) {
        std::fill_n(pixels.begin(),4,uint8_t(y)); pixels[4]=uint8_t(u); pixels[5]=uint8_t(vv);
        CHECK(projection_video_bgra(&v,static_cast<projection_video_color>(color),output.data(),output.size(),8)==0);
        auto expected=reference(y,u,vv,color);
        for(unsigned p=0;p<4;++p) { for(unsigned c=0;c<3;++c) CHECK(std::abs(int(output[p*4+c])-expected[c])<=1); CHECK(output[p*4+3]==255); }
        ++checked;
    }
    std::cout<<checked<<" colour triples / "<<checked*4<<" output pixels checked against independent double-precision equations\n";
}
static void geometry() {
    Bytes input(24); for(unsigned i=0;i<input.size();++i) input[i]=uint8_t(i*11); auto v=view(input,4,4); Bytes output(80,0xa5);
    CHECK(projection_video_bgra(&v,PROJECTION_VIDEO_BT709_FULL,output.data(),output.size(),20)==0);
    for(unsigned y=0;y<4;++y) for(unsigned x=0;x<4;++x) {
        auto expected=reference(input[y*4+x],input[16+(y/2)*2+x/2],input[20+(y/2)*2+x/2],4);
        for(unsigned c=0;c<3;++c) CHECK(std::abs(int(output[y*20+x*4+c])-expected[c])<=1);
    }
    for(unsigned y=0;y<4;++y) for(unsigned i=16;i<20;++i) CHECK(output[y*20+i]==0xa5);
    projection_video_rect r{};
    CHECK(projection_video_fit(1920,1080,800,480,&r)==0&&r.x==0&&r.y==15&&r.width==800&&r.height==450);
    CHECK(projection_video_fit(4,4,9,4,&r)==0&&r.x==2&&r.y==0&&r.width==4&&r.height==4);
    CHECK(projection_video_fit(1920,2,1,1,&r)==0&&r.width==1&&r.height==1);
    auto before=r; CHECK(projection_video_fit(0,1,1,1,&r)==-1&&r.width==before.width&&r.height==before.height);
    CHECK(projection_video_fit(2,2,4097,1,&r)==-1&&projection_video_fit(2,2,1,0,&r)==-1);
    for(uint32_t tw=1;tw<=4096;tw+=17) for(uint32_t th=1;th<=4096;th+=31) {
        CHECK(projection_video_fit(152,100,tw,th,&r)==0&&r.width&&r.height&&r.x+r.width<=tw&&r.y+r.height<=th);
    }
}
static void invalid() {
    Bytes input(24,123),output(80,0xa5); auto v=view(input,4,4),before=v;
    for(unsigned mode=0;mode<13;++mode) {
        v=before; auto color=PROJECTION_VIDEO_BT601_LIMITED; size_t stride=16,capacity=output.size();
        if(mode==0) v.width=3; if(mode==1) v.height=0; if(mode==2) v.width=UINT32_MAX;
        if(mode==3) --v.bytes; if(mode==4) v.plane[1]=v.plane[2]; if(mode==5) ++v.stride[2];
        if(mode==6) v.plane[0]=nullptr; if(mode==7) color=static_cast<projection_video_color>(0);
        if(mode==8) stride=15; if(mode==9) capacity=63; if(mode==10) stride=SIZE_MAX;
        if(mode==11) v.plane[0]=reinterpret_cast<const uint8_t*>(UINTPTR_MAX-4);
        if(mode==12) color=static_cast<projection_video_color>(5);
        CHECK(projection_video_bgra(&v,color,output.data(),capacity,stride)==-1&&std::all_of(output.begin(),output.end(),[](auto b){return b==0xa5;}));
    }
    v=before; CHECK(projection_video_bgra(&v,PROJECTION_VIDEO_BT601_FULL,input.data(),80,16)==-1);
    CHECK(std::all_of(input.begin(),input.end(),[](auto b){return b==123;}));
    CHECK(projection_video_bgra(nullptr,PROJECTION_VIDEO_BT601_FULL,output.data(),80,16)==-1);
}
static void maximum() {
    constexpr uint32_t w=PROJECTION_H264_MAX_WIDTH,h=PROJECTION_H264_MAX_HEIGHT;
    Bytes input(size_t(w)*h*3/2,128); std::fill_n(input.begin(),size_t(w)*h,16); auto v=view(input,w,h);
    size_t stride=size_t(w)*4+7; Bytes output(stride*h+17,0xa5);
    CHECK(projection_video_bgra(&v,PROJECTION_VIDEO_BT709_LIMITED,output.data(),output.size(),stride)==0);
    for(uint32_t y=0;y<h;++y) {
        for(uint32_t x=0;x<w;++x) { size_t at=y*stride+x*4; CHECK(!output[at]&&!output[at+1]&&!output[at+2]&&output[at+3]==255); }
        for(size_t x=size_t(w)*4;x<stride;++x) CHECK(output[y*stride+x]==0xa5);
    }
    CHECK(std::all_of(output.end()-17,output.end(),[](auto b){return b==0xa5;}));
}
static void source_metadata() {
    projection_h264_source s{}; s.vui_present=s.signal_present=s.colour_present=1; s.primaries=s.transfer=1;
    for(unsigned matrix:{1u,5u,6u}) for(unsigned range=0;range<2;++range) {
        s.matrix=uint8_t(matrix); s.full_range=uint8_t(range); auto color=PROJECTION_VIDEO_SOURCE;
        CHECK(projection_video_source_color(&s,&color)==0&&unsigned(color)==(matrix==1?3u:1u)+range);
    }
    auto valid=s;
    for(unsigned mode=0;mode<11;++mode) { s=valid; auto color=PROJECTION_VIDEO_SOURCE;
        if(mode==0) s.vui_present=0; if(mode==1) s.signal_present=0; if(mode==2) s.colour_present=0;
        if(mode==3) s.full_range=2; if(mode==4) s.matrix=2; if(mode==5) s.matrix=9;
        if(mode==6) s.transfer=16; if(mode==7) s.transfer=18; if(mode==8) s.primaries=9;
        if(mode==9) s.transfer=2; if(mode==10) s.primaries=2;
        CHECK(projection_video_source_color(&s,&color)==-1&&color==PROJECTION_VIDEO_SOURCE);
    }
    projection_video_rect r{}; CHECK(projection_video_fit_sar(720,576,16,15,800,480,&r)==0&&r.x==80&&r.y==0&&r.width==640&&r.height==480);
    CHECK(projection_video_fit_sar(152,100,2,1,304,200,&r)==0&&r.width==304&&r.height==100&&r.y==50);
    CHECK(projection_video_fit_sar(152,100,1,2,304,200,&r)==0&&r.width==152&&r.height==200&&r.x==76);
    auto before=r; CHECK(projection_video_fit_sar(152,100,0,1,304,200,&r)==-1&&r.x==before.x);
    CHECK(projection_video_fit_sar(152,100,1,65536,304,200,&r)==-1);
    for(unsigned sw:{1u,2u,15u,65535u}) for(unsigned sh:{1u,2u,16u,65535u})
        for(unsigned tw:{1u,257u,4096u}) for(unsigned th:{1u,513u,4096u}) {
            CHECK(projection_video_fit_sar(1920,1088,sw,sh,tw,th,&r)==0);
            double ratio=1920.0*sw/(1088.0*sh);
            unsigned ew,eh; if(ratio>double(tw)/th) { ew=tw; eh=std::max(1u,unsigned(std::floor(tw/ratio))); }
            else { eh=th; ew=std::max(1u,unsigned(std::floor(th*ratio))); }
            CHECK(r.width==ew&&r.height==eh&&r.x==(tw-ew)/2&&r.y==(th-eh)/2);
        }
}
int main() { CHECK(projection_video_pixels_c_api_test()); colors(); geometry(); invalid(); maximum(); source_metadata(); std::cout<<"PASS: explicit I420/BGRA conversion, padding/alias/bounds, source colour and sample-aspect fit\n"; }
