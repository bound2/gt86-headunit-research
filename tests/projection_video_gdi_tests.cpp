/* SPDX-License-Identifier: GPL-3.0-only; real GDI surfaces/TCP/decoder, no visible window. */
#include "projection_video_socket_fixture.h"
#include "projection_video_gdi.h"
#include "projection_h264_source_fixture.h"
#include <cstdlib>
#include <thread>
#include <fcntl.h>
#include <io.h>
#undef CHECK
#define CHECK(x) do { if(!(x)) { std::cerr<<#x<<" line "<<__LINE__<<" Windows="<<GetLastError()<<'\n'; std::abort(); } } while(0)
extern "C" int projection_video_gdi_c_api_test(void);
struct Dib {
    HDC dc=nullptr; HBITMAP bitmap=nullptr; HGDIOBJ original=nullptr; uint8_t *pixels=nullptr; uint32_t width=0,height=0;
    Dib(uint32_t w=4,uint32_t h=4) { dc=CreateCompatibleDC(nullptr); CHECK(dc); resize(w,h); }
    void resize(uint32_t w,uint32_t h,unsigned depth=32) {
        if(bitmap) { CHECK(SelectObject(dc,original)); CHECK(DeleteObject(bitmap)); bitmap=nullptr; }
        BITMAPINFO info{}; info.bmiHeader.biSize=sizeof(info.bmiHeader); info.bmiHeader.biWidth=LONG(w);
        info.bmiHeader.biHeight=-LONG(h); info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=WORD(depth); info.bmiHeader.biCompression=BI_RGB;
        void *p=nullptr; bitmap=CreateDIBSection(nullptr,&info,DIB_RGB_COLORS,&p,nullptr,0); CHECK(bitmap&&p);
        auto previous=SelectObject(dc,bitmap); CHECK(previous&&previous!=HGDI_ERROR); if(!original) original=previous;
        pixels=static_cast<uint8_t*>(p); width=w; height=h; std::memset(pixels,0xa5,size_t(w)*h*depth/8);
    }
    bool black() const { CHECK(GdiFlush()); for(size_t p=0;p<size_t(width)*height;++p) if(pixels[p*4]||pixels[p*4+1]||pixels[p*4+2]) return false; return true; }
    Bytes copy() const { CHECK(GdiFlush()); return {pixels,pixels+size_t(width)*height*4}; }
    ~Dib() { if(bitmap) { SelectObject(dc,original); DeleteObject(bitmap); } if(dc) DeleteDC(dc); }
};
struct Picture {
    Bytes pixels=Bytes(24); projection_h264_view view{}; projection_video_metadata meta{};
    Picture() {
        for(unsigned i=0;i<16;++i) pixels[i]=uint8_t(16+i*14); pixels[16]=16; pixels[17]=128; pixels[18]=240; pixels[19]=96;
        pixels[20]=240; pixels[21]=128; pixels[22]=16; pixels[23]=192;
        view={{pixels.data(),pixels.data()+16,pixels.data()+20},4,4,{4,2,2},91,0,pixels.size()};
        meta.generation=91; meta.configuration_epoch=1; meta.frame_authenticated=1;
    }
    void counter(uint64_t n) { view.timestamp=meta.counter=n; }
};
struct Render {
    projection_video_gdi_config cfg{}; projection_video_gdi *g=nullptr;
    explicit Render(Dib &target,unsigned color=1,bool init=true) {
        cfg.count=1; cfg.targets[0]={110,static_cast<projection_video_color>(color),0,reinterpret_cast<uintptr_t>(target.dc)};
        cfg.max_width=1920; cfg.max_height=1088; cfg.max_target_width=cfg.max_target_height=4096; if(init) create();
    }
    ~Render() { projection_video_gdi_destroy(g); }
    void create() { CHECK(projection_video_gdi_create(&cfg,91,&g)==IAP2_OK&&g); }
    projection_video_sink sink() { return projection_video_gdi_sink(g); }
    uint64_t open(unsigned type=110) { auto p=sink(); uint64_t child=0; projection_session_resource q{}; q.type=type;
        CHECK(p.open(p.context,91,&q,&child)==IAP2_OK&&child); return child; }
    void configure(uint64_t child,uint64_t epoch=1) { auto p=sink(); projection_video_configuration c{91,epoch,66,4,0}; CHECK(p.configure(p.context,91,child,&c)==IAP2_OK); }
    void start(uint64_t child) { auto p=sink(); CHECK(p.start(p.context,91,child)==IAP2_OK); }
    void submit(uint64_t child,const Picture &v) { auto p=sink(); CHECK(p.submit(p.context,91,child,&v.view,&v.meta)==IAP2_OK); }
    projection_video_gdi_status status(unsigned type=110) { projection_video_gdi_status out{}; CHECK(projection_video_gdi_get_status(g,91,type,&out)==IAP2_OK); return out; }
};
static void rgb_equal(const Bytes &a,const Bytes &b) {
    CHECK(a.size()==b.size()); for(size_t i=0;i<a.size();++i) if(i%4!=3) CHECK(a[i]==b[i]);
}
static void lifecycle() {
    for(unsigned color=1;color<=4;++color) {
        Dib target; Render render(target,color); auto p=render.sink(); auto initial=target.copy(); uint64_t child=render.open();
        CHECK(target.copy()==initial&&!render.status().has_frame); render.configure(child); CHECK(target.black());
        render.start(child); Picture v; render.submit(child,v); auto baseline=target.copy(); CHECK(!target.black());
        Bytes expected(64); CHECK(projection_video_bgra(&v.view,static_cast<projection_video_color>(color),expected.data(),expected.size(),16)==0); rgb_equal(baseline,expected);
        auto st=render.status(); CHECK(st.draws==1&&st.has_frame&&st.width==4&&st.height==4&&st.counter==0&&st.epoch==1);
        // Input lifetime ends: resizing must use an independently retained copy.
        std::fill(v.pixels.begin(),v.pixels.end(),0); target.resize(8,8); CHECK(p.poll(p.context,91,child,1000000)==IAP2_OK);
        auto scaled=target.copy(); for(unsigned y=0;y<8;++y) for(unsigned x=0;x<8;++x) for(unsigned c=0;c<3;++c)
            CHECK(scaled[(y*8+x)*4+c]==baseline[((y/2)*4+x/2)*4+c]);
        CHECK(render.status().draws==1&&render.status().repaints==1);
        target.resize(12,8); CHECK(p.poll(p.context,91,child,1000000)==IAP2_OK);
        scaled=target.copy(); for(unsigned y=0;y<8;++y) for(unsigned x=0;x<12;++x) for(unsigned c=0;c<3;++c)
            CHECK(scaled[(y*12+x)*4+c]==(x<2||x>=10?0:baseline[((y/2)*4+(x-2)/2)*4+c]));
        render.configure(child,2); CHECK(target.black()&&!render.status().has_frame); target.resize(4,4);
        CHECK(p.poll(p.context,91,child,1000000)==IAP2_OK&&target.black());
        v.meta.configuration_epoch=2; v.counter(1); render.submit(child,v); CHECK(render.status().counter==1);
        p.close(p.context,90,child); CHECK(render.status().active); p.close(p.context,91,child); CHECK(target.black()&&!render.status().active);
        p.close(p.context,91,child); uint64_t next=render.open(); CHECK(next!=child); render.configure(next); render.start(next);
        v.meta.configuration_epoch=1; v.counter(0); render.submit(next,v); CHECK(render.status().counter==0);
    }
}
static void state_and_failure() {
    for(unsigned mode=0;mode<10;++mode) {
        Dib target; Render render(target); auto p=render.sink(); auto child=render.open(); Picture v;
        if(mode!=0) render.configure(child); if(mode!=1) render.start(child);
        if(mode==2) v.meta.configuration_epoch=2; if(mode==3) v.meta.frame_authenticated=0;
        if(mode==4) v.meta.configuration_authenticated=1; if(mode==5) v.view.generation=90;
        if(mode==6) v.view.stride[0]=3; if(mode==7) v.view.width=1922;
        if(mode==8) { render.submit(child,v); render.configure(child,2); v.meta.configuration_epoch=2; }
        if(mode==9) { render.submit(child,v); } // Replay in the same epoch.
        CHECK(p.submit(p.context,91,child,&v.view,&v.meta)==PROJECTION_VIDEO_GDI_CLOSED);
        CHECK(projection_video_gdi_error(render.g)==IAP2_INVALID&&target.black());
    }
    { Dib target; Render render(target); auto p=render.sink(); auto child=render.open(); render.configure(child); render.start(child); Picture v;
      projection_video_gdi_status before=render.status();
      std::thread wrong([&]{CHECK(p.submit(p.context,91,child,&v.view,&v.meta)==IAP2_INVALID);}); wrong.join();
      CHECK(render.status().draws==before.draws&&!render.status().has_frame); render.submit(child,v);
      target.resize(4,4,24); CHECK(p.poll(p.context,91,child,1000000)==PROJECTION_VIDEO_GDI_CLOSED);
      CHECK(projection_video_gdi_error(render.g)==IAP2_INVALID); }
    for(unsigned mode=0;mode<8;++mode) {
        Dib target; Render render(target,1,false);
        if(mode==0) render.cfg.count=0; if(mode==1) render.cfg.targets[0].color=static_cast<projection_video_color>(0);
        if(mode==2) render.cfg.targets[0].type=100; if(mode==3) render.cfg.targets[0].window=1;
        if(mode==4) render.cfg.max_width=1921; if(mode==5) render.cfg.max_target_height=0;
        if(mode==6) { render.cfg.count=2; render.cfg.targets[1]=render.cfg.targets[0]; }
        if(mode==7) render.cfg.targets[0].memory_dc=1;
        CHECK(projection_video_gdi_create(&render.cfg,91,&render.g)<0&&!render.g);
    }
}
static void dc_state_and_screens() {
    Dib main,alt; Render render(main,1,false); render.cfg.count=2; render.cfg.targets[1]={111,PROJECTION_VIDEO_BT709_FULL,0,reinterpret_cast<uintptr_t>(alt.dc)}; render.create();
    auto first=render.open(),second=render.open(111); render.configure(first); render.configure(second); render.start(first); render.start(second);
    CHECK(SetGraphicsMode(main.dc,GM_ADVANCED)); XFORM shift{1,0,0,1,91,43}; CHECK(SetWorldTransform(main.dc,&shift));
    CHECK(SetViewportOrgEx(main.dc,13,27,nullptr)); CHECK(SetStretchBltMode(main.dc,HALFTONE));
    HRGN clip=CreateRectRgn(0,0,1,1); CHECK(clip&&SelectClipRgn(main.dc,clip)!=ERROR); DeleteObject(clip);
    Picture v; render.submit(first,v); render.submit(second,v); CHECK(!main.black()&&!alt.black());
    XFORM current{}; POINT origin{}; CHECK(GetWorldTransform(main.dc,&current)&&current.eDx==91&&current.eDy==43);
    CHECK(GetViewportOrgEx(main.dc,&origin)&&origin.x==13&&origin.y==27&&GetStretchBltMode(main.dc)==HALFTONE);
    Bytes expected(64); CHECK(projection_video_bgra(&v.view,PROJECTION_VIDEO_BT601_LIMITED,expected.data(),64,16)==0); rgb_equal(main.copy(),expected);
    auto p=render.sink(); p.close(p.context,91,first); CHECK(main.black()&&!alt.black()&&render.status(111).active);
    projection_video_gdi_close(render.g); CHECK(main.black()&&alt.black());
}
struct Hidden { HWND window=nullptr; projection_video_gdi *g=nullptr; unsigned paints=0; };
static LRESULT CALLBACK hidden_proc(HWND window,UINT message,WPARAM w,LPARAM l) {
    auto *h=reinterpret_cast<Hidden*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_PAINT&&h&&h->g) { int r=projection_video_gdi_paint(h->g,91,110); CHECK(r==IAP2_OK||r==IAP2_MORE); ++h->paints; return 0; }
    return DefWindowProcW(window,message,w,l);
}
static void hidden_window(bool terminal) {
    auto saved_dpi=SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2); CHECK(saved_dpi);
    WNDCLASSW cls{}; cls.lpfnWndProc=hidden_proc; cls.hInstance=GetModuleHandleW(nullptr); cls.lpszClassName=L"GT86GdiHiddenTest";
    CHECK(RegisterClassW(&cls)); Hidden h; h.window=CreateWindowExW(0,cls.lpszClassName,L"",WS_POPUP,0,0,16,16,nullptr,nullptr,cls.hInstance,nullptr);
    CHECK(h.window&&!IsWindowVisible(h.window)); SetWindowLongPtrW(h.window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(&h));
    projection_video_gdi_config config{}; config.count=1; config.targets[0]={110,PROJECTION_VIDEO_BT601_LIMITED,reinterpret_cast<uintptr_t>(h.window),0};
    config.max_width=1920; config.max_height=1088; config.max_target_width=config.max_target_height=4096;
    CHECK(SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_UNAWARE));
    CHECK(projection_video_gdi_create(&config,91,&h.g)==IAP2_UNSUPPORTED&&!h.g);
    CHECK(SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));
    CHECK(projection_video_gdi_create(&config,91,&h.g)==IAP2_OK); auto p=projection_video_gdi_sink(h.g);
    projection_session_resource q{}; q.type=110; uint64_t child=0; CHECK(p.open(p.context,91,&q,&child)==IAP2_OK);
    projection_video_configuration c{91,1,66,4,0}; CHECK(p.configure(p.context,91,child,&c)==IAP2_OK&&p.start(p.context,91,child)==IAP2_OK);
    Picture v; CHECK(p.submit(p.context,91,child,&v.view,&v.meta)==IAP2_MORE&&p.poll(p.context,91,child,1000000)==IAP2_MORE);
    CHECK(InvalidateRect(h.window,nullptr,FALSE)); SendMessageW(h.window,WM_PAINT,0,0); CHECK(h.paints==1);
    projection_video_gdi_status st{}; CHECK(projection_video_gdi_get_status(h.g,91,110,&st)==IAP2_OK&&!st.has_frame&&!st.draws);
    p.close(p.context,91,child); SendMessageW(h.window,WM_PAINT,0,0); CHECK(h.paints==2);
    CHECK(p.open(p.context,91,&q,&child)==IAP2_OK&&p.start(p.context,91,child)==IAP2_OK);
    if(terminal) {
        projection_video_gdi_close(h.g); CHECK(InvalidateRect(h.window,nullptr,FALSE)); SendMessageW(h.window,WM_PAINT,0,0); CHECK(h.paints==3);
        CHECK(p.poll(p.context,91,child,1000000)==PROJECTION_VIDEO_GDI_CLOSED);
        SetWindowLongPtrW(h.window,GWLP_USERDATA,0); CHECK(DestroyWindow(h.window));
    } else {
        // Simulated OS target loss, not a reusable target binding.
        CHECK(DestroyWindow(h.window)); CHECK(p.poll(p.context,91,child,1000000)==PROJECTION_VIDEO_GDI_CLOSED);
    }
    projection_video_gdi_destroy(h.g); CHECK(UnregisterClassW(cls.lpszClassName,cls.hInstance)); CHECK(SetThreadDpiAwarenessContext(saved_dpi));
}
static uint64_t test_clock(void*) { return 1000000; }
struct Video { projection_video_services *s=nullptr; ~Video(){projection_video_services_destroy(s);} };
static void stream(const Media &m,unsigned color,bool v6,bool emit,bool source=false) {
    Dib target(source?304:152,source?200:100); Render render(target,source?5:color); Video video;
    projection_video_services_config config{}; config.local=config.peer=loopback(v6); config.clock_ns=test_clock;
    config.video={1920,1088,1000,2000,2,1}; config.sink=render.sink(); config.accept_ms=1000; config.poll_ms=2;
    CHECK(projection_video_services_create(&config,91,&video.s)==IAP2_OK); auto p=projection_video_services_provider(video.s);
    projection_session_resource q{}; q.type=110; projection_session_keys keys{}; projection_session_endpoint e{};
    CHECK(p.open(p.context,91,&q,0,&keys,&e)==IAP2_OK); Socket phone(SOCK_STREAM,v6); phone.connect_to(e.data_port);
    auto until=[&](auto condition) { auto end=std::chrono::steady_clock::now()+std::chrono::seconds(3);
        while(!condition()) { CHECK(std::chrono::steady_clock::now()<end); CHECK(projection_video_services_poll(video.s,91)==IAP2_OK); if(!condition()) Sleep(1); } };
    phone.send_bytes(record(1,{})); phone.send_bytes(record(1,Bytes{0,0,0,0,'a','v','c','C'}));
    phone.send_bytes(m.reserved_config()); phone.send_bytes(m.frame(keys.read,0)); until([&]{return render.status().epoch==1;});
    for(unsigned i=0;i<5;++i) CHECK(projection_video_services_poll(video.s,91)==IAP2_OK);
    CHECK(!render.status().started&&!render.status().has_frame&&target.black()); CHECK(p.start(p.context,91,&e.lease,1)==IAP2_OK);
    for(unsigned i=0;i<10;++i) {
        if(i) { phone.send_bytes(record(1,{})); phone.send_bytes(i%2?m.config:m.reserved_config()); phone.send_bytes(m.frame(keys.read,i,i+2)); }
        until([&]{return render.status().draws==i+1;});
        CHECK(render.status().counter==i&&render.status().width==152&&render.status().height==100&&render.status().epoch==1);
        if(source) CHECK(unsigned(render.status().color)==color&&render.status().sar_width==(color%2?2u:1u)&&render.status().sar_height==(color%2?1u:2u));
        if(emit) { uint32_t header[]={color,target.width,target.height,i}; auto pixels=target.copy();
            std::cout.write(reinterpret_cast<const char*>(header),sizeof(header)); std::cout.write(reinterpret_cast<const char*>(pixels.data()),std::streamsize(pixels.size())); }
    }
    Media replacement=m;
    if(!source) { replacement.nals[0]=source_fixture::sps(source_fixture::Spec{}); replacement.configure(); }
    if(source) { source_fixture::Spec spec; spec.matrix=color<=2?6:1; spec.full=color%2;
        spec.sw=color%2?1:2; spec.sh=color%2?2:1; replacement.nals[0]=source_fixture::sps(spec); replacement.configure(); }
    phone.send_bytes(replacement.config); until([&]{return render.status().epoch==2;}); CHECK(target.black()&&!render.status().has_frame);
    phone.send_bytes(m.frame(keys.read,10)); until([&]{return render.status().has_frame!=0;}); CHECK(render.status().counter==10);
    if(source) CHECK(unsigned(render.status().color)==(color%2?color+1:color-1)&&render.status().sar_width==(color%2?1u:2u)&&render.status().sar_height==(color%2?2u:1u));
    auto bad=m.frame(keys.read,11,3); bad.back()^=1; phone.send_bytes(bad); auto end=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    int result=IAP2_OK; while(result==IAP2_OK) { CHECK(std::chrono::steady_clock::now()<end); result=projection_video_services_poll(video.s,91); }
    CHECK(result==PROJECTION_VIDEO_SERVICES_CLOSED&&projection_video_services_error(video.s)==PROJECTION_VIDEO_AUTH&&target.black()&&!render.status().active);
}
static void source_policy() {
    { Dib target(8,8); Render render(target,5); auto child=render.open(); render.configure(child); render.start(child);
      Picture v; auto &s=v.view.source; s.vui_present=s.aspect_present=s.signal_present=s.colour_present=1;
      s.sar_width=2; s.sar_height=1; s.primaries=s.transfer=s.matrix=1; render.submit(child,v);
      auto first=target.copy(); Bytes raw(64); CHECK(projection_video_bgra(&v.view,PROJECTION_VIDEO_BT709_LIMITED,raw.data(),64,16)==0);
      for(unsigned y=0;y<8;++y) for(unsigned x=0;x<8;++x) for(unsigned c=0;c<3;++c)
          CHECK(first[(y*8+x)*4+c]==(y<2||y>=6?0:raw[((y-2)*4+x/2)*4+c]));
      // Retained SAR too: source descriptor lifetime ends with submit.
      s.sar_width=1; s.sar_height=2; target.resize(16,16); auto p=render.sink(); CHECK(p.poll(p.context,91,child,1000000)==IAP2_OK);
      CHECK(render.status().sar_width==2&&render.status().sar_height==1);
      auto bigger=target.copy(); for(unsigned y=0;y<16;++y) for(unsigned x=0;x<16;++x) for(unsigned c=0;c<3;++c)
          CHECK(bigger[(y*16+x)*4+c]==(y<4||y>=12?0:raw[(((y-4)/2)*4+x/4)*4+c]));
      render.configure(child,2); CHECK(target.black()&&!render.status().sar_width);
    }
    for(unsigned mode=0;mode<7;++mode) {
        Dib target; Render render(target,5); auto child=render.open(); render.configure(child); render.start(child);
        Picture v; auto &s=v.view.source; s.vui_present=s.aspect_present=s.signal_present=s.colour_present=1;
        s.sar_width=s.sar_height=1; s.primaries=s.transfer=s.matrix=1;
        render.submit(child,v); v.counter(1);
        if(mode==0) s.colour_present=0; if(mode==1) s.sar_width=0; if(mode==2) s.matrix=2;
        if(mode==3) s.transfer=16; if(mode==4) s.aspect_present=0; if(mode==5) s.sar_height=65536; if(mode==6) s.primaries=9;
        auto p=render.sink(); CHECK(p.submit(p.context,91,child,&v.view,&v.meta)==PROJECTION_VIDEO_GDI_CLOSED);
        CHECK(projection_video_gdi_error(render.g)==IAP2_UNSUPPORTED&&target.black());
    }
}
int main(int argc,char **argv) {
    try {
        CHECK(argc==2||argc==3); bool emit=argc==3,source=emit&&std::string(argv[2])=="--emit-source";
        if(emit) { CHECK(source||std::string(argv[2])=="--emit"); CHECK(_setmode(_fileno(stdout),_O_BINARY)!=-1); }
        CHECK(projection_video_gdi_c_api_test()); Winsock sockets; Media media(argv[1]);
        if(!emit) { lifecycle(); state_and_failure(); dc_state_and_screens(); source_policy(); hidden_window(false); hidden_window(true); }
        if(!source) for(unsigned color=1;color<=4;++color) { stream(media,color,false,emit); if(!emit) stream(media,color,true,false); }
        if(!emit||source) for(unsigned color=1;color<=4;++color) {
            Media specified=media; source_fixture::Spec spec; spec.matrix=color<=2?6:1; spec.full=color%2==0;
            spec.sw=color%2?2:1; spec.sh=color%2?1:2; specified.nals[0]=source_fixture::sps(spec); specified.configure();
            if(emit) { uint32_t n=uint32_t(specified.nals[0].size()); std::cout.write(reinterpret_cast<const char*>(&n),sizeof(n));
                std::cout.write(reinterpret_cast<const char*>(specified.nals[0].data()),n); }
            stream(specified,color,false,emit,true); if(!emit) stream(specified,color,true,false,true);
        }
        if(!emit) std::cout<<"PASS: real GDI pixels, owned repaint/resize, epochs/cleanup, hidden HWND backpressure and IPv4/IPv6 TCP/AEAD/H264 rendering; no visible window\n";
        return 0;
    } catch(...) { std::cerr<<"Unexpected exception in GDI test\n"; return 1; }
}
