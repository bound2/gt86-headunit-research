/* SPDX-License-Identifier: GPL-3.0-only */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "projection_video_gdi.h"
#include <array>
#include <new>
#include <utility>

namespace {
struct Slot {
    projection_video_gdi_status status{};
    uint8_t *front=nullptr,*work=nullptr; size_t front_capacity=0,work_capacity=0;
    uint64_t last_counter=0; bool counted=false;
};
void pixels_free(Slot &a) {
    if(a.front) { pair_crypto_wipe(a.front,a.front_capacity); delete[] a.front; }
    if(a.work) { pair_crypto_wipe(a.work,a.work_capacity); delete[] a.work; }
    a.front=a.work=nullptr; a.front_capacity=a.work_capacity=0; a.status.has_frame=0;
    a.status.width=a.status.height=0;
    a.status.sar_width=a.status.sar_height=0; a.status.color=static_cast<projection_video_color>(0);
}
}
struct projection_video_gdi {
    projection_video_gdi_config config{}; std::array<Slot,2> slots{};
    uint64_t generation=0,next_lease=1; DWORD thread=0;
    bool failed=false,finalized=false; int last_error=0;
};
namespace {
int owner(const projection_video_gdi *s,uint64_t gen) {
    if(!s||!gen) return IAP2_ARGUMENT;
    if(gen!=s->generation||s->thread!=GetCurrentThreadId()) return IAP2_INVALID;
    return s->failed?PROJECTION_VIDEO_GDI_CLOSED:IAP2_OK;
}
size_t binding(const projection_video_gdi *s,uint32_t type) {
    for(size_t i=0;i<s->config.count;++i) if(s->config.targets[i].type==type) return i;
    return 2;
}
size_t leased(const projection_video_gdi *s,uint64_t lease) {
    for(size_t i=0;i<s->config.count;++i) if(s->slots[i].status.active&&lease&&s->slots[i].status.lease==lease) return i;
    return 2;
}
int target_size(const projection_video_gdi *s,size_t i,uint32_t &w,uint32_t &h,bool &ready) {
    const auto &t=s->config.targets[i]; w=h=0; ready=true;
    if(t.window) {
        HWND window=reinterpret_cast<HWND>(t.window); DWORD pid=0;
        if(GetWindowThreadProcessId(window,&pid)!=s->thread||pid!=GetCurrentProcessId()) return IAP2_INVALID;
        if(GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext())!=DPI_AWARENESS_PER_MONITOR_AWARE||
           GetAwarenessFromDpiAwarenessContext(GetWindowDpiAwarenessContext(window))!=DPI_AWARENESS_PER_MONITOR_AWARE) return IAP2_UNSUPPORTED;
        RECT r{}; if(!GetClientRect(window,&r)||r.right<0||r.bottom<0) return IAP2_PROVIDER_FAILED;
        w=static_cast<uint32_t>(r.right); h=static_cast<uint32_t>(r.bottom);
        ready=IsWindowVisible(window)&&!IsIconic(window)&&w&&h;
    } else {
        HDC dc=reinterpret_cast<HDC>(t.memory_dc); DIBSECTION dib{};
        if(GetObjectType(dc)!=OBJ_MEMDC||GetObjectW(GetCurrentObject(dc,OBJ_BITMAP),sizeof(dib),&dib)!=sizeof(dib)||
           !dib.dsBm.bmBits||dib.dsBm.bmBitsPixel!=32||dib.dsBm.bmPlanes!=1||dib.dsBm.bmWidth<=0||dib.dsBm.bmHeight<=0||
           dib.dsBmih.biCompression!=BI_RGB) return IAP2_INVALID;
        w=static_cast<uint32_t>(dib.dsBm.bmWidth); h=static_cast<uint32_t>(dib.dsBm.bmHeight);
    }
    return w>s->config.max_target_width||h>s->config.max_target_height?IAP2_UNSUPPORTED:IAP2_OK;
}
int draw_dc(HDC dc,const uint8_t *pixels,uint32_t w,uint32_t h,uint32_t tw,uint32_t th,uint32_t sw,uint32_t sh) {
    if(!tw||!th) return IAP2_MORE;
    int saved=SaveDC(dc); if(!saved) return IAP2_PROVIDER_FAILED;
    XFORM identity{1,0,0,1,0,0};
    bool ok=SetGraphicsMode(dc,GM_ADVANCED)!=0&&SetWorldTransform(dc,&identity)&&SetGraphicsMode(dc,GM_COMPATIBLE)!=0&&
        SetLayout(dc,0)!=GDI_ERROR&&SetMapMode(dc,MM_TEXT)!=0&&SetWindowOrgEx(dc,0,0,nullptr)&&SetViewportOrgEx(dc,0,0,nullptr)&&
        SetStretchBltMode(dc,COLORONCOLOR)!=0&&SetICMMode(dc,ICM_OFF)!=0&&SelectClipRgn(dc,nullptr)!=ERROR;
    RECT clip{}; int clipping=ok?GetClipBox(dc,&clip):ERROR;
    if(clipping==NULLREGION) {
        bool restored=RestoreDC(dc,saved)!=0; bool flushed=GdiFlush()!=0;
        return restored&&flushed?IAP2_MORE:IAP2_PROVIDER_FAILED;
    }
    if(clipping==ERROR) ok=false;
    RECT rect{0,0,static_cast<LONG>(tw),static_cast<LONG>(th)};
    if(ok) ok=FillRect(dc,&rect,static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)))!=0;
    if(ok&&pixels) {
        projection_video_rect fit{}; ok=projection_video_fit_sar(w,h,sw,sh,tw,th,&fit)==0;
        if(ok) {
            BITMAPINFO info{}; info.bmiHeader.biSize=sizeof(info.bmiHeader); info.bmiHeader.biWidth=static_cast<LONG>(w);
            info.bmiHeader.biHeight=-static_cast<LONG>(h); info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32; info.bmiHeader.biCompression=BI_RGB;
            int copied=StretchDIBits(dc,static_cast<int>(fit.x),static_cast<int>(fit.y),static_cast<int>(fit.width),static_cast<int>(fit.height),
                0,0,static_cast<int>(w),static_cast<int>(h),pixels,&info,DIB_RGB_COLORS,SRCCOPY);
            ok=copied>0;
        }
    }
    if(!RestoreDC(dc,saved)) ok=false;
    if(!GdiFlush()) ok=false;
    return ok?IAP2_OK:IAP2_PROVIDER_FAILED;
}
int draw_target(projection_video_gdi *s,size_t i,const uint8_t *pixels,uint32_t w,uint32_t h,bool repaint,uint32_t sw=1,uint32_t sh=1) {
    uint32_t tw=0,th=0; bool ready=false; int r=target_size(s,i,tw,th,ready); if(r) return r;
    if(!ready) return IAP2_MORE;
    const auto &t=s->config.targets[i]; HWND window=reinterpret_cast<HWND>(t.window);
    HDC dc=window?GetDC(window):reinterpret_cast<HDC>(t.memory_dc); if(!dc) return IAP2_PROVIDER_FAILED;
    r=draw_dc(dc,pixels,w,h,tw,th,sw,sh);
    if(window&&!(GetClassLongPtrW(window,GCL_STYLE)&(CS_OWNDC|CS_CLASSDC))&&!ReleaseDC(window,dc)) r=IAP2_PROVIDER_FAILED;
    if(r==IAP2_OK) {
        auto &status=s->slots[i].status; status.target_width=tw; status.target_height=th;
        if(pixels) { auto &count=repaint?status.repaints:status.draws; if(count!=UINT64_MAX) ++count; }
    }
    return r;
}
void retire(projection_video_gdi *s,size_t i) {
    auto &a=s->slots[i]; bool active=a.status.active!=0; pixels_free(a); a=Slot{};
    if(active) {
        if(s->config.targets[i].window) InvalidateRect(reinterpret_cast<HWND>(s->config.targets[i].window),nullptr,FALSE);
        (void)draw_target(s,i,nullptr,0,0,false);
    }
}
int fail(projection_video_gdi *s,int error) {
    if(!s->failed) { s->failed=true; s->last_error=error; for(size_t i=0;i<s->config.count;++i) retire(s,i); }
    return PROJECTION_VIDEO_GDI_CLOSED;
}
int open(void *context,uint64_t gen,const projection_session_resource *q,uint64_t *child) {
    if(child) *child=0; auto *s=static_cast<projection_video_gdi*>(context); int r=owner(s,gen); if(r) return r;
    if(!q||!child||!s->next_lease) return IAP2_ARGUMENT;
    size_t i=binding(s,q->type); if(i==2) return IAP2_UNSUPPORTED; auto &a=s->slots[i];
    if(a.status.active) return IAP2_INVALID;
    uint32_t w,h; bool ready; r=target_size(s,i,w,h,ready); if(r) return fail(s,r);
    a.status.active=1; a.status.lease=s->next_lease++; *child=a.status.lease; return IAP2_OK;
}
int start(void *context,uint64_t gen,uint64_t child) {
    auto *s=static_cast<projection_video_gdi*>(context); int r=owner(s,gen); if(r) return r;
    size_t i=leased(s,child); if(i==2||s->slots[i].status.started) return IAP2_INVALID;
    s->slots[i].status.started=1; return IAP2_OK;
}
int configure(void *context,uint64_t gen,uint64_t child,const projection_video_configuration *c) {
    auto *s=static_cast<projection_video_gdi*>(context); int r=owner(s,gen); if(r) return r;
    size_t i=leased(s,child); if(i==2||!c) return IAP2_INVALID; auto &a=s->slots[i];
    if(c->generation!=gen||c->authenticated||c->epoch<=a.status.epoch||c->epoch>64||
       (c->profile!=66&&c->profile!=77&&c->profile!=100)||(c->length_size!=1&&c->length_size!=2&&c->length_size!=4)) return fail(s,IAP2_INVALID);
    pixels_free(a); a.status.epoch=c->epoch; a.status.counter=0;
    if(s->config.targets[i].window&&!InvalidateRect(reinterpret_cast<HWND>(s->config.targets[i].window),nullptr,FALSE)) return fail(s,IAP2_PROVIDER_FAILED);
    r=draw_target(s,i,nullptr,0,0,false); return r==IAP2_OK||r==IAP2_MORE?IAP2_OK:fail(s,r);
}
int submit(void *context,uint64_t gen,uint64_t child,const projection_h264_view *v,const projection_video_metadata *m) {
    auto *s=static_cast<projection_video_gdi*>(context); int r=owner(s,gen); if(r) return r;
    size_t i=leased(s,child); if(i==2||!v||!m) return IAP2_INVALID; auto &a=s->slots[i];
    if(!a.status.started||!a.status.epoch||v->generation!=gen||m->generation!=gen||m->configuration_epoch!=a.status.epoch||
       m->frame_authenticated!=1||m->configuration_authenticated||v->timestamp!=m->counter||
       (a.counted&&m->counter<=a.last_counter)||v->width>s->config.max_width||v->height>s->config.max_height) return fail(s,IAP2_INVALID);
    auto color=s->config.targets[i].color; uint32_t sw=1,sh=1;
    if(color==PROJECTION_VIDEO_SOURCE) {
        sw=v->source.sar_width; sh=v->source.sar_height;
        if(projection_video_source_color(&v->source,&color)||v->source.aspect_present!=1||
           !sw||!sh||sw>65535||sh>65535) return fail(s,IAP2_UNSUPPORTED);
    }
    uint32_t tw,th; bool ready; r=target_size(s,i,tw,th,ready); if(r) return fail(s,r); if(!ready) return IAP2_MORE;
    size_t bytes=static_cast<size_t>(v->width)*v->height*4;
    if(!bytes) return fail(s,IAP2_INVALID);
    if(bytes>a.work_capacity) {
        if(a.work) { pair_crypto_wipe(a.work,a.work_capacity); delete[] a.work; }
        a.work=nullptr; a.work_capacity=0;
        auto *p=new(std::nothrow) uint8_t[bytes]; if(!p) return fail(s,IAP2_NO_SPACE);
        a.work=p; a.work_capacity=bytes;
    }
    if(projection_video_bgra(v,color,a.work,a.work_capacity,static_cast<size_t>(v->width)*4)) return fail(s,IAP2_INVALID);
    r=draw_target(s,i,a.work,v->width,v->height,false,sw,sh); if(r!=IAP2_OK) return r==IAP2_MORE?r:fail(s,r);
    std::swap(a.front,a.work); std::swap(a.front_capacity,a.work_capacity);
    a.status.has_frame=1; a.status.width=v->width; a.status.height=v->height; a.status.counter=m->counter;
    a.status.sar_width=sw; a.status.sar_height=sh; a.status.color=color;
    a.last_counter=m->counter; a.counted=true; return IAP2_OK;
}
int poll(void *context,uint64_t gen,uint64_t child,uint64_t) {
    auto *s=static_cast<projection_video_gdi*>(context); int r=owner(s,gen); if(r) return r;
    size_t i=leased(s,child); if(i==2||!s->slots[i].status.started) return IAP2_INVALID; auto &a=s->slots[i];
    uint32_t w,h; bool ready; r=target_size(s,i,w,h,ready); if(r) return fail(s,r); if(!ready) return IAP2_MORE;
    if(w==a.status.target_width&&h==a.status.target_height) return IAP2_OK;
    r=draw_target(s,i,a.status.has_frame?a.front:nullptr,a.status.width,a.status.height,true,a.status.sar_width,a.status.sar_height);
    return r==IAP2_OK||r==IAP2_MORE?r:fail(s,r);
}
void close(void *context,uint64_t gen,uint64_t child) {
    auto *s=static_cast<projection_video_gdi*>(context); if(!s||gen!=s->generation||s->thread!=GetCurrentThreadId()||s->finalized) return;
    size_t i=leased(s,child); if(i!=2) retire(s,i);
}
}
extern "C" int projection_video_gdi_create(const projection_video_gdi_config *c,uint64_t gen,projection_video_gdi **out) {
    if(out) *out=nullptr;
    if(!out||!c||!gen||!c->count||c->count>2||c->max_width<2||c->max_height<2||
       c->max_width>PROJECTION_H264_MAX_WIDTH||c->max_height>PROJECTION_H264_MAX_HEIGHT||
       !c->max_target_width||!c->max_target_height||c->max_target_width>4096||c->max_target_height>4096) return IAP2_ARGUMENT;
    for(size_t i=0;i<c->count;++i) {
        const auto &t=c->targets[i];
        if((t.type!=110&&t.type!=111)||t.color<1||t.color>5||bool(t.window)==bool(t.memory_dc)) return IAP2_ARGUMENT;
        for(size_t j=0;j<i;++j) if(t.type==c->targets[j].type||(t.window&&t.window==c->targets[j].window)||
            (t.memory_dc&&t.memory_dc==c->targets[j].memory_dc)) return IAP2_ARGUMENT;
    }
    auto *s=new(std::nothrow) projection_video_gdi; if(!s) return IAP2_NO_SPACE;
    s->config=*c; s->generation=gen; s->thread=GetCurrentThreadId();
    for(size_t i=0;i<c->count;++i) { uint32_t w,h; bool ready; int r=target_size(s,i,w,h,ready); if(r) { delete s; return r; } }
    *out=s; return IAP2_OK;
}
extern "C" projection_video_sink projection_video_gdi_sink(projection_video_gdi *s) { return {s,open,start,configure,submit,poll,close}; }
extern "C" int projection_video_gdi_paint(projection_video_gdi *s,uint64_t gen,uint32_t type) {
    int r=owner(s,gen); if(r&&r!=PROJECTION_VIDEO_GDI_CLOSED) return r; size_t i=binding(s,type);
    if(i==2||!s->config.targets[i].window) return IAP2_UNSUPPORTED;
    uint32_t w,h; bool ready; r=target_size(s,i,w,h,ready); if(r) return fail(s,r);
    HWND window=reinterpret_cast<HWND>(s->config.targets[i].window); PAINTSTRUCT paint{};
    HDC dc=BeginPaint(window,&paint); if(!dc) return fail(s,IAP2_PROVIDER_FAILED);
    auto &a=s->slots[i]; bool frame=!s->failed&&a.status.active&&a.status.started&&a.status.has_frame;
    r=draw_dc(dc,frame?a.front:nullptr,a.status.width,a.status.height,w,h,a.status.sar_width,a.status.sar_height);
    if(!EndPaint(window,&paint)) r=IAP2_PROVIDER_FAILED;
    if(r==IAP2_OK) { a.status.target_width=w; a.status.target_height=h; if(frame&&a.status.repaints!=UINT64_MAX) ++a.status.repaints; }
    return r==IAP2_OK||r==IAP2_MORE?r:fail(s,r);
}
extern "C" int projection_video_gdi_get_status(const projection_video_gdi *s,uint64_t gen,uint32_t type,projection_video_gdi_status *out) {
    if(out) *out={}; int r=owner(s,gen); if(r) return r; if(!out) return IAP2_ARGUMENT;
    size_t i=binding(s,type); if(i==2) return IAP2_UNSUPPORTED; *out=s->slots[i].status; return IAP2_OK;
}
extern "C" int projection_video_gdi_error(const projection_video_gdi *s) { return s?s->last_error:IAP2_ARGUMENT; }
extern "C" void projection_video_gdi_close(projection_video_gdi *s) {
    if(!s||s->finalized||s->thread!=GetCurrentThreadId()) return;
    fail(s,IAP2_END); s->finalized=true;
}
extern "C" void projection_video_gdi_destroy(projection_video_gdi *s) {
    if(s&&s->thread==GetCurrentThreadId()) { projection_video_gdi_close(s); delete s; }
}
