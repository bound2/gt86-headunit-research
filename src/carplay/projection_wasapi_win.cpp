/* SPDX-License-Identifier: GPL-3.0-only */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <new>
#include <cwchar>
#include "projection_wasapi.h"
#include "projection_pcm_output.hpp"
/* These SDK declarations are not supplied by this SDK's uuid.lib. Define them
 * from the SDK's own MIDL type metadata, never handwritten GUID literals.
 * __uuidof is the deliberate Windows compiler extension at this boundary. */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wlanguage-extension-token"
#endif
extern "C" const CLSID CLSID_MMDeviceEnumerator=__uuidof(MMDeviceEnumerator);
extern "C" const IID IID_IMMDeviceEnumerator=__uuidof(IMMDeviceEnumerator);
extern "C" const IID IID_IMMEndpoint=__uuidof(IMMEndpoint);
extern "C" const IID IID_IAudioClient=__uuidof(IAudioClient);
extern "C" const IID IID_IAudioRenderClient=__uuidof(IAudioRenderClient);
extern "C" const IID IID_IAudioClock=__uuidof(IAudioClock);
#ifdef __clang__
#pragma clang diagnostic pop
#endif
namespace {
template<class T> void release(T*& p) noexcept { if(p) { p->Release(); p=nullptr; } }
int result(HRESULT r) noexcept { return r==S_OK?IAP2_OK:r==AUDCLNT_E_UNSUPPORTED_FORMAT?IAP2_UNSUPPORTED:IAP2_PROVIDER_FAILED; }
struct WasapiDevice final:projection_pcm::Device {
    IAudioClient *client=nullptr;
    IAudioRenderClient *render=nullptr;
    IAudioClock *clock=nullptr;
    ~WasapiDevice() noexcept override {
        if(client) client->Stop();
        ::release(clock); ::release(render); ::release(client);
    }
    int padding(uint32_t& n) noexcept override { return result(client->GetCurrentPadding(&n)); }
    int acquire(uint32_t n,uint8_t*& p) noexcept override { return result(render->GetBuffer(n,&p)); }
    int release(uint32_t n) noexcept override { return result(render->ReleaseBuffer(n,0)); }
    int start() noexcept override { return result(client->Start()); }
    int reset() noexcept override {
        HRESULT r=client->Stop(); if(FAILED(r)) return result(r);
        return result(client->Reset());
    }
    int position(uint64_t& p,uint64_t& q) noexcept override {
        UINT64 raw=0; HRESULT r=clock->GetPosition(&p,&raw);
        if(r==S_FALSE) return IAP2_MORE;
        if(r!=S_OK||raw>UINT64_MAX/100) return IAP2_PROVIDER_FAILED;
        q=raw*100; return IAP2_OK;
    }
};
}
struct projection_wasapi {
    DWORD thread=GetCurrentThreadId();
    wchar_t endpoint[1024]{};
    bool com=false;
    projection_pcm::Output output;
    projection_wasapi(uint64_t gen,uint32_t buffer,uint32_t startup) noexcept:
        output({this,open,clock,on_thread},gen,buffer,startup) {}
    static bool on_thread(void *p) noexcept { return static_cast<projection_wasapi*>(p)->thread==GetCurrentThreadId(); }
    static uint64_t clock(void*) noexcept { return projection_wasapi_clock_ns(nullptr); }
    static int open(void *p,const projection_audio_format& f,uint32_t buffer,projection_pcm::Device*& out) noexcept {
        auto& owner=*static_cast<projection_wasapi*>(p);
        out=nullptr;
        IMMDeviceEnumerator *enumerator=nullptr; IMMDevice *device=nullptr; IMMEndpoint *endpoint=nullptr;
        auto *stream=new(std::nothrow) WasapiDevice;
        if(!stream) return IAP2_NO_SPACE;
        HRESULT r=CoCreateInstance(CLSID_MMDeviceEnumerator,nullptr,CLSCTX_INPROC_SERVER,IID_IMMDeviceEnumerator,reinterpret_cast<void**>(&enumerator));
        if(r==S_OK) r=enumerator->GetDevice(owner.endpoint,&device);
        DWORD state=0; EDataFlow flow=eAll;
        if(r==S_OK) r=device->GetState(&state);
        if(r==S_OK&&state!=DEVICE_STATE_ACTIVE) r=AUDCLNT_E_DEVICE_INVALIDATED;
        if(r==S_OK) r=device->QueryInterface(IID_IMMEndpoint,reinterpret_cast<void**>(&endpoint));
        if(r==S_OK) r=endpoint->GetDataFlow(&flow);
        if(r==S_OK&&flow!=eRender) r=AUDCLNT_E_WRONG_ENDPOINT_TYPE;
        if(r==S_OK) r=device->Activate(IID_IAudioClient,CLSCTX_INPROC_SERVER,nullptr,reinterpret_cast<void**>(&stream->client));
        WAVEFORMATEX format{};
        format.wFormatTag=WAVE_FORMAT_PCM; format.nChannels=f.channels; format.nSamplesPerSec=f.clock_rate;
        format.wBitsPerSample=16; format.nBlockAlign=WORD(2*f.channels); format.nAvgBytesPerSec=f.clock_rate*format.nBlockAlign;
        GUID session{};
        if(r==S_OK) r=CoCreateGuid(&session); // Private nonpersistent session, no saved-volume mutation.
        if(r==S_OK) r=stream->client->Initialize(AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM|AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY|AUDCLNT_STREAMFLAGS_NOPERSIST,
            REFERENCE_TIME(buffer)*10000,0,&format,&session);
        REFERENCE_TIME period=0;
        if(r==S_OK) r=stream->client->GetBufferSize(&stream->capacity);
        if(r==S_OK) r=stream->client->GetDevicePeriod(&period,nullptr);
        if(r==S_OK&&(period<=0||period>1000000)) r=AUDCLNT_E_INVALID_DEVICE_PERIOD;
        if(r==S_OK) stream->period_ns=uint64_t(period)*100;
        if(r==S_OK) r=stream->client->GetService(IID_IAudioRenderClient,reinterpret_cast<void**>(&stream->render));
        if(r==S_OK) r=stream->client->GetService(IID_IAudioClock,reinterpret_cast<void**>(&stream->clock));
        if(r==S_OK) r=stream->clock->GetFrequency(&stream->frequency);
        ::release(endpoint); ::release(device); ::release(enumerator);
        if(r!=S_OK) { delete stream; return result(r); }
        out=stream; return IAP2_OK;
    }
};
extern "C" uint64_t projection_wasapi_clock_ns(void*) {
    LARGE_INTEGER ticks{},frequency{}; uint64_t ns=0;
    if(!QueryPerformanceFrequency(&frequency)||!QueryPerformanceCounter(&ticks)||frequency.QuadPart<=0||ticks.QuadPart<0||
       !projection_pcm::scale(uint64_t(ticks.QuadPart),uint64_t(frequency.QuadPart),1000000000,ns)) return UINT64_MAX;
    return ns;
}
extern "C" int projection_wasapi_create(const projection_wasapi_config *c,uint64_t gen,projection_wasapi **out) {
    if(out) *out=nullptr;
    if(!c||!out||!gen||!c->endpoint_id||!c->endpoint_id[0]||c->buffer_ms<40||c->buffer_ms>500||c->startup_ms>500) return IAP2_ARGUMENT;
    size_t n=0; while(n<1024&&c->endpoint_id[n]) ++n;
    if(n==1024) return IAP2_ARGUMENT;
    auto *owner=new(std::nothrow) projection_wasapi(gen,c->buffer_ms,c->startup_ms);
    if(!owner) return IAP2_NO_SPACE;
    HRESULT r=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(r)) { delete owner; return IAP2_PROVIDER_FAILED; }
    owner->com=true; std::wmemcpy(owner->endpoint,c->endpoint_id,n+1);
    *out=owner; return IAP2_OK;
}
extern "C" projection_audio_sink projection_wasapi_sink(projection_wasapi *p) {
    return p&&projection_wasapi::on_thread(p)?p->output.sink():projection_audio_sink{};
}
extern "C" int projection_wasapi_destroy(projection_wasapi *p) {
    if(!p) return IAP2_OK;
    if(!projection_wasapi::on_thread(p)) return IAP2_INVALID;
    bool com=p->com;
    delete p; if(com) CoUninitialize(); return IAP2_OK;
}
