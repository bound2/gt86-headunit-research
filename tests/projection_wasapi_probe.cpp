/* SPDX-License-Identifier: GPL-3.0-only */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <mmdeviceapi.h>
#include <functiondiscoverykeys_devpkey.h>
#include "projection_wasapi.h"
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#define CHECK(x) do { if(!(x)) throw std::runtime_error(std::string(__func__)+":"+std::to_string(__LINE__)+": " #x); } while(0)
template<class T> struct Com {
    T *p=nullptr;
    ~Com() { if(p) p->Release(); }
};
struct Apartment {
    Apartment() { CHECK(SUCCEEDED(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED))); }
    ~Apartment() { CoUninitialize(); }
};
struct Owner {
    projection_wasapi *p=nullptr;
    ~Owner() { projection_wasapi_destroy(p); }
};
static void arguments() {
    projection_wasapi *p=reinterpret_cast<projection_wasapi*>(1);
    CHECK(projection_wasapi_create(nullptr,91,&p)==IAP2_ARGUMENT&&!p);
    projection_wasapi_config config{L"not-a-real-render-endpoint-gt86-test",100,20,50,500};
    for(int bad=0;bad<8;++bad) {
        auto c=config; uint64_t gen=91;
        if(bad==0) c.endpoint_id=nullptr;
        if(bad==1) c.endpoint_id=L"";
        if(bad==2) c.buffer_ms=39;
        if(bad==3) c.buffer_ms=501;
        if(bad==4) c.startup_ms=501;
        if(bad==5) gen=0;
        if(bad==6) c.late_ms=1001;
        if(bad==7) c.drift_ppm=1001;
        CHECK(projection_wasapi_create(&c,gen,&p)==IAP2_ARGUMENT&&!p);
    }
    std::wstring long_id(1024,L'x'); auto c=config; c.endpoint_id=long_id.c_str();
    CHECK(projection_wasapi_create(&c,91,&p)==IAP2_ARGUMENT&&!p);
    CHECK(projection_wasapi_destroy(nullptr)==IAP2_OK&&!projection_wasapi_sink(nullptr).open);
    Owner owner; CHECK(projection_wasapi_create(&config,91,&owner.p)==IAP2_OK&&owner.p);
    auto sink=projection_wasapi_sink(owner.p);
    projection_audio_format format{}; CHECK(projection_audio_format_get(32768,&format)==IAP2_OK);
    projection_session_resource r{}; r.type=100; r.audio_format=format.bit; uint64_t lease=99;
    CHECK(sink.open(sink.context,91,&r,&format,&lease)==IAP2_PROVIDER_FAILED&&!lease); // No fallback device.
    int wrong=0; bool exposed=true;
    std::thread worker([&] { wrong=projection_wasapi_destroy(owner.p); exposed=projection_wasapi_sink(owner.p).open!=nullptr; });
    worker.join(); CHECK(wrong==IAP2_INVALID&&!exposed);
    CHECK(projection_wasapi_destroy(owner.p)==IAP2_OK); owner.p=nullptr;
    CHECK(SUCCEEDED(CoInitializeEx(nullptr,COINIT_MULTITHREADED)));
    int code=projection_wasapi_create(&config,91,&p); CoUninitialize();
    CHECK(code==IAP2_PROVIDER_FAILED&&!p);
    uint64_t before=projection_wasapi_clock_ns(nullptr),after=projection_wasapi_clock_ns(nullptr);
    CHECK(before!=UINT64_MAX&&after>=before&&after!=UINT64_MAX);
    std::cout<<"PASS: WASAPI arguments, missing explicit endpoint, thread/COM balance and QPC clock; no device started.\n";
}
static void list() {
    Apartment apartment;
    Com<IMMDeviceEnumerator> enumerator; Com<IMMDeviceCollection> collection;
    CHECK(CoCreateInstance(CLSID_MMDeviceEnumerator,nullptr,CLSCTX_INPROC_SERVER,IID_IMMDeviceEnumerator,reinterpret_cast<void**>(&enumerator.p))==S_OK);
    CHECK(enumerator.p->EnumAudioEndpoints(eRender,DEVICE_STATE_ACTIVE,&collection.p)==S_OK);
    UINT count=0; CHECK(collection.p->GetCount(&count)==S_OK);
    std::wcout<<L"Active rendering endpoints (read-only; none selected): "<<count<<L'\n';
    for(UINT i=0;i<count;++i) {
        Com<IMMDevice> device; CHECK(collection.p->Item(i,&device.p)==S_OK);
        Com<IPropertyStore> properties; PROPVARIANT name{};
        if(device.p->OpenPropertyStore(STGM_READ,&properties.p)==S_OK&&
           properties.p->GetValue(PKEY_Device_FriendlyName,&name)==S_OK&&name.vt==VT_LPWSTR&&name.pwszVal)
            std::wcout<<name.pwszVal<<L'\n';
        PropVariantClear(&name);
        LPWSTR id=nullptr; CHECK(device.p->GetId(&id)==S_OK);
        std::wcout<<id<<L'\n'; CoTaskMemFree(id);
    }
}
static void device(const wchar_t *id,bool silent,bool drift=false) {
    Owner owner; projection_wasapi_config config{id,100,20,drift?30u:0u,drift?500u:0u};
    CHECK(projection_wasapi_create(&config,91,&owner.p)==IAP2_OK);
    auto sink=projection_wasapi_sink(owner.p);
    projection_audio_format f{}; CHECK(projection_audio_format_get(32768,&f)==IAP2_OK);
    projection_session_resource resource{}; resource.type=100; resource.audio_format=f.bit; resource.frames_per_packet=480;
    uint64_t lease=0;
    int opened=sink.open(sink.context,91,&resource,&f,&lease);
    if(opened!=IAP2_OK) { std::cerr<<"Explicit endpoint open failed: "<<opened<<'\n'; CHECK(false); }
    projection_playback_position p{};
    CHECK(sink.playback(sink.context,91,lease,&p)==IAP2_OK&&!p.has_position&&p.sample_rate==48000);
    if(!silent) {
        sink.close(sink.context,91,lease);
        std::cout<<"PASS: explicit endpoint prepared for 48 kHz stereo PCM and closed; no Start or audio submission.\n";
        return;
    }
    CHECK(sink.start(sink.context,91,lease)==IAP2_OK);
    // Opt-in ONLY. All bytes are zero, no tone, loopback capture, mic or volume API.
    std::vector<uint8_t> zeros(1920,0);
    projection_audio_packet packet{}; packet.data=zeros.data(); packet.size=zeros.size(); packet.frames=480; packet.sample_time=10000;
    uint64_t base=projection_wasapi_clock_ns(nullptr); CHECK(base<UINT64_MAX-100000000); base+=100000000;
    packet.timed=static_cast<uint8_t>(drift); if(drift) packet.presentation_ns=base;
    bool observed=false; unsigned accepted=0;
    auto end=std::chrono::steady_clock::now()+std::chrono::seconds(drift?12:2);
    while(std::chrono::steady_clock::now()<end) {
        uint64_t now=projection_wasapi_clock_ns(nullptr);
        int code=sink.poll(sink.context,91,lease,now); CHECK(code==IAP2_OK||code==IAP2_MORE);
        code=sink.submit(sink.context,91,lease,&f,&packet); CHECK(code==IAP2_OK||code==IAP2_MORE);
        if(code==IAP2_OK) { packet.sample_time+=480; ++accepted; if(drift) packet.presentation_ns=base+uint64_t(accepted)*10000000; }
        CHECK(sink.playback(sink.context,91,lease,&p)==IAP2_OK);
        if(p.has_position) {
            CHECK(p.sample_rate==48000&&p.raw_ns<=projection_wasapi_clock_ns(nullptr)&&p.sample_time>=10000&&p.sample_time<packet.sample_time);
            observed=true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    sink.close(sink.context,91,lease);
    CHECK(observed&&accepted>0);
    std::cout<<"PASS: explicit endpoint accepted zero PCM and returned device-clock media observations; no audible signal or capture requested.\n";
    if(drift) std::cout<<"Drift mode: per-stream rate adjustment enabled; this smoke check does not establish acoustic quality or a known-drift calibration.\n";
}
int wmain(int argc,wchar_t **argv) {
    try {
        if(argc==2&&std::wstring(argv[1])==L"--arguments") arguments();
        else if(argc==2&&std::wstring(argv[1])==L"--list") list();
        else if(argc==3&&std::wstring(argv[1])==L"--prepare") device(argv[2],false);
        else if(argc==3&&std::wstring(argv[1])==L"--silent-smoke") device(argv[2],true);
        else if(argc==3&&std::wstring(argv[1])==L"--prepare-drift") device(argv[2],false,true);
        else if(argc==3&&std::wstring(argv[1])==L"--silent-drift") device(argv[2],true,true);
        else { std::cerr<<"Usage: projection_wasapi_probe --arguments | --list | --prepare ENDPOINT_ID | --silent-smoke ENDPOINT_ID | --prepare-drift ENDPOINT_ID | --silent-drift ENDPOINT_ID\n"; return 2; }
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
