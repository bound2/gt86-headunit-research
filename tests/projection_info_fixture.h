/* SPDX-License-Identifier: GPL-3.0-only
 * Explicit PUBLIC SYNTHETIC capabilities; no real hardware, valid HID or icon.
 */
#ifndef GT86_PROJECTION_INFO_FIXTURE_H
#define GT86_PROJECTION_INFO_FIXTURE_H
#include "projection_info.h"
#include "pair_test_support.h"
inline rtsp_slice info_text(const char* s) { return {reinterpret_cast<const uint8_t*>(s),std::strlen(s)}; }
inline projection_info_profile info_fixture(unsigned variant) {
    static const auto descriptor=[] { std::array<uint8_t,1024> b{}; for(size_t i=0;i<b.size();++i) b[i]=static_cast<uint8_t>(i*7+1); return b; }();
    static const auto icon=[] { std::array<uint8_t,8192> b{}; for(size_t i=0;i<b.size();++i) b[i]=static_cast<uint8_t>(i*11+3); return b; }();
    static const char* hid_ids[]={"12340001","12340002","12340003","12340004"};
    static const char* extensions[]={"vocoderInfo","enhancedRequestCarUI","testExtension2","testExtension3","testExtension4","testExtension5","testExtension6","testExtension7"};
    projection_info_profile p{};
    p.source_version=info_text("PUBLIC-TEST-1.0"); p.model=info_text("Synthetic receiver"); p.manufacturer=info_text("Test only");
    p.device_id=info_text("02:00:00:00:00:01"); p.name=info_text("Public capability fixture");
    if(!variant) return p;
    p.bluetooth_id=info_text("02:00:00:00:00:02"); p.features=UINT64_C(0x615653aee2); p.status_flags=4; p.speech_mode=-1;
    p.display_count=variant==2?2:1;
    for(size_t i=0;i<p.display_count;++i) {
        auto& d=p.displays[i]; d.uuid=info_text(i?"00000000-2222-4000-8000-000000000002":"00000000-1111-4000-8000-000000000001");
        d.type=i?111:110; d.width=800; d.height=480; d.width_mm=160; d.height_mm=96; d.max_fps=60; d.features=10; d.primary_input=3;
        if(variant==2) { d.has_view=d.has_safe=d.draw_outside_safe=1; d.view={10,20,780,440}; d.safe={20,30,760,420}; d.initial_url=info_text("maps://"); }
    }
    p.hid_count=4;
    for(size_t i=0;i<p.hid_count;++i) {
        auto& h=p.hids[i]; h.uuid=info_text(hid_ids[i]); h.name=info_text("Opaque synthetic HID"); h.display_uuid=p.displays[0].uuid;
        h.product_id=static_cast<uint16_t>(i+1); h.vendor_id=2; h.descriptor={descriptor.data(),variant==2?descriptor.size():size_t(17)};
    }
    p.audio_count=9;
    p.audio[0]={100,0x554,0xffc,PROJECTION_AUDIO_COMPATIBILITY}; p.audio[1]={101,0,0xffc,PROJECTION_AUDIO_COMPATIBILITY};
    p.audio[2]={100,0x70000554,0x70000ffc,PROJECTION_AUDIO_DEFAULT}; p.audio[3]={100,0,0x70000ffc,PROJECTION_AUDIO_ALERT};
    p.audio[4]={100,0,0xffc,PROJECTION_AUDIO_MEDIA}; p.audio[5]={100,0x70000554,0x70000554,PROJECTION_AUDIO_TELEPHONY};
    p.audio[6]={100,0x70000554,0x70000554,PROJECTION_AUDIO_SPEECH}; p.audio[7]={101,0,0x70000ffc,PROJECTION_AUDIO_DEFAULT};
    p.audio[8]={102,0,0x400000,PROJECTION_AUDIO_MEDIA};
    p.latency_count=9;
    p.latencies[0]={100,0,0,PROJECTION_AUDIO_ANY}; p.latencies[1]={100,10,20,PROJECTION_AUDIO_DEFAULT};
    p.latencies[2]={100,20,40,PROJECTION_AUDIO_MEDIA}; p.latencies[3]={100,30,60,PROJECTION_AUDIO_TELEPHONY};
    p.latencies[4]={100,40,80,PROJECTION_AUDIO_SPEECH}; p.latencies[5]={100,50,100,PROJECTION_AUDIO_ALERT};
    p.latencies[6]={101,60,120,PROJECTION_AUDIO_ANY}; p.latencies[7]={101,70,140,PROJECTION_AUDIO_DEFAULT}; p.latencies[8]={102,80,160,PROJECTION_AUDIO_DEFAULT};
    p.resource_count=2; p.resources[0]={1,1,100,100,100,100}; p.resources[1]={2,1,100,100,100,100};
    p.extension_count=variant==2?8:2;
    for(size_t i=0;i<p.extension_count;++i) p.extensions[i]=info_text(extensions[i]);
    if(variant==2) {
        p.features=p.status_flags=UINT64_MAX; p.right_hand_drive=p.keep_alive_low_power=p.keep_alive_stats=p.hevc=p.call_active=p.turn_by_turn_active=1;
        p.icon_count=2; p.oem_label=info_text("Synthetic icon data");
        for(size_t i=0;i<p.icon_count;++i) p.icons[i]={{icon.data(),icon.size()},256,256,1};
    }
    return p;
}
inline Bytes info_encode(const projection_info_profile& p) {
    size_t n=0; CHECK(projection_info_encode(&p,nullptr,0,&n)==IAP2_OK&&n<=PROJECTION_INFO_LIMIT);
    Bytes b(n); size_t written=0; CHECK(projection_info_encode(&p,b.data(),b.size(),&written)==IAP2_OK&&written==n); return b;
}
#endif
