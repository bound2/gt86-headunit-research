/* SPDX-License-Identifier: GPL-3.0-only; PUBLIC SYNTHETIC timing/control data. */
#ifndef GT86_PROJECTION_SYNC_FIXTURE_H
#define GT86_PROJECTION_SYNC_FIXTURE_H
#include "projection_audio_fixture.h"
#include "projection_timing.h"
inline Bytes audio_sync_packet(uint64_t ntp,uint32_t play,uint32_t sender) {
    Bytes b(20); b[0]=0x90; b[1]=0xd4; b[3]=4;
    for(unsigned i=0;i<4;++i) { b[4+i]=static_cast<uint8_t>(play>>(24-8*i)); b[16+i]=static_cast<uint8_t>(sender>>(24-8*i)); }
    for(unsigned i=0;i<8;++i) b[8+i]=static_cast<uint8_t>(ntp>>(56-8*i));
    return b;
}
inline void audio_sync_clock(projection_timing& s,uint64_t& now) {
    projection_timing_config cfg{}; projection_timing_default_config(&cfg); cfg.interval_ms=1;
    CHECK(projection_timing_init(&s,&cfg,now,UINT64_C(0x1234567880000000))==IAP2_OK);
    // Two matched zero-RTT synthetic D3 replies, NOT a physical peer clock.
    // They establish the actual filter state; no direct synced-field assignment.
    for(unsigned i=0;i<2;++i) {
        std::array<uint8_t,32> probe{},out{};
        CHECK(projection_timing_probe(&s,now,probe.data())==IAP2_OK);
        CHECK(projection_timing_sent(&s,now,projection_timing_now(&s,now))==IAP2_OK);
        auto reply=probe; reply[1]=0xd3;
        std::copy(probe.begin()+24,probe.end(),reply.begin()+8);
        std::copy(probe.begin()+24,probe.end(),reply.begin()+16);
        CHECK(projection_timing_feed(&s,reply.data(),reply.size(),now,now,out.data())==(i?PROJECTION_TIMING_SAMPLE:IAP2_OK));
        now+=1000000;
    }
    CHECK(s.synced);
}
#endif
