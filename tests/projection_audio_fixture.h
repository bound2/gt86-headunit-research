/* SPDX-License-Identifier: GPL-3.0-only; PUBLIC SYNTHETIC packet construction. */
#ifndef GT86_PROJECTION_AUDIO_FIXTURE_H
#define GT86_PROJECTION_AUDIO_FIXTURE_H
#include "projection_audio.h"
#include "pair_test_support.h"
inline Bytes audio_packet(const uint8_t* key,uint64_t counter,uint32_t sample,const Bytes& plain,uint16_t sequence=0,uint32_t ssrc=0xaabbccdd) {
    Bytes b(plain.size()+36); b[0]=0x80; b[1]=0x60; b[2]=static_cast<uint8_t>(sequence>>8); b[3]=static_cast<uint8_t>(sequence);
    for(unsigned i=0;i<4;++i) { b[4+i]=static_cast<uint8_t>(sample>>(24-8*i)); b[8+i]=static_cast<uint8_t>(ssrc>>(24-8*i)); }
    uint8_t nonce[12]{}; for(unsigned i=0;i<8;++i) nonce[4+i]=static_cast<uint8_t>(counter>>(8*i));
    size_t written=0; CHECK(pair_aead_seal(key,nonce,b.data()+4,8,plain.data(),plain.size(),b.data()+12,plain.size()+16,&written)==IAP2_OK&&written==plain.size()+16);
    std::copy(nonce+4,nonce+12,b.end()-8); return b;
}
#endif
