/* SPDX-License-Identifier: GPL-3.0-only */
#include "pair_tlv.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do { if(!(x)) throw std::runtime_error(std::string(#x)+" line "+std::to_string(__LINE__)); } while(0)
using Bytes=std::vector<uint8_t>;
static void roundtrip() {
    for(size_t length: {0u,1u,254u,255u,256u,510u,511u,4096u}) {
        Bytes value(length,0x5a),wire(PAIR_TLV_MAX_WIRE),arena(PAIR_TLV_MAX_WIRE);
        pair_tlv items[]={{3,value.data(),value.size()},{3,nullptr,0},{6,value.data(),std::min(length,size_t(1))}};
        pair_tlv decoded[32],v;size_t n=0,count=0,needed=0;
        CHECK(pair_tlv_encode(items,3,nullptr,0,&needed)==IAP2_OK);
        CHECK(pair_tlv_encode(items,3,wire.data(),wire.size(),&n)==IAP2_OK&&n==needed);
        CHECK(pair_tlv_decode(wire.data(),n,decoded,32,arena.data(),arena.size(),&count)==IAP2_OK&&count==3);
        CHECK(decoded[0].type==3&&decoded[0].size==length&&decoded[1].size==0);
        CHECK(std::equal(value.begin(),value.end(),decoded[0].data));
        CHECK(pair_tlv_get(decoded,count,3,&v)==IAP2_INVALID&&!v.data&&!v.size);
        CHECK(pair_tlv_get(decoded,count,6,&v)==IAP2_OK&&v.size==std::min(length,size_t(1)));
        CHECK(pair_tlv_get(decoded,count,42,&v)==IAP2_END&&!v.data&&!v.size);
    }
}
static void invalid_and_bounds() {
    std::array<pair_tlv,32> items{};Bytes arena(8192,0xaa);size_t n;
    for(const auto& b:std::vector<Bytes>{{1},{1,2,3},{255,1,3},{3,255,1}}) {
        auto saved=items;auto old=arena;
        CHECK(pair_tlv_decode(b.data(),b.size(),items.data(),32,arena.data(),arena.size(),&n)==IAP2_INVALID&&n==0);
        CHECK(std::memcmp(items.data(),saved.data(),sizeof(items))==0&&arena==old);
    }
    Bytes wire={6,1,1};CHECK(pair_tlv_decode(wire.data(),wire.size(),items.data(),0,arena.data(),arena.size(),&n)==IAP2_NO_SPACE);
    CHECK(pair_tlv_decode(wire.data(),wire.size(),items.data(),32,arena.data(),0,&n)==IAP2_NO_SPACE);
    pair_tlv out={3,arena.data(),8192};Bytes dest(8192,0xaa),old=dest;
    CHECK(pair_tlv_encode(&out,1,dest.data(),dest.size(),&n)==IAP2_NO_SPACE&&n==0&&dest==old);
    out.size=255;CHECK(pair_tlv_encode(&out,1,dest.data(),256,&n)==IAP2_NO_SPACE&&dest==old);
    out.type=255;CHECK(pair_tlv_encode(&out,1,dest.data(),dest.size(),&n)==IAP2_ARGUMENT);
    wire.clear();for(int i=0;i<33;++i) { wire.push_back(static_cast<uint8_t>(i));wire.push_back(0); }
    CHECK(pair_tlv_decode(wire.data(),wire.size(),items.data(),32,arena.data(),arena.size(),&n)==IAP2_NO_SPACE&&n==0);
    wire={3,0,3,0};CHECK(pair_tlv_decode(wire.data(),wire.size(),items.data(),32,nullptr,0,&n)==IAP2_OK&&n==2);
    CHECK(pair_tlv_decode(nullptr,0,nullptr,0,nullptr,0,&n)==IAP2_OK&&n==0);
}
static void mutations() {
    uint32_t seed=86;auto random=[&](){seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return seed;};
    Bytes wire(8192),arena(8192),again(8192),arena2(8192);pair_tlv fields[32],fields2[32];
    for(int i=0;i<6000;++i) {
        size_t length=random()%700,count=0;for(size_t j=0;j<length;++j) wire[j]=static_cast<uint8_t>(random());
        int r=pair_tlv_decode(wire.data(),length,fields,32,arena.data(),arena.size(),&count);
        if(r!=IAP2_OK) { CHECK(count==0);continue; }
        size_t n=0,count2=0;CHECK(pair_tlv_encode(fields,count,again.data(),again.size(),&n)==IAP2_OK);
        CHECK(pair_tlv_decode(again.data(),n,fields2,32,arena2.data(),arena2.size(),&count2)==IAP2_OK&&count2==count);
        for(size_t j=0;j<count;++j) CHECK(fields[j].type==fields2[j].type&&fields[j].size==fields2[j].size&&
            std::equal(fields[j].data,fields[j].data+fields[j].size,fields2[j].data));
    }
}
int main() { try { roundtrip();invalid_and_bounds();mutations();std::cout<<"PASS: 3 TLV8 groups, 6000 deterministic mutations\n";return 0; }
    catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; } }
