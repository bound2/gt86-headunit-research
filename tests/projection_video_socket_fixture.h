/* SPDX-License-Identifier: GPL-3.0-only; public synthetic screen records. */
#ifndef GT86_PROJECTION_VIDEO_SOCKET_FIXTURE_H
#define GT86_PROJECTION_VIDEO_SOCKET_FIXTURE_H
#include "projection_socket_fixture.h"
#include <filesystem>
#include <fstream>
static Bytes record(uint8_t opcode,const Bytes &body) {
    Bytes b(128); for(unsigned i=0;i<4;++i) b[i]=uint8_t(body.size()>>(8*i)); b[4]=opcode;
    b.insert(b.end(),body.begin(),body.end()); return b;
}
static Bytes sealed(const uint8_t *key,uint64_t counter,const Bytes &plain) {
    Bytes b=record(0,Bytes(plain.size()+16)); auto n=nonce(counter); size_t written=0;
    CHECK(pair_aead_seal(key,n.data(),b.data(),128,plain.data(),plain.size(),b.data()+128,plain.size()+16,&written)==IAP2_OK&&written==plain.size()+16);
    return b;
}
static void be16(Bytes &b,size_t n) { b.push_back(uint8_t(n>>8)); b.push_back(uint8_t(n)); }
struct Media {
    std::vector<Bytes> nals;
    Bytes config;
    explicit Media(const std::filesystem::path &root) {
        std::ifstream file(root/"Static.264",std::ios::binary); CHECK(file.good()); Bytes b(std::istreambuf_iterator<char>(file),{});
        size_t begin=0;
        for(size_t i=0;i+3<b.size();) {
            size_t n=0;
            if(!b[i]&&!b[i+1]) { if(b[i+2]==1) n=3; else if(!b[i+2]&&b[i+3]==1) n=4; }
            if(n) { if(begin) nals.emplace_back(b.begin()+begin,b.begin()+i); begin=i+n; i=begin; } else ++i;
        }
        CHECK(begin); nals.emplace_back(b.begin()+begin,b.end()); CHECK(nals.size()==12);
        CHECK((nals[0][0]&31)==7 && (nals[1][0]&31)==8 && (nals[2][0]&31)==5);
        config={1,nals[0][1],nals[0][2],nals[0][3],0xff,0xe1};
        be16(config,nals[0].size()); config.insert(config.end(),nals[0].begin(),nals[0].end()); config.push_back(1);
        be16(config,nals[1].size()); config.insert(config.end(),nals[1].begin(),nals[1].end()); config=record(1,config);
    }
    Bytes frame(const uint8_t *key,uint64_t counter,size_t index=2) const {
        Bytes b{0,0}; be16(b,nals.at(index).size()); b.insert(b.end(),nals[index].begin(),nals[index].end()); return sealed(key,counter,b);
    }
};
#endif
