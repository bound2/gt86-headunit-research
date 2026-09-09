/* SPDX-License-Identifier: GPL-3.0-only
 * Host-only helpers. All loaded keys are PUBLIC synthetic fixtures.
 */
#ifndef GT86_PAIR_TEST_SUPPORT_H
#define GT86_PAIR_TEST_SUPPORT_H
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#define CHECK(x) do { if(!(x)) throw std::runtime_error(std::string(#x)+" line "+std::to_string(__LINE__)); } while(0)
using Bytes=std::vector<uint8_t>;
using Vectors=std::map<std::string,Bytes>;
inline Bytes hex(const std::string& s) { CHECK(s.size()%2==0);Bytes b;for(size_t i=0;i<s.size();i+=2) b.push_back(static_cast<uint8_t>(std::stoul(s.substr(i,2),nullptr,16)));return b; }
inline Vectors load_vectors(const char* path,size_t count) {
    std::ifstream f(path);CHECK(f.good());Vectors v;std::string line;
    while(std::getline(f,line)) { if(!line.empty()&&line.back()=='\r') line.pop_back();if(line.empty()||line[0]=='#') continue;
        auto p=line.find('=');CHECK(p!=std::string::npos&&v.emplace(line.substr(0,p),hex(line.substr(p+1))).second); }
    CHECK(v.size()==count);return v;
}
inline bool zeroed(const void* p,size_t n) { auto b=static_cast<const uint8_t*>(p);return std::all_of(b,b+n,[](uint8_t c){return c==0;}); }
inline bool equal(const uint8_t* p,const Bytes& b) { return std::equal(b.begin(),b.end(),p); }
inline Bytes bytes(const std::string& s) { return {s.begin(),s.end()}; }
#endif
