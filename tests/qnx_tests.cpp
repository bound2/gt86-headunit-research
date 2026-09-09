#include "qnx.hpp"
#include "minilzo.h"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <stdexcept>

using firmware::Bytes;
static void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
template<class F> static void rejects(F action, const char* message) {
    bool failed=false;
    try { action(); } catch (const std::runtime_error&) { failed=true; }
    check(failed,message);
}
static void put32(Bytes& b, std::size_t p, std::uint32_t n) {
    for (unsigned i=0;i<4;++i) b.at(p+i)=static_cast<std::uint8_t>(n>>(i*8));
}
static void seal(Bytes& b) {
    put32(b,b.size()-4,0);
    std::uint32_t sum=0;
    for (std::size_t p=0;p<b.size();p+=4)
        for (unsigned i=0;i<4;++i) sum+=std::uint32_t(b[p+i])<<(8*i);
    put32(b,b.size()-4,0U-sum);
}
static void str(Bytes& b,std::size_t p,const char* s) {
    do { b.at(p++)=static_cast<std::uint8_t>(*s); } while (*s++);
}
// Hand-constructed layout: one file, one symlink, a terminator, and payload.
static Bytes fixture() {
    Bytes b(256,0);
    str(b,0,"imagefs"); put32(b,8,256); put32(b,12,184); put32(b,16,92);
    b[92]=48; put32(b,96,1); put32(b,100,0x81ed);
    put32(b,116,192); put32(b,120,4); str(b,124,"bin/demo");
    b[140]=40; put32(b,144,2); put32(b,148,0xa1ff);
    b[164]=5; b[166]=4; str(b,168,"link"); str(b,173,"demo");
    str(b,192,"abc"); seal(b); return b;
}
static Bytes compress_blocks(const Bytes& input) {
    check(lzo_init()==LZO_E_OK,"LZO initialization");
    std::vector<lzo_align_t> work((LZO1X_1_MEM_COMPRESS+sizeof(lzo_align_t)-1)/sizeof(lzo_align_t));
    Bytes out;
    for (std::size_t p=0;p<input.size();p+=32768) {
        const auto n=std::min<std::size_t>(32768,input.size()-p);
        Bytes compressed(n+n/16+64+3);
        lzo_uint size=compressed.size();
        check(lzo1x_1_compress(input.data()+p,n,compressed.data(),&size,work.data())==LZO_E_OK,"LZO compression");
        check(size<65536,"test block fits header");
        out.push_back(static_cast<std::uint8_t>(size>>8));
        out.push_back(static_cast<std::uint8_t>(size));
        out.insert(out.end(),compressed.begin(),compressed.begin()+size);
    }
    out.insert(out.end(),{0,0}); return out;
}
int main(int argc,char** argv) {
    try {
        auto b=fixture(); const auto entries=firmware::qnx_directory(b);
        check(entries.size()==2,"file and link count");
        check(entries[0].path=="bin/demo" && entries[0].offset==192 && entries[0].size==4,"file layout");
        check(entries[1].path=="link" && entries[1].target=="demo","symlink offset is relative to path");
        auto bad=b; bad[192]^=1;
        rejects([&]{firmware::qnx_directory(bad);},"corrupt payload checksum");
        bad=b; put32(bad,116,92); seal(bad);
        rejects([&]{firmware::qnx_directory(bad);},"metadata overlap");
        bad=b; bad[92]=255; seal(bad);
        rejects([&]{firmware::qnx_directory(bad);},"record bounds");
        bad=b; bad[164]=39; seal(bad);
        rejects([&]{firmware::qnx_directory(bad);},"symlink bounds");
        bad=b; bad[180]=24; seal(bad);
        rejects([&]{firmware::qnx_directory(bad);},"missing terminator");
        bad=b; put32(bad,8,260); seal(bad);
        rejects([&]{firmware::qnx_directory(bad);},"declared image length");
        for (const auto* path:{"../escape","a/../../b","/absolute","C:/x","a\\b","a//b","a/","a/.","NUL.txt","a/LPT1","a:b","a. ","a\nrow"})
            check(!firmware::safe_relative_path(path),"unsafe filename rejected");
        check(firmware::safe_relative_path("usr/lib/libscreen.so.1"),"normal filename allowed");
        Bytes data(100000);
        for (std::size_t i=0;i<data.size();++i) data[i]=static_cast<std::uint8_t>(i*13+i/255);
        auto packed=compress_blocks(data);
        check(firmware::lzo_blocks(packed,data.size())==data,"multi-block decompression");
        rejects([&]{firmware::lzo_blocks(packed,data.size()-1);},"overlarge decompression");
        rejects([&]{firmware::lzo_blocks(packed,data.size()+1);},"short decompression");
        packed.pop_back();
        rejects([&]{firmware::lzo_blocks(packed,data.size());},"truncated terminator");
        packed=compress_blocks(data); packed.push_back(1);
        rejects([&]{firmware::lzo_blocks(packed,data.size());},"trailing data");
        const Bytes invalid{0,1,0,0,0};
        rejects([&]{firmware::lzo_blocks(invalid,16);},"invalid compressed block");
        packed=compress_blocks(b); Bytes container(64,0);
        str(container,0,"hbcifs"); put32(container,8,static_cast<std::uint32_t>(b.size()));
        put32(container,12,static_cast<std::uint32_t>(packed.size()));
        container[24]=2; container[25]=2; container[26]=0x88;
        container.insert(container.end(),packed.begin(),packed.end());
        const auto images=firmware::qnx_images(container);
        check(images.size()==1 && images[0].data==b,"HBCIFS container decode");
        container[24]=3;
        rejects([&]{firmware::qnx_images(container);},"unknown container variant");
        Bytes startup(256,0); put32(startup,0,0x00ff7eeb); startup[4]=1;
        startup[6]=9; startup[9]=1; startup[10]=40;
        put32(startup,32,256); put32(startup,36,static_cast<std::uint32_t>(256+packed.size()+4));
        put32(startup,44,static_cast<std::uint32_t>(b.size()));
        startup.insert(startup.end(),packed.begin(),packed.end()); startup.resize(startup.size()+4);
        check(firmware::qnx_images(startup)[0].data==b,"startup container decode");
        startup.pop_back();
        rejects([&]{firmware::qnx_images(startup);},"truncated startup container");
        put32(startup,32,0xffffffffU);
        rejects([&]{firmware::qnx_images(startup);},"startup size integer wraparound");
        if (argc==3 && std::string(argv[1])=="--write-fixture") {
            // A duplicate name with different bytes plus an archive symlink.
            b=fixture(); b.resize(320,0);
            std::copy_n(b.begin()+92,48,b.begin()+180);
            put32(b,184,3); put32(b,204,244);
            put32(b,116,240); put32(b,8,320); put32(b,12,232);
            b[228]=0; b[229]=0; str(b,240,"abc"); str(b,244,"xyz"); seal(b);
            packed=compress_blocks(b); container.assign(64,0);
            str(container,0,"hbcifs"); put32(container,8,static_cast<std::uint32_t>(b.size()));
            put32(container,12,static_cast<std::uint32_t>(packed.size()));
            container[24]=2; container[25]=2; container[26]=0x88;
            container.insert(container.end(),packed.begin(),packed.end());
            std::ofstream out(argv[2],std::ios::binary);
            if (!out.write(reinterpret_cast<const char*>(container.data()),container.size())) throw std::runtime_error("fixture write failed");
        } else if (argc!=1) throw std::runtime_error("Unknown test arguments");
        std::cout<<"All QNX parser tests passed\n";
    } catch (const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
