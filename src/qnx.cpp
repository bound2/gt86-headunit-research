#include "qnx.hpp"
#include "minilzo.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>
#include <string_view>

namespace firmware {
namespace {
constexpr std::size_t limit = 512ULL * 1024 * 1024;
void bounds(std::span<const std::uint8_t> b, std::size_t p, std::size_t n) {
    if (p > b.size() || n > b.size() - p) throw std::runtime_error("QNX field outside input bounds");
}
std::uint16_t u16(std::span<const std::uint8_t> b, std::size_t p) {
    bounds(b,p,2); return static_cast<std::uint16_t>(b[p] | (b[p+1] << 8));
}
std::uint32_t u32(std::span<const std::uint8_t> b, std::size_t p) {
    bounds(b,p,4); return std::uint32_t(b[p]) | (std::uint32_t(b[p+1]) << 8) |
        (std::uint32_t(b[p+2]) << 16) | (std::uint32_t(b[p+3]) << 24);
}
bool magic(std::span<const std::uint8_t> b, std::size_t p, std::string_view s) {
    return p <= b.size() && s.size() <= b.size()-p &&
        std::equal(s.begin(),s.end(),b.begin()+p,[](char x, std::uint8_t y){return static_cast<std::uint8_t>(x)==y;});
}
std::string cstring(std::span<const std::uint8_t> b, std::size_t p, std::size_t end) {
    if (end > b.size() || p >= end) throw std::runtime_error("Invalid QNX string range");
    auto e = p;
    while (e < end && b[e]) ++e;
    if (e == end) throw std::runtime_error("Unterminated QNX string at "+std::to_string(p)+" end="+std::to_string(end));
    return std::string(reinterpret_cast<const char*>(b.data()+p), e-p);
}
}

Bytes lzo_blocks(std::span<const std::uint8_t> input, std::size_t expected_size) {
    if (!expected_size || expected_size > limit) throw std::runtime_error("Invalid LZO output size");
    if (lzo_init() != LZO_E_OK) throw std::runtime_error("LZO initialization failed");
    Bytes output;
    output.reserve(expected_size);
    std::array<unsigned char,65536> block{};
    std::size_t p=0;
    for (;;) {
        bounds(input,p,2);
        const auto count = static_cast<std::size_t>((input[p] << 8) | input[p+1]);
        p+=2;
        if (!count) break;
        bounds(input,p,count);
        lzo_uint out_size = block.size();
        const auto status = lzo1x_decompress_safe(input.data()+p, static_cast<lzo_uint>(count), block.data(), &out_size, nullptr);
        if (status != LZO_E_OK) throw std::runtime_error("LZO block decompression failed at " + std::to_string(p) + " status=" + std::to_string(status));
        if (out_size > expected_size-output.size()) throw std::runtime_error("LZO output exceeds declared size");
        output.insert(output.end(),block.begin(),block.begin()+out_size);
        p+=count;
    }
    if (output.size()!=expected_size) throw std::runtime_error("LZO output size does not match header");
    // QNX containers can pad the terminator to a word boundary.
    if (input.size()-p > 4 || !std::all_of(input.begin()+p,input.end(),[](auto c){return c==0;}))
        throw std::runtime_error("Unexpected data following LZO terminator");
    return output;
}

std::vector<QnxImage> qnx_images(std::span<const std::uint8_t> input) {
    std::vector<QnxImage> images;
    for (std::size_t p=0;p+64<=input.size();++p) {
        if (magic(input,p,std::string_view("hbcifs\0\0",8))) {
            const auto raw_size=u32(input,p+8), stored=u32(input,p+12);
            if (!raw_size || raw_size>limit || !stored || stored>input.size()-p-64) continue;
            // Observed Toyota v2 header: two version bytes followed by
            // QNX-style compression flags. Do not accept other Harman variants.
            if (input[p+24]!=2 || input[p+25]!=2 || input[p+26]!=0x88 || input[p+27]!=0)
                throw std::runtime_error("Unsupported HBCIFS variant at "+std::to_string(p));
            auto data=lzo_blocks(input.subspan(p+64,stored),raw_size);
            (void)qnx_directory(data); // Validate structure and checksum before accepting.
            images.push_back({p,64+stored,"HBCIFS-v2/LZO-blocks",std::move(data)});
            p+=63+stored;
        } else if (u32(input,p)==0x00ff7eebU) {
            if (u16(input,p+4)!=1 || u16(input,p+8)!=256 || u16(input,p+10)!=40) continue;
            if (input[p+6]&2) throw std::runtime_error("Big-endian startup is unsupported");
            const auto startup=u32(input,p+32), stored=u32(input,p+36), raw_size=u32(input,p+44);
            if (startup<256 || startup>stored || stored-startup<4 || stored>input.size()-p || raw_size>limit)
                throw std::runtime_error("Invalid QNX startup image sizes");
            if ((input[p+6]&0x1c)!=8) throw std::runtime_error("Only LZO startup images are supported");
            auto data=lzo_blocks(input.subspan(p+startup,stored-startup-4),raw_size);
            (void)qnx_directory(data);
            images.push_back({p,stored,"QNX-startup/LZO-blocks",std::move(data)});
            p+=stored-1;
        }
    }
    if (images.empty()) throw std::runtime_error("No supported QNX containers found");
    return images;
}

std::vector<QnxEntry> qnx_directory(std::span<const std::uint8_t> image) {
    if (!magic(image,0,"imagefs")) throw std::runtime_error("Missing imagefs signature");
    bounds(image,0,92);
    if (image[7]&1) throw std::runtime_error("Big-endian imagefs is unsupported");
    const auto size=u32(image,8), directory_end=u32(image,12), directory_start=u32(image,16);
    if (size!=image.size() || size%4 || size<96 || directory_start<92 || directory_end<directory_start || directory_end>size-4)
        throw std::runtime_error("Invalid imagefs header bounds");
    std::uint32_t checksum=0;
    for (std::size_t p=0;p<size;p+=4) checksum+=u32(image,p);
    if (checksum) throw std::runtime_error("imagefs 32-bit additive checksum mismatch");
    std::vector<QnxEntry> entries;
    auto p=std::size_t(directory_start);
    bool terminated=false;
    while (p+2<=directory_end) {
        const auto record_size=u16(image,p);
        if (!record_size) { terminated=true; break; }
        if (record_size<24 || record_size>directory_end-p) throw std::runtime_error("Invalid imagefs directory record");
        const auto inode=u32(image,p+4), mode=u32(image,p+8), type=mode&0xf000;
        const auto end=p+record_size;
        QnxEntry entry{{},{},mode,inode,0,0};
        if (type==0x8000) {
            if (record_size<33) throw std::runtime_error("Truncated regular file record");
            entry.offset=u32(image,p+24); entry.size=u32(image,p+28);
            bounds(image,entry.offset,entry.size);
            if (entry.size && (entry.offset<directory_end || entry.offset+entry.size>size-4))
                throw std::runtime_error("File payload overlaps image metadata");
            entry.path=cstring(image,p+32,end);
        } else if (type==0x4000) entry.path=cstring(image,p+24,end);
        else if (type==0xa000) {
            if (record_size<29) throw std::runtime_error("Truncated symlink record");
            entry.path=cstring(image,p+28,end);
            const auto target_offset=u16(image,p+24), target_size=u16(image,p+26);
            if (target_offset>=record_size-28 || target_size>record_size-28-target_offset) throw std::runtime_error("Invalid symlink target bounds");
            // sym_size is the target byte count; it excludes any NUL padding.
            entry.target=std::string(reinterpret_cast<const char*>(image.data()+p+28+target_offset),target_size);
            if (!entry.target.empty() && entry.target.back()=='\0') entry.target.pop_back();
            if (entry.target.find('\0')!=std::string::npos) throw std::runtime_error("Embedded NUL in symlink target");
        } else if (record_size>=33) entry.path=cstring(image,p+32,end);
        else throw std::runtime_error("Unknown imagefs directory record type");
        if (inode) entries.push_back(std::move(entry));
        p=end;
    }
    if (!terminated) throw std::runtime_error("Missing imagefs directory terminator");
    return entries;
}

bool safe_relative_path(const std::string& path) {
    if (path.empty() || path.front()=='/' || path.find('\\')!=std::string::npos || path.find(':')!=std::string::npos) return false;
    for (unsigned char c:path) if (c<32 || c>126 || c=='<' || c=='>' || c=='"' || c=='|' || c=='?' || c=='*') return false;
    for (std::size_t p=0;p<path.size();) {
        const auto end=path.find('/',p);
        auto part=path.substr(p,end==std::string::npos?end:end-p);
        if (part.empty() || part=="." || part==".." || part.back()=='.' || part.back()==' ') return false;
        std::transform(part.begin(),part.end(),part.begin(),[](unsigned char c){return static_cast<char>(std::toupper(c));});
        const auto base=part.substr(0,part.find('.'));
        if (base=="CON" || base=="PRN" || base=="AUX" || base=="NUL" ||
            (base.size()==4 && (base.starts_with("COM") || base.starts_with("LPT")) && base[3]>='0' && base[3]<='9')) return false;
        if (end==std::string::npos) break;
        p=end+1;
        if (p==path.size()) return false;
    }
    return true;
}
}
