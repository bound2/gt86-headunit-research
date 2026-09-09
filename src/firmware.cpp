#include "firmware.hpp"
#include <array>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace firmware {
Bytes read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("Cannot open input file");
    const auto size = in.tellg();
    if (size < 0 || size > 1024LL * 1024 * 1024)
        throw std::runtime_error("Input exceeds 1 GiB research limit or has invalid size");
    Bytes data(static_cast<std::size_t>(size));
    in.seekg(0);
    if (!data.empty() && !in.read(reinterpret_cast<char*>(data.data()), size))
        throw std::runtime_error("Input read failed");
    return data;
}

std::uint32_t crc32(std::span<const std::uint8_t> data) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> result{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            auto c = i;
            for (int bit = 0; bit < 8; ++bit)
                c = (c >> 1) ^ ((c & 1) ? 0xedb88320U : 0U);
            result[i] = c;
        }
        return result;
    }();
    std::uint32_t value = 0xffffffffU;
    for (const auto byte : data) value = table[(value ^ byte) & 255] ^ (value >> 8);
    return value ^ 0xffffffffU;
}

static bool match(std::span<const std::uint8_t> data, std::size_t offset,
                  std::string_view signature) {
    if (offset > data.size() || signature.size() > data.size() - offset) return false;
    for (std::size_t i = 0; i < signature.size(); ++i)
        if (data[offset + i] != static_cast<std::uint8_t>(signature[i])) return false;
    return true;
}

std::string identify(std::span<const std::uint8_t> data) {
    std::ostringstream out;
    if (match(data, 0, "\x7f" "ELF")) {
        if (data.size() < 16) throw std::runtime_error("Truncated ELF identification");
        const auto cls = data[4];
        const auto endian = data[5];
        if ((cls != 1 && cls != 2) || (endian != 1 && endian != 2) || data[6] != 1)
            throw std::runtime_error("Invalid ELF identification");
        const std::size_t header_size = cls == 1 ? 52 : 64;
        if (data.size() < header_size) throw std::runtime_error("Truncated ELF header");
        const auto machine = endian == 1 ? data[18] | (data[19] << 8)
                                         : (data[18] << 8) | data[19];
        const auto type = endian == 1 ? data[16] | (data[17] << 8)
                                      : (data[16] << 8) | data[17];
        out << "ELF" << (cls == 1 ? 32 : 64) << ' '
            << (endian == 1 ? "little-endian" : "big-endian")
            << " machine=" << machine;
        switch (machine) {
            case 40: out << " (ARM)"; break;
            case 183: out << " (AArch64)"; break;
            case 3: out << " (x86)"; break;
            case 62: out << " (x86-64)"; break;
        }
        out << " type=" << type << " osabi=" << static_cast<unsigned>(data[7]);
        // OSABI=0 is not evidence of Linux: QNX executables may also use it.
        return out.str();
    }
    if (match(data, 0, "\x1bLua")) {
        if (data.size() < 12) throw std::runtime_error("Truncated Lua bytecode header");
        out << "Lua bytecode version=" << static_cast<unsigned>(data[4] >> 4)
            << '.' << static_cast<unsigned>(data[4] & 15);
        if (data[4] == 0x51)
            out << " format=" << static_cast<unsigned>(data[5])
                << " endian=" << (data[6] == 1 ? "little" : "big")
                << " int_bytes=" << static_cast<unsigned>(data[7])
                << " size_t_bytes=" << static_cast<unsigned>(data[8])
                << " instruction_bytes=" << static_cast<unsigned>(data[9])
                << " number_bytes=" << static_cast<unsigned>(data[10]);
        return out.str();
    }
    if (data.size() >= 32775 && data[32768] == 1 && match(data, 32769, "CD001"))
        return "ISO 9660 primary volume descriptor";
    if (match(data, 0, "PK\x03\x04")) return "ZIP local file header";
    return "Unknown/raw data (no supported header recognized)";
}

void strings(std::span<const std::uint8_t> data, std::size_t minimum,
             const std::function<void(std::size_t, const std::string&)>& emit) {
    if (minimum == 0) throw std::runtime_error("Minimum string length must be positive");
    std::size_t begin = 0;
    for (std::size_t i = 0; i <= data.size(); ++i) {
        if (i < data.size() && data[i] >= 32 && data[i] <= 126) continue;
        if (i - begin >= minimum) {
            emit(begin, std::string(reinterpret_cast<const char*>(data.data() + begin), i - begin));
        }
        begin = i + 1;
    }
}
}
