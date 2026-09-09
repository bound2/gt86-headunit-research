#include "firmware.hpp"
#include <iostream>
#include <stdexcept>

static void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

int main() {
    try {
        const firmware::Bytes reference{'1','2','3','4','5','6','7','8','9'};
        check(firmware::crc32(reference) == 0xcbf43926U, "CRC32 standard check vector");
        check(firmware::crc32({}) == 0, "CRC32 empty input");
        firmware::Bytes elf(52, 0);
        elf[0]=0x7f; elf[1]='E'; elf[2]='L'; elf[3]='F'; elf[4]=1; elf[5]=1; elf[6]=1; elf[18]=40;
        check(firmware::identify(elf).find("ELF32 little-endian machine=40 (ARM)") == 0, "ARM little endian");
        elf[5]=2; elf[18]=0; elf[19]=40;
        check(firmware::identify(elf).find("ELF32 big-endian machine=40 (ARM)") == 0, "ARM big endian");
        elf.resize(20);
        bool threw=false;
        try { (void)firmware::identify(elf); } catch (const std::runtime_error&) { threw=true; }
        check(threw, "Truncated ELF must fail");
        elf.resize(52); elf[4]=7;
        threw=false;
        try { (void)firmware::identify(elf); } catch (const std::runtime_error&) { threw=true; }
        check(threw, "Invalid ELF class must fail");
        const firmware::Bytes lua{0x1b,'L','u','a',0x51,0,1,4,4,4,8,0};
        check(firmware::identify(lua).find("Lua bytecode version=5.1") == 0, "Lua version");
        const firmware::Bytes text{0,'h','e','l','l','o',0,'w','o','r','l','d'};
        std::vector<std::size_t> offsets;
        firmware::strings(text, 5, [&](std::size_t offset, const std::string&) { offsets.push_back(offset); });
        check(offsets == std::vector<std::size_t>{1,7}, "String offsets and unterminated final string");
        check(firmware::identify({}).find("Unknown") == 0, "Empty input");
        std::cout << "All firmware reader tests passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
