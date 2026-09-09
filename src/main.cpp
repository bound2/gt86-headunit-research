#include "firmware.hpp"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <stdexcept>

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

int main(int argc, char** argv) {
    try {
        if (argc < 3) {
            std::cerr << "Usage: fwinspect info FILE\n"
                         "       fwinspect strings FILE [case-insensitive-substring ...]\n"
                         "       fwinspect crc FILE EXPECTED_HEX\n";
            return 2;
        }
        const std::string command = argv[1];
        if (command != "info" && command != "strings" && command != "crc")
            throw std::runtime_error("Unknown command");
        const auto data = firmware::read_file(argv[2]);
        if (command == "strings") {
            std::vector<std::string> filters;
            for (int i = 3; i < argc; ++i) filters.push_back(lower(argv[i]));
            firmware::strings(data, 5, [&](std::size_t offset, const std::string& s) {
                const auto folded = lower(s);
                if (filters.empty() || std::any_of(filters.begin(), filters.end(), [&](const auto& f) { return folded.find(f) != std::string::npos; }))
                    std::cout << "0x" << std::hex << offset << std::dec << '\t' << s << '\n';
            });
            return 0;
        }
        const auto crc = firmware::crc32(data);
        if (command == "crc") {
            if (argc != 4) throw std::runtime_error("crc requires expected hexadecimal CRC32");
            const std::string expected = argv[3];
            if (expected.size() != 8 || !std::all_of(expected.begin(), expected.end(), [](unsigned char c) { return std::isxdigit(c); }))
                throw std::runtime_error("CRC32 must contain exactly eight hexadecimal digits");
            const auto target = std::stoul(expected, nullptr, 16);
            std::cout << (crc == target ? "PASS" : "FAIL") << " CRC32 " << std::hex << std::setw(8) << std::setfill('0') << crc << '\n';
            return crc == target ? 0 : 1;
        }
        std::cout << "File: " << argv[2] << "\nBytes: " << data.size()
                  << "\nCRC32: " << std::hex << std::setw(8) << std::setfill('0') << crc << std::dec
                  << "\nFormat: " << firmware::identify(data) << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
