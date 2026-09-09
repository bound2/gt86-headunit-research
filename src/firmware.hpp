#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace firmware {
using Bytes = std::vector<std::uint8_t>;
Bytes read_file(const std::filesystem::path& path);
std::uint32_t crc32(std::span<const std::uint8_t> data);
std::string identify(std::span<const std::uint8_t> data);
void strings(std::span<const std::uint8_t> data, std::size_t minimum,
             const std::function<void(std::size_t, const std::string&)>& emit);
}
