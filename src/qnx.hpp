#pragma once
#include "firmware.hpp"
namespace firmware {
struct QnxImage {
    std::size_t container_offset;
    std::size_t stored_size;
    std::string container;
    Bytes data;
};
struct QnxEntry {
    std::string path;
    std::string target;
    std::uint32_t mode;
    std::uint32_t inode;
    std::size_t offset;
    std::size_t size;
};
std::vector<QnxImage> qnx_images(std::span<const std::uint8_t> input);
std::vector<QnxEntry> qnx_directory(std::span<const std::uint8_t> image);
bool safe_relative_path(const std::string& path);
Bytes lzo_blocks(std::span<const std::uint8_t> input, std::size_t expected_size);
}
