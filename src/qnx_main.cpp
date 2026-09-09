#include "qnx.hpp"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

static bool write_new(const std::filesystem::path& path,std::span<const std::uint8_t> data) {
    if (std::filesystem::exists(path)) {
        // Some imagefs tables repeat identical regular-file paths. The root is
        // newly created by this run and no archive links are ever materialized.
        const auto previous=firmware::read_file(path);
        return previous.size()==data.size() && std::equal(previous.begin(),previous.end(),data.begin());
    }
    std::filesystem::create_directories(path.parent_path());
    std::ofstream file(path,std::ios::binary);
    if (!file || !file.write(reinterpret_cast<const char*>(data.data()),static_cast<std::streamsize>(data.size())))
        throw std::runtime_error("Output write failed");
    return true;
}

int main(int argc,char** argv) {
    try {
        if (argc!=4 || std::string(argv[1])!="unpack") {
            std::cerr<<"Usage: qnxinspect unpack INPUT NEW_OUTPUT_DIRECTORY\n"; return 2;
        }
        const auto input=firmware::read_file(argv[2]);
        const auto images=firmware::qnx_images(input);
        const auto root=std::filesystem::absolute(argv[3]);
        if (!std::filesystem::create_directory(root)) throw std::runtime_error("Output root must not already exist");
        std::ofstream inventory(root/"inventory.tsv");
        if (!inventory) throw std::runtime_error("Cannot create inventory");
        inventory<<"image\ttype\tmode\tinode\toffset\tsize\tcrc32\tpath\ttarget\textracted_path\n";
        std::size_t duplicates=0;
        for (const auto& image:images) {
            std::ostringstream id; id<<"image-"<<std::hex<<image.container_offset;
            const auto entries=firmware::qnx_directory(image.data);
            write_new(root/(id.str()+".imagefs"),image.data);
            std::cout<<id.str()<<" "<<image.container<<" stored="<<image.stored_size<<" unpacked="<<image.data.size()<<" entries="<<entries.size()<<" imagefs_checksum=PASS\n";
            std::size_t record=0;
            for (const auto& e:entries) {
                ++record;
                std::string extracted_path;
                const auto type=e.mode&0xf000;
                const char* label=type==0x8000?"file":type==0x4000?"directory":type==0xa000?"symlink":"device";
                std::uint32_t crc=0;
                const bool directory_marker=type==0x8000 && e.size==0 && e.path.ends_with('/');
                if (directory_marker) label="empty-file-directory-marker";
                if (type==0x8000 && !directory_marker) {
                    if (!firmware::safe_relative_path(e.path)) throw std::runtime_error("Unsafe archive filename: "+e.path);
                    const auto payload=std::span(image.data).subspan(e.offset,e.size);
                    crc=firmware::crc32(payload);
                    auto relative=std::filesystem::path(id.str())/e.path;
                    if (!write_new(root/relative,payload)) {
                        // Preserve both versions without guessing QNX duplicate lookup semantics.
                        relative=std::filesystem::path("duplicates")/id.str()/std::to_string(record)/e.path;
                        if (!write_new(root/relative,payload)) throw std::runtime_error("Duplicate storage collision");
                        ++duplicates;
                    }
                    extracted_path=relative.generic_string();
                }
                // Symlinks and devices are described in the inventory, never created.
                inventory<<id.str()<<'\t'<<label<<'\t'<<std::oct<<e.mode<<std::dec<<'\t'<<e.inode<<'\t'<<e.offset<<'\t'<<e.size<<'\t'<<std::hex<<crc<<std::dec<<'\t'<<e.path<<'\t'<<e.target<<'\t'<<extracted_path<<'\n';
            }
        }
        inventory.flush();
        if (!inventory) throw std::runtime_error("Inventory write failed");
        std::cout<<"Conflicting duplicate files preserved separately: "<<duplicates<<'\n';
        return 0;
    } catch(const std::exception& e) { std::cerr<<"Error: "<<e.what()<<'\n'; return 1; }
}
