/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_h264.h"
#include "sha1.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#define REQUIRE(x) do { if (!(x)) throw std::runtime_error(std::string(#x) + " line " + std::to_string(__LINE__)); } while (0)
using Bytes = std::vector<uint8_t>;
using Decoder = std::unique_ptr<projection_h264, decltype(&projection_h264_destroy)>;
using Frame = std::unique_ptr<projection_h264_frame, decltype(&projection_h264_frame_destroy)>;
extern "C" int projection_h264_c_api_test(void);
static Decoder create(uint64_t generation = 17, uint32_t w = 1920, uint32_t h = 1088) {
    projection_h264 *p = nullptr;
    REQUIRE(projection_h264_create(generation, w, h, &p) == PROJECTION_H264_MORE);
    REQUIRE(p);
    return Decoder(p, projection_h264_destroy);
}
static Bytes load(const std::filesystem::path &path) {
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file.good());
    return Bytes(std::istreambuf_iterator<char>(file), {});
}
static std::vector<Bytes> split(const Bytes &input) {
    std::vector<size_t> starts;
    for (size_t i = 0; i + 3 < input.size();) {
        size_t len = 0;
        if (input[i] == 0 && input[i + 1] == 0) {
            if (input[i + 2] == 1) len = 3;
            else if (input[i + 2] == 0 && input[i + 3] == 1) len = 4;
        }
        if (len) { starts.push_back(i); i += len; } else ++i;
    }
    REQUIRE(!starts.empty() && starts.front() == 0);
    starts.push_back(input.size());
    std::vector<Bytes> out;
    for (size_t i = 1; i < starts.size(); ++i)
        out.emplace_back(input.begin() + starts[i - 1], input.begin() + starts[i]);
    return out;
}
static unsigned type(const Bytes &nal) { return nal[nal[2] == 1 ? 3 : 4] & 31; }
static unsigned first_mb(const Bytes &nal) {
    // Test-fixture splitter only; these streams are progressive, no ASO/FMO.
    Bytes rbsp; unsigned zeros = 0;
    for (size_t i = (nal[2] == 1 ? 4 : 5); i < nal.size(); ++i) {
        if (zeros == 2 && nal[i] == 3) { zeros = 0; continue; }
        rbsp.push_back(nal[i]); zeros = nal[i] == 0 ? zeros + 1 : 0;
    }
    size_t pos = 0;
    auto bit = [&]() { REQUIRE(pos < rbsp.size() * 8); size_t i = pos++; return (rbsp[i / 8] >> (7 - i % 8)) & 1; };
    unsigned leading = 0; while (!bit()) { REQUIRE(++leading < 24); }
    unsigned value = 1; for (unsigned i = 0; i < leading; ++i) value = (value << 1) | bit();
    return value - 1;
}
static std::string hash(SHA1Context &ctx) {
    std::array<uint8_t, SHA_DIGEST_LENGTH> digest{};
    REQUIRE(SHA1Result(&ctx, digest.data()));
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto v : digest) { result += hex[v >> 4]; result += hex[v & 15]; }
    return result;
}
static Bytes pixels(const projection_h264_frame *frame) {
    projection_h264_view v{};
    REQUIRE(projection_h264_frame_view(frame, &v) == PROJECTION_H264_FRAME);
    REQUIRE(v.plane[1] == v.plane[0] + size_t(v.width) * v.height);
    REQUIRE(v.plane[2] == v.plane[1] + size_t(v.width) * v.height / 4);
    REQUIRE(v.stride[0] == v.width && v.stride[1] == v.width / 2 && v.stride[2] == v.width / 2);
    REQUIRE(v.bytes == size_t(v.width) * v.height * 3 / 2);
    return Bytes(v.plane[0], v.plane[0] + v.bytes);
}
struct Fixture { const char *file; const char *golden; unsigned profile; unsigned frames; };
static constexpr Fixture fixtures[] = {
    {"Static.264", "91dd4a7a796805b2cd015cae8fd630d96c663f42", 66, 10},
    {"test_qcif_cabac.264", "587d1d05943f3cd416bf69469975fdee05361e69", 77, 30},
    {"test_scalinglist_jm.264", "f690a3af2896a53360215fb5d35016bfd41499b3", 100, 5},
    {"Adobe_PDF_sample_a_1024x768_50Frms.264", "9aa9a4d9598eb3e1093311826844f37c43e4c521", 66, 50},
    {"test_cif_P_CABAC_slice.264", "521bbd0ba2422369b724c7054545cf107a56f959", 77, 300}
};
static void golden(const std::filesystem::path &root, const Fixture &fixture, bool terminal_au) {
    auto input = split(load(root / fixture.file));
    auto decoder = create();
    SHA1Context ctx{}; SHA1Reset(&ctx);
    Frame retained(nullptr, projection_h264_frame_destroy);
    Bytes saved;
    unsigned count = 0, drained = 0, width = 0, height = 0;
    std::vector<uint64_t> timestamps, submitted;
    auto output = [&](int result, projection_h264_frame *raw) {
        Frame frame(raw, projection_h264_frame_destroy);
        REQUIRE(result == PROJECTION_H264_FRAME || result == PROJECTION_H264_MORE || result == PROJECTION_H264_END);
        REQUIRE(bool(frame) == (result == PROJECTION_H264_FRAME));
        if (retained) REQUIRE(pixels(retained.get()) == saved);
        if (!frame) return;
        projection_h264_view v{};
        REQUIRE(projection_h264_frame_view(frame.get(), &v) == PROJECTION_H264_FRAME);
        REQUIRE(v.generation == 17);
        REQUIRE(std::find(submitted.begin(), submitted.end(), v.timestamp) != submitted.end());
        timestamps.push_back(v.timestamp);
        auto p = pixels(frame.get());
        SHA1Input(&ctx, p.data(), static_cast<unsigned>(p.size()));
        ++count; width = v.width; height = v.height;
        if (!retained) { saved = p; retained = std::move(frame); }
    };
    unsigned sps_profile = 0;
    bool in_au = false;
    uint64_t stamp = 1000;
    for (size_t i = 0; i < input.size(); ++i) {
        Bytes nal = input[i];
        unsigned kind = type(nal);
        if (kind == 7) sps_profile = nal[(nal[2] == 1 ? 3 : 4) + 1];
        bool vcl = kind == 1 || kind == 5;
        if (in_au && ((!vcl && kind >= 6 && kind <= 9) || (vcl && first_mb(nal) == 0))) {
            projection_h264_frame *frame = nullptr;
            int result = projection_h264_end_access_unit(decoder.get(), 17, &frame);
            output(result, frame); in_au = false;
        }
        if (vcl && !in_au) { stamp += 100; submitted.push_back(stamp); in_au = true; }
        projection_h264_frame *frame = nullptr;
        int result = projection_h264_push(decoder.get(), 17, nal.data(), nal.size(), stamp, &frame);
        if (result < 0) std::cerr << fixture.file << " NAL " << i << " type " << kind << " result " << result << '\n';
        std::fill(nal.begin(), nal.end(), 0xcc); // input lifetime ends immediately
        output(result, frame);
    }
    if (!terminal_au) {
        projection_h264_frame *frame = nullptr;
        int result = projection_h264_end_access_unit(decoder.get(), 17, &frame);
        output(result, frame);
    }
    REQUIRE(sps_profile == fixture.profile);
    bool ended = false;
    for (unsigned i = 0; i < 19; ++i) {
        projection_h264_frame *frame = nullptr;
        int result = projection_h264_drain(decoder.get(), 17, &frame);
        if (result == PROJECTION_H264_FRAME) ++drained;
        output(result, frame);
        if (result == PROJECTION_H264_END) { ended = true; break; }
    }
    REQUIRE(ended);
    REQUIRE(count == fixture.frames);
    auto digest = hash(ctx);
    if (digest != fixture.golden) std::cerr << fixture.file << " actual hash " << digest << '\n';
    REQUIRE(digest == fixture.golden);
    projection_h264_frame *frame = nullptr;
    REQUIRE(projection_h264_drain(decoder.get(), 17, &frame) == PROJECTION_H264_END && !frame);
    REQUIRE(projection_h264_push(decoder.get(), 17, input[0].data(), input[0].size(), 0, &frame) == PROJECTION_H264_STATE);
    REQUIRE(projection_h264_end_access_unit(decoder.get(), 17, &frame) == PROJECTION_H264_STATE);
    REQUIRE(std::is_sorted(timestamps.begin(), timestamps.end())); // admitted I/P pictures only
    decoder.reset();
    REQUIRE(retained && pixels(retained.get()) == saved); // independent of decoder lifetime
    auto replacement = create(18);
    REQUIRE(projection_h264_push(replacement.get(), 17, input[0].data(), input[0].size(), 0, &frame) == PROJECTION_H264_STALE);
    REQUIRE(projection_h264_push(replacement.get(), 18, input[0].data(), input[0].size(), 0, &frame) == PROJECTION_H264_MORE && !frame);
    REQUIRE(pixels(retained.get()) == saved);
    std::cout << fixture.file << " profile=" << fixture.profile << " " << width << 'x' << height
              << " frames=" << count << " drained=" << drained << " terminal_au=" << terminal_au << " golden_sha1=" << digest << '\n';
}

// Locally generated SPS syntax, no copyrighted media, used only for rejection gates.
struct Writer {
    std::vector<bool> bits;
    void put(uint32_t v, unsigned n) { for (unsigned i = n; i; --i) bits.push_back((v >> (i - 1)) & 1); }
    void ue(uint32_t v) {
        uint32_t code = v + 1; unsigned n = 0;
        for (uint32_t t = code; t; t >>= 1) ++n;
        put(0, n - 1); put(code, n);
    }
    Bytes sps(unsigned profile, unsigned w, unsigned h, unsigned refs = 1, bool progressive = true,
              unsigned chroma = 1, unsigned depth = 0, bool empty_crop = false) {
        put(profile, 8); put(0, 8); put(31, 8); ue(0);
        if (profile == 100) { ue(chroma); ue(depth); ue(depth); put(0, 1); put(0, 1); }
        ue(0); ue(0); ue(0); ue(refs); put(0, 1); ue(w / 16 - 1); ue(h / 16 - 1);
        put(progressive, 1); if (!progressive) put(0, 1);
        put(1, 1); put(empty_crop, 1);
        if (empty_crop) { ue(w / 2); ue(0); ue(0); ue(0); }
        put(0, 1); put(1, 1);
        while (bits.size() % 8) put(0, 1);
        Bytes nal{0, 0, 0, 1, 0x67}; unsigned zeros = 0;
        for (size_t i = 0; i < bits.size(); i += 8) {
            uint8_t v = 0; for (unsigned j = 0; j < 8; ++j) v = uint8_t((v << 1) | bits[i + j]);
            if (zeros == 2 && v <= 3) { nal.push_back(3); zeros = 0; }
            nal.push_back(v); zeros = v == 0 ? zeros + 1 : 0;
        }
        return nal;
    }
};
static void rejected(const Bytes &nal, int expected) {
    auto decoder = create(17, 640, 480);
    auto *frame = reinterpret_cast<projection_h264_frame *>(uintptr_t(1));
    int result = projection_h264_push(decoder.get(), 17, nal.data(), nal.size(), 0, &frame);
    REQUIRE(result == expected && !frame);
    REQUIRE(projection_h264_end_access_unit(decoder.get(), 17, &frame) == PROJECTION_H264_STATE);
}
static void gates(const std::filesystem::path &root) {
    projection_h264 *raw = reinterpret_cast<projection_h264 *>(uintptr_t(1));
    REQUIRE(projection_h264_create(0, 640, 480, &raw) == PROJECTION_H264_ARGUMENT && !raw);
    REQUIRE(projection_h264_create(17, 641, 480, &raw) == PROJECTION_H264_ARGUMENT && !raw);
    REQUIRE(projection_h264_create(17, 640, 480, nullptr) == PROJECTION_H264_ARGUMENT);
    auto decoder = create(17, 640, 480);
    auto nals = split(load(root / "Static.264"));
    auto *frame = reinterpret_cast<projection_h264_frame *>(uintptr_t(1));
    REQUIRE(projection_h264_push(decoder.get(), 18, nals[0].data(), nals[0].size(), 0, &frame) == PROJECTION_H264_STALE && !frame);
    REQUIRE(projection_h264_drain(decoder.get(), 18, &frame) == PROJECTION_H264_STALE);
    REQUIRE(projection_h264_end_access_unit(decoder.get(), 18, &frame) == PROJECTION_H264_STALE);
    REQUIRE(projection_h264_push(decoder.get(), 17, nullptr, 1, 0, &frame) == PROJECTION_H264_ARGUMENT);
    REQUIRE(projection_h264_push(decoder.get(), 17, nals[0].data(), nals[0].size(), 0, nullptr) == PROJECTION_H264_ARGUMENT);
    REQUIRE(projection_h264_end_access_unit(decoder.get(), 17, &frame) == PROJECTION_H264_MORE);
    REQUIRE(projection_h264_push(decoder.get(), 17, nals[0].data(), nals[0].size(), 0, &frame) == PROJECTION_H264_MORE);
    REQUIRE(!frame); // initialization and SPS are NOT pictures
    auto empty = create();
    REQUIRE(projection_h264_drain(empty.get(), 17, &frame) == PROJECTION_H264_END && !frame);
    projection_h264_view view{};
    view.width = 99;
    REQUIRE(projection_h264_frame_view(nullptr, &view) == PROJECTION_H264_ARGUMENT && view.width == 0);
    projection_h264_frame_destroy(nullptr); projection_h264_destroy(nullptr);
    rejected(Writer{}.sps(66, 656, 480), PROJECTION_H264_LIMIT);
    rejected(Writer{}.sps(66, 640, 496), PROJECTION_H264_LIMIT);
    rejected(Writer{}.sps(66, 640, 480, 17), PROJECTION_H264_LIMIT);
    rejected(Writer{}.sps(110, 640, 480), PROJECTION_H264_BITSTREAM);
    rejected(Writer{}.sps(100, 640, 480, 1, true, 2), PROJECTION_H264_BITSTREAM);
    rejected(Writer{}.sps(100, 640, 480, 1, true, 1, 1), PROJECTION_H264_BITSTREAM);
    rejected(Writer{}.sps(66, 640, 480, 1, false), PROJECTION_H264_BITSTREAM);
    rejected(Writer{}.sps(66, 640, 480, 1, true, 1, 0, true), PROJECTION_H264_BITSTREAM);
    rejected(Bytes{0, 0, 1, 0x65, 0x80}, PROJECTION_H264_BITSTREAM); // no SPS
    rejected(Bytes{0, 0, 1, 0xe7, 0x80}, PROJECTION_H264_BITSTREAM); // forbidden bit
    rejected(Bytes{0, 0, 1, 0x6f, 0x80}, PROJECTION_H264_BITSTREAM); // subset SPS
    rejected(Bytes{0, 0, 1, 0x67, 66, 0, 0, 3, 4, 0x80}, PROJECTION_H264_BITSTREAM);
    rejected(Bytes{0, 0, 1, 0x67, 66, 0, 0, 2, 0x80}, PROJECTION_H264_BITSTREAM);
    auto doubled = nals[0]; doubled.insert(doubled.end(), nals[1].begin(), nals[1].end());
    rejected(doubled, PROJECTION_H264_BITSTREAM); // one NAL contract
    auto oversize = nals[0]; oversize.resize(PROJECTION_H264_MAX_NAL + 1, 0xff);
    rejected(oversize, PROJECTION_H264_LIMIT);
    for (size_t len = 1; len < 8; ++len) rejected(Bytes(nals[0].begin(), nals[0].begin() + len), PROJECTION_H264_BITSTREAM);
    auto budget = create();
    REQUIRE(projection_h264_push(budget.get(), 17, nals[0].data(), nals[0].size(), 0, &frame) == PROJECTION_H264_MORE);
    const Bytes aud{0, 0, 1, 9, 0xf0};
    for (unsigned i = 1; i < 256; ++i)
        REQUIRE(projection_h264_push(budget.get(), 17, aud.data(), aud.size(), 0, &frame) == PROJECTION_H264_MORE && !frame);
    REQUIRE(projection_h264_push(budget.get(), 17, aud.data(), aud.size(), 0, &frame) == PROJECTION_H264_LIMIT && !frame);
    auto byte_budget = create();
    REQUIRE(projection_h264_push(byte_budget.get(), 17, nals[0].data(), nals[0].size(), 0, &frame) == PROJECTION_H264_MORE);
    Bytes filler(PROJECTION_H264_MAX_NAL - nals[0].size() + 1, 0xff);
    filler[0] = filler[1] = 0; filler[2] = 1; filler[3] = 12; filler.back() = 0x80;
    REQUIRE(projection_h264_push(byte_budget.get(), 17, filler.data(), filler.size(), 0, &frame) == PROJECTION_H264_LIMIT && !frame);
    auto missing_boundary = create();
    for (unsigned i = 0; i < 3; ++i)
        REQUIRE(projection_h264_push(missing_boundary.get(), 17, nals[i].data(), nals[i].size(), 0, &frame) == PROJECTION_H264_MORE);
    REQUIRE(projection_h264_push(missing_boundary.get(), 17, nals[3].data(), nals[3].size(), 0, &frame) == PROJECTION_H264_BITSTREAM && !frame);
    for (uint8_t syntax : {uint8_t(0x93), uint8_t(0x97)}) { // first_mb=0; SP/SI slice
        auto restricted = create();
        REQUIRE(projection_h264_push(restricted.get(), 17, nals[0].data(), nals[0].size(), 0, &frame) == PROJECTION_H264_MORE);
        Bytes slice{0, 0, 1, 0x61, syntax};
        REQUIRE(projection_h264_push(restricted.get(), 17, slice.data(), slice.size(), 0, &frame) == PROJECTION_H264_BITSTREAM && !frame);
    }
    auto slices = split(load(root / "test_cif_P_CABAC_slice.264"));
    auto timestamp_change = create();
    for (unsigned i = 0; i < 3; ++i)
        REQUIRE(projection_h264_push(timestamp_change.get(), 17, slices[i].data(), slices[i].size(), 100, &frame) == PROJECTION_H264_MORE);
    REQUIRE(first_mb(slices[3]) != 0);
    REQUIRE(projection_h264_push(timestamp_change.get(), 17, slices[3].data(), slices[3].size(), 101, &frame) == PROJECTION_H264_BITSTREAM && !frame);
    uint32_t random = 0x786a43b1;
    for (unsigned i = 0; i < 256; ++i) {
        auto mutated = nals[0];
        random = random * 1664525u + 1013904223u;
        mutated[5 + (random % (mutated.size() - 5))] ^= uint8_t(1u << ((random >> 24) % 8));
        auto test = create();
        int result = projection_h264_push(test.get(), 17, mutated.data(), mutated.size(), 0, &frame);
        REQUIRE(result == PROJECTION_H264_MORE || result == PROJECTION_H264_BITSTREAM || result == PROJECTION_H264_LIMIT);
        REQUIRE(!frame); // no picture can come from an SPS mutation alone
        if (result < 0) REQUIRE(projection_h264_end_access_unit(test.get(), 17, &frame) == PROJECTION_H264_STATE);
    }
    std::cout << "argument, stale-token, format, coded-size, syntax and closed-owner gates OK\n";
}
static void reject_b(const std::filesystem::path &root, const char *file) {
    auto decoder = create();
    auto input = split(load(root / file));
    Frame retained(nullptr, projection_h264_frame_destroy); Bytes saved;
    for (size_t i = 0; i < 5; ++i) {
        projection_h264_frame *frame = nullptr;
        int result = projection_h264_push(decoder.get(), 17, input[i].data(), input[i].size(), 1000 + i * 100, &frame);
        if (i == 4) {
            REQUIRE(result == PROJECTION_H264_BITSTREAM && !frame);
            REQUIRE(projection_h264_drain(decoder.get(), 17, &frame) == PROJECTION_H264_STATE);
            break;
        }
        REQUIRE(result == PROJECTION_H264_MORE && !frame);
        if (type(input[i]) == 5) {
            result = projection_h264_end_access_unit(decoder.get(), 17, &frame);
            REQUIRE(result == PROJECTION_H264_MORE || result == PROJECTION_H264_FRAME);
            if (frame) { retained.reset(frame); saved = pixels(frame); }
        }
    }
    decoder.reset();
    REQUIRE(retained && pixels(retained.get()) == saved);
    std::cout << file << " first B slice rejected; held I-frame remains valid\n";
}
int main(int argc, char **argv) {
    try {
        REQUIRE(argc == 2);
        REQUIRE(projection_h264_c_api_test());
        gates(argv[1]);
        for (const auto &fixture : fixtures) {
            golden(argv[1], fixture, false);
            golden(argv[1], fixture, true);
        }
        reject_b(argv[1], "Cisco_Men_whisper_640x320_CABAC_Bframe_9.264");
        reject_b(argv[1], "Cisco_Men_whisper_640x320_CAVLC_Bframe_9.264");
        std::cout << "projection_h264 tests passed\n";
        return 0;
    } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
