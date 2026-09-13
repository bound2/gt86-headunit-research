/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_video.h"
#include "monocypher.h"
#include "sha1.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#define REQUIRE(x) do { if (!(x)) throw std::runtime_error(std::string(#x) + " line " + std::to_string(__LINE__)); } while (0)
using Bytes = std::vector<uint8_t>;
using Video = std::unique_ptr<projection_video, decltype(&projection_video_destroy)>;
using Frame = std::unique_ptr<projection_h264_frame, decltype(&projection_h264_frame_destroy)>;
extern "C" int projection_video_c_api_test(void);
static std::array<uint8_t, 32> key() { std::array<uint8_t, 32> k{}; for (unsigned i = 0; i < 32; ++i) k[i] = uint8_t(i); return k; }
static Video create(uint8_t queue = 4, uint64_t generation = 17) {
    projection_video_config cfg{1920, 1088, 1000, 2000, queue, 1};
    projection_video *v = nullptr;
    REQUIRE(projection_video_create(&cfg, key().data(), generation, 0, &v) == PROJECTION_VIDEO_MORE);
    return Video(v, projection_video_destroy);
}
static Bytes load(const std::filesystem::path &p) {
    std::ifstream file(p, std::ios::binary); REQUIRE(file.good());
    return Bytes(std::istreambuf_iterator<char>(file), {});
}
static std::vector<Bytes> split(const Bytes &input) {
    std::vector<Bytes> out; size_t begin = 0;
    for (size_t i = 0; i + 3 < input.size();) {
        size_t prefix = 0;
        if (!input[i] && !input[i + 1]) {
            if (input[i + 2] == 1) prefix = 3;
            else if (!input[i + 2] && input[i + 3] == 1) prefix = 4;
        }
        if (prefix) {
            if (begin) out.emplace_back(input.begin() + begin, input.begin() + i);
            begin = i + prefix; i = begin;
        } else ++i;
    }
    REQUIRE(begin); out.emplace_back(input.begin() + begin, input.end()); return out;
}
static void be(Bytes &out, size_t value, unsigned width) {
    for (unsigned i = width; i; --i) out.push_back(uint8_t(value >> ((i - 1) * 8)));
}
static Bytes avcc(const std::vector<Bytes> &nals, unsigned width = 4) {
    REQUIRE(nals.size() >= 3 && (nals[0][0] & 31) == 7 && (nals[1][0] & 31) == 8);
    Bytes out{1, nals[0][1], nals[0][2], nals[0][3], uint8_t(0xfc | (width - 1)), 0xe1};
    be(out, nals[0].size(), 2); out.insert(out.end(), nals[0].begin(), nals[0].end());
    out.push_back(1); be(out, nals[1].size(), 2); out.insert(out.end(), nals[1].begin(), nals[1].end()); return out;
}
static Bytes box(const char *name, const Bytes &data) {
    Bytes out; be(out, data.size() + 8, 4); out.insert(out.end(), name, name + 4);
    out.insert(out.end(), data.begin(), data.end()); return out;
}
static Bytes extended_box(const char *name, const Bytes &data) {
    Bytes out; be(out, 1, 4); out.insert(out.end(), name, name + 4);
    be(out, 0, 4); be(out, data.size() + 16, 4);
    out.insert(out.end(), data.begin(), data.end()); return out;
}
static Bytes record(uint8_t opcode, const Bytes &body) {
    Bytes out(128);
    for (unsigned i = 5; i < 128; ++i) out[i] = uint8_t(i * 3);
    for (unsigned i = 0; i < 4; ++i) out[i] = uint8_t(body.size() >> (i * 8));
    out[4] = opcode; out.insert(out.end(), body.begin(), body.end()); return out;
}
static Bytes encrypted(const Bytes &plain, uint64_t counter) {
    Bytes body(plain.size() + 16), out = record(0, body); uint8_t nonce[12]{};
    for (unsigned i = 0; i < 8; ++i) { nonce[i + 4] = uint8_t(counter); counter >>= 8; }
    crypto_aead_ctx ctx; crypto_aead_init_ietf(&ctx, key().data(), nonce);
    crypto_aead_write(&ctx, out.data() + 128, out.data() + 128 + plain.size(), out.data(), 128, plain.data(), plain.size());
    crypto_wipe(&ctx, sizeof(ctx)); return out;
}
static Bytes au(const Bytes &nal, unsigned width = 4) {
    REQUIRE(width == 4 || nal.size() < (size_t(1) << (width * 8)));
    Bytes out; be(out, nal.size(), width); out.insert(out.end(), nal.begin(), nal.end()); return out;
}
static int feed(projection_video *v, const Bytes &data, uint64_t now = 0, size_t chunk = 4093) {
    int result = PROJECTION_VIDEO_MORE; size_t offset = 0;
    do {
        size_t used = 0, count = std::min(chunk, data.size() - offset);
        result = projection_video_feed(v, 17, data.data() + offset, count, &used, now);
        REQUIRE(used <= count); offset += used;
        if (result < 0 || result == PROJECTION_VIDEO_BUSY) return result;
        REQUIRE(used || !count);
    } while (offset < data.size());
    return result;
}
static Frame take(projection_video *v, uint64_t counter, uint64_t epoch = 1, uint64_t now = 0) {
    projection_h264_frame *frame = nullptr; projection_video_metadata meta{};
    REQUIRE(projection_video_take(v, 17, &frame, &meta, now) == PROJECTION_VIDEO_FRAME);
    REQUIRE(frame && meta.generation == 17 && meta.counter == counter && meta.configuration_epoch == epoch);
    REQUIRE(meta.frame_authenticated == 1 && meta.configuration_authenticated == 0 && meta.header[4] == 0);
    projection_h264_view view{}; REQUIRE(projection_h264_frame_view(frame, &view) == PROJECTION_H264_FRAME);
    REQUIRE(view.generation == 17 && view.timestamp == counter);
    return Frame(frame, projection_h264_frame_destroy);
}
static Bytes pixels(const projection_h264_frame *f) {
    projection_h264_view v{}; REQUIRE(projection_h264_frame_view(f, &v) == PROJECTION_H264_FRAME);
    return Bytes(v.plane[0], v.plane[0] + v.bytes);
}
static void basic(const std::vector<Bytes> &nals) {
    for (unsigned width : {2u, 4u}) {
        auto v = create(2); auto cfg = record(1, avcc(nals, width));
        REQUIRE(feed(v.get(), cfg, 0, 1) == PROJECTION_VIDEO_CONFIG);
        projection_video_configuration info{};
        REQUIRE(projection_video_get_configuration(v.get(), 17, &info) == PROJECTION_VIDEO_CONFIG);
        REQUIRE(info.epoch == 1 && info.profile == 66 && info.length_size == width && !info.authenticated);
        auto first = encrypted(au(nals[2], width), 0);
        REQUIRE(feed(v.get(), first, 0, 17) == PROJECTION_VIDEO_PACKET);
        projection_h264_frame *raw = nullptr; projection_video_metadata meta{};
        REQUIRE(projection_video_take(v.get(), 17, &raw, &meta, 0) == PROJECTION_VIDEO_BUSY && !raw);
        size_t used = 99;
        REQUIRE(projection_video_feed(v.get(), 17, first.data(), first.size(), &used, 0) == PROJECTION_VIDEO_BUSY && !used);
        REQUIRE(projection_video_start(v.get(), 17, 0) == PROJECTION_VIDEO_MORE);
        auto frame = take(v.get(), 0); auto saved = pixels(frame.get());
        REQUIRE(feed(v.get(), encrypted(au(nals[3], width), 1)) == PROJECTION_VIDEO_PACKET);
        auto second = take(v.get(), 1);
        REQUIRE(projection_video_finish(v.get(), 17, 0) == PROJECTION_VIDEO_END);
        REQUIRE(projection_video_take(v.get(), 17, &raw, &meta, 0) == PROJECTION_VIDEO_END && !raw);
        REQUIRE(feed(v.get(), cfg) == PROJECTION_VIDEO_STATE);
        v.reset(); REQUIRE(pixels(frame.get()) == saved);
    }
    auto v = create();
    REQUIRE(feed(v.get(), record(1, avcc(nals, 1))) == PROJECTION_VIDEO_CONFIG);
    REQUIRE(feed(v.get(), encrypted(au(nals[0], 1), 0)) == PROJECTION_VIDEO_PACKET); // valid 1-byte parameter NAL
    REQUIRE(feed(v.get(), encrypted({}, 1)) == PROJECTION_VIDEO_PACKET); // tagged empty, not fake video
    REQUIRE(projection_video_start(v.get(), 17, 0) == PROJECTION_VIDEO_MORE);
    projection_h264_frame *raw = nullptr; projection_video_metadata meta{};
    REQUIRE(projection_video_take(v.get(), 17, &raw, &meta, 0) == PROJECTION_VIDEO_MORE && !raw);
    auto coalesced = create(); Bytes joined = record(1, avcc(nals)); size_t config_size = joined.size();
    auto packet = encrypted(au(nals[2]), 0); joined.insert(joined.end(), packet.begin(), packet.end());
    size_t used = 0;
    REQUIRE(projection_video_feed(coalesced.get(), 17, joined.data(), joined.size(), &used, 0) == PROJECTION_VIDEO_CONFIG);
    REQUIRE(used == config_size);
    REQUIRE(projection_video_feed(coalesced.get(), 17, joined.data() + used, joined.size() - used, &used, 0) == PROJECTION_VIDEO_PACKET);
    REQUIRE(used == packet.size());
    std::cout << "owned frames, RECORD gate, backpressure, counter metadata and prefix widths OK\n";
}
static void reconfigure(const std::vector<Bytes> &nals) {
    auto v = create(); auto config = avcc(nals);
    REQUIRE(feed(v.get(), record(1, box("avcC", config))) == PROJECTION_VIDEO_CONFIG);
    REQUIRE(projection_video_start(v.get(), 17, 0) == PROJECTION_VIDEO_MORE);
    REQUIRE(feed(v.get(), encrypted(au(nals[2]), 0)) == PROJECTION_VIDEO_PACKET);
    auto old = take(v.get(), 0); auto saved = pixels(old.get());
    REQUIRE(feed(v.get(), encrypted(au(nals[3]), 1)) == PROJECTION_VIDEO_PACKET); // queued, discarded by config
    Bytes entry(78); entry[7] = 1; entry[25] = 152; entry[27] = 100;
    auto child = box("avcC", config); entry.insert(entry.end(), child.begin(), child.end());
    REQUIRE(feed(v.get(), record(1, box("avc1", entry))) == PROJECTION_VIDEO_CONFIG);
    projection_h264_frame *raw = nullptr; projection_video_metadata meta{};
    REQUIRE(projection_video_take(v.get(), 17, &raw, &meta, 0) == PROJECTION_VIDEO_MORE && !raw);
    REQUIRE(feed(v.get(), record(4, Bytes{1, 2, 3})) == PROJECTION_VIDEO_IGNORED);
    REQUIRE(feed(v.get(), encrypted(au(nals[2]), 2)) == PROJECTION_VIDEO_PACKET); // nonce did NOT reset
    auto current = take(v.get(), 2, 2); REQUIRE(pixels(old.get()) == saved);
    REQUIRE(feed(v.get(), encrypted(au(nals[3]), 0)) == PROJECTION_VIDEO_AUTH);
    v.reset(); REQUIRE(pixels(old.get()) == saved);
    auto require_idr = create();
    REQUIRE(feed(require_idr.get(), record(1, config)) == PROJECTION_VIDEO_CONFIG);
    REQUIRE(feed(require_idr.get(), encrypted(au(nals[3]), 0)) == PROJECTION_VIDEO_FORMAT);
    std::cout << "clear configuration epochs, queue retirement, IDR requirement and nonce retention OK\n";
}
static void hostile(const std::vector<Bytes> &nals) {
    auto config = record(1, avcc(nals)); auto packet = encrypted(au(nals[2]), 0);
    for (size_t change : {size_t(60), size_t(128), packet.size() - 1}) {
        auto v = create(); REQUIRE(feed(v.get(), config) == PROJECTION_VIDEO_CONFIG);
        auto corrupt = packet; corrupt[change] ^= 1;
        REQUIRE(feed(v.get(), corrupt) == PROJECTION_VIDEO_AUTH);
        REQUIRE(feed(v.get(), packet) == PROJECTION_VIDEO_STATE);
    }
    for (size_t length : {size_t(0), size_t(1), size_t(15)}) {
        auto v = create(); REQUIRE(feed(v.get(), record(0, Bytes(length))) == PROJECTION_VIDEO_AUTH);
    }
    auto before_config = create(); REQUIRE(feed(before_config.get(), packet) == PROJECTION_VIDEO_FORMAT);
    auto malformed = create(); REQUIRE(feed(malformed.get(), config) == PROJECTION_VIDEO_CONFIG);
    auto truncated = au(nals[2]); truncated.push_back(0);
    REQUIRE(feed(malformed.get(), encrypted(truncated, 0)) == PROJECTION_VIDEO_FORMAT);
    auto multiple = create(); REQUIRE(feed(multiple.get(), config) == PROJECTION_VIDEO_CONFIG);
    auto two_aus = au(nals[2]); auto next = au(nals[3]); two_aus.insert(two_aus.end(), next.begin(), next.end());
    REQUIRE(feed(multiple.get(), encrypted(two_aus, 0)) == PROJECTION_VIDEO_FORMAT);
    auto changed_sets = create(); REQUIRE(feed(changed_sets.get(), config) == PROJECTION_VIDEO_CONFIG);
    auto modified_sps = nals[0]; modified_sps[3] ^= 1;
    REQUIRE(feed(changed_sets.get(), encrypted(au(modified_sps), 0)) == PROJECTION_VIDEO_FORMAT);
    auto oversize = create(); Bytes header(128, 0); header[0] = 17; header[2] = 16;
    REQUIRE(feed(oversize.get(), header) == PROJECTION_VIDEO_LIMIT);
    auto partial = create(); Bytes first(packet.begin(), packet.begin() + 32);
    REQUIRE(feed(partial.get(), first) == PROJECTION_VIDEO_MORE);
    REQUIRE(projection_video_next_delay(partial.get()) == 1000);
    REQUIRE(projection_video_check(partial.get(), 18, 999999) == PROJECTION_VIDEO_STALE);
    REQUIRE(projection_video_check(partial.get(), 17, 999) == PROJECTION_VIDEO_MORE);
    REQUIRE(feed(partial.get(), Bytes{packet[32]}, 999) == PROJECTION_VIDEO_MORE);
    REQUIRE(projection_video_next_delay(partial.get()) == 1);
    REQUIRE(projection_video_check(partial.get(), 17, 1000) == PROJECTION_VIDEO_DEADLINE);
    auto eof = create(); REQUIRE(feed(eof.get(), first) == PROJECTION_VIDEO_MORE);
    REQUIRE(projection_video_finish(eof.get(), 17, 0) == PROJECTION_VIDEO_WIRE);
    auto held = create(); REQUIRE(feed(held.get(), config) == PROJECTION_VIDEO_CONFIG);
    REQUIRE(feed(held.get(), packet, 20) == PROJECTION_VIDEO_PACKET);
    REQUIRE(projection_video_next_delay(held.get()) == 2000);
    REQUIRE(projection_video_check(held.get(), 17, 19) == PROJECTION_VIDEO_ARGUMENT);
    REQUIRE(projection_video_check(held.get(), 17, 2019) == PROJECTION_VIDEO_MORE);
    REQUIRE(projection_video_check(held.get(), 17, 2020) == PROJECTION_VIDEO_DEADLINE);
    std::cout << "AAD/tag/ciphertext tampering, no plaintext fallback, size/deadline/EOF gates OK\n";
}
static void bad_configs(const std::vector<Bytes> &nals) {
    auto good = avcc(nals);
    for (size_t length = 0; length < good.size(); ++length) {
        auto v = create(); REQUIRE(feed(v.get(), record(1, Bytes(good.begin(), good.begin() + length))) == PROJECTION_VIDEO_FORMAT);
    }
    std::vector<Bytes> bad;
    auto c = good; c[4] = 0xfe; bad.push_back(c); // reserved length size 3
    c = good; c[5] = 0xe0; bad.push_back(c); // no SPS
    c = good; c.push_back(0); bad.push_back(c); // trailing bytes in baseline record
    c = box("avcC", good); c[3] ^= 1; bad.push_back(c); // inconsistent box size
    c = box("hvcC", good); bad.push_back(c);
    c = extended_box("avcC", good); c[8] = 1; bad.push_back(c); // overflowing 64-bit size
    c = extended_box("avcC", good); c.resize(15); bad.push_back(c); // truncated extended header
    c = box("avcC", good); std::fill(c.begin(), c.begin() + 4, 0); bad.push_back(c); // size-to-EOF not admitted
    c = box("avcC", good); Bytes tail(c.begin(), c.begin() + 8); c.insert(c.end(), tail.begin(), tail.end()); bad.push_back(c);
    Bytes fake(14); auto child = box("avcC", good); fake.insert(fake.end(), child.begin(), child.end());
    bad.push_back(box("avc1", fake)); // marker search would wrongly accept
    Bytes duplicate(78); duplicate.insert(duplicate.end(), child.begin(), child.end()); duplicate.insert(duplicate.end(), child.begin(), child.end());
    bad.push_back(box("avc1", duplicate));
    for (const auto &data : bad) { auto v = create(); REQUIRE(feed(v.get(), record(1, data)) == PROJECTION_VIDEO_FORMAT); }
    projection_video_config cfg{1920, 1088, 1000, 2000, 4, 0}; projection_video *out = nullptr;
    REQUIRE(projection_video_create(&cfg, key().data(), 17, 0, &out) == PROJECTION_VIDEO_ARGUMENT && !out);
    std::cout << "exact avcC/box bounds, reserved fields, no marker fallback and explicit clear-config policy OK\n";
}
static void config_variants(const std::vector<Bytes> &baseline, const std::vector<Bytes> &high) {
    auto good = avcc(baseline);
    Bytes entry(78);
    auto unknown = box("pasp", Bytes{0, 0, 0, 1, 0, 0, 0, 1});
    auto child = extended_box("avcC", good);
    entry.insert(entry.end(), unknown.begin(), unknown.end());
    entry.insert(entry.end(), child.begin(), child.end());
    entry.insert(entry.end(), 4, 0); // bounded optional sample-description terminator
    for (const auto &body : {extended_box("avcC", good), extended_box("avc1", entry)}) {
        auto v = create(); REQUIRE(feed(v.get(), record(1, body), 0, 1) == PROJECTION_VIDEO_CONFIG);
        REQUIRE(projection_video_start(v.get(), 17, 0) == PROJECTION_VIDEO_MORE);
        REQUIRE(feed(v.get(), encrypted(au(baseline[2]), 0)) == PROJECTION_VIDEO_PACKET);
        auto frame = take(v.get(), 0);
    }
    auto extension = avcc(high); REQUIRE(extension[1] == 100);
    extension.insert(extension.end(), {0xfd, 0xf8, 0xf8, 0});
    auto v = create(); REQUIRE(feed(v.get(), record(1, extension)) == PROJECTION_VIDEO_CONFIG);
    for (size_t offset = extension.size() - 4; offset < extension.size(); ++offset) {
        auto wrong = extension; wrong[offset] ^= 1;
        auto rejected = create(); REQUIRE(feed(rejected.get(), record(1, wrong)) == PROJECTION_VIDEO_FORMAT);
    }
    std::cout << "extended box sizes, bounded unknown children/terminator and High extension gates OK\n";
}
static int stdin_decode() {
#ifdef _WIN32
    REQUIRE(_setmode(_fileno(stdin), _O_BINARY) != -1);
#endif
    auto v = create(2); REQUIRE(projection_video_start(v.get(), 17, 0) == PROJECTION_VIDEO_MORE);
    SHA1Context ctx{}; SHA1Reset(&ctx); unsigned frames = 0, width = 0, height = 0; uint64_t last_counter = 0;
    auto drain_queue = [&]() {
        for (;;) {
            projection_h264_frame *raw = nullptr; projection_video_metadata meta{};
            int result = projection_video_take(v.get(), 17, &raw, &meta, 0);
            Frame frame(raw, projection_h264_frame_destroy);
            if (result == PROJECTION_VIDEO_MORE || result == PROJECTION_VIDEO_END) { REQUIRE(!frame); break; }
            REQUIRE(result == PROJECTION_VIDEO_FRAME && frame);
            REQUIRE(meta.frame_authenticated && !meta.configuration_authenticated);
            REQUIRE(!frames || meta.counter > last_counter); last_counter = meta.counter;
            projection_h264_view view{}; REQUIRE(projection_h264_frame_view(frame.get(), &view) == PROJECTION_H264_FRAME);
            REQUIRE(view.timestamp == meta.counter); width = view.width; height = view.height;
            SHA1Input(&ctx, view.plane[0], static_cast<unsigned>(view.bytes)); ++frames;
        }
    };
    std::array<uint8_t, 4093> chunk{};
    while (std::cin) {
        std::cin.read(reinterpret_cast<char *>(chunk.data()), chunk.size()); size_t size = size_t(std::cin.gcount()), offset = 0;
        while (offset < size) {
            size_t used = 0; int result = projection_video_feed(v.get(), 17, chunk.data() + offset, size - offset, &used, 0);
            REQUIRE(result > 0); REQUIRE(used || result == PROJECTION_VIDEO_BUSY);
            offset += used; drain_queue();
        }
    }
    for (unsigned i = 0; i < 20; ++i) {
        int result = projection_video_finish(v.get(), 17, 0); REQUIRE(result > 0); drain_queue();
        if (result == PROJECTION_VIDEO_END) {
            std::array<uint8_t, 20> digest{}; REQUIRE(SHA1Result(&ctx, digest.data()));
            static constexpr char hex[] = "0123456789abcdef"; std::string h;
            for (auto b : digest) { h += hex[b >> 4]; h += hex[b & 15]; }
            std::cout << "wire frames=" << frames << " size=" << width << 'x' << height << " sha1=" << h << '\n'; return 0;
        }
    }
    throw std::runtime_error("drain did not terminate");
}
int main(int argc, char **argv) {
    try {
        REQUIRE(argc == 2);
        REQUIRE(projection_video_c_api_test());
        if (std::string(argv[1]) == "--wire-stdin") return stdin_decode();
        auto nals = split(load(std::filesystem::path(argv[1]) / "Static.264"));
        basic(nals); reconfigure(nals); hostile(nals); bad_configs(nals);
        config_variants(nals, split(load(std::filesystem::path(argv[1]) / "test_scalinglist_jm.264")));
        std::cout << "projection_video tests passed\n"; return 0;
    } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
