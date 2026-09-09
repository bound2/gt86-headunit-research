// SPDX-License-Identifier: GPL-3.0-only
// Independent synthetic mux bytes; no USB, pairing records or physical device.
#include "usbmux_wire.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
using Bytes = std::vector<uint8_t>;
using Vectors = std::map<std::string, Bytes>;
static void check(bool value, const char *why) { if (!value) throw std::runtime_error(why); }
static Bytes hex(const std::string& text) {
    check(text.size() % 2 == 0, "hex length"); Bytes out;
    for (size_t i = 0; i < text.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return out;
}
static Bytes encode(const usbmux_frame& frame) {
    Bytes out(USBMUX_FRAME_LIMIT); size_t n;
    check(usbmux_frame_encode(&frame, out.data(), out.size(), &n) == 0, "frame encode"); out.resize(n); return out;
}
static usbmux_frame decode(const Bytes& bytes) {
    usbmux_frame frame{}; size_t used;
    check(usbmux_frame_decode(bytes.data(), bytes.size(), &frame, &used) == 0 && used == bytes.size(), "one complete mux frame");
    return frame;
}
template<class T> static auto snapshot(const T& value) {
    std::array<uint8_t, sizeof value> out{}; std::memcpy(out.data(), &value, sizeof value); return out;
}
static void golden_frames(const Vectors& vectors) {
    for (const auto& [name, bytes] : vectors) {
        const auto frame = decode(bytes); check(encode(frame) == bytes, "independent mux frame golden roundtrip");
        check(frame.payload >= bytes.data() && frame.payload + frame.payload_size == bytes.data() + bytes.size(), "payload borrows exact frame extent");
        Bytes output(bytes.size() + 2, 0xa5);
        for (size_t capacity = 0; capacity <= bytes.size(); ++capacity) {
            std::fill(output.begin(), output.end(), 0xa5); size_t n = 999;
            const auto status = usbmux_frame_encode(&frame, output.data() + 1, capacity, &n);
            if (capacity < bytes.size()) check(status == IAP2_NO_SPACE && !n && output == Bytes(bytes.size() + 2, 0xa5), "every short golden capacity unchanged");
            else check(status == 0 && n == bytes.size() && output.front() == 0xa5 && output.back() == 0xa5 &&
                       std::equal(bytes.begin(), bytes.end(), output.begin() + 1), "exact golden capacity canaries");
        }
    }
    const auto livi = decode(vectors.at("SetupLivi")), muxd = decode(vectors.at("SetupUsbmuxd"));
    check(livi.rx_sequence == 0 && muxd.rx_sequence == 65535 && livi.payload[0] == 7 && muxd.payload[0] == 7,
          "reference setup sequence difference is explicit");
    const auto opaque = decode(vectors.at("OpaqueControl"));
    check(opaque.magic == 0xdeadbeef && opaque.tx_sequence == 17 && opaque.rx_sequence == 34, "incoming extended header preserved without guessed semantics");
}
static void version_payloads(const Vectors& vectors) {
    for (const auto *name : {"Version1", "Version2"}) {
        const auto frame = decode(vectors.at(name)); usbmux_version version{}; uint8_t out[12]; size_t n;
        check(usbmux_version_decode(frame.payload, frame.payload_size, &version) == 0 && !version.minor && !version.padding &&
              version.major == (std::string(name) == "Version1" ? 1u : 2u), "initial version payload");
        check(usbmux_version_encode(&version, out, sizeof out, &n) == 0 && n == 12 &&
              Bytes(out, out + n) == Bytes(frame.payload, frame.payload + frame.payload_size), "version encoding independent of handshake policy");
    }
    usbmux_version value{UINT32_MAX, UINT32_MAX, UINT32_MAX}, decoded{}; uint8_t out[12]; size_t n;
    check(usbmux_version_encode(&value, out, sizeof out, &n) == 0 && usbmux_version_decode(out, n, &decoded) == 0 &&
          decoded.major == UINT32_MAX && decoded.minor == UINT32_MAX && decoded.padding == UINT32_MAX, "codec preserves full-width version fields");
    for (size_t size = 0; size < 12; ++size) {
        const auto before = snapshot(decoded); std::array<uint8_t,12> destination{}; destination.fill(0xa5);
        check(usbmux_version_decode(out, size, &decoded) == IAP2_INVALID && snapshot(decoded) == before, "invalid version extent preserves output");
        check(usbmux_version_encode(&value, destination.data(), size, &n) == IAP2_NO_SPACE && !n &&
              std::all_of(destination.begin(), destination.end(), [](uint8_t b) { return b == 0xa5; }), "version capacity transaction");
    }
}
static void tcp_payloads(const Vectors& vectors) {
    const auto syn = decode(vectors.at("LockdownSyn")); usbmux_tcp tcp{};
    check(usbmux_tcp_decode(syn.payload, syn.payload_size, &tcp) == 0 && tcp.source_port == 1 && tcp.destination_port == 62078 &&
          !tcp.sequence && !tcp.acknowledgement && tcp.flags == 2 && tcp.window == 512 && !tcp.checksum && !tcp.urgent && !tcp.payload_size,
          "independent SYN fields and scaled-window wire value");
    for (const auto *name : {"LockdownSyn", "PayloadAck"}) {
        const auto frame = decode(vectors.at(name)); check(usbmux_tcp_decode(frame.payload, frame.payload_size, &tcp) == 0, "TCP decode");
        Bytes out(frame.payload_size + 2, 0xa5); size_t n;
        check(usbmux_tcp_encode(&tcp, out.data() + 1, frame.payload_size, &n) == 0 && n == frame.payload_size &&
              Bytes(out.begin() + 1, out.end() - 1) == Bytes(frame.payload, frame.payload + frame.payload_size) &&
              out.front() == 0xa5 && out.back() == 0xa5, "TCP exact golden bytes and canaries");
        for (size_t capacity = 0; capacity < frame.payload_size; ++capacity) {
            std::fill(out.begin(), out.end(), 0xa5);
            check(usbmux_tcp_encode(&tcp, out.data() + 1, capacity, &n) == IAP2_NO_SPACE && !n &&
                  out == Bytes(out.size(), 0xa5), "all short TCP output capacities unchanged");
        }
    }
    check(tcp.sequence == UINT32_MAX && tcp.acknowledgement == 1 && tcp.window == 1 &&
          Bytes(tcp.payload, tcp.payload + tcp.payload_size) == Bytes{'a','b','c'}, "TCP payload and wrapping sequence bits preserved");
    tcp.flags = 255; tcp.checksum = 65535; tcp.urgent = 65535; tcp.window = 65535; tcp.source_port = 0; tcp.destination_port = 65535;
    Bytes encoded(64); size_t n;
    check(usbmux_tcp_encode(&tcp, encoded.data(), encoded.size(), &n) == 0 && usbmux_tcp_decode(encoded.data(), n, &tcp) == 0 &&
          tcp.flags == 255 && tcp.checksum == 65535 && tcp.urgent == 65535 && tcp.window == 65535 && !tcp.source_port && tcp.destination_port == 65535,
          "codec does not invent connection/checksum/flag policy");
}
static void malformed_frames(const Vectors& vectors) {
    for (const auto& [name, bytes] : vectors) for (size_t size = 0; size < bytes.size(); ++size) {
        usbmux_frame value{}; const auto before = snapshot(value); size_t used = 999;
        check(usbmux_frame_decode(bytes.data(), size, &value, &used) == IAP2_MORE && !used && snapshot(value) == before,
              "truncated frame leaves destination and count unchanged");
    }
    for (const auto *text : {"0000000000000008", "0000000000000015", "0000000200000010", "0000000200000012", "0000000600000023", "000000010000000f"}) {
        const auto bytes = hex(text); usbmux_frame out{}; size_t used = 999; const auto before = snapshot(out);
        check(usbmux_frame_decode(bytes.data(), bytes.size(), &out, &used) == IAP2_INVALID && !used && snapshot(out) == before,
              "invalid lengths detected from bounded prefix");
    }
    for (const auto *text : {"00000001ffffffff", "0000000600010001"}) {
        const auto bytes = hex(text); usbmux_frame out{}; size_t used;
        check(usbmux_frame_decode(bytes.data(), bytes.size(), &out, &used) == IAP2_NO_SPACE && !used, "oversized advertised lengths rejected immediately");
    }
    const auto unknown = hex("ffffffff00000010"); usbmux_frame out{}; size_t used;
    check(usbmux_frame_decode(unknown.data(), unknown.size(), &out, &used) == IAP2_UNSUPPORTED && !used, "unknown protocol rejected");
    auto version = decode(vectors.at("Version2")); version.tx_sequence = 1; Bytes destination(64, 0xa5); size_t n;
    check(usbmux_frame_encode(&version, destination.data(), destination.size(), &n) == IAP2_ARGUMENT && !n &&
          destination == Bytes(64, 0xa5), "initial version cannot silently discard extended-header fields");
}
static void malformed_tcp(const Vectors& vectors) {
    const auto frame = decode(vectors.at("LockdownSyn")); const Bytes original(frame.payload, frame.payload + frame.payload_size);
    for (size_t size = 0; size < 20; ++size) {
        usbmux_tcp out{}; const auto before = snapshot(out);
        check(usbmux_tcp_decode(original.data(), size, &out) == IAP2_INVALID && snapshot(out) == before, "short TCP header transactional");
    }
    for (uint8_t offset : {0, 0x40, 0x51, 0x60, 0xf0}) {
        auto bytes = original; bytes[12] = offset; usbmux_tcp out{}; const auto before = snapshot(out);
        check(usbmux_tcp_decode(bytes.data(), bytes.size(), &out) == ((offset == 0x60 || offset == 0xf0) ? IAP2_UNSUPPORTED : IAP2_INVALID) &&
              snapshot(out) == before, "invalid/unsupported TCP header offset and reserved bits");
    }
}
static void stream_fragmentation(const Vectors& vectors) {
    for (const auto& [name, bytes] : vectors) for (size_t split = 0; split <= bytes.size(); ++split) {
        uint8_t storage[128]; usbmux_stream stream{}; usbmux_frame out{}; size_t used = 999;
        check(usbmux_stream_init(&stream, storage, sizeof storage) == 0, "stream init");
        const auto first = usbmux_stream_push(&stream, bytes.data(), split, &used, &out);
        check(used == split && first == (split == bytes.size() ? IAP2_OK : IAP2_MORE), "every stream split prefix");
        if (split != bytes.size()) check(usbmux_stream_push(&stream, bytes.data() + split, bytes.size() - split, &used, &out) == 0 &&
                                        used == bytes.size() - split, "every stream split suffix");
        check(encode(out) == bytes && stream.ready && out.payload >= storage && out.payload + out.payload_size <= storage + sizeof storage,
              "stream view owns complete reassembled frame");
    }
}
static void coalesced_and_reset(const Vectors& vectors) {
    Bytes joined; for (const auto& [name, bytes] : vectors) joined.insert(joined.end(), bytes.begin(), bytes.end());
    uint8_t storage[128]; usbmux_stream stream{}; usbmux_frame out{}; size_t used, offset = 0;
    check(usbmux_stream_init(&stream, storage, sizeof storage) == 0, "coalesced init");
    for (const auto& [name, bytes] : vectors) {
        check(usbmux_stream_push(&stream, joined.data() + offset, joined.size() - offset, &used, &out) == 0 && used == bytes.size() && encode(out) == bytes,
              "one coalesced packet per push preserves following input"); offset += used;
    }
    check(offset == joined.size() && usbmux_stream_push(&stream, nullptr, 0, &used, &out) == IAP2_MORE && !used, "empty chunk is not EOF");
    const auto& first = vectors.at("Version2");
    check(usbmux_stream_push(&stream, first.data(), 7, &used, &out) == IAP2_MORE && used == 7, "partial before EOF");
    usbmux_stream_reset(&stream);
    check(!stream.used && !stream.expected && !stream.ready && !stream.error &&
          usbmux_stream_push(&stream, first.data(), first.size(), &used, &out) == 0 && encode(out) == first, "explicit EOF/reset discards old partial bytes");
}
static void stream_errors_and_limits(const Vectors& vectors) {
    std::array<uint8_t,38> storage{}; storage.fill(0xa5); usbmux_stream stream{}; usbmux_frame out{}; size_t used;
    check(usbmux_stream_init(&stream, storage.data() + 1, 36) == 0, "minimal stream buffer");
    const auto& oversized = vectors.at("PayloadAck"); const auto before = snapshot(out);
    check(usbmux_stream_push(&stream, oversized.data(), oversized.size(), &used, &out) == IAP2_NO_SPACE && used == 8 &&
          snapshot(out) == before && storage.front() == 0xa5 && storage.back() == 0xa5, "capacity error consumes only length prefix");
    const auto& good = vectors.at("Version2");
    check(usbmux_stream_push(&stream, good.data(), good.size(), &used, &out) == IAP2_NO_SPACE && !used, "stream error latches without scanning");
    usbmux_stream_reset(&stream);
    const auto bad = hex("0000000200000000");
    for (size_t i = 0; i < bad.size(); ++i) {
        const auto status = usbmux_stream_push(&stream, bad.data() + i, 1, &used, &out);
        check(used == 1 && status == (i == 7 ? IAP2_INVALID : IAP2_MORE), "invalid fragmented length fails at eighth byte");
    }
    usbmux_stream_reset(&stream); check(usbmux_stream_push(&stream, good.data(), good.size(), &used, &out) == 0, "reset clears latched error");
    const auto saved = snapshot(stream);
    check(usbmux_stream_init(&stream, storage.data(), 35) == IAP2_ARGUMENT && snapshot(stream) == saved &&
          usbmux_stream_init(&stream, storage.data(), USBMUX_FRAME_LIMIT + 1) == IAP2_ARGUMENT && snapshot(stream) == saved,
          "invalid stream initialization preserves state");
}
static void maximum_frames() {
    Bytes payload(USBMUX_TCP_PAYLOAD_LIMIT, 0x31), tcp_bytes(USBMUX_FRAME_LIMIT - 16), output(USBMUX_FRAME_LIMIT + 2, 0xa5);
    usbmux_tcp tcp{65535, 62078, UINT32_MAX, UINT32_MAX, 0x10, 65535, 0, 0, payload.data(), payload.size()}; size_t n;
    check(usbmux_tcp_encode(&tcp, tcp_bytes.data(), tcp_bytes.size(), &n) == 0 && n == tcp_bytes.size(), "maximum TCP payload");
    usbmux_frame frame{USBMUX_TCP, USBMUX_HOST_MAGIC, 65535, 65535, tcp_bytes.data(), tcp_bytes.size()};
    check(usbmux_frame_encode(&frame, output.data() + 1, USBMUX_FRAME_LIMIT - 1, &n) == IAP2_NO_SPACE && !n &&
          output == Bytes(output.size(), 0xa5), "maximum frame short output transaction");
    check(usbmux_frame_encode(&frame, output.data() + 1, USBMUX_FRAME_LIMIT, &n) == 0 && n == USBMUX_FRAME_LIMIT &&
          output.front() == 0xa5 && output.back() == 0xa5, "maximum frame exact output");
    Bytes storage(USBMUX_FRAME_LIMIT); usbmux_stream stream{}; usbmux_frame decoded{}; size_t used, offset = 0;
    check(usbmux_stream_init(&stream, storage.data(), storage.size()) == 0, "maximum stream capacity");
    while (offset < n) {
        const auto amount = std::min<size_t>(137, n - offset);
        const auto status = usbmux_stream_push(&stream, output.data() + 1 + offset, amount, &used, &decoded); offset += used;
        check(used == amount && status == (offset == n ? IAP2_OK : IAP2_MORE), "maximum stream bounded chunks");
    }
    check(usbmux_tcp_decode(decoded.payload, decoded.payload_size, &tcp) == 0 && tcp.payload_size == payload.size() &&
          std::equal(payload.begin(), payload.end(), tcp.payload), "maximum roundtrip payload preserved");
    ++tcp.payload_size;
    check(usbmux_tcp_encode(&tcp, output.data(), output.size(), &n) == IAP2_NO_SPACE && !n, "oversized TCP rejected before reading payload");
}
static void arguments() {
    usbmux_frame frame{}; usbmux_tcp tcp{}; usbmux_version version{}; usbmux_stream stream{}; uint8_t out[64]{}; size_t n = 999;
    check(usbmux_frame_decode(nullptr, 0, &frame, &n) == IAP2_MORE && !n &&
          usbmux_frame_decode(nullptr, 1, &frame, &n) == IAP2_ARGUMENT && !n &&
          usbmux_frame_decode(out, 8, nullptr, &n) == IAP2_ARGUMENT && usbmux_frame_decode(out, 8, &frame, nullptr) == IAP2_ARGUMENT, "frame argument contract");
    check(usbmux_frame_encode(nullptr, out, sizeof out, &n) == IAP2_ARGUMENT && !n &&
          usbmux_tcp_encode(nullptr, out, sizeof out, &n) == IAP2_ARGUMENT && usbmux_version_encode(nullptr, out, sizeof out, &n) == IAP2_ARGUMENT,
          "encoder null arguments");
    check(usbmux_tcp_decode(nullptr, 0, &tcp) == IAP2_ARGUMENT && usbmux_version_decode(nullptr, 0, &version) == IAP2_ARGUMENT &&
          usbmux_stream_push(&stream, out, 8, &n, &frame) == IAP2_ARGUMENT && !n &&
          usbmux_stream_init(nullptr, out, sizeof out) == IAP2_ARGUMENT, "typed and uninitialized stream arguments");
    usbmux_stream_reset(nullptr);
}
int main(int argc, char **argv) {
    try {
        check(argc == 2, "provide independent mux vectors path"); std::ifstream input(argv[1]); check(bool(input), "open mux vectors");
        Vectors vectors; std::string name, bytes; while (input >> name >> bytes) vectors.emplace(name, hex(bytes));
        check(vectors.size() == 7, "seven independent mux fixtures");
        golden_frames(vectors); version_payloads(vectors); tcp_payloads(vectors); malformed_frames(vectors); malformed_tcp(vectors);
        stream_fragmentation(vectors); coalesced_and_reset(vectors); stream_errors_and_limits(vectors); maximum_frames(); arguments();
        std::cout << "PASS: 10 bounded USBmux wire/stream groups; seven independent synthetic fixtures, no USB I/O.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
