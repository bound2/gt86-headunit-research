// SPDX-License-Identifier: GPL-3.0-or-later
// Golden frames from LIVI; see third_party/README.md. All auth providers below
// are test doubles, and their byte responses are not valid certificates/signatures.
#include "iap2_wire.h"
#include "iap2_auth.h"
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
static void check(bool ok, const char* what) {
    if (!ok) throw std::runtime_error(what);
}
static Bytes hex(const std::string& text) {
    check(text.size() % 2 == 0, "invalid test hex length");
    Bytes out;
    for (size_t i = 0; i < text.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return out;
}
static Bytes encode(const iap2_frame& frame) {
    Bytes out(65535);
    size_t size = 0;
    check(iap2_frame_encode(&frame, out.data(), out.size(), &size) == IAP2_OK, "encode frame");
    out.resize(size);
    return out;
}
static void fix_header_checksum(Bytes& frame) {
    unsigned sum = 0;
    for (size_t i = 0; i < 8; ++i) sum += frame[i];
    frame[8] = static_cast<uint8_t>(0u - sum);
}

static size_t golden_messages(const char* path) {
    std::ifstream file(path);
    check(file.is_open(), "cannot open committed upstream vectors");
    std::string name, wire;
    size_t count = 0;
    while (file >> name >> wire) {
        auto bytes = hex(wire);
        iap2_message message{};
        size_t consumed = 123;
        check(iap2_message_decode(bytes.data(), bytes.size(), &message, &consumed) == IAP2_OK,
              "upstream CSM vector rejected");
        check(consumed == bytes.size(), "upstream CSM length");
        std::vector<iap2_param> params;
        size_t offset = 0;
        iap2_param param{};
        int status;
        while ((status = iap2_param_next(&message, &offset, &param)) == IAP2_OK)
            params.push_back(param);
        check(status == IAP2_END, "golden parameter iteration");
        Bytes output(bytes.size(), 0xcc);
        size_t written = 0;
        check(iap2_message_encode(message.id, params.data(), params.size(), output.data(),
                                 output.size(), &written) == IAP2_OK, "CSM encode");
        check(output == bytes && written == bytes.size(), "byte-exact upstream CSM vector");
        for (size_t n = 0; n < bytes.size(); ++n) {
            consumed = 123;
            check(iap2_message_decode(bytes.data(), n, &message, &consumed) == IAP2_MORE,
                  "truncated CSM must wait");
            check(consumed == 0, "partial CSM consumed input");
        }
        ++count;
    }
    check(count == 33, "unexpected upstream vector count");
    return count;
}

static void frame_tests() {
    const auto ack = hex("ff5a000940630500f6");
    iap2_frame frame{0x40, 0x63, 0x05, 0, 0, nullptr, 0};
    check(encode(frame) == ack, "upstream golden ACK");
    const auto syn = hex("ff5a001d80630000a7011effff0fa001f404030a00010b02010c010210");
    const auto lsp = hex("011effff0fa001f404030a00010b02010c0102");
    frame = {0x80, 99, 0, 0, 1, lsp.data(), lsp.size()};
    check(encode(frame) == syn, "upstream golden SYN");
    size_t consumed;
    for (size_t n = 0; n < syn.size(); ++n) {
        check(iap2_frame_decode(syn.data(), n, &frame, &consumed) == IAP2_MORE,
              "all truncated link boundaries");
        check(consumed == 0, "partial link consumed input");
    }
    check(iap2_frame_decode(syn.data(), syn.size(), &frame, &consumed) == IAP2_OK,
          "decode golden SYN");
    check(frame.control == 0x80 && frame.sequence == 99 && frame.payload_size == lsp.size(),
          "SYN metadata");
    for (size_t i = 0; i < syn.size(); ++i) {
        auto bad = syn; bad[i] ^= 1;
        check(iap2_frame_decode(bad.data(), bad.size(), &frame, &consumed) == IAP2_INVALID,
              "every one-byte corrupted frame rejected");
    }
    auto invalid = ack;
    invalid[3] = 8; fix_header_checksum(invalid);
    check(iap2_frame_decode(invalid.data(), invalid.size(), &frame, &consumed) == IAP2_INVALID,
          "short advertised length even with valid checksum");
    frame = {0x40, 255, 0, 10, 1, nullptr, 0};
    auto empty = encode(frame);
    check(empty.size() == 10 && empty.back() == 0, "empty payload has checksum");
    check(iap2_frame_decode(empty.data(), empty.size(), &frame, &consumed) == IAP2_OK &&
          frame.has_payload && frame.payload_size == 0, "empty payload preserved");
    Bytes largest(65525, 0x81);
    frame.payload = largest.data(); frame.payload_size = largest.size();
    auto maximum = encode(frame);
    check(maximum.size() == 65535, "maximum link frame");
    check(iap2_frame_decode(maximum.data(), maximum.size(), &frame, &consumed) == IAP2_OK,
          "maximum link frame decodes");
    std::array<uint8_t, 16> sentinel; sentinel.fill(0xa5);
    size_t written = 1;
    check(iap2_frame_encode(&frame, sentinel.data(), sentinel.size(), &written) == IAP2_NO_SPACE,
          "small output rejected");
    check(written == 0 && sentinel[0] == 0xa5, "failed encoding leaves output untouched");
    frame.payload_size = std::numeric_limits<size_t>::max();
    check(iap2_frame_encode(&frame, sentinel.data(), sentinel.size(), &written) == IAP2_NO_SPACE,
          "size overflow rejected before payload read");
}

static void stream_tests() {
    const auto syn = hex("ff5a001d80630000a7011effff0fa001f404030a00010b02010c010210");
    const auto ack = hex("ff5a000940630500f6");
    std::array<uint8_t, 64> buffer{};
    iap2_stream stream{};
    iap2_frame frame{};
    size_t consumed;
    for (size_t split = 0; split <= syn.size(); ++split) {
        check(iap2_stream_init(&stream, buffer.data(), buffer.size()) == IAP2_OK, "stream init");
        int first = iap2_stream_push(&stream, syn.data(), split, &consumed, &frame);
        check(consumed == split, "fragment consumption");
        if (split < syn.size()) {
            check(first == IAP2_MORE, "partial stream status");
            check(iap2_stream_push(&stream, syn.data() + split, syn.size() - split,
                                  &consumed, &frame) == IAP2_OK, "fragment reassembly");
        } else check(first == IAP2_OK, "whole frame status");
        check(frame.control == 0x80 && frame.payload_size == 19, "reassembled frame");
    }
    iap2_stream_init(&stream, buffer.data(), buffer.size());
    for (size_t i = 0; i < syn.size(); ++i) {
        const auto result = iap2_stream_push(&stream, syn.data()+i, 1, &consumed, &frame);
        check(result == (i+1 == syn.size() ? IAP2_OK : IAP2_MORE), "one-byte fragmentation");
    }
    Bytes noisy{0xde, 0xad, 0xff};
    auto bad_header = ack; bad_header[8] ^= 1;
    noisy.insert(noisy.end(), bad_header.begin(), bad_header.end());
    noisy.insert(noisy.end(), syn.begin(), syn.end());
    noisy.insert(noisy.end(), ack.begin(), ack.end());
    iap2_stream_init(&stream, buffer.data(), buffer.size());
    check(iap2_stream_push(&stream, noisy.data(), noisy.size(), &consumed, &frame) == IAP2_OK,
          "resynchronize after garbage and damaged header");
    check(consumed == 3 + bad_header.size() + syn.size() && stream.discarded == 12,
          "coalesced next frame retained by caller");
    size_t second;
    check(iap2_stream_push(&stream, noisy.data()+consumed, noisy.size()-consumed,
                          &second, &frame) == IAP2_OK && second == ack.size(), "second coalesced frame");
    auto bad = syn; bad.back() ^= 1;
    check(iap2_stream_push(&stream, bad.data(), bad.size(), &consumed, &frame) == IAP2_INVALID,
          "bad body checksum reported");
    check(stream.used == 0, "failed body clears stream");
    iap2_stream_init(&stream, buffer.data(), 9);
    check(iap2_stream_push(&stream, syn.data(), syn.size(), &consumed, &frame) == IAP2_NO_SPACE &&
          consumed == 9, "oversized advertised length rejected at header");
}

static void malformed_messages() {
    iap2_message msg{};
    size_t used;
    for (const auto* value : {"40410006aa00", "40400005aa00", "40400007aa00ff",
                              "4040000aaa0100030000", "4040000aaa0100050000"}) {
        const auto bytes = hex(value);
        check(iap2_message_decode(bytes.data(), bytes.size(), &msg, &used) == IAP2_INVALID,
              "malformed CSM rejected completely");
        check(used == 0, "invalid CSM consumed input");
    }
    auto two = hex("40400006aa0040400006aa05");
    check(iap2_message_decode(two.data(), two.size(), &msg, &used) == IAP2_OK && used == 6,
          "coalesced CSM consumes one message");
    iap2_param huge{0, two.data(), std::numeric_limits<size_t>::max()};
    std::array<uint8_t, 10> out; out.fill(0xcc);
    check(iap2_message_encode(0xaa01, &huge, 1, out.data(), out.size(), &used) == IAP2_NO_SPACE,
          "parameter size overflow");
    check(out[0] == 0xcc && used == 0, "CSM preflight does not write");
    check(iap2_message_encode(0, &huge, std::numeric_limits<size_t>::max(), out.data(),
                              out.size(), &used) == IAP2_NO_SPACE, "parameter count bound");
    check(iap2_frame_decode(nullptr, 1, nullptr, &used) == IAP2_ARGUMENT, "null pointers");
}

struct MockProvider { int certificates = 0, signs = 0; bool fail = false, oversize = false; };
static int certificate(void* context, uint8_t* out, size_t cap, size_t* written) {
    auto& mock = *static_cast<MockProvider*>(context); ++mock.certificates;
    if (mock.fail || cap < 3) return IAP2_PROVIDER_FAILED;
    out[0]=1; out[1]=2; out[2]=0xff;
    *written = mock.oversize ? cap+1 : 3;
    return IAP2_OK;
}
static int sign(void* context, const uint8_t* challenge, size_t size,
                uint8_t* out, size_t cap, size_t* written) {
    auto& mock = *static_cast<MockProvider*>(context); ++mock.signs;
    check(size == 2 && challenge[0] == 0xaa && challenge[1] == 0xbb, "challenge forwarded intact");
    if (mock.fail || cap < 2) return IAP2_PROVIDER_FAILED;
    out[0]=0x12; out[1]=0x34; *written=2;
    return IAP2_OK;
}
static void auth_tests() {
    MockProvider mock;
    iap2_auth_provider provider{&mock, certificate, sign};
    iap2_auth auth{};
    std::array<uint8_t, 128> scratch{}, reply{};
    size_t written = 0;
    auto reset = [&] { mock = {}; check(iap2_auth_init(&auth, &provider, scratch.data(),
                                                     scratch.size()) == IAP2_OK, "auth init"); };
    auto handle = [&](const char* text) {
        auto bytes = hex(text);
        return iap2_auth_handle(&auth, bytes.data(), bytes.size(), reply.data(), reply.size(), &written);
    };
    reset();
    check(handle("40400006aa00") == IAP2_OK && auth.state == IAP2_AUTH_WAIT_CHALLENGE, "certificate request");
    check(Bytes(reply.begin(), reply.begin()+written) == hex("4040000daa01000700000102ff"),
          "upstream certificate vector exact");
    check(handle("4040000caa0200060000aabb") == IAP2_OK && auth.state == IAP2_AUTH_WAIT_RESULT,
          "challenge request");
    check(Bytes(reply.begin(), reply.begin()+written) == hex("4040000caa03000600001234"),
          "challenge-response message");
    check(auth.state != IAP2_AUTH_ACCEPTED, "a local signature alone does not authenticate");
    check(handle("40400006aa05") == IAP2_OK && written == 0 && auth.state == IAP2_AUTH_ACCEPTED,
          "phone acceptance after challenge");
    check(mock.certificates == 1 && mock.signs == 1, "provider calls");
    reset();
    check(handle("40400006aa05") == IAP2_INVALID && auth.state == IAP2_AUTH_REJECTED,
          "early success notification rejected");
    check(handle("40400006aa00") == IAP2_AUTH_FAILED && mock.certificates == 0,
          "failed session requires explicit reset");
    reset();
    check(handle("4040000caa0200060000aabb") == IAP2_INVALID && mock.signs == 0,
          "challenge before certificate rejected");
    reset(); mock.fail = true;
    check(handle("40400006aa00") == IAP2_PROVIDER_FAILED && written == 0, "provider failure stops auth");
    reset(); mock.oversize = true;
    check(handle("40400006aa00") == IAP2_PROVIDER_FAILED && written == 0, "provider size checked");
    reset(); auth.provider.certificate = nullptr;
    check(handle("40400006aa00") == IAP2_PROVIDER_FAILED, "no fallback certificate");
    reset();
    check(handle("40400006aa00") == IAP2_OK, "certificate before failure");
    check(handle("40400006aa04") == IAP2_AUTH_FAILED && auth.state == IAP2_AUTH_REJECTED,
          "phone rejection stops auth");
    reset();
    check(handle("40400006aa00") == IAP2_OK, "certificate before duplicate challenge fields");
    check(handle("40400012aa0200060000aabb00060000ccdd") == IAP2_INVALID && mock.signs == 0,
          "duplicate challenge fields rejected");
    reset();
    check(handle("40400006aa00") == IAP2_OK, "certificate before empty challenge");
    check(handle("4040000aaa0200040000") == IAP2_INVALID && mock.signs == 0,
          "empty challenge rejected");
    reset();
    check(handle("404000064300") == IAP2_UNSUPPORTED && auth.state == IAP2_AUTH_IDLE,
          "non-auth message routed elsewhere");
}

int main(int argc, char** argv) {
    try {
        check(argc == 2, "usage: iap2_tests VECTORS");
        auto count = golden_messages(argv[1]);
        frame_tests(); stream_tests(); malformed_messages(); auth_tests();
        std::cout << "PASS: " << count << " upstream CSM vectors, golden link frames, fragmentation, "
                     "checksums, malformed lengths, and authentication sequencing\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
