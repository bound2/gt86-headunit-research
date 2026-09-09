// SPDX-License-Identifier: GPL-3.0-or-later
// Pinned public field vectors and a deliberately minimal synthetic profile.
#include "iap2_identification.h"
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
static void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
static Bytes hex(const std::string& s) {
    check(s.size() % 2 == 0, "hex fixture length"); Bytes b;
    for (size_t i = 0; i < s.size(); i += 2) b.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return b;
}
static iap2_identification_text text(const char *s) { return {s, std::strlen(s)}; }
static iap2_identification_metadata metadata() {
    iap2_identification_metadata m{};
    m.name = text("LIVI"); m.model = text("LIVI-1"); m.manufacturer = text("f-io");
    m.serial = text("0123456"); m.firmware = text("1.0"); m.hardware = text("1.0");
    m.current_language = m.languages[0] = text("en"); m.language_count = 1;
    m.power_capability = 2; m.maximum_current_ma = 0; return m;
}
static Bytes encode(const iap2_identification_metadata& m) {
    Bytes b(1024, 0xa5); size_t n = 777;
    check(iap2_identification_encode(&m, b.data(), b.size(), &n) == IAP2_OK, "encode minimal identification");
    b.resize(n); return b;
}
static Bytes csm(uint16_t id, const std::vector<iap2_param>& params = {}) {
    Bytes b(1024); size_t n;
    check(iap2_message_encode(id, params.data(), params.size(), b.data(), b.size(), &n) == IAP2_OK, "encode test CSM");
    b.resize(n); return b;
}
static std::map<uint16_t, std::vector<Bytes>> fields(const Bytes& bytes) {
    iap2_message m{}; size_t used, offset = 0;
    check(iap2_message_decode(bytes.data(), bytes.size(), &m, &used) == IAP2_OK && used == bytes.size() && m.id == 0x1d01,
        "identification frame decode");
    std::map<uint16_t, std::vector<Bytes>> result; iap2_param p{}; int status;
    while ((status = iap2_param_next(&m, &offset, &p)) == IAP2_OK) result[p.id].emplace_back(p.data, p.data + p.size);
    check(status == IAP2_END, "identification parameters end"); return result;
}
static int handle(iap2_identification& id, const Bytes& b, Bytes& out, size_t& n) {
    return iap2_identification_handle(&id, b.data(), b.size(), out.data(), out.size(), &n);
}
static void pinned_fields(const std::map<std::string, Bytes>& vectors) {
    const auto golden = fields(vectors.at("IdentificationInformation"));
    const auto actual = fields(encode(metadata()));
    for (uint16_t p : {0,1,2,3,4,5,8,9,12,13}) check(actual.at(p) == golden.at(p), "pinned common identity field bytes");
    check(actual.size() == 12 && actual.at(6) == std::vector<Bytes>{hex("aa01aa031d01")} &&
        actual.at(7) == std::vector<Bytes>{hex("aa00aa02aa04aa051d001d021d03")}, "only implemented message IDs advertised");
    for (uint16_t p : {10,11,14,15,16,17,20,21,22,24,30}) check(!actual.contains(p), "no unsupported component/CarPlay advertisement");
    iap2_identification id{}; const auto m = metadata(); Bytes out(1024); size_t n;
    check(iap2_identification_init(&id, &m) == IAP2_OK, "vector init");
    check(handle(id, csm(0x1d00), out, n) == IAP2_OK && handle(id, vectors.at("IdentificationRejected"), out, n) ==
        IAP2_IDENTIFICATION_FAILED && id.rejected_fields == 9 && !n, "pinned rejection fields name/serial");
    iap2_identification_reset(&id);
    check(handle(id, csm(0x1d00), out, n) == IAP2_OK && handle(id, vectors.at("IdentificationAccepted"), out, n) == IAP2_OK &&
        id.state == IAP2_IDENTIFICATION_ACCEPTED && !n, "pinned accepted notification");
}
static void metadata_validation() {
    for (unsigned test = 0; test < 13; ++test) {
        auto m = metadata(); const std::string long_name(128, 'x');
        switch (test) {
        case 0: m.name = {nullptr, 2}; break;
        case 1: m.model.size = 0; break;
        case 2: m.manufacturer = {long_name.data(), long_name.size()}; break;
        case 3: m.serial = {"a\0b", 3}; break;
        case 4: m.firmware = {"a\nb", 3}; break;
        case 5: m.hardware = {"\xc3\xa9", 2}; break;
        case 6: m.language_count = 0; break;
        case 7: m.language_count = 5; break;
        case 8: m.current_language = text("et"); break;
        case 9: m.language_count = 2; m.languages[1] = m.languages[0]; break;
        case 10: m.languages[0] = {long_name.data(), 17}; break;
        case 11: m.power_capability = 1; break;
        case 12: m.power_capability = 255; break;
        }
        Bytes out(1024, 0xa5); size_t n = 777;
        check(iap2_identification_encode(&m, out.data(), out.size(), &n) == IAP2_ARGUMENT && !n &&
            out == Bytes(1024, 0xa5), "metadata preflight transaction");
        iap2_identification id{}; const auto valid = metadata(); check(iap2_identification_init(&id, &valid) == IAP2_OK, "valid init");
        const auto before = id;
        check(iap2_identification_init(&id, &m) == IAP2_ARGUMENT && std::memcmp(&before, &id, sizeof id) == 0,
            "invalid reinit retains prior identity and state");
    }
}
static void maximum_and_capacity() {
    auto m = metadata(); const std::string name(127, 'x'); const std::array<std::string,4> languages = {
        std::string(16, 'a'), std::string(16, 'b'), std::string(16, 'c'), std::string(16, 'd')};
    m.name = m.model = m.manufacturer = m.serial = m.firmware = m.hardware = {name.data(), name.size()};
    m.language_count = 4;
    for (size_t i = 0; i < 4; ++i) m.languages[i] = {languages[i].data(), languages[i].size()};
    m.current_language = m.languages[2]; m.maximum_current_ma = 65535; m.power_capability = 0;
    const auto b = encode(m); check(b.size() == 942, "bounded maximum encoded size");
    Bytes out(b.size() + 2, 0xa5); size_t n = 777;
    check(iap2_identification_encode(&m, out.data() + 1, b.size() - 1, &n) == IAP2_NO_SPACE && !n &&
        out == Bytes(b.size() + 2, 0xa5), "one byte short output unchanged");
    check(iap2_identification_encode(&m, out.data() + 1, b.size(), &n) == IAP2_OK && n == b.size() &&
        out.front() == 0xa5 && out.back() == 0xa5 && std::equal(b.begin(), b.end(), out.begin() + 1), "exact capacity canaries");
    const auto decoded = fields(b);
    check(decoded.at(9) == std::vector<Bytes>{hex("ffff")} && decoded.at(13).size() == 4, "current/language encoding boundaries");
}
static void sequence_and_snapshot() {
    auto m = metadata(); std::string source = "Synthetic test"; m.name = {source.data(), source.size()};
    const auto expected = encode(m); iap2_identification id{}; size_t n = 777; Bytes out(10, 0xa5);
    check(iap2_identification_init(&id, &m) == IAP2_OK, "snapshot init"); source.assign(source.size(), 'z');
    check(handle(id, csm(0x1d00), out, n) == IAP2_NO_SPACE && !n && id.state == IAP2_IDENTIFICATION_IDLE &&
        out == Bytes(10, 0xa5), "small reply permits retry");
    out.resize(1024);
    check(handle(id, csm(0x1d00), out, n) == IAP2_OK && Bytes(out.begin(), out.begin() + n) == expected &&
        id.state == IAP2_IDENTIFICATION_WAIT_RESULT, "metadata snapshot owned by sequencer");
    check(handle(id, csm(0x1234), out, n) == IAP2_UNSUPPORTED && !n && id.state == IAP2_IDENTIFICATION_WAIT_RESULT,
        "unknown message no state change");
    check(handle(id, csm(0x1d02), out, n) == IAP2_OK && !n && id.state == IAP2_IDENTIFICATION_ACCEPTED, "ordered success");
    iap2_identification_reset(&id);
    check(id.state == IAP2_IDENTIFICATION_IDLE && !id.rejected_fields && id.information_size == expected.size(), "reset clears acceptance retains metadata");
    check(handle(id, csm(0x1d02), out, n) == IAP2_INVALID && id.state == IAP2_IDENTIFICATION_REJECTED, "stale acceptance rejected");
    check(handle(id, csm(0x1d00), out, n) == IAP2_IDENTIFICATION_FAILED, "no restart after failure without reset");
}
static void malformed_sequences() {
    const auto m = metadata(); Bytes out(1024); size_t n;
    const std::vector<Bytes> invalid{csm(0x1d01), csm(0x1d02), csm(0x1d03), csm(0x1d00, {{0,nullptr,0}}),
        hex("404000051d00"), hex("404000071d0000"), hex("404000061d0000"), hex("414000061d00")};
    for (const auto& input : invalid) {
        iap2_identification id{}; check(iap2_identification_init(&id, &m) == IAP2_OK, "malformed init");
        check(handle(id, input, out, n) == IAP2_INVALID && !n && id.state == IAP2_IDENTIFICATION_REJECTED, "invalid sequence/message");
    }
    for (const auto& input : {csm(0x1d00), csm(0x1d02, {{0,nullptr,0}}), csm(0x1d03, {{0,nullptr,0},{0,nullptr,0}}),
        hex("4040000b1d030005000001")}) {
        iap2_identification id{}; check(iap2_identification_init(&id, &m) == IAP2_OK && handle(id,csm(0x1d00),out,n) == IAP2_OK, "waiting result init");
        check(handle(id, input, out, n) == IAP2_INVALID && !n && !id.rejected_fields, "duplicate start or malformed result");
    }
}
static void rejection_boundaries() {
    const auto m = metadata(); Bytes out(1024); size_t n;
    for (uint16_t flag : {0,31,32,65535}) {
        iap2_identification id{}; check(iap2_identification_init(&id, &m) == IAP2_OK && handle(id,csm(0x1d00),out,n) == IAP2_OK, "rejection init");
        const auto status = handle(id, csm(0x1d03, {{flag,nullptr,0}}), out, n);
        check(status == (flag < 32 ? IAP2_IDENTIFICATION_FAILED : IAP2_UNSUPPORTED) && !n &&
            id.state == IAP2_IDENTIFICATION_REJECTED && id.rejected_fields == (flag < 32 ? uint32_t(1) << flag : 0), "bounded rejection flag mask");
    }
    iap2_identification id{}; check(iap2_identification_init(&id, &m) == IAP2_OK && handle(id,csm(0x1d00),out,n) == IAP2_OK, "empty rejection init");
    check(handle(id, csm(0x1d03), out, n) == IAP2_IDENTIFICATION_FAILED && !id.rejected_fields, "empty rejection still failure");
}
static void arguments_and_disabled() {
    auto m = metadata(); iap2_identification id{}; uint8_t out[1024]; size_t n = 777;
    const auto start = csm(0x1d00);
    check(iap2_identification_encode(nullptr, out, sizeof out, &n) == IAP2_ARGUMENT && !n, "null metadata");
    check(iap2_identification_encode(&m, nullptr, sizeof out, &n) == IAP2_ARGUMENT && !n, "null output");
    check(iap2_identification_init(nullptr, &m) == IAP2_ARGUMENT, "null sequencer");
    check(iap2_identification_handle(nullptr, start.data(), start.size(), out, sizeof out, &n) == IAP2_ARGUMENT && !n, "null handler");
    check(iap2_identification_handle(&id, start.data(), start.size(), out, sizeof out, &n) == IAP2_UNSUPPORTED && !n &&
        id.state == IAP2_IDENTIFICATION_DISABLED, "disabled identification does not invent identity");
    iap2_identification_reset(nullptr);
}
int main(int argc, char **argv) {
    try {
        check(argc == 2, "provide pinned CSM vectors path"); std::ifstream input(argv[1]); check(bool(input), "open vectors");
        std::map<std::string,Bytes> vectors; std::string name, bytes;
        while (input >> name >> bytes) vectors.emplace(name, hex(bytes));
        check(vectors.size() == 33, "pinned vector count");
        pinned_fields(vectors); metadata_validation(); maximum_and_capacity(); sequence_and_snapshot();
        malformed_sequences(); rejection_boundaries(); arguments_and_disabled();
        std::cout << "PASS: 7 minimal identification test groups; pinned fields, no real identity or CarPlay advertisement.\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}
