// SPDX-License-Identifier: GPL-3.0-or-later
// Pinned public CSM vectors and synthetic metadata; never hardware/network I/O.
#include "iap2_carplay.h"
#include "iap2_power.h"
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
static void check(bool ok, const char *why) { if (!ok) throw std::runtime_error(why); }
static Bytes hex(const std::string& s) {
    check(s.size() % 2 == 0, "hex length"); Bytes bytes;
    for (size_t i = 0; i < s.size(); i += 2) bytes.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return bytes;
}
static iap2_carplay_text text(const char *s) { return {s, std::strlen(s)}; }
static std::string str(iap2_carplay_text s) { return s.data ? std::string(s.data, s.size) : ""; }
static Bytes tlv(uint16_t id, const Bytes& bytes) {
    Bytes out{static_cast<uint8_t>((bytes.size() + 4) >> 8), static_cast<uint8_t>(bytes.size() + 4),
              static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id)};
    out.insert(out.end(), bytes.begin(), bytes.end()); return out;
}
static void append(Bytes& out, const Bytes& in) { out.insert(out.end(), in.begin(), in.end()); }
static Bytes csm(uint16_t id, const Bytes& params = {}) {
    Bytes out{0x40, 0x40, static_cast<uint8_t>((params.size() + 6) >> 8), static_cast<uint8_t>(params.size() + 6),
              static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id)};
    append(out, params); return out;
}
static Bytes nul(const std::string& s) { Bytes b(s.begin(), s.end()); b.push_back(0); return b; }
template<class T, class Encoder> static Bytes encode(const T& value, Encoder encoder) {
    Bytes out(1026, 0xa5); size_t n = 999;
    check(encoder(&value, out.data() + 1, 1024, &n) == 0 && n <= 1024, "typed encode");
    check(out.front() == 0xa5 && out.back() == 0xa5 && out[n + 1] == 0xa5, "encoder canaries");
    return Bytes(out.begin() + 1, out.begin() + 1 + n);
}
template<class T, class Decoder> static void reject(const Bytes& bytes, Decoder decoder, int expected) {
    T target; std::memset(&target, 0xa5, sizeof target);
    std::array<uint8_t, sizeof(T)> before; std::memcpy(before.data(), &target, sizeof target);
    check(decoder(bytes.data(), bytes.size(), &target) == expected, "expected typed rejection");
    check(std::memcmp(before.data(), &target, sizeof target) == 0, "failed decode unchanged");
}
static iap2_carplay_wired_start profile() {
    iap2_carplay_wired_start v{}; v.address_count = 2;
    v.addresses[0] = text("10.0.0.1"); v.addresses[1] = text("169.254.5.5");
    v.has_port = 1; v.port = 5000; return v;
}
static void pinned_roundtrips(const Vectors& vectors) {
    iap2_carplay_transport_ids ids{};
    const auto& id_bytes = vectors.at("DeviceTransportIdentifierNotification");
    check(iap2_carplay_transport_ids_decode(id_bytes.data(), id_bytes.size(), &ids) == 0 &&
          str(ids.bluetooth) == "AA:BB:CC:DD:EE:FF" && str(ids.usb) == "usb-1", "pinned transport IDs");
    check(encode(ids, iap2_carplay_transport_ids_encode) == id_bytes, "ID roundtrip");
    const auto& update = vectors.at("WirelessCarPlayUpdate"); uint8_t available = 99, out[11]; size_t n;
    check(iap2_carplay_wireless_update_decode(update.data(), update.size(), &available) == 0 && available == 1 &&
          iap2_carplay_wireless_update_encode(available, out, sizeof out, &n) == 0 && Bytes(out, out + n) == update, "pinned update roundtrip");
    iap2_carplay_availability a{}; const auto& offer = vectors.at("CarPlayAvailability");
    check(iap2_carplay_availability_decode(offer.data(), offer.size(), &a) == 0 && a.wired.present &&
          a.wired.has_available && a.wired.available && str(a.wired.identifier) == "usbid" &&
          a.wireless.present && a.wireless.has_available && !a.wireless.available, "pinned availability");
    check(encode(a, iap2_carplay_availability_encode) == offer, "availability roundtrip");
    iap2_carplay_wired_start start{}; const auto& wired = vectors.at("CarPlayStartSession#wired");
    check(iap2_carplay_wired_start_decode(wired.data(), wired.size(), &start) == 0 && start.address_count == 2 &&
          str(start.addresses[0]) == "10.0.0.1" && str(start.addresses[1]) == "169.254.5.5" &&
          start.has_port && start.port == 5000, "split packed address list into two views");
    check(encode(start, iap2_carplay_wired_start_encode) == wired && encode(profile(), iap2_carplay_wired_start_encode) == wired, "wired golden bytes");
    reject<iap2_carplay_wired_start>(vectors.at("CarPlayStartSession#wireless"), iap2_carplay_wired_start_decode, IAP2_UNSUPPORTED);
}
static void presence_and_scalar_width() {
    iap2_carplay_wired_start empty{}, decoded{};
    check(encode(empty, iap2_carplay_wired_start_encode) == hex("4040000a430100040000"), "empty wired group matches upstream codec test");
    for (uint32_t port : {0u, 1u, 65535u, 65536u, UINT32_MAX}) {
        empty.has_port = 1; empty.port = port;
        const auto bytes = encode(empty, iap2_carplay_wired_start_encode);
        check(bytes.size() == 18 && iap2_carplay_wired_start_decode(bytes.data(), bytes.size(), &decoded) == 0 &&
              decoded.has_port && decoded.port == port, "codec preserves u32 port, not operational approval");
    }
    iap2_carplay_availability a{}, b{}; a.wired.present = 1;
    const auto bytes = encode(a, iap2_carplay_availability_encode);
    check(iap2_carplay_availability_decode(bytes.data(), bytes.size(), &b) == 0 && b.wired.present &&
          !b.wired.has_available && !b.wireless.present, "absent group and missing boolean are distinct");
}
static void text_and_address_rules() {
    for (Bytes invalid : {Bytes{}, Bytes{0}, Bytes{'x'}, Bytes{'x', 0, 'y', 0}, Bytes{'x', '\n', 0}, Bytes{0xc3, 0xa9, 0}}) {
        Bytes params = tlv(0, invalid); append(params, tlv(1, nul("usb")));
        reject<iap2_carplay_transport_ids>(csm(0x4e0e, params), iap2_carplay_transport_ids_decode, IAP2_INVALID);
    }
    for (Bytes list : {Bytes{}, Bytes{0}, Bytes{'a', 0, 0}, Bytes{'a', 0, 'b'}, Bytes{'a', '\n', 0}})
        reject<iap2_carplay_wired_start>(csm(0x4301, tlv(0, tlv(0, list))), iap2_carplay_wired_start_decode, IAP2_INVALID);
    auto v = profile(); v.addresses[0] = text("fe80::1234%usb0");
    const auto bytes = encode(v, iap2_carplay_wired_start_encode); iap2_carplay_wired_start decoded{};
    check(iap2_carplay_wired_start_decode(bytes.data(), bytes.size(), &decoded) == 0 && str(decoded.addresses[0]) == "fe80::1234%usb0", "opaque IPv6-like text preserved without network lookup");
}
static void duplicates_unknown_and_mixed() {
    const auto field = tlv(0, nul("bt")); Bytes params = field; append(params, field); append(params, tlv(1, nul("usb")));
    reject<iap2_carplay_transport_ids>(csm(0x4e0e, params), iap2_carplay_transport_ids_decode, IAP2_INVALID);
    reject<iap2_carplay_transport_ids>(csm(0x4e0e, tlv(2, nul("unknown"))), iap2_carplay_transport_ids_decode, IAP2_UNSUPPORTED);
    Bytes group = tlv(0, {1}); append(group, tlv(0, {0}));
    reject<iap2_carplay_availability>(csm(0x4300, tlv(0, group)), iap2_carplay_availability_decode, IAP2_INVALID);
    reject<iap2_carplay_availability>(csm(0x4300, tlv(0, tlv(2, {}))), iap2_carplay_availability_decode, IAP2_UNSUPPORTED);
    group = tlv(0, nul("a")); append(group, tlv(0, nul("b")));
    reject<iap2_carplay_wired_start>(csm(0x4301, tlv(0, group)), iap2_carplay_wired_start_decode, IAP2_INVALID);
    group = tlv(0, nul("a")); append(group, tlv(7, {}));
    reject<iap2_carplay_wired_start>(csm(0x4301, tlv(0, group)), iap2_carplay_wired_start_decode, IAP2_UNSUPPORTED);
    params = tlv(0, {}); append(params, tlv(1, {}));
    reject<iap2_carplay_wired_start>(csm(0x4301, params), iap2_carplay_wired_start_decode, IAP2_UNSUPPORTED);
    params = tlv(0, {}); append(params, tlv(0, {}));
    reject<iap2_carplay_wired_start>(csm(0x4301, params), iap2_carplay_wired_start_decode, IAP2_INVALID);
    reject<iap2_carplay_wired_start>(csm(0x4301, tlv(6, {})), iap2_carplay_wired_start_decode, IAP2_UNSUPPORTED);
    Bytes update = tlv(0, {1}); append(update, tlv(0, {0}));
    reject<uint8_t>(csm(0x4e0d, update), iap2_carplay_wireless_update_decode, IAP2_INVALID);
    update = tlv(0, {1}); append(update, tlv(4, {}));
    reject<uint8_t>(csm(0x4e0d, update), iap2_carplay_wireless_update_decode, IAP2_UNSUPPORTED);
}
static void malformed_scalars_and_groups() {
    for (const auto& value : {Bytes{}, Bytes{2}, Bytes{1, 0}}) {
        reject<uint8_t>(csm(0x4e0d, tlv(0, value)), iap2_carplay_wireless_update_decode, IAP2_INVALID);
        reject<iap2_carplay_availability>(csm(0x4300, tlv(0, tlv(0, value))), iap2_carplay_availability_decode, IAP2_INVALID);
    }
    for (Bytes port : {Bytes{}, Bytes{0}, Bytes{0, 1}, Bytes{0, 0, 1}, Bytes{0, 0, 0, 0, 1}}) {
        Bytes params = tlv(0, {}); append(params, tlv(2, port));
        reject<iap2_carplay_wired_start>(csm(0x4301, params), iap2_carplay_wired_start_decode, IAP2_INVALID);
    }
    for (Bytes group : {Bytes{0}, Bytes{0, 4, 0}, Bytes{0, 3, 0, 0}, Bytes{0, 8, 0, 0, 1}}) {
        reject<iap2_carplay_wired_start>(csm(0x4301, tlv(0, group)), iap2_carplay_wired_start_decode, IAP2_INVALID);
        reject<iap2_carplay_availability>(csm(0x4300, tlv(0, group)), iap2_carplay_availability_decode, IAP2_INVALID);
    }
    reject<iap2_carplay_wired_start>(csm(0x4301), iap2_carplay_wired_start_decode, IAP2_INVALID);
    reject<iap2_carplay_transport_ids>(csm(0x4e0e), iap2_carplay_transport_ids_decode, IAP2_INVALID);
    reject<uint8_t>(csm(0x4e0d), iap2_carplay_wireless_update_decode, IAP2_INVALID);
}
static void exact_frame_boundaries(const Vectors& vectors) {
    const auto exercise = []<class T>(const Bytes& bytes, auto decoder, T) {
        for (size_t n = 0; n < bytes.size(); ++n) {
            const Bytes partial(bytes.begin(), bytes.begin() + n);
            // Empty vector's data pointer may be null; either argument/header rejection is valid.
            T value{}; check(decoder(partial.data(), partial.size(), &value) < 0, "all truncated messages rejected");
        }
        auto trailing = bytes; trailing.push_back(0);
        reject<T>(trailing, decoder, IAP2_INVALID);
        auto wrong = bytes; wrong[4] ^= 1; reject<T>(wrong, decoder, IAP2_UNSUPPORTED);
        wrong = bytes; wrong[0] ^= 1; reject<T>(wrong, decoder, IAP2_INVALID);
        wrong = bytes; wrong.resize(1025); reject<T>(wrong, decoder, IAP2_NO_SPACE);
    };
    exercise(vectors.at("DeviceTransportIdentifierNotification"), iap2_carplay_transport_ids_decode, iap2_carplay_transport_ids{});
    exercise(vectors.at("WirelessCarPlayUpdate"), iap2_carplay_wireless_update_decode, uint8_t{});
    exercise(vectors.at("CarPlayAvailability"), iap2_carplay_availability_decode, iap2_carplay_availability{});
    exercise(vectors.at("CarPlayStartSession#wired"), iap2_carplay_wired_start_decode, iap2_carplay_wired_start{});
}
static void maximum_and_capacity() {
    const std::string address(63, 'a'), identity(127, 'x'); auto v = profile(); v.address_count = 4;
    for (auto& a : v.addresses) a = {address.data(), address.size()};
    v.device_identifier = v.public_key = v.source_version = {identity.data(), identity.size()};
    const auto bytes = encode(v, iap2_carplay_wired_start_encode);
    check(bytes.size() == 674, "maximum local wired profile wire size");
    iap2_carplay_wired_start decoded{};
    check(iap2_carplay_wired_start_decode(bytes.data(), bytes.size(), &decoded) == 0 && decoded.address_count == 4, "maximum decode");
    for (size_t capacity = 0; capacity <= bytes.size(); ++capacity) {
        Bytes out(1026, 0xa5); size_t n = 777;
        const auto status = iap2_carplay_wired_start_encode(&v, out.data() + 1, capacity, &n);
        if (capacity < bytes.size()) check(status == IAP2_NO_SPACE && !n && out == Bytes(1026, 0xa5), "capacity transaction");
        else check(status == 0 && n == bytes.size() && out.front() == 0xa5 && out[n + 1] == 0xa5, "exact capacity");
    }
    Bytes list; for (unsigned i = 0; i < 5; ++i) append(list, nul("a"));
    reject<iap2_carplay_wired_start>(csm(0x4301, tlv(0, tlv(0, list))), iap2_carplay_wired_start_decode, IAP2_NO_SPACE);
    reject<iap2_carplay_wired_start>(csm(0x4301, tlv(0, tlv(0, nul(std::string(64, 'a'))))), iap2_carplay_wired_start_decode, IAP2_NO_SPACE);
    Bytes params = tlv(0, nul(identity + 'x')); append(params, tlv(1, nul("usb")));
    reject<iap2_carplay_transport_ids>(csm(0x4e0e, params), iap2_carplay_transport_ids_decode, IAP2_NO_SPACE);
}
static void invalid_encoder_inputs() {
    for (unsigned i = 0; i < 10; ++i) {
        auto value = profile(); const std::string long_text(128, 'x');
        if (i == 0) value.address_count = 5;
        if (i == 1) value.addresses[0] = {nullptr, 1};
        if (i == 2) value.addresses[0] = {"", 0};
        if (i == 3) value.addresses[0] = {"a\0b", 3};
        if (i == 4) value.has_port = 2;
        if (i == 5) value.has_port = 0;
        if (i == 6) value.device_identifier = {long_text.data(), long_text.size()};
        if (i == 7) value.public_key = {nullptr, 1};
        if (i == 8) value.source_version = {"", 0};
        if (i == 9) value.addresses[0] = {long_text.data(), 64};
        Bytes out(1024, 0xa5); size_t n = 777;
        check(iap2_carplay_wired_start_encode(&value, out.data(), out.size(), &n) == IAP2_ARGUMENT && !n && out == Bytes(1024, 0xa5), "invalid wired encode transaction");
    }
    for (unsigned i = 0; i < 4; ++i) {
        iap2_carplay_availability a{};
        if (i == 0) a.wired.present = 2;
        if (i == 1) a.wired.has_available = 1;
        if (i == 2) a.wired.available = 1;
        if (i == 3) a.wired.identifier = text("unexpected");
        Bytes out(1024, 0xa5); size_t n;
        check(iap2_carplay_availability_encode(&a, out.data(), out.size(), &n) == IAP2_ARGUMENT && !n && out == Bytes(1024, 0xa5), "invalid presence transaction");
    }
    uint8_t out[11]; size_t n;
    check(iap2_carplay_wireless_update_encode(2, out, sizeof out, &n) == IAP2_ARGUMENT && !n, "invalid wireless status encode");
}
static void borrowed_views_and_arguments(const Vectors& vectors) {
    const auto& bytes = vectors.at("CarPlayStartSession#wired"); iap2_carplay_wired_start v{};
    check(iap2_carplay_wired_start_decode(bytes.data(), bytes.size(), &v) == 0, "view decode");
    for (size_t i = 0; i < v.address_count; ++i) {
        const auto *p = reinterpret_cast<const uint8_t *>(v.addresses[i].data);
        check(p >= bytes.data() && p + v.addresses[i].size < bytes.data() + bytes.size(), "views point inside input");
    }
    uint8_t out[1024]; size_t n = 777;
    check(iap2_carplay_wired_start_encode(nullptr, out, sizeof out, &n) == IAP2_ARGUMENT && !n, "null metadata");
    check(iap2_carplay_wired_start_encode(&v, nullptr, sizeof out, &n) == IAP2_ARGUMENT && !n, "null output");
    check(iap2_carplay_wired_start_encode(&v, out, sizeof out, nullptr) == IAP2_ARGUMENT, "null written");
    check(iap2_carplay_wired_start_decode(nullptr, 1, &v) == IAP2_ARGUMENT &&
          iap2_carplay_wired_start_decode(bytes.data(), bytes.size(), nullptr) == IAP2_ARGUMENT, "null decode");
    check(iap2_carplay_reply_wired_start(nullptr, &v, 0) == IAP2_ARGUMENT, "null endpoint helper");
}
static void power_source_fields(const Vectors& vectors) {
    const auto& golden = vectors.at("PowerSourceUpdate"); iap2_power_source decoded{};
    check(iap2_power_source_decode(golden.data(), golden.size(), &decoded) == 0 &&
          decoded.has_available_current && decoded.available_current_ma == 2400 && decoded.has_should_charge && decoded.should_charge,
          "pinned power source fields, fixture rating is not a hardware default");
    check(encode(decoded, iap2_power_source_encode) == golden, "exact pinned power-source roundtrip");
    for (unsigned mask = 0; mask < 4; ++mask) for (uint16_t current : {0, 1, 65535}) for (uint8_t charge : {0, 1}) {
        iap2_power_source value{static_cast<uint8_t>(mask & 1), static_cast<uint16_t>((mask & 1) ? current : 0),
            static_cast<uint8_t>((mask >> 1) & 1), static_cast<uint8_t>((mask & 2) ? charge : 0)};
        Bytes params;
        if (mask & 1) append(params, tlv(0, {static_cast<uint8_t>(current >> 8), static_cast<uint8_t>(current)}));
        if (mask & 2) append(params, tlv(1, {charge}));
        const auto bytes = encode(value, iap2_power_source_encode);
        check(bytes == csm(0xae03, params) && iap2_power_source_decode(bytes.data(), bytes.size(), &decoded) == 0 &&
              decoded.has_available_current == value.has_available_current && decoded.available_current_ma == value.available_current_ma &&
              decoded.has_should_charge == value.has_should_charge && decoded.should_charge == value.should_charge,
              "power optional presence and explicit zero values preserved");
    }
}
static void power_source_rejections(const Vectors& vectors) {
    for (const auto& bytes : {Bytes{}, Bytes{1}, Bytes{0, 1, 2}})
        reject<iap2_power_source>(csm(0xae03, tlv(0, bytes)), iap2_power_source_decode, IAP2_INVALID);
    for (const auto& bytes : {Bytes{}, Bytes{2}, Bytes{0, 1}})
        reject<iap2_power_source>(csm(0xae03, tlv(1, bytes)), iap2_power_source_decode, IAP2_INVALID);
    for (unsigned field = 0; field < 2; ++field) {
        const auto field_bytes = tlv(static_cast<uint16_t>(field), field ? Bytes{1} : Bytes{0, 1});
        auto params = field_bytes; append(params, field_bytes);
        reject<iap2_power_source>(csm(0xae03, params), iap2_power_source_decode, IAP2_INVALID);
    }
    reject<iap2_power_source>(csm(0xae03, tlv(2, {})), iap2_power_source_decode, IAP2_UNSUPPORTED);
    reject<iap2_power_source>(csm(0xae01), iap2_power_source_decode, IAP2_UNSUPPORTED);
    reject<iap2_power_source>(csm(0xae03, {0, 8, 0, 0, 1}), iap2_power_source_decode, IAP2_INVALID);
    const auto& golden = vectors.at("PowerSourceUpdate");
    for (size_t size = 0; size < golden.size(); ++size) {
        iap2_power_source value{1, 9, 1, 0}; std::array<uint8_t, sizeof value> before;
        std::memcpy(before.data(), &value, sizeof value);
        check(iap2_power_source_decode(golden.data(), size, &value) == IAP2_INVALID &&
              !std::memcmp(&value, before.data(), sizeof value), "every truncated power CSM rejected transactionally");
    }
    auto trailing = golden; trailing.push_back(0); reject<iap2_power_source>(trailing, iap2_power_source_decode, IAP2_INVALID);
    auto wrong = golden; wrong[0] = 0; reject<iap2_power_source>(wrong, iap2_power_source_decode, IAP2_INVALID);
    reject<iap2_power_source>(Bytes(1025), iap2_power_source_decode, IAP2_NO_SPACE);
}
static void power_source_output_bounds() {
    iap2_power_source value{1, 65535, 1, 0}; const auto expected = encode(value, iap2_power_source_encode);
    for (size_t capacity = 0; capacity <= 17; ++capacity) {
        Bytes output(19, 0xa5); size_t n = 999;
        const int status = iap2_power_source_encode(&value, output.data() + 1, capacity, &n);
        if (capacity < 17) check(status == IAP2_NO_SPACE && !n && output == Bytes(19, 0xa5), "power output capacity transaction");
        else check(status == 0 && n == 17 && output.front() == 0xa5 && output.back() == 0xa5 &&
                   Bytes(output.begin() + 1, output.end() - 1) == expected, "power exact output capacity");
    }
    for (unsigned variant = 0; variant < 5; ++variant) {
        auto invalid = value;
        if (variant == 0) invalid.has_available_current = 2;
        if (variant == 1) invalid.has_should_charge = 2;
        if (variant == 2) invalid.should_charge = 2;
        if (variant == 3) invalid.has_available_current = 0;
        if (variant == 4) { invalid.has_should_charge = 0; invalid.should_charge = 1; }
        Bytes output(17, 0xa5); size_t n = 999;
        check(iap2_power_source_encode(&invalid, output.data(), output.size(), &n) == IAP2_ARGUMENT && !n && output == Bytes(17, 0xa5),
              "power invalid metadata output transaction");
    }
    uint8_t out[17]; size_t n = 999;
    check(iap2_power_source_encode(nullptr, out, sizeof out, &n) == IAP2_ARGUMENT && !n &&
          iap2_power_source_encode(&value, nullptr, 17, &n) == IAP2_ARGUMENT &&
          iap2_power_source_encode(&value, out, 17, nullptr) == IAP2_ARGUMENT, "power encode null checks");
    check(iap2_power_source_decode(nullptr, 0, &value) == IAP2_ARGUMENT &&
          iap2_power_source_decode(expected.data(), expected.size(), nullptr) == IAP2_ARGUMENT &&
          iap2_power_source_notify(nullptr, &value, 0) == IAP2_ARGUMENT, "power decode/helper null checks");
}
int main(int argc, char **argv) {
    try {
        check(argc == 2, "provide pinned vectors path"); std::ifstream input(argv[1]); check(bool(input), "open vectors");
        Vectors vectors; std::string name, bytes; while (input >> name >> bytes) vectors.emplace(name, hex(bytes));
        check(vectors.size() == 33, "existing pinned vector set");
        pinned_roundtrips(vectors); presence_and_scalar_width(); text_and_address_rules(); duplicates_unknown_and_mixed();
        malformed_scalars_and_groups(); exact_frame_boundaries(vectors); maximum_and_capacity(); invalid_encoder_inputs();
        borrowed_views_and_arguments(vectors);
        power_source_fields(vectors); power_source_rejections(vectors); power_source_output_bounds();
        std::cout << "PASS: 12 bounded CarPlay/power CSM codec groups; five exact pinned roundtrips, no hardware/network I/O.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
