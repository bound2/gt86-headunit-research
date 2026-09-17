"""Offline factory ELF profile and optional pinned, in-memory candidate comparison.

--fetch-candidate reads three public reference files into memory, never executes
or installs them, and checks length, Git blob ID and SHA-256 before ELF parsing.
Symbol-name comparison is not ABI or runtime compatibility verification.
"""
import argparse
import hashlib
import json
import re
import struct
from urllib.request import urlopen

from inspect_ipod_auth import ROOT

COMMIT = "baa45224f18ae6b13c2e9c77c6663bb8181eb6a1"
URL = "https://raw.githubusercontent.com/luka-dev/qnx65-armv7-toolchain/" + COMMIT + "/"
FACTORY = {
    "libc": ("image-8/lib/libc.so.3", "4d500f6b228e180f937ffa139473779b2da63bb967dea02ccb937b8575df9b26"),
    "socket": ("image-120000/lib/libsocket.so.3", "9d3797040bc26cf2f0ec76e882dbbcb1886f5aff907c84ad3242d56002081b7b"),
    "stack": ("image-380000/sbin/io-pkt-v4-hc", "f0f0624759c6d06e77dcd459dcd2d95bb3577d0f94730a9c031382bdab27b13b"),
    "ncm": ("image-380000/lib/dll/devnp-ncm.so", "bdabe7a1b29cd4070c03e0cb5c98403c632a0147c8d5da1686d2b41b834ff996"),
}
CANDIDATE = {
    "libc": ("sdp/target/qnx6/armle-v7/lib/libc.so.3", 667874,
             "c7e7b5aa9dd3ef8580d1a215c013cbe252ca80e7", "3ea952170deb54ee7916ff8a6d35d0cd056af3b27c13f92f319f069562d40e00"),
    "socket": ("sdp/target/qnx6/armle-v7/lib/libsocket.so.3", 213477,
               "0e2b7c1a493f32d68ef193e6b06b398043fb70a6", "965e36a0977935b315a697df269aaa7d6a22ec951ec3992d2097afccfb8aac74"),
    "stack": ("sdp/target/qnx6/armle-v7/sbin/io-pkt-v6-hc", 1366586,
              "8f073dd7f03e160cd03b46efc77174d59158452d", "a51a2c4fd4aba6ddcaf8559dd734d1326d8bd102ef4388a307035375f5fca0f9"),
}


def profile(data):
    if not 52 <= len(data) <= 64 * 1024 * 1024 or data[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected bounded ELF32 little-endian input")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if machine != 40 or kind not in (2, 3):
        raise ValueError("Expected ARM executable or shared object")
    phoff = struct.unpack_from("<I", data, 28)[0]
    phsize, count = struct.unpack_from("<HH", data, 42)
    if phsize != 32 or not 1 <= count <= 32 or phoff + count * phsize > len(data):
        raise ValueError("Program header bounds")
    segments = [struct.unpack_from("<8I", data, phoff + i * 32) for i in range(count)]
    for _, offset, _, _, size, _, _, _ in segments:
        if offset + size > len(data):
            raise ValueError("Segment file bounds")

    def offset(va, size):
        for tag, start, base, _, length, _, _, _ in segments:
            if tag == 1 and base <= va and va + size <= base + length:
                return start + va - base
        raise ValueError("Virtual range outside file-backed load segments")

    dynamic_segments = [s for s in segments if s[0] == 2]
    if len(dynamic_segments) != 1 or dynamic_segments[0][4] % 8:
        raise ValueError("Expected one aligned dynamic segment")
    _, start, _, _, length, _, _, _ = dynamic_segments[0]
    dynamic, needed, terminated = {}, [], False
    for pos in range(start, start + length, 8):
        tag, value = struct.unpack_from("<II", data, pos)
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            needed.append(value)
        elif tag in (4, 5, 6, 10, 11):
            if tag in dynamic:
                raise ValueError("Duplicate selected dynamic tag")
            dynamic[tag] = value
    if not terminated or set(dynamic) != {4, 5, 6, 10, 11} or dynamic[11] != 16:
        raise ValueError("Expected terminated SysV ELF symbol metadata")
    symbol_count = struct.unpack_from("<I", data, offset(dynamic[4], 8) + 4)[0]
    if not 1 <= symbol_count <= 250000 or not 1 <= dynamic[10] <= 16 * 1024 * 1024:
        raise ValueError("Symbol/string table bounds")
    strings_start = offset(dynamic[5], dynamic[10])
    strings = data[strings_start:strings_start + dynamic[10]]

    def string(index):
        if not 0 <= index < len(strings):
            raise ValueError("String index bounds")
        end = strings.find(b"\0", index)
        if end < 0:
            raise ValueError("Unterminated dynamic string")
        return strings[index:end].decode("ascii")

    table = offset(dynamic[6], symbol_count * 16)
    imports, weak, exports = set(), set(), set()
    for i in range(symbol_count):
        name, _, _, info, other, section = struct.unpack_from("<IIIBBH", data, table + i * 16)
        symbol = string(name)
        if not symbol or info >> 4 not in (1, 2):
            continue
        if not section:
            (weak if info >> 4 == 2 else imports).add(symbol)
        elif (other & 3) in (0, 3):
            exports.add(symbol)
    interpreters = []
    for tag, start, _, _, length, _, _, _ in segments:
        if tag == 3:
            raw = data[start:start + length]
            if not raw.endswith(b"\0"):
                raise ValueError("Unterminated interpreter")
            interpreters.append(raw[:-1].decode("ascii"))
    metadata = [v.decode("ascii") for v in re.findall(rb"[ -~]{8,}", data)
                if v.startswith((b"NAME=", b"VERSION=", b"DATE=", b"TAGID="))]
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                elf_type=kind, machine=machine, flags=hex(struct.unpack_from("<I", data, 36)[0]),
                interpreters=interpreters, needed=[string(i) for i in needed], metadata=metadata,
                imports=sorted(imports), weak_imports=sorted(weak), exports=sorted(exports))


def fetch(key):
    path, size, blob, digest = CANDIDATE[key]
    with urlopen(URL + path, timeout=20) as response:
        data = response.read(size + 1)
    if (len(data) != size or hashlib.sha256(data).hexdigest() != digest or
            hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + data).hexdigest() != blob):
        raise ValueError("Not the pinned runtime candidate: " + key)
    return data


def inspect(fetch_candidate=False):
    raw = {key: (ROOT / "extracted/qnx-system-v3" / path).read_bytes() for key, (path, _) in FACTORY.items()}
    for key, data in raw.items():
        if hashlib.sha256(data).hexdigest() != FACTORY[key][1]:
            raise ValueError("Not the pinned factory runtime: " + key)
    factory = {key: profile(data) for key, data in raw.items()}
    result = dict(factory=factory, candidate_commit=COMMIT,
                  abi_compatibility_verified=False, native_executable_built=False)
    if fetch_candidate:
        candidate = {key: profile(fetch(key)) for key in CANDIDATE}
        required = set(factory["ncm"]["imports"])
        factory_stack = set(factory["stack"]["exports"])
        result.update(candidate=candidate, ncm_stack_imports_missing_in_candidate=sorted(
            (required & factory_stack) - set(candidate["stack"]["exports"])))
    # Keep selected evidence readable; the complete sets above are used for the
    # comparison but are not a substitute for structures, symbol versions, or
    # loader/runtime testing.
    for group in (factory, result.get("candidate", {})):
        for item in group.values():
            item["ipv6_domain_exported"] = "inet6domain" in item["exports"]
            for field in ("imports", "weak_imports", "exports"):
                item[field + "_count"] = len(item.pop(field))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch-candidate", action="store_true", help="read pinned public candidate files into memory")
    print(json.dumps(inspect(parser.parse_args().fetch_candidate), indent=2))
