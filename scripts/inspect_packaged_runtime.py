"""Read-only audit of the seven ZIP members in the pinned installation ISO.

Reads/decompresses every ZIP member in memory with size and CRC checks. Does not
extract files, execute vendor content, recurse into opaque formats, or establish
what is installed on the owner's unit. Host tar is used only on the pinned ISO.
"""
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import stat
import struct
import subprocess
import zipfile

from inspect_ncm_lifecycle import ISO, ISO_SHA256, TAR

PREFIX = "usr/share/MMC_PROG_DATA/"
ARCHIVES = {
    "usr/bin/nav/NNG_SyncTool/content/global_cfg/global_cfg.zip":
        (8091235, "1d971b7f7df9508b905fbf60fabe49c915d6ac8539e482c311341be7066f9a2c"),
    PREFIX + "bin/nav/content/global_cfg/global_cfg.zip":
        (8091235, "1d971b7f7df9508b905fbf60fabe49c915d6ac8539e482c311341be7066f9a2c"),
    PREFIX + "nav/NNG/data.zip":
        (16531045, "fbcef5fa20df38b63293f86ce0f32129ad859652894df867c74b8a786fa98dfe"),
    PREFIX + "nav/NNG/skin/skin_opennav_toyota_cy13_eu_blue_high.zip":
        (1010394, "e3904d174d2080b2e434366a0bd9577544201b0bf30dd5e1ceb1af35a0b8b90c"),
    PREFIX + "nav/NNG/skin/skin_opennav_toyota_cy13_eu_blue.zip":
        (1187574, "91c366548eb0e43e5c734e5549ecc84194f7199e0fa33c7af7ba6d57a2be4da7"),
    PREFIX + "nav/NNG/ux/junctionview.zip":
        (20264, "8835401a7fad03366f68b235000c0ac8ea12d32df6ed07a36669d82a9da9702c"),
    PREFIX + "nav/NNG/ux/opennav_toyota.zip":
        (312108, "65564014edb05243ba919a2c51a32b00b2a2bb18166c9ccfb699662b6cb9628f"),
}
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_MEMBER = 8 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
NAME_PATTERN = re.compile(r"io-pkt|devnp-|lsm-|libsocket|netinet|ipv6|tcpip|qcc|neutrino\.h|crt[1in]\.o", re.I)
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z")
MARKERS = (b"io-pkt-v6-hc", b"inet6domain", b"ip6_input", b"QNX_TARGET",
           b"gcc_ntoarmv7le", b"sys/neutrino.h")


def safe_name(name):
    parts = name.rstrip("/").split("/")
    if (not name or "\\" in name or ":" in name or "\0" in name or
            any(ord(c) < 32 for c in name) or any(p in ("", ".", "..") for p in parts)):
        raise ValueError("Noncanonical archive member name")
    return name


def inspect_zip(data):
    """Complete member reads, but signature/marker evidence is not format proof."""
    if not 0 < len(data) <= MAX_ARCHIVE:
        raise ValueError("Archive byte bound")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if not 0 < len(entries) <= MAX_ENTRIES:
            raise ValueError("Archive entry bound")
        seen, total = set(), 0
        for entry in entries:
            name = safe_name(entry.filename)
            if name in seen:
                raise ValueError("Duplicate archive member")
            seen.add(name)
            if entry.flag_bits & 1:
                raise ValueError("Encrypted archive member")
            if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError("Unsupported compression method")
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("Nonregular archive member")
            if not 0 <= entry.file_size <= MAX_MEMBER:
                raise ValueError("Member byte bound")
            total += entry.file_size
            if total > MAX_TOTAL:
                raise ValueError("Total expanded byte bound")
            if entry.is_dir() and entry.file_size:
                raise ValueError("Directory has payload")
        inventory, names, binaries, nested, markers = [], [], [], [], []
        extensions, methods = {}, {}
        files = 0
        for entry in entries:
            # Reading to EOF makes zipfile verify the uncompressed CRC. The
            # central-directory bounds above apply before decompression begins.
            with archive.open(entry) as stream:
                payload = stream.read(MAX_MEMBER + 1)
                if len(payload) != entry.file_size or stream.read(1):
                    raise ValueError("Expanded size mismatch")
            name = entry.filename
            methods[str(entry.compress_type)] = methods.get(str(entry.compress_type), 0) + 1
            if not entry.is_dir():
                files += 1
                suffix = PurePosixPath(name).suffix.lower() or "<none>"
                extensions[suffix] = extensions.get(suffix, 0) + 1
            inventory.append([name, entry.file_size, entry.compress_size, entry.CRC,
                              hashlib.sha256(payload).hexdigest()])
            if NAME_PATTERN.search(name):
                names.append(name)
            # Include embedded ELF magic so changing a filename alone cannot
            # hide an ELF from this audit; a hit still needs ELF validation.
            if b"\x7fELF" in payload or payload.startswith(b"MZ"):
                evidence = dict(member=name, bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
                                elf_magic_offset=payload.find(b"\x7fELF"))
                if payload.startswith(b"MZ") and len(payload) >= 64:
                    pe = struct.unpack_from("<I", payload, 60)[0]
                    if 64 <= pe <= len(payload) - 24 and payload[pe:pe + 4] == b"PE\0\0":
                        evidence["pe_machine"] = hex(struct.unpack_from("<H", payload, pe + 4)[0])
                binaries.append(evidence)
            signatures = (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"BZh",
                          b"\xfd7zXZ\0", b"7z\xbc\xaf\x27\x1c")
            if (not entry.is_dir() and
                    (name.lower().endswith(ARCHIVE_SUFFIXES) or payload.startswith(signatures) or
                     payload[257:262] == b"ustar")):
                nested.append(name)
            hits = [m.decode("ascii") for m in MARKERS if m in payload]
            if hits:
                markers.append(dict(member=name, markers=hits))
        encoded = json.dumps(sorted(inventory), ensure_ascii=True, separators=(",", ":")).encode("ascii")
        return dict(entries=len(entries), files=files, directories=len(entries) - files,
                    expanded_bytes=total, compression_methods=methods, extensions=extensions,
                    inventory_sha256=hashlib.sha256(encoded).hexdigest(),
                    network_or_sdk_names=names, binary_signature_members=binaries,
                    nested_archive_candidates=nested, runtime_marker_members=markers,
                    all_members_crc_checked=True)


def inspect(iso=ISO, tar=TAR):
    with iso.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != ISO_SHA256:
        raise ValueError("Not the pinned installation ISO")
    listing = subprocess.run([str(tar), "-tf", str(iso)], capture_output=True,
                             timeout=20, check=True).stdout
    if not 0 < len(listing) <= 4 * 1024 * 1024:
        raise ValueError("ISO listing byte bound")
    names = listing.decode("utf-8", errors="strict").splitlines()
    archives = [name for name in names if name.lower().endswith(ARCHIVE_SUFFIXES)]
    if len(names) != 842 or len(archives) != len(ARCHIVES) or set(archives) != set(ARCHIVES):
        raise ValueError("Outer archive inventory changed")
    results = {}
    for name, (size, expected) in ARCHIVES.items():
        data = subprocess.run([str(tar), "-xOf", str(iso), name], capture_output=True,
                              timeout=20, check=True).stdout
        if len(data) != size or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Not the pinned nested archive: " + name)
        results[name] = dict(bytes=size, sha256=expected, **inspect_zip(data))
    return dict(iso_sha256=digest, outer_entries=len(names), archives=results,
                target_runtime_or_sdk_supplied=False,
                limits=["Seven named ZIPs fully CRC-read; no extraction or vendor execution",
                        "Signature and selected marker search, not an audit of opaque/custom encodings",
                        "Does not re-audit all outer files or the installed 6.9.0WL unit"])


if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2))
