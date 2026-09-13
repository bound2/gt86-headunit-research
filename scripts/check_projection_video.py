"""Real H.264 over independently encrypted synthetic screen records.

No sockets/phone/firmware. Public input stays in the ignored OpenH264 checkout.
Uses pinned-version PyCA from build/pair-reference; feeds bytes through stdin.
Pixel goldens were independently checked with native FFmpeg in Step 87.
"""
from pathlib import Path
import hashlib
import re
import struct
import subprocess
import sys

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from check_projection_h264 import PINS


def first_mb(nal: bytes) -> int:
    rbsp = nal[1:].replace(b"\x00\x00\x03", b"\x00\x00")
    bits = "".join(f"{b:08b}" for b in rbsp[:16])
    prefix = bits.find("1")
    if prefix < 0 or prefix > 30 or len(bits) < 2 * prefix + 1:
        raise ValueError("bad fixture slice prefix")
    return int(bits[prefix:2 * prefix + 1], 2) - 1


def packet(opcode: int, body: bytes, counter: int | None = None) -> bytes:
    header = bytearray(128)
    for i in range(5, 128):
        header[i] = (i * 3) & 255
    struct.pack_into("<I", header, 0, len(body) + (16 if counter is not None else 0))
    header[4] = opcode
    if counter is not None:
        nonce = b"\0" * 4 + struct.pack("<Q", counter)
        body = ChaCha20Poly1305(bytes(range(32))).encrypt(nonce, body, bytes(header))
    return bytes(header) + body


def stream(data: bytes, length_size: int) -> tuple[bytes, int]:
    nals = re.split(b"\x00\x00\x00?\x01", data)
    if nals.pop(0):
        raise ValueError("fixture is not Annex B")
    params = []
    while nals and nals[0][0] & 31 in (7, 8):
        params.append(nals.pop(0))
    sps = [p for p in params if p[0] & 31 == 7]
    pps = [p for p in params if p[0] & 31 == 8]
    if not sps or not pps:
        raise ValueError("missing initial fixture configuration")
    config = bytes([1, *sps[0][1:4], 0xfc | (length_size - 1), 0xe0 | len(sps)])
    for p in sps:
        config += struct.pack(">H", len(p)) + p
    config += bytes([len(pps)])
    for p in pps:
        config += struct.pack(">H", len(p)) + p
    records = [packet(1, config)]
    units = []
    current = []
    for nal in nals:
        kind = nal[0] & 31
        if current and ((kind in (1, 5) and first_mb(nal) == 0) or kind in (6, 7, 8, 9)):
            units.append(current)
            current = []
        current.append(nal)
    if current:
        units.append(current)
    largest = 0
    for counter, unit in enumerate(units):
        plain = b"".join(len(n).to_bytes(length_size, "big") + n for n in unit)
        largest = max(largest, len(plain))
        records.append(packet(0, plain, counter))
    return b"".join(records), largest


GOLDENS = {
    "Static.264": (10, 152, 100, "91dd4a7a796805b2cd015cae8fd630d96c663f42"),
    "test_qcif_cabac.264": (30, 176, 144, "587d1d05943f3cd416bf69469975fdee05361e69"),
    "test_scalinglist_jm.264": (5, 320, 192, "f690a3af2896a53360215fb5d35016bfd41499b3"),
    "Adobe_PDF_sample_a_1024x768_50Frms.264": (50, 1024, 768, "9aa9a4d9598eb3e1093311826844f37c43e4c521"),
    "test_cif_P_CABAC_slice.264": (300, 352, 288, "521bbd0ba2422369b724c7054545cf107a56f959"),
}


def check(executable: Path, root: Path) -> None:
    if cryptography.__version__ != "50.0.1":
        raise RuntimeError("Use cryptography 50.0.1 from the reference environment")
    total = 0
    for name, golden in GOLDENS.items():
        data = (root / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != PINS[name]:
            raise RuntimeError(f"input fixture mismatch: {name}")
        widths = (4,) if name.startswith("Adobe") else (2, 4)
        for width in widths:
            wire, largest = stream(data, width)
            run = subprocess.run([str(executable.resolve()), "--wire-stdin"], input=wire,
                                 capture_output=True, timeout=60)
            if run.returncode:
                raise RuntimeError(run.stderr.decode("utf-8", errors="replace"))
            match = re.fullmatch(rb"wire frames=(\d+) size=(\d+)x(\d+) sha1=([0-9a-f]{40})\s*", run.stdout)
            if not match:
                raise RuntimeError(f"unexpected decoder response: {run.stdout!r}")
            actual = (*map(int, match.group(1, 2, 3)), match.group(4).decode())
            if actual != golden:
                raise RuntimeError(f"wire/decoder disagreement: {name}: {actual} != {golden}")
            total += golden[0]
            print(f"PASS PyCA -> fragmented screen records -> H264: {name}, length={width}, "
                  f"{golden[0]} frames, largest AU={largest}")
    print(f"PASS: {total} decrypted/decoded frames; wire framing is synthetic, not captured from a phone.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_projection_video.py TEST_EXE OPENH264_RES_DIRECTORY")
    check(Path(sys.argv[1]), Path(sys.argv[2]))
