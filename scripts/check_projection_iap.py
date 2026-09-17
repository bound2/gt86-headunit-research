"""Independent PyCA wire producer for the receive-only iAP DataStream owner.

Synthetic packages, not a handset capture or a USB/iAP link implementation.
Uses the existing pinned build/pair-reference environment. No files/devices written.
"""
from pathlib import Path
import struct
import subprocess
import sys

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

COMM = 0x636F6D6D
LIMIT = 4 * 1024 * 1024


def package(body: bytes, kind: int = COMM) -> bytes:
    header = bytearray((i * 7 + 3) & 255 for i in range(32))
    struct.pack_into(">I", header, 0, len(body) + 32)
    struct.pack_into(">I", header, 16, kind)
    return bytes(header) + body


def records(plain: bytes, sizes: tuple[int, ...]) -> bytes:
    if not sizes or not any(sizes) or any(not 0 <= n <= 16384 for n in sizes):
        raise ValueError("Fixture record sizes must make bounded progress")
    cipher = ChaCha20Poly1305(bytes(range(32)))
    wire = bytearray()
    offset = counter = 0
    while offset < len(plain):
        size = min(sizes[counter % len(sizes)], len(plain) - offset)
        if not 0 <= size <= 16384:
            raise ValueError("Invalid fixture record size")
        prefix = struct.pack("<H", size)
        nonce = b"\0" * 4 + struct.pack("<Q", counter)
        wire += prefix + cipher.encrypt(nonce, plain[offset:offset + size], prefix)
        counter += 1
        offset += size
    return bytes(wire)


def check(executable: Path) -> None:
    if cryptography.__version__ != "50.0.1":
        raise RuntimeError("Use cryptography 50.0.1 from build/pair-reference")
    failure = subprocess.run([str(executable.resolve()), "--failure-test"], capture_output=True, timeout=10)
    if failure.returncode != 1 or failure.stdout or not failure.stderr.startswith(b"CHECK failed: false at "):
        raise RuntimeError("Assertion-reporting failure path is broken")
    total = cases = 0
    payloads = [b"", b"\x40\x40", bytes(range(251)), bytes(range(256)) * 256]
    accepted = [package(p) for p in payloads]
    ignored = package(b"not iAP", 0x64617461)
    plain = ignored + b"".join(p + ignored for p in accepted)
    # Exercise arbitrary encrypted-record boundaries across the package header,
    # body and following package, including zero-length authenticated records.
    for sizes in ((1,), (7, 0, 11), (31, 32, 33), (16384,), (3, 0, 16384, 1)):
        wire = records(plain, sizes)
        run = subprocess.run([str(executable.resolve()), "--wire-stdin"], input=wire,
                             capture_output=True, timeout=60)
        if run.returncode or run.stdout != b"".join(accepted):
            raise RuntimeError(f"Independent wire mismatch {sizes}: {run.stderr!r}")
        cases += 1
        total += sum(map(len, payloads))
        print(f"PASS record sizes={sizes}: {len(accepted)} exact headers/bodies, unknown packages skipped")
    largest = bytes(range(256)) * ((LIMIT - 32) // 256) + bytes(range((LIMIT - 32) % 256))
    run = subprocess.run([str(executable.resolve()), "--wire-stdin"], input=records(package(largest), (16384,)),
                         capture_output=True, timeout=60)
    if run.returncode or run.stdout != package(largest):
        raise RuntimeError(f"Independent maximum package mismatch: {run.stderr!r}")
    cases += 1
    total += len(largest)
    # Neither tag failure nor encrypted-length tampering may expose a package.
    for index in (0, 2, -1):
        corrupt = bytearray(records(package(b"private"), (16384,)))
        corrupt[index] ^= 1
        run = subprocess.run([str(executable.resolve()), "--wire-stdin"], input=corrupt,
                             capture_output=True, timeout=10)
        if not run.returncode or run.stdout:
            raise RuntimeError("Corrupted input was accepted or exposed plaintext")
    print(f"PASS: {cases} independent wire cases / {total} delivered body bytes; 3 tamper cases rejected")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_projection_iap.py TEST_EXE")
    check(Path(sys.argv[1]))
