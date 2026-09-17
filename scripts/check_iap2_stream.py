# SPDX-License-Identifier: GPL-3.0-only
"""Independently encode the explicit stream-profile wire sample using Python.

No phone/helper/USB access, receiver changes or third-party dependencies.
"""
from pathlib import Path
import struct
import subprocess
import sys


def frame(control: int, sequence: int, acknowledgement: int, session: int, payload: bytes | None = None) -> bytes:
    header = struct.pack(">HHBBBB", 0xFF5A, 9 if payload is None else len(payload) + 10,
                         control, sequence, acknowledgement, session)
    wire = header + bytes([-sum(header) & 255])
    return wire if payload is None else wire + payload + bytes([-sum(payload) & 255])


def check(executable: Path) -> None:
    lsp = struct.pack(">BBHHHBB", 1, 4, 1024, 0, 0, 0, 0) + bytes([10, 0, 2])
    expected = {"lsp": lsp, "marker": bytes.fromhex("ff550200ee10"),
                "syn": frame(0x80, 99, 0, 0, lsp), "ack": frame(0x40, 99, 42, 0),
                "data": frame(0x40, 100, 42, 10, bytes.fromhex("40400006a100")), "no_retry": b""}
    run = subprocess.run([str(executable.resolve()), "--stream-vectors"], check=True,
                         capture_output=True, text=True, timeout=10)
    lines = run.stdout.splitlines()
    if len(lines) != len(expected):
        raise ValueError("Unexpected stream vector count")
    actual = {key: bytes.fromhex(value) for key, value in (line.split("=", 1) for line in lines)}
    if actual != expected:
        raise ValueError("Independent stream-profile wire mismatch")
    print("PASS: 6 independent stream-profile values, including exact LSP/checksums and no automatic retry")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_iap2_stream.py IAP2_LINK_TESTS_EXE")
    check(Path(sys.argv[1]))
