"""Independent FFmpeg VUI interpretation and native GDI sample-aspect readback.

Only locally generated SPS metadata and the pinned public Static.264 fixture.
No phone, display capture, vehicle, private credentials or presentation clock.
"""
from pathlib import Path
from fractions import Fraction
import hashlib
import io
import re
import struct
import subprocess
import sys

from check_projection_h264 import PINS
from check_projection_video_render import convert


def check(executable: Path, fixtures: Path) -> None:
    import av

    if av.__version__ != "18.1.0" or av.library_versions["libavcodec"] != (62, 28, 102):
        raise RuntimeError("Use pinned PyAV 18.1.0 / libavcodec 62.28.102")
    original = (fixtures / "Static.264").read_bytes()
    if hashlib.sha256(original).hexdigest() != PINS["Static.264"]:
        raise RuntimeError("Compressed fixture SHA256 mismatch")
    nals = [n for n in re.split(b"\x00\x00(?:\x00)?\x01", original) if n]
    if len(nals) != 12 or nals[0][0] & 31 != 7:
        raise RuntimeError("Unexpected source NAL layout")
    run = subprocess.run([str(executable.resolve()), str(fixtures.resolve()), "--emit-source"],
                         check=True, capture_output=True, timeout=60)
    data, at, total = run.stdout, 0, 0

    def take(n: int) -> bytes:
        nonlocal at
        if n < 0 or n > len(data) - at:
            raise RuntimeError("Truncated source readback")
        out = data[at:at + n]
        at += n
        return out

    for mode in range(1, 5):
        size, = struct.unpack("<I", take(4))
        if not 1 <= size <= 4096:
            raise RuntimeError("Invalid SPS export size")
        sps = take(size)
        stream = b"\x00\x00\x00\x01".join([b"", sps, *nals[1:]])
        with av.open(io.BytesIO(stream), format="h264") as container:
            ctx = container.streams.video[0].codec_context
            if ctx.codec.name != "h264":
                raise RuntimeError("Reference must be native FFmpeg h264")
            frames = list(container.decode(video=0))
            sar = ctx.sample_aspect_ratio
        if len(frames) != 10 or sar != (Fraction(2, 1) if mode % 2 else Fraction(1, 2)):
            raise RuntimeError("Independent sample aspect or frame count disagreement")
        worst = 0
        for counter, frame in enumerate(frames):
            if (frame.width, frame.height) != (152, 100) or frame.format.name not in ("yuv420p", "yuvj420p"):
                raise RuntimeError(f"Unexpected independent pixel format: {frame.format.name}")
            matrix, full_range = int(frame.colorspace), int(frame.color_range) == 2
            if (matrix, int(frame.color_range), int(frame.color_primaries), int(frame.color_trc)) != (
                    6 if mode <= 2 else 1, 1 if mode % 2 else 2, 1, 1):
                raise RuntimeError("Independent colour code-point disagreement")
            resolved = (3 if matrix == 1 else 1) + int(full_range)
            if struct.unpack("<IIII", take(16)) != (mode, 304, 200, counter):
                raise RuntimeError("Unexpected readback header/order")
            source = convert(frame, resolved)
            aspect = Fraction(frame.width, frame.height) * sar
            if aspect > Fraction(304, 200):
                dw, dh = 304, max(1, int(Fraction(304) / aspect))
            else:
                dw, dh = max(1, int(200 * aspect)), 200
            x0, y0 = (304 - dw) // 2, (200 - dh) // 2
            actual, expected = take(304 * 200 * 4), bytearray(304 * 200 * 4)
            # Chosen SARs give exact integer upscales, independently verified.
            if dw % frame.width or dh % frame.height:
                raise RuntimeError("Oracle only claims integer scaling here")
            for y in range(dh):
                for x in range(dw):
                    src = ((y * frame.height // dh) * frame.width + x * frame.width // dw) * 4
                    dest = ((y + y0) * 304 + x + x0) * 4
                    expected[dest:dest + 3] = source[src:src + 3]
            error = max(abs(a - b) for i, (a, b) in enumerate(zip(actual, expected)) if i % 4 != 3)
            if error > 1:
                raise RuntimeError(f"Source render mismatch: mode={mode}, frame={counter}, error={error}")
            worst = max(worst, error)
            total += 1
        print(f"PASS source mode={mode}, FFmpeg SAR={sar}: 10 TCP/AEAD/H264/GDI frames, RGB error={worst}")
    if at != len(data):
        raise RuntimeError("Unexpected trailing source readback")
    print(f"PASS: {total} VUI-selected renders independently verified; no physical presentation claim.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_projection_video_source.py TEST_EXE OPENH264_RES_DIRECTORY")
    check(Path(sys.argv[1]), Path(sys.argv[2]))
