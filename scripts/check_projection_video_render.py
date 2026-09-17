"""Independent FFmpeg + floating-point oracle for real TCP/decoder/GDI pixels.

Public pinned fixture only. No image editor, screen capture, phone or vehicle I/O.
GDI destination alpha is unspecified; compare B/G/R, never claim scan-out timing.
"""
from pathlib import Path
import hashlib
import math
import struct
import subprocess
import sys

from check_projection_h264 import PINS


def convert(frame, color: int) -> bytes:
    width, height = frame.width, frame.height
    planes = []
    for plane in frame.planes:
        data = bytes(plane)
        planes.append(b"".join(data[y * plane.line_size:y * plane.line_size + plane.width]
                               for y in range(plane.height)))
    kr, kb = (0.299, 0.114) if color <= 2 else (0.2126, 0.0722)
    kg = 1 - kr - kb
    limited = color in (1, 3)
    yscale, cscale = (255 / 219, 255 / 224) if limited else (1, 1)
    offset = 16 if limited else 0
    output = bytearray(width * height * 4)
    for y in range(height):
        for x in range(width):
            uv = (y // 2) * (width // 2) + x // 2
            luma = (planes[0][y * width + x] - offset) * yscale
            cb, cr = (planes[1][uv] - 128) * cscale, (planes[2][uv] - 128) * cscale
            channels = (luma + 2 * (1 - kb) * cb,
                        luma - 2 * kb * (1 - kb) / kg * cb - 2 * kr * (1 - kr) / kg * cr,
                        luma + 2 * (1 - kr) * cr)
            at = (y * width + x) * 4
            for c, value in enumerate(channels):
                output[at + c] = max(0, min(255, math.floor(value + 0.5)))
            output[at + 3] = 255
    return bytes(output)


def check(executable: Path, fixtures: Path) -> None:
    import av

    if av.__version__ != "18.1.0" or av.library_versions["libavcodec"] != (62, 28, 102):
        raise RuntimeError("Use pinned PyAV 18.1.0 / libavcodec 62.28.102")
    source = fixtures / "Static.264"
    if hashlib.sha256(source.read_bytes()).hexdigest() != PINS[source.name]:
        raise RuntimeError("Compressed fixture SHA256 mismatch")
    with av.open(str(source), format="h264") as container:
        if container.streams.video[0].codec_context.codec.name != "h264":
            raise RuntimeError("Independent reference must use FFmpeg native h264")
        frames = list(container.decode(video=0))
    if len(frames) != 10 or any((f.width, f.height, f.format.name) != (152, 100, "yuv420p") for f in frames):
        raise RuntimeError("Unexpected independent frame layout/count")
    run = subprocess.run([str(executable.resolve()), str(fixtures.resolve()), "--emit"],
                         check=True, capture_output=True, timeout=60)
    data, at, total = run.stdout, 0, 0
    for color in range(1, 5):
        worst = 0
        for counter, frame in enumerate(frames):
            if at + 16 > len(data) or struct.unpack_from("<IIII", data, at) != (color, 152, 100, counter):
                raise RuntimeError("Unexpected GDI readback header/order")
            at += 16
            size = frame.width * frame.height * 4
            actual = data[at:at + size]
            expected = convert(frame, color)
            if len(actual) != size:
                raise RuntimeError("Truncated GDI readback")
            error = max(abs(a - b) for i, (a, b) in enumerate(zip(actual, expected)) if i % 4 != 3)
            if error > 1:
                raise RuntimeError(f"Rendered pixel mismatch: color={color} frame={counter} error={error}")
            worst = max(worst, error)
            at += size
            total += 1
        print(f"PASS colour={color}: 10 TCP/AEAD/H264/GDI frames, maximum RGB component error={worst}")
    if at != len(data):
        raise RuntimeError("Unexpected trailing GDI readback output")
    print(f"PASS: {total} independently checked rendered frames; no physical presentation or vehicle claim.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_projection_video_render.py TEST_EXE OPENH264_RES_DIRECTORY")
    check(Path(sys.argv[1]), Path(sys.argv[2]))
