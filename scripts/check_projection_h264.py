"""Independent FFmpeg pixel/order check; public pinned fixtures, no vehicle I/O.

Use the existing hash-pinned PyAV environment (media-reference-requirements.txt).
SHA1 here compares pixels with upstream test conventions, not authentication.
"""
from pathlib import Path
import hashlib
import re
import subprocess
import sys

import av

PINS = {
    "Static.264": "46ce837b059b07d9e44f2df957772335a51d17162e3357b613f3988143c1f420",
    "test_qcif_cabac.264": "d5a2d70c45100cf8143572d9e9e48a867c04890690e4de7633ed4e655dd95f9e",
    "test_scalinglist_jm.264": "883fd8d5a66cd30ebcc2f21a1447fe336a07180137336829df489afbfdc62c76",
    "Adobe_PDF_sample_a_1024x768_50Frms.264": "ae1cc5362fb1a674924446f6a4218eb31fc1d339b02c10478f2dc16fc3124dc6",
    "test_cif_P_CABAC_slice.264": "944f2e22dac9c910270a04ea68da398fd3e53afcc42ef5ec114a28527436261b",
}


def check(executable: Path, fixtures: Path) -> None:
    if av.__version__ != "18.1.0" or av.library_versions["libavcodec"] != (62, 28, 102):
        raise RuntimeError("Use pinned PyAV 18.1.0 / libavcodec 62.28.102")
    for name, expected in PINS.items():
        if hashlib.sha256((fixtures / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"Fixture SHA256 mismatch: {name}")
    run = subprocess.run([str(executable.resolve()), str(fixtures.resolve())],
                         check=True, capture_output=True, text=True, timeout=60)
    pattern = re.compile(r"^(\S+) profile=\d+ (\d+)x(\d+) frames=(\d+) drained=\d+ "
                         r"terminal_au=([01]) golden_sha1=([0-9a-f]{40})$", re.M)
    rows = pattern.findall(run.stdout)
    if len(rows) != 2 * len(PINS) or {r[0] for r in rows} != set(PINS):
        raise RuntimeError("Unexpected C++ decoder results")
    total = 0
    for name in PINS:
        digest = hashlib.sha1()
        count = 0
        width = height = 0
        with av.open(str(fixtures / name), format="h264") as container:
            if container.streams.video[0].codec_context.codec.name != "h264":
                raise RuntimeError("Reference must use FFmpeg's native h264, not libopenh264")
            for frame in container.decode(video=0):
                if frame.format.name != "yuv420p":
                    raise RuntimeError("Unexpected reference pixel format")
                width, height = frame.width, frame.height
                for plane in frame.planes:
                    data = bytes(plane)
                    for y in range(plane.height):
                        digest.update(data[y * plane.line_size:y * plane.line_size + plane.width])
                count += 1
        actual = digest.hexdigest()
        selected = [r for r in rows if r[0] == name]
        if {r[4] for r in selected} != {"0", "1"}:
            raise RuntimeError(f"Missing final-AU/drain variant: {name}")
        for row in selected:
            if (width, height, count, actual) != (int(row[1]), int(row[2]), int(row[3]), row[5]):
                raise RuntimeError(f"Independent pixel/order disagreement: {name}, {row}, {actual}")
        total += count
        print(f"FFmpeg native h264 agrees: {name}, {count} frames, {width}x{height}, {actual}")
    print(f"PASS: {total} independently decoded frames match both adapter drain variants; "
          "B-frame support remains disabled, no target execution.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_projection_h264.py TEST_EXE OPENH264_RES_DIRECTORY")
    check(Path(sys.argv[1]), Path(sys.argv[2]))
