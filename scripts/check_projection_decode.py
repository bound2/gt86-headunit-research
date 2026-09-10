# SPDX-License-Identifier: GPL-3.0-only
"""Test-only PyAV/FFmpeg packet encoder and independent native-decoder oracle.

No device/network/file writes. --fixtures prints synthetic raw codec packets;
normal mode checks committed packets and compares the trusted local C decoder.
"""
from array import array
from fractions import Fraction
from pathlib import Path
import math
import struct
import subprocess
import sys
import av

CASES = [("aac44100", "aac", 44100, 2, 1024, 4),
         ("aac48000", "aac", 48000, 2, 1024, 4),
         ("opus20", "libopus", 48000, 1, 960, 4),
         ("opus120", "libopus", 48000, 1, 5760, 2),
         ("aac44100_np", "aac", 44100, 2, 1024, 4),
         ("aac48000_np", "aac", 48000, 2, 1024, 4),
         ("opus20_celt", "libopus", 48000, 1, 960, 4)]


def packets():
    assert av.__version__ == "18.1.0", "Use the pinned media-reference environment"
    values = {}
    for name, codec, rate, channels, count, blocks in CASES:
        enc = av.CodecContext.create(codec, "w")
        enc.sample_rate = rate
        enc.layout = "stereo" if channels == 2 else "mono"
        enc.format = "fltp" if codec == "aac" else "s16"
        enc.bit_rate = 96000 if codec == "aac" else 32000
        enc.time_base = Fraction(1, rate)
        if name.endswith("_np"):
            enc.options = {"aac_pns": "0"}  # Deterministic spectral reference; keep original PNS cases too.
        if codec == "libopus":
            enc.options = {"frame_duration": str(count * 1000 // rate), "application": "lowdelay" if name.endswith("_celt") else "audio", "vbr": "off"}
        enc.open()
        assert enc.frame_size == count
        result = []
        for block in range(blocks):
            frame = av.AudioFrame(format=enc.format.name, layout=enc.layout.name, samples=count)
            frame.sample_rate, frame.pts, frame.time_base = rate, block * count, Fraction(1, rate)
            for channel, plane in enumerate(frame.planes):
                signal = [0.15 * math.sin(2 * math.pi * (440 + 277 * channel) * (block * count + i) / rate)
                          + 0.035 * math.sin(2 * math.pi * 1231 * (block * count + i) / rate) for i in range(count)]
                samples = array("f", signal) if codec == "aac" else array("h", (round(v * 32767) for v in signal))
                assert sys.byteorder == "little"
                plane.update(samples.tobytes())
            result.extend(enc.encode(frame))
        result.extend(enc.encode(None))
        assert len(result) == blocks + 1
        for i, packet in enumerate(result):
            values[f"{name}_{i}"] = bytes(packet)
        if codec == "aac":
            assert enc.extradata[:2] == bytes.fromhex("1210" if rate == 44100 else "1190")
    return values


def read_values(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, data = line.split("=", 1)
        assert name not in values
        values[name] = bytes.fromhex(data)
    return values


def pcm_reference(name, codec, rate, channels, encoded, wrapped_opus=False):
    decoder_name = "aac" if codec == "aac" else "libopus" if wrapped_opus else "opus"
    decoder = av.CodecContext.create(decoder_name, "r")
    # Select FFmpeg's native decoder, not its libopus wrapper. No Ogg pre-skip.
    assert decoder.codec.name == decoder_name
    decoder.extradata = (bytes.fromhex("1210" if rate == 44100 else "1190") if codec == "aac" else
                         b"OpusHead" + struct.pack("<BBHIhB", 1, 1, 0, 48000, 0, 0))
    decoder.open()
    resampler = av.AudioResampler(format="s16", layout="stereo" if channels == 2 else "mono", rate=rate)
    result = []
    for value in encoded:
        frames = decoder.decode(av.Packet(value))
        assert len(frames) == 1
        converted = resampler.resample(frames[0])
        assert len(converted) == 1
        frame = converted[0]
        result.append(bytes(frame.planes[0])[:frame.samples * channels * 2])
    return result


def main():
    expected = packets()
    if sys.argv[1:] == ["--fixtures"]:
        print("# Synthetic packets encoded by pinned PyAV 18.1.0; no recorded/user media.")
        for key, value in expected.items():
            print(f"{key}={value.hex()}")
        return
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_projection_decode.py DECODER_EXE FIXTURES | --fixtures")
    fixture = Path(sys.argv[2])
    actual = read_values(fixture.read_text(encoding="ascii"))
    assert actual == expected, "Committed packet bytes differ from the pinned encoder"
    output = read_values(subprocess.check_output([sys.argv[1], str(fixture), "--emit"], text=True))
    compared = 0
    for name, codec, rate, channels, count, blocks in CASES:
        encoded = [actual[f"{name}_{i}"] for i in range(blocks + 1)]
        reference = pcm_reference(name, codec, rate, channels, encoded)
        # Native FFmpeg hybrid SILK/CELT is not a pointwise libopus oracle on
        # this fixture. Keep/report that disagreement and separately compare
        # PyAV's libopus wrapper; do NOT describe it as an independent algorithm.
        wrapped = pcm_reference(name, codec, rate, channels, encoded, True) if name == "opus20" else None
        maximum = 0
        native_maximum = 0
        minimum_snr = float("inf")
        for i, data in enumerate(reference):
            value = output.pop(f"{name}_{i}")
            if codec == "aac" and i == 0:
                assert not value, "FAAD's initial priming AU must not fabricate PCM"
                continue
            assert len(value) == len(data) == count * channels * 2
            decoded = struct.unpack("<" + "h" * (len(value) // 2), value)
            wanted = struct.unpack("<" + "h" * (len(data) // 2), data)
            error = max(abs(a - b) for a, b in zip(decoded, wanted))
            native_maximum = max(native_maximum, error)
            if wrapped is not None:
                assert len(wrapped[i]) == len(value)
                wanted = struct.unpack("<" + "h" * (len(value) // 2), wrapped[i])
                error = max(abs(a - b) for a, b in zip(decoded, wanted))
            maximum = max(maximum, error)
            if codec == "aac" and not name.endswith("_np"):
                # PNS uses decoder-generated noise: compare energy with a
                # bounded residual, not identical random samples. The _np
                # controls below still enforce the original <=8 LSB test.
                noise = sum((a - b) ** 2 for a, b in zip(decoded, wanted))
                snr = 10 * math.log10(sum(b * b for b in wanted) / max(1, noise))
                minimum_snr = min(minimum_snr, snr)
                assert error <= 256 and snr >= 40, (name, i, error, snr)
            else:
                assert error <= 8, (name, i, error)
            assert max(abs(v) for v in decoded) > 1000, "A silence stub is not decoding"
            compared += len(decoded)
        label = "PyAV/libopus wrapper (same algorithm)" if wrapped is not None else "native FFmpeg"
        print(f"PASS: {name}: {label}, max PCM16 error {maximum}" +
              (f", minimum PNS SNR {minimum_snr:.2f} dB" if minimum_snr != float("inf") else ""))
        if wrapped is not None:
            print(f"LIMITATION: {name}: native FFmpeg differs by up to {native_maximum} PCM16; not claimed pointwise equivalent")
    assert not output
    print(f"PASS: {len(actual)} exact encoded packets; {compared} decoded samples compared (hybrid via same-algorithm wrapper); no playback")
    print(f"Reference libraries: {av.library_versions}")


if __name__ == "__main__":
    main()
