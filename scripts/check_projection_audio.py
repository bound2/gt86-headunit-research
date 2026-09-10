# SPDX-License-Identifier: GPL-3.0-only
"""Independent synthetic audio wire fixtures/checker, no file writes/network.

PyCA is a developer-only fixture oracle; the receiver uses pinned Monocypher.
Compressed fixture bytes are opaque transport samples, NOT decoded audio.
"""
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY = bytes([9])*32


def seal(payload, sample, counter, sequence=0, ssrc=0xaabbccdd):
    header = struct.pack('>BBHII', 0x80, 0x60, sequence, sample, ssrc)
    short = counter.to_bytes(8, 'little')
    return header + ChaCha20Poly1305(KEY).encrypt(bytes(4)+short, payload, header[4:]) + short


def fixtures():
    values = dict(key=KEY, native_plain=b'first', pcm_plain=bytes.fromhex('8000000000017fff'),
                  aac_plain=bytes.fromhex('211004608c1c'), opus_plain=bytes.fromhex('f8fffe'))
    values['native'] = seal(values['native_plain'], 4242, 0)
    values['pcm'] = seal(values['pcm_plain'], 2**32-1, 2**64-1, 65535)
    values['aac'] = seal(values['aac_plain'], 12345, 2**63)
    values['opus'] = seal(values['opus_plain'], 480, 17)
    streams = [dict(type=100, streamConnectionID=10, audioType='media', audioFormat=16),
               dict(type=101, streamConnectionID=11, audioType='default', audioFormat=32768),
               dict(type=102, streamConnectionID=12, audioType='media', audioFormat=4194304)]
    for key, obj in dict(session=dict(timingPort=27001), streams=dict(streams=streams),
                         retire=dict(streams=[dict(type=100)]),
                         replacement=dict(streams=[dict(streams[0], streamConnectionID=13)])).items():
        values[key] = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY, sort_keys=False)
    return values


def formats():
    result = []
    for rate, bits in [(8000, (4, 8)), (16000, (16, 32)), (24000, (64, 128)),
                       (32000, (256, 512)), (44100, (1024, 2048)), (48000, (16384, 32768))]:
        for channels, bit in enumerate(bits, 1):
            result.append((bit, rate, rate, 1, channels, 0))
    result += [(4194304, 44100, 44100, 2, 2, 0x1210), (8388608, 48000, 48000, 2, 2, 0x1190)]
    result += [(bit, 48000, rate, 3, 1, 0) for bit, rate in [(0x10000000, 16000), (0x20000000, 24000), (0x40000000, 48000)]]
    return b''.join(struct.pack('<IIIBBH', *item) for item in result)


def main():
    expected = fixtures()
    if sys.argv[1:] == ['--fixtures']:
        print('# PUBLIC SYNTHETIC encrypted audio and session fixtures. Not real credentials or decoded compressed audio.')
        for key, value in expected.items():
            print(f'{key}={value.hex()}')
        return
    if len(sys.argv) != 3:
        raise SystemExit('usage: check_projection_audio.py <trusted local projection_audio_tests executable> <fixture>')
    executable, fixture = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])
    values = dict(line.split('=', 1) for line in fixture.read_text().splitlines() if line and not line.startswith('#'))
    assert values == {key: value.hex() for key, value in expected.items()}
    run = subprocess.run([str(executable), str(fixture), '--emit'], check=True, capture_output=True, text=True, timeout=30)
    actual = dict(line.split('=', 1) for line in run.stdout.splitlines())
    wanted = {key: expected[key].hex() for key in ['native_plain', 'aac_plain', 'opus_plain']}
    wanted.update(pcm_le='008000000100ff7f', formats=formats().hex())
    assert actual == wanted
    print(f'PASS: {len(expected)} independent PyCA/plist fixtures, 17 exact format mappings and four C-decrypted payloads/PCM conversion')


if __name__ == '__main__':
    main()
