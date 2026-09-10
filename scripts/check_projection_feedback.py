# SPDX-License-Identifier: GPL-3.0-only
"""Independently decode C-generated feedback. Public synthetic observations only.

Runs the explicitly supplied local test executable; no file writes or network.
"""
from pathlib import Path
import plistlib
import subprocess
import sys


def expected():
    descriptors = [dict(type=100, sampleRate=8000), dict(type=101, sampleRate=8000),
                   dict(type=102, sampleRate=44100)]
    playing = [dict(item, streamConnectionID=connection, timestamp=2**63-2**29,
                    timestampRawNs=1_000_000, sampleTime=2**32-1)
               for item, connection in zip(descriptors, [2**63, 3, 4])]
    replacement = playing[1:] + [dict(playing[0], streamConnectionID=2**64-1)]
    wrapped = [dict(item, timestamp=2**64-4, timestampRawNs=2**64-2, sampleTime=0)
               for item in replacement]
    return dict(empty=None, prepared=dict(streams=descriptors), playing=dict(streams=playing),
                retired=dict(streams=playing[1:]), replacement=dict(streams=replacement),
                wrap=dict(streams=wrapped), missing=dict(streams=descriptors[1:]+descriptors[:1]))


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: check_projection_feedback.py <trusted local projection_session_tests executable> <session fixture>')
    executable = Path(sys.argv[1]).resolve(strict=True)
    fixture = Path(sys.argv[2]).resolve(strict=True)
    run = subprocess.run([str(executable), str(fixture), '--feedback'], check=True,
                         capture_output=True, text=True, timeout=30)
    values = dict(line.split('=', 1) for line in run.stdout.splitlines())
    wanted = expected()
    assert values.keys() == wanted.keys()
    for name, value in wanted.items():
        raw = bytes.fromhex(values[name])
        if value is None:
            assert raw == b''
        else:
            actual = plistlib.loads(raw)
            # Exact typed values: plain equality alone could confuse bool/int.
            assert plistlib.dumps(actual, fmt=plistlib.FMT_BINARY, sort_keys=True) == plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=True), name
        print(f'PASS: {name}, {len(raw)} bytes, independently decoded feedback')
    print('PASS: 7 feedback states; no-position omission, actual sample counter, NTP wrap and full unsigned 64-bit values')


if __name__ == '__main__':
    main()
