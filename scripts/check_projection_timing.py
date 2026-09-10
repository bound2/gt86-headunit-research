#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read a trusted local timing-test executable's trace; no file writes/network."""
from fractions import Fraction
from pathlib import Path
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: check_projection_timing.py <trusted local projection_timing_tests executable>')
    executable = Path(sys.argv[1]).resolve(strict=True)
    output = subprocess.run([str(executable), '--trace'], check=True,
                            capture_output=True, text=True, timeout=10).stdout
    mask, unit, epoch = (1 << 64) - 1, 1 << 32, 0x1234567880000000
    expected = {}
    for sign, encoded in [(1, 1), (-1, mask)]:
        # First step .5 s; small .015625 s residual is slewed by1/8;
        # larger RTT group is ignored; final .5 s residual steps again.
        for i, phase in enumerate([Fraction(1, 2), Fraction(257, 512),
                                   Fraction(257, 512), Fraction(513, 512)]):
            expected[('phase', str(encoded), str(i))] = (epoch + sign * int(phase * unit)) & mask
    for ns in [1, 999999999, 1000000001, mask]:
        expected[('clock', str(ns))] = (epoch + int(Fraction(ns, 1000000000) * unit)) & mask
    actual = {}
    for line in output.splitlines():
        *key, value = line.split()
        key = tuple(key)
        if key in actual:
            raise AssertionError(f'duplicate trace key: {key}')
        actual[key] = int(value)
    if actual != expected:
        raise AssertionError(f'clock/filter trace differs: {actual!r}')
    print('PASS: 12 C clock/filter values cross-checked with unbounded Python integers/Fraction')


if __name__ == '__main__':
    main()
