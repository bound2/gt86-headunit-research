#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently decode a trusted local encoder's public synthetic commands."""
from pathlib import Path
import plistlib
import subprocess
import sys


def same(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(same(actual[k], v) for k, v in expected.items())
    return actual == expected


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: check_projection_commands.py <trusted local projection_events_tests executable>')
    output = subprocess.run([str(Path(sys.argv[1]).resolve(strict=True)), '--fixtures'],
                            check=True, capture_output=True, text=True, timeout=10).stdout
    payload = bytes.fromhex('01020300ff')
    expected = {
        'hid': dict(type='hidSendReport', uuid='12340001', hidReport=payload),
        'night_on': dict(type='setNightMode', params=dict(nightMode=True)),
        'night_off': dict(type='setNightMode', params=dict(nightMode=False)),
        'siri_down': dict(type='requestSiri', params=dict(siriAction=2)),
        'siri_up': dict(type='requestSiri', params=dict(siriAction=3)),
        'iap': dict(type='iAPSendMessage', params=dict(data=payload)),
        'keyframe_main': dict(type='forceKeyFrame', params=dict(uuid='00000000-1111-4000-8000-000000000001')),
        'keyframe_alt': dict(type='forceKeyFrame', params=dict(uuid='00000000-2222-4000-8000-000000000002')),
    }
    seen = set()
    for line in output.splitlines():
        name, value = line.split('=', 1)
        if name not in expected or name in seen:
            raise AssertionError(f'unexpected or duplicate fixture: {name}')
        seen.add(name)
        decoded = plistlib.loads(bytes.fromhex(value), fmt=plistlib.FMT_BINARY)
        if not same(decoded, expected[name]):
            raise AssertionError(f'wrong command schema/types: {name}: {decoded!r}')
    if seen != expected.keys():
        raise AssertionError('missing command fixture')
    print('PASS: 8 C-generated command plists independently decoded; exact dictionaries/types/data')


if __name__ == '__main__':
    main()
