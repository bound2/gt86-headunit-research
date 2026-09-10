#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independently decode an explicit local capability-test executable's PUBLIC output.

No phone, network, file writes, credentials, descriptor validation or real backend.
The executable is trusted test code, not an arbitrary downloaded binary.
"""
from pathlib import Path
import plistlib
import subprocess
import sys


def expected(variant):
    result = dict(sourceVersion='PUBLIC-TEST-1.0', features=0, statusFlags=0,
                  model='Synthetic receiver', manufacturer='Test only', deviceID='02:00:00:00:00:01',
                  bluetoothIDs=[], name='Public capability fixture', rightHandDrive=False,
                  keepAliveLowPower=False, keepAliveSendStatsAsBody=False)
    resources = []
    if variant:
        for identity in (1, 2):
            resources.append(dict(resourceID=identity, transferType=1, transferPriority=100,
                                  takeConstraint=100, borrowConstraint=100, unborrowConstraint=100))
    result['modes'] = dict(resources=resources, appStates=[dict(appStateID=2, state=variant == 2),
                           dict(appStateID=1, speechMode=-1.0 if variant else 0),
                           dict(appStateID=3, state=variant == 2)])
    if variant:
        result.update(features=0x615653aee2, statusFlags=4, bluetoothIDs=['02:00:00:00:00:02'])
        latency_types = ((100, None), (100, 'default'), (100, 'media'), (100, 'telephony'),
                         (100, 'speechRecognition'), (100, 'alert'), (101, None), (101, 'default'), (102, 'default'))
        result['audioLatencies'] = []
        for index, (stream, kind) in enumerate(latency_types):
            latency = dict(type=stream, inputLatencyMicros=index * 10, outputLatencyMicros=index * 20)
            if kind:
                latency['audioType'] = kind
            result['audioLatencies'].append(latency)
        pcm, mono, opus = 0xffc, 0x554, 0x70000000
        formats = ((100, 'compatibility', pcm, mono), (101, 'compatibility', pcm, 0),
                   (100, 'default', pcm | opus, mono | opus), (100, 'alert', pcm | opus, 0),
                   (100, 'media', pcm, 0), (100, 'telephony', mono | opus, mono | opus),
                   (100, 'speechRecognition', mono | opus, mono | opus),
                   (101, 'default', pcm | opus, 0), (102, 'media', 0x400000, 0))
        result['audioFormats'] = []
        for stream, kind, output, incoming in formats:
            entry = dict(type=stream, audioType=kind, audioOutputFormats=output)
            if incoming:
                entry['audioInputFormats'] = incoming
            result['audioFormats'].append(entry)
    result['extendedFeatures'] = [] if not variant else ['vocoderInfo', 'enhancedRequestCarUI']
    if variant == 2:
        result['extendedFeatures'] += [f'testExtension{i}' for i in range(2, 8)]
    result['displays'] = []
    for index in range(0 if not variant else 2 if variant == 2 else 1):
        uid = f'00000000-{2222 if index else 1111}-4000-8000-00000000000{index + 1}'
        display = dict(uuid=uid, type=110 + index, maxFPS=60, widthPixels=800,
                       heightPixels=480, widthPhysical=160, heightPhysical=96, features=10, primaryInputDevice=3)
        if variant == 2:
            display['viewAreas'] = [dict(widthPixels=780, heightPixels=440, originXPixels=10, originYPixels=20,
                                  safeArea=dict(widthPixels=760, heightPixels=420, originXPixels=20,
                                                originYPixels=30, drawUIOutsideSafeArea=True))]
            display['initialViewArea'] = 0
            display['initialURL'] = 'maps://'
        result['displays'].append(display)
    result['hidDevices'] = []
    if variant:
        descriptor = bytes((index * 7 + 1) % 256 for index in range(1024 if variant == 2 else 17))
        for index in range(4):
            result['hidDevices'].append(dict(hidProductID=index + 1, hidVendorID=2, hidCountryCode=0,
                                       uuid=f'1234000{index + 1}', name='Opaque synthetic HID',
                                       displayUUID=result['displays'][0]['uuid'], hidDescriptor=descriptor))
    if variant == 2:
        result.update(features=(1 << 64) - 1, statusFlags=(1 << 64) - 1, rightHandDrive=True,
                      keepAliveLowPower=True, keepAliveSendStatsAsBody=True, oemIconVisible=True,
                      oemIconLabel='Synthetic icon data')
        icon = bytes((index * 11 + 3) % 256 for index in range(8192))
        result['oemIcons'] = [dict(imageData=icon, widthPixels=256, heightPixels=256, prerendered=True) for _ in range(2)]
        result['hevcInfo'] = {}
    return result


def compare(actual, want, path='root'):
    assert type(actual) is type(want), (path, type(actual), type(want))
    if isinstance(want, dict):
        assert list(actual) == list(want), (path, list(actual), list(want))
        for key in want:
            compare(actual[key], want[key], f'{path}.{key}')
    elif isinstance(want, list):
        assert len(actual) == len(want), (path, len(actual), len(want))
        for index, item in enumerate(want):
            compare(actual[index], item, f'{path}[{index}]')
    else:
        assert actual == want, path


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: check_projection_info.py <trusted local projection_info_tests executable>')
    executable = Path(sys.argv[1]).resolve(strict=True)
    run = subprocess.run([str(executable), '--emit'], check=True, capture_output=True, text=True, timeout=30)
    lines = run.stdout.splitlines()
    assert len(lines) == 3
    for variant, line in enumerate(lines):
        label, data = line.split('=', 1)
        assert label == str(variant)
        wire = bytes.fromhex(data)
        assert wire.startswith(b'bplist00') and len(wire) <= 32768
        decoded = plistlib.loads(wire, fmt=plistlib.FMT_BINARY)
        compare(decoded, expected(variant))
        compare(plistlib.loads(plistlib.dumps(decoded, fmt=plistlib.FMT_BINARY, sort_keys=False)), expected(variant))
        print(f'PASS: profile {variant}, {len(wire)} bytes independently decoded; exact types/keys/values/order')
    print('PASS: 3 public synthetic capability profiles; no real HID/icon/backend or phone acceptance claim')


if __name__ == '__main__':
    main()
