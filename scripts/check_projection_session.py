# SPDX-License-Identifier: GPL-3.0-only
"""Independent public session fixtures and hashlib/plistlib output cross-check.

--fixtures prints fixture text only; normal mode never writes files or uses I/O
other than reading the supplied fixture and executing the explicit local test.
"""
import hmac
from pathlib import Path
import plistlib
import subprocess
import sys

SHARED = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
STREAMS = [dict(type=110, streamConnectionID=0), dict(type=111, streamConnectionID=1),
           dict(type=100, streamConnectionID=2**63, audioType='telephony', audioFormat=4,
                dataPort=27000, framesPerPacket=480, audioLatencyMs=20),
           dict(type=101, streamConnectionID=3, audioType='default', audioFormat=4),
           dict(type=102, streamConnectionID=4, audioType='media', audioFormat=0x400000),
           dict(type=130, seed=5, clientTypeUUID='E9459FD0-BCAD-4C45-820F-1E72447EF2F2')]
SESSION = dict(timingPort=27001, timingProtocol='NTP', keepAliveLowPower=True,
               name='Public synthetic phone', sessionUUID='00000000-1111-4000-8000-000000000001')


def fixtures():
    objects = dict(session=SESSION, streams=dict(streams=STREAMS), empty={},
                   audio_new=dict(streams=[dict(type=100, streamConnectionID=2**64-1, audioType='telephony', audioFormat=4)]),
                   screen_new=dict(streams=[dict(type=110, streamConnectionID=7)]),
                   teardown_audio=dict(streams=[dict(type=100, streamConnectionID=2**63)]),
                   teardown_screen=dict(streams=[dict(type=110)]),
                   teardown_wrong_id=dict(streams=[dict(type=100, streamConnectionID=0)]))
    for name, key, value in [('port_bool', 'timingPort', True), ('port_real', 'timingPort', 2.0),
                              ('port_zero', 'timingPort', 0), ('port_large', 'timingPort', 65536),
                              ('port_negative', 'timingPort', -1), ('port_text', 'timingPort', '27001'),
                              ('ptp', 'timingProtocol', 'PTP'), ('keep_integer', 'keepAliveLowPower', 1),
                              ('name_data', 'name', b'not text'), ('name_long', 'name', 'a'*257),
                              ('encryption', 'ekey', b'x'), ('wrong_streams', 'streams', {})]:
        objects['bad_'+name] = dict(SESSION, **{key: value})
    objects['bad_array'] = []
    objects['bad_empty_streams'] = dict(streams=[])
    objects['bad_unknown_stream'] = dict(streams=[dict(type=999)])
    objects['bad_seven_streams'] = dict(streams=STREAMS+[dict(type=110, streamConnectionID=20)])
    objects['bad_duplicate_type'] = dict(streams=[STREAMS[0], dict(type=110, streamConnectionID=8)])
    objects['bad_duplicate_id'] = dict(streams=[STREAMS[0], dict(type=111, streamConnectionID=0)])
    for name, key, value in [('format_bool', 'audioFormat', True), ('format_real', 'audioFormat', 4.0),
                              ('format_multiple', 'audioFormat', 12), ('format_unadvertised', 'audioFormat', 2),
                              ('id_real', 'streamConnectionID', 1.0), ('id_negative', 'streamConnectionID', -1),
                              ('audio_type', 'audioType', 'invented'), ('mic_port', 'dataPort', 65536),
                              ('mic_frames', 'framesPerPacket', 0), ('latency', 'audioLatencyMs', 60001),
                              ('stream_encryption', 'eiv', b'x')]:
        entry = dict(STREAMS[2], **{key: value})
        objects['bad_'+name] = dict(streams=[entry])
    objects['bad_iap_uuid'] = dict(streams=[dict(STREAMS[5], clientTypeUUID='unknown')])
    objects['bad_id_reuse'] = dict(streams=[dict(STREAMS[2], streamConnectionID=0)])
    result = {'shared': SHARED}
    result.update((name, plistlib.dumps(obj, fmt=plistlib.FMT_BINARY, sort_keys=False)) for name, obj in objects.items())
    result['bad_duplicate_key'] = bytes.fromhex('62706c6973743030d20101020351780908080d0f100000000000000101000000000000000400000000000000000000000000000011')
    result['bad_xml'] = b'<plist version="1.0"><dict/></plist>'
    return result


def derive(salt, label):
    prk = hmac.digest(salt.encode(), SHARED, 'sha512')
    return hmac.digest(prk, label.encode()+b'\x01', 'sha512')[:32]


def expected():
    outputs = dict(session_read=derive('Events-Salt', 'Events-Read-Encryption-Key'),
                   session_write=derive('Events-Salt', 'Events-Write-Encryption-Key'))
    for stream in STREAMS:
        prefix = f'stream_{stream["type"]}'
        salt = 'DataStream-Salt'+str(stream.get('streamConnectionID', stream.get('seed')))
        outputs[prefix+'_read'] = derive(salt, 'DataStream-Output-Encryption-Key')
        outputs[prefix+'_write'] = derive(salt, 'DataStream-Input-Encryption-Key') if stream['type'] == 100 else bytes(32)
    outputs['replacement_read'] = derive('DataStream-Salt'+str(2**64-1), 'DataStream-Output-Encryption-Key')
    outputs['replacement_write'] = bytes(32)
    return outputs


def main():
    if sys.argv[1:] == ['--fixtures']:
        print('# PUBLIC SYNTHETIC session requests/shared secret. NEVER provision a receiver.')
        for name, data in fixtures().items():
            print(f'{name}={data.hex()}')
        return
    if len(sys.argv) != 3:
        raise SystemExit('usage: check_projection_session.py <trusted local projection_session_tests executable> <fixture>')
    fixture = Path(sys.argv[2]).resolve(strict=True)
    actual_fixture = dict(line.split('=', 1) for line in fixture.read_text().splitlines() if line and not line.startswith('#'))
    assert actual_fixture == {key: value.hex() for key, value in fixtures().items()}
    executable = Path(sys.argv[1]).resolve(strict=True)
    run = subprocess.run([str(executable), str(fixture), '--emit'], check=True, capture_output=True, text=True, timeout=30)
    values = dict((key, bytes.fromhex(value)) for key, value in (line.split('=', 1) for line in run.stdout.splitlines()))
    keys = expected()
    assert set(values) == set(keys) | {'session_reply', 'streams_reply', 'replacement_reply'}
    for key, value in keys.items():
        assert values[key] == value, key
    session = dict(timingPort=4001, eventPort=4000, keepAlivePort=4002,
                   enabledFeatures=['viewAreas', 'iAPChannel', 'hevc', 'altScreen'])
    streams = []
    for request in STREAMS:
        kind = request['type']
        item = dict(type=kind, dataPort=5000+kind*2)
        if kind in (100, 101, 102):
            item.update(controlPort=5001+kind*2, streamConnectionID=request['streamConnectionID'])
        if kind == 130:
            item['streamID'] = 77
        streams.append(item)
    replacement = dict(streams=[dict(type=100, dataPort=5200, controlPort=5201, streamConnectionID=2**64-1)])
    for name, wanted in [('session_reply', session), ('streams_reply', dict(streams=streams)), ('replacement_reply', replacement)]:
        actual = plistlib.loads(values[name])
        # Re-encoding exact parsed types/values guards int/bool coercion in equality.
        assert plistlib.dumps(actual, fmt=plistlib.FMT_BINARY, sort_keys=True) == plistlib.dumps(wanted, fmt=plistlib.FMT_BINARY, sort_keys=True), name
        print(f'PASS: {name}, {len(values[name])} bytes, independently parsed ports/features/full uint64 correlation')
    print(f'PASS: {len(keys)} directional key/zero values and {len(actual_fixture)} independently reproduced public fixture values')


if __name__ == '__main__':
    main()
