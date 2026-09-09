#!/usr/bin/env python3
"""Public synthetic control records independently computed with PyCA, no device I/O."""
from pathlib import Path
import hashlib
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from check_pair_vectors import vectors as pairing_vectors


def frame(key, counter, plain):
    header = len(plain).to_bytes(2, 'little')
    nonce = bytes(4) + counter.to_bytes(8, 'little')
    return header + ChaCha20Poly1305(key).encrypt(nonce, plain, header)


def vectors():
    pair = pairing_vectors()
    read, write = pair['accessory_read_key'], pair['accessory_write_key']
    request = b'GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n'
    response = b'RTSP/1.0 501 Not Implemented\r\nCSeq: 9\r\nContent-Length: 0\r\n\r\n'
    large = bytes(range(256)) * 64
    return {
        'read_key': read, 'write_key': write, 'request': request, 'response': response,
        'read_0': frame(read, 0, request), 'read_1': frame(read, 1, request),
        'read_empty_2': frame(read, 2, b''),
        'read_max': frame(read, 2**64-1, request),
        'read_endian': frame(read, 0x0102030405060708, request),
        'write_0': frame(write, 0, response), 'write_1': frame(write, 1, response),
        'max_payload_sha512': hashlib.sha512(frame(write, 0, large)).digest(),
    }


def main():
    expected = vectors()
    if len(sys.argv) == 2 and sys.argv[1] == '--emit':
        print('# PUBLIC synthetic keys/records only; NEVER provision a real receiver.')
        print('# Independently generated with PyCA; nonce zero32 || LE64, LE16 AAD.')
        for name, value in expected.items():
            print(name + '=' + value.hex())
        return
    if len(sys.argv) != 2:
        raise SystemExit('Usage: check_control_vectors.py FIXTURE | --emit')
    actual = {}
    for line in Path(sys.argv[1]).read_text(encoding='ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        name, value = line.split('=', 1)
        if name in actual:
            raise ValueError('Duplicate vector: ' + name)
        actual[name] = bytes.fromhex(value)
    if actual != expected:
        raise ValueError('Control fixture differs from the independent reference')
    print(f'PASS: all {len(expected)} public control-frame vectors independently reproduced with PyCA')


if __name__ == '__main__':
    main()
