# SPDX-License-Identifier: GPL-3.0-only
"""Independent PyCA reference for PUBLIC, synthetic pairing vectors. No key files/devices.

Print (--emit) or verify an explicitly named text fixture; never write a file.
Host-only optional reference, not a receiver dependency. Tested with cryptography 50.0.1.
"""
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def tlv(items):
    out = bytearray()
    for kind, value in items:
        for start in range(0, max(1, len(value)), 255):
            chunk = value[start:start + 255]
            out.extend(bytes((kind, len(chunk))) + chunk)
    return bytes(out)


def hkdf(secret, salt, info, size=32):
    return HKDF(algorithm=hashes.SHA512(), length=size, salt=salt, info=info).derive(secret)


def vectors():
    # RFC 8032 section 7.1 test 1 and test 2; publicly known, NEVER production keys.
    own_seed = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
    ctrl_seed = bytes.fromhex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')
    own = ed25519.Ed25519PrivateKey.from_private_bytes(own_seed)
    ctrl = ed25519.Ed25519PrivateKey.from_private_bytes(ctrl_seed)
    # RFC 7748 section 6.1 Alice/Bob X25519 inputs.
    own_eph = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
    ctrl_eph = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
    own_x = x25519.X25519PrivateKey.from_private_bytes(own_eph)
    ctrl_x = x25519.X25519PrivateKey.from_private_bytes(ctrl_eph)
    own_pk, ctrl_pk = public(own_x), public(ctrl_x)
    shared = own_x.exchange(ctrl_x.public_key())
    assert shared == ctrl_x.exchange(own_x.public_key())
    own_id, ctrl_id = b'GT86-TEST-ACCESSORY', b'GT86-TEST-CONTROLLER'
    key = hkdf(shared, b'Pair-Verify-Encrypt-Salt', b'Pair-Verify-Encrypt-Info')
    own_sig = own.sign(own_pk + own_id + ctrl_pk)
    ctrl_sig = ctrl.sign(ctrl_pk + ctrl_id + own_pk)
    own.public_key().verify(own_sig, own_pk + own_id + ctrl_pk)
    ctrl.public_key().verify(ctrl_sig, ctrl_pk + ctrl_id + own_pk)
    m2 = ChaCha20Poly1305(key).encrypt(b'\0' * 4 + b'PV-Msg02', tlv([(1, own_id), (10, own_sig)]), None)
    m3 = ChaCha20Poly1305(key).encrypt(b'\0' * 4 + b'PV-Msg03', tlv([(1, ctrl_id), (10, ctrl_sig)]), None)
    return {
        'own_seed': own_seed, 'own_public': public(own), 'empty_signature': own.sign(b''),
        'ctrl_seed': ctrl_seed, 'ctrl_public': public(ctrl), 'single_signature': ctrl.sign(b'\x72'),
        'own_identifier': own_id, 'ctrl_identifier': ctrl_id,
        'own_ephemeral_secret': own_eph, 'own_ephemeral_public': own_pk,
        'ctrl_ephemeral_secret': ctrl_eph, 'ctrl_ephemeral_public': ctrl_pk,
        'shared_secret': shared, 'encrypt_key': key,
        'm1': tlv([(6, b'\x01'), (3, ctrl_pk)]),
        'm2': tlv([(6, b'\x02'), (3, own_pk), (5, m2)]),
        'm3': tlv([(6, b'\x03'), (5, m3)]), 'm4': tlv([(6, b'\x04')]),
        'accessory_read_key': hkdf(shared, b'Control-Salt', b'Control-Write-Encryption-Key'),
        'accessory_write_key': hkdf(shared, b'Control-Salt', b'Control-Read-Encryption-Key'),
        'hkdf_82': hkdf(bytes([11])*22, bytes(range(13)), bytes(range(240, 250)), 82),
    }


def main():
    expected = vectors()
    if len(sys.argv) == 2 and sys.argv[1] == '--emit':
        print('# PUBLIC synthetic test keys: NEVER use for a real receiver or phone.')
        print('# RFC 8032 / RFC 7748 seeds; PyCA-independent pairing transcript.')
        for name, value in expected.items():
            print(name + '=' + value.hex())
        return
    if len(sys.argv) != 2:
        raise SystemExit('Usage: check_pair_vectors.py FIXTURE | --emit')
    actual = {}
    for line in Path(sys.argv[1]).read_text(encoding='ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        name, value = line.split('=', 1)
        if name in actual:
            raise ValueError('Duplicate vector: ' + name)
        actual[name] = bytes.fromhex(value)
    if actual != expected:
        raise ValueError('Pairing fixture differs from the independent reference')
    print(f'PASS: all {len(expected)} public crypto/pair-verify vectors independently reproduced with PyCA')


if __name__ == '__main__':
    main()
