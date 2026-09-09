#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent PUBLIC MFiSAP framing/crypto vectors, NOT Apple credentials/signatures."""
from pathlib import Path
import hashlib
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from check_pair_vectors import vectors as pairing_vectors


def vectors():
    own_secret, peer_secret = bytes(range(65, 97)), bytes(range(97, 129))
    own, peer = X25519PrivateKey.from_private_bytes(own_secret), X25519PrivateKey.from_private_bytes(peer_secret)
    own_pub, peer_pub = own.public_key().public_bytes_raw(), peer.public_key().public_bytes_raw()
    shared = own.exchange(peer.public_key())
    assert shared == peer.exchange(own.public_key())
    key, iv = hashlib.sha1(b'AES-KEY' + shared).digest()[:16], hashlib.sha1(b'AES-IV' + shared).digest()[:16]

    def encrypt(data):
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return cipher.update(data) + cipher.finalize()

    def response(cert, sig):
        return own_pub + len(cert).to_bytes(4, 'big') + cert + len(sig).to_bytes(4, 'big') + encrypt(sig)

    certificate = b'PUBLIC SYNTHETIC CERTIFICATE; NOT AN APPLE CREDENTIAL'
    # Opaque synthetic provider results, not software-generated MFi licensing.
    sig2 = bytes((i * 7 + 3) % 256 for i in range(128))
    sig3 = bytes((i * 11 + 5) % 256 for i in range(64))
    long_sig = bytes((i * 13 + 17) % 256 for i in range(512))
    max_cert = bytes((i * 3 + 1) % 256 for i in range(4096))
    result = {'pv_' + name: value for name, value in pairing_vectors().items()}
    result.update({
        'own_secret': own_secret, 'peer_secret': peer_secret, 'own_public': own_pub, 'peer_public': peer_pub,
        'shared': shared, 'aes_key': key, 'aes_iv': iv, 'request': b'\x01' + peer_pub, 'certificate': certificate,
        'digest2': hashlib.sha1(own_pub + peer_pub).digest(), 'digest3': hashlib.sha256(own_pub + peer_pub).digest(),
        'signature2': sig2, 'signature3': sig3, 'response2': response(certificate, sig2), 'response3': response(certificate, sig3),
        'long_signature': long_sig, 'encrypted_long_signature': encrypt(long_sig),
        'max_response_sha512': hashlib.sha512(response(max_cert, long_sig)).digest(),
    })
    return result


def main():
    expected = vectors()
    if len(sys.argv) == 2 and sys.argv[1] == '--emit':
        print('# PUBLIC synthetic keys, certificates and signature bytes only. NEVER provision a receiver.')
        print('# X25519 / SHA1 / SHA256 / AES128-CTR independently computed with PyCA/hashlib.')
        for name, value in expected.items():
            print(name + '=' + value.hex())
        return
    if len(sys.argv) != 2:
        raise SystemExit('Usage: check_mfi_sap_vectors.py FIXTURE | --emit')
    actual = {}
    for line in Path(sys.argv[1]).read_text(encoding='ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        name, value = line.split('=', 1)
        if name in actual:
            raise ValueError('Duplicate vector: ' + name)
        actual[name] = bytes.fromhex(value)
    if actual != expected:
        raise ValueError('MFiSAP fixture differs from independent reference')
    print(f'PASS: all {len(expected)} public MFiSAP/pairing vectors independently reproduced; no real MFi credential')


if __name__ == '__main__':
    main()
