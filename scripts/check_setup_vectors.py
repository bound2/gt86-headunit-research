#!/usr/bin/env python3
"""Independent Python-integer SRP client/server + PyCA pair-setup fixtures.

PUBLIC deterministic credentials only. No device/network I/O or file writes.
Selected LIVI profile: padded A/B in proofs, minimal unsigned S in K.
"""
import hashlib
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from check_pair_vectors import vectors as pair_vectors, hkdf, tlv

N = int('''
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183
995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A
85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7AB
F5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8
7602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208
E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
'''.replace('\n', ''), 16)


def pad(n):
    return n.to_bytes(384, 'big')


def minimal(n):
    return n.to_bytes(max(1, (n.bit_length()+7)//8), 'big')


def h(*parts):
    return hashlib.sha512(b''.join(parts)).digest()


def transcript(salt, a, b):
    g, identity = 5, b'Pair-Setup'
    x = int.from_bytes(h(salt, h(identity, b':3939')), 'big')
    multiplier = int.from_bytes(h(pad(N), pad(g)), 'big')
    verifier = pow(g, x, N)
    A, B = pow(g, a, N), (multiplier*verifier + pow(g, b, N)) % N
    u = int.from_bytes(h(pad(A), pad(B)), 'big')
    client_S = pow((B - multiplier*pow(g, x, N)) % N, a+u*x, N)
    server_S = pow((A*pow(verifier, u, N)) % N, b, N)
    if client_S != server_S or not 1 < A < N-1 or not 1 < client_S < N-1 or not u:
        raise ValueError('SRP agreement/safety failed')
    K = h(minimal(client_S))
    mix = bytes(x ^ y for x, y in zip(h(pad(N)), h(minimal(g))))
    M1 = h(mix, h(identity), salt, pad(A), pad(B), K)
    M2 = h(pad(A), M1, K)
    return {'salt': salt, 'a': a.to_bytes(32, 'big'), 'b': b.to_bytes(32, 'big'),
            'A': pad(A), 'B': pad(B), 'S': pad(client_S), 'K': K, 'M1': M1, 'M2': M2}


def vectors():
    p = pair_vectors()
    names = ('own_seed', 'own_public', 'own_identifier', 'ctrl_seed', 'ctrl_public',
             'ctrl_identifier', 'own_ephemeral_secret', 'm1', 'm2', 'm3', 'm4',
             'accessory_read_key', 'accessory_write_key')
    out = {'pv_'+name: p[name] for name in names}
    salt = bytes.fromhex('beb25379d1a8581eb5a727673a2441ee')
    a = int.from_bytes(p['ctrl_ephemeral_secret'], 'big')
    b = int.from_bytes(p['own_ephemeral_secret'], 'big')
    srp = transcript(salt, a, b)
    out['N'] = pad(N)
    out.update(srp)
    key = hkdf(srp['K'], b'Pair-Setup-Encrypt-Salt', b'Pair-Setup-Encrypt-Info')
    out['encrypt_key'] = key
    ctrl_sign = hkdf(srp['K'], b'Pair-Setup-Controller-Sign-Salt', b'Pair-Setup-Controller-Sign-Info')
    own_sign = hkdf(srp['K'], b'Pair-Setup-Accessory-Sign-Salt', b'Pair-Setup-Accessory-Sign-Info')
    ctrl = Ed25519PrivateKey.from_private_bytes(p['ctrl_seed'])
    own = Ed25519PrivateKey.from_private_bytes(p['own_seed'])
    c_sig = ctrl.sign(ctrl_sign + p['ctrl_identifier'] + p['ctrl_public'])
    a_sig = own.sign(own_sign + p['own_identifier'] + p['own_public'])
    m5 = tlv([(1, p['ctrl_identifier']), (3, p['ctrl_public']), (10, c_sig)])
    m6 = tlv([(1, p['own_identifier']), (3, p['own_public']), (10, a_sig)])
    out.update({
        'setup_1': tlv([(6, b'\x01'), (0, b'\x00')]),
        'setup_2': tlv([(6, b'\x02'), (3, srp['B']), (2, salt)]),
        'setup_3': tlv([(6, b'\x03'), (3, srp['A']), (4, srp['M1'])]),
        'setup_4': tlv([(6, b'\x04'), (4, srp['M2'])]),
        'setup_5': tlv([(6, b'\x05'), (5, ChaCha20Poly1305(key).encrypt(bytes(4)+b'PS-Msg05', m5, b''))]),
        'setup_6': tlv([(6, b'\x06'), (5, ChaCha20Poly1305(key).encrypt(bytes(4)+b'PS-Msg06', m6, b''))]),
    })
    # Tiny deterministic client exponents below are test-only, never secrets.
    for prefix, ca, sb in [('edge_a', 1, b), ('edge_s', 538, b), ('edge_b', a, 1708)]:
        t = transcript(salt, ca, sb)
        edge = {'edge_a': 'A', 'edge_s': 'S', 'edge_b': 'B'}[prefix]
        if t[edge][0] != 0:
            raise ValueError('Expected leading-zero edge missing')
        out.update({prefix+'_'+name: t[name] for name in ('a', 'b', 'A', 'B', 'K', 'M1', 'M2')})
    return out


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--find-edges':
        p = pair_vectors();salt = bytes.fromhex('beb25379d1a8581eb5a727673a2441ee')
        a, b = (int.from_bytes(p[x], 'big') for x in ('ctrl_ephemeral_secret', 'own_ephemeral_secret'))
        for name in ('A', 'S', 'B'):
            for i in range(1, 10000):
                t = transcript(salt, a if name == 'B' else i, i if name == 'B' else b)
                if t[name][0] == 0:
                    print(name, i)
                    break
            else:
                raise ValueError('No edge found')
        return
    expected = vectors()
    if len(sys.argv) == 2 and sys.argv[1] == '--emit':
        print('# PUBLIC deterministic SRP / pair-setup data, NEVER production credentials.')
        print('# Python integer client/server agreement + PyCA Ed25519/AEAD/HKDF.')
        for name, value in expected.items():
            print(name+'='+value.hex())
        return
    if len(sys.argv) != 2:
        raise SystemExit('Usage: check_setup_vectors.py FIXTURE | --emit | --find-edges')
    actual = {}
    for line in Path(sys.argv[1]).read_text(encoding='ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        name, value = line.split('=', 1)
        if name in actual:
            raise ValueError('Duplicate vector: '+name)
        actual[name] = bytes.fromhex(value)
    if actual != expected:
        raise ValueError('Setup fixture differs from independent reference')
    print(f'PASS: {len(expected)} SRP/setup fixture values independently reproduced')


if __name__ == '__main__':
    main()
