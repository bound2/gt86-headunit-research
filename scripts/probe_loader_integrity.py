"""Local, fixed-content integrity experiment; does not create an update ISO.

The sole replacement manifest returns a research marker. Changes to the ISO
exist only in emulator memory. No installation or device access is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import subprocess
import zlib
from emulate_isodigest import DigestEmulator, ROOT


def marker_manifest(original):
    prefix = b"return { research_probe = 'GT86_LOCAL_ONLY' }\n--[["
    suffix = b']]\n'
    n = len(original)-len(prefix)-len(suffix)
    if not 100 <= n <= 2000:
        raise ValueError('Unexpected manifest size for this fixed-content experiment')
    target = zlib.adler32(original)
    required_sum = (target & 65535)-1-sum(prefix)-sum(suffix)
    if not 32*n <= required_sum <= 126*n:
        raise ValueError('Cannot build printable padding for this manifest')
    rng = random.Random(86)
    for attempt in range(2000):
        padding = [32]*n
        remaining = required_sum-32*n
        positions = list(range(n))
        rng.shuffle(positions)
        for pos in positions:
            change = min(remaining, rng.randrange(40,95))
            padding[pos] += change
            remaining -= change
        for pos in positions:
            change = min(remaining,126-padding[pos])
            padding[pos] += change
            remaining -= change
        if remaining:
            continue
        candidate = bytearray(prefix+bytes(padding)+suffix)
        current = zlib.adler32(candidate)
        assert (current & 65535) == (target & 65535)
        delta = ((target >> 16)-(current >> 16)) % 65521
        p,q,r,s = len(prefix),len(prefix)+n-1,len(prefix)+1,len(prefix)+n-3
        inverse = pow(s-r,-1,65521)
        low = max(32-candidate[p],candidate[q]-126)
        high = min(126-candidate[p],candidate[q]-32)
        for first in range(low,high+1):
            second = ((delta-first*(q-p))*inverse) % 65521
            if second > 32760:
                second -= 65521
            if not max(32-candidate[r],candidate[s]-126) <= second <= min(126-candidate[r],candidate[s]-32):
                continue
            altered = candidate.copy()
            altered[p] += first
            altered[q] -= first
            altered[r] += second
            altered[s] -= second
            if b']]' in altered[len(prefix):-len(suffix)]:
                continue
            assert len(altered) == len(original)
            assert zlib.adler32(altered) == target
            return bytes(altered)
    raise RuntimeError('No printable fixed-content test manifest found')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path,help='New evidence directory')
    args = parser.parse_args()
    original_iso = (ROOT/'downloads/6.17.0L/swdl.iso').read_bytes()
    original_manifest = (ROOT/'extracted/swdl/etc/manifest.lua').read_bytes()
    if hashlib.sha256(original_iso).hexdigest() != '8b87658c8963a88245fee68e471ada1c3fb922c1fe636089089415ce0fba9082':
        raise ValueError('Unexpected original ISO')
    base = DigestEmulator(original_iso)
    baseline = base.run()
    matches = [e for e in base.entries if e['path']=='manifest.lua' and
               original_iso[e['offset']:e['offset']+e['size']]==original_manifest]
    if len(matches) != 1:
        raise ValueError('Manifest extent is not unique')
    entry = matches[0]
    marker = marker_manifest(original_manifest)
    altered = bytearray(original_iso)
    altered[entry['offset']:entry['offset']+entry['size']] = marker
    modified = DigestEmulator(altered)
    changed_digest = modified.run()
    if baseline != changed_digest:
        raise RuntimeError('Signed fast-digest text changed')
    # Negative control: a one-byte change without checksum compensation.
    control = bytearray(original_iso)
    control[entry['offset']] ^= 1
    if DigestEmulator(control).run() == baseline:
        raise RuntimeError('Negative control failed to change fast digest')
    args.output.mkdir()
    (args.output/'marker-manifest.lua').write_bytes(marker)
    (args.output/'original.digest').write_bytes(baseline)
    (args.output/'modified.digest').write_bytes(changed_digest)
    (args.output/'original.signature').write_bytes(original_iso[:64])
    openssl = Path('C:/Program Files/Git/usr/bin/openssl.exe')
    for name in ['original','modified']:
        result = subprocess.run([str(openssl),'dgst','-sha256','-verify',
            str(ROOT/'extracted/qnx-system-v3/image-8/etc/keys/apps.pub'),
            '-signature',str(args.output/'original.signature'),str(args.output/(name+'.digest'))],
            capture_output=True,check=True)
        if result.stdout.strip() != b'Verified OK':
            raise RuntimeError('Unexpected signature verification output')
    lua = ROOT/'build/lua-host/Release/lua.exe'
    loader = ROOT/'extracted/qnx-system-v3/image-380000/usr/share/lua/service/swdlMediaDetect/loader.lua'
    if hashlib.sha256(loader.read_bytes()).hexdigest() != '3fcfa1ff457b99d4cb28f6a589ccf8666716feccc849e9bdc134b474651dd214':
        raise ValueError('Unexpected resident loader source')
    run = subprocess.run([str(lua),str(ROOT/'tests/resident_loader_probe.lua'),str(loader),
                          str(args.output/'marker-manifest.lua')],capture_output=True,check=True)
    (args.output/'loader-mock.txt').write_bytes(run.stdout)
    stored_hash = original_iso[64:96].hex()
    actual_hash = hashlib.sha256(altered[32768:]).hexdigest()
    if stored_hash == actual_hash:
        raise RuntimeError('Full payload hash unexpectedly unchanged')
    summary = dict(experiment='Fixed harmless manifest, in-memory ISO only',
                   original_iso_sha256=hashlib.sha256(original_iso).hexdigest(),
                   manifest_extent=entry,marker_sha256=hashlib.sha256(marker).hexdigest(),
                   original_adler32=f'{zlib.adler32(original_manifest):08x}',
                   modified_adler32=f'{zlib.adler32(marker):08x}',
                   fast_digest_identical=True,existing_signature_verifies_both=True,
                   uncompensated_mutation_rejected=True,stored_payload_sha256=stored_hash,
                   modified_payload_sha256=actual_hash,full_payload_hash_matches=False,
                   resident_loader_mock=run.stdout.decode().strip(),
                   modified_iso_written=False,car_tested=False)
    (args.output/'result.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8')
    print(json.dumps(summary,indent=2))


if __name__ == '__main__':
    main()
