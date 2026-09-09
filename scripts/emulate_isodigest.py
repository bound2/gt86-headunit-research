"""Run the pinned isodigest ARM computation with an in-memory libc/ISO model.

No guest syscall, host pathname, shell command, or hardware access is forwarded.
This is an analysis harness, not a QNX system emulator or an installer.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/python-libs'))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

BINARY = ROOT / 'extracted/qnx-system-v3/image-120000/usr/bin/isodigest'
PIN = 'b7d99165bbd5865b32f2028c8332da8828904aee9f611ddd1db3544e75ac6aa6'
IMPORTS = ['printf', '_init_array', '__cxa_begin_cleanup', '_preinit_array',
           'memcpy', 'puts', '__cxa_finalize', 'malloc', 'lseek', 'abort',
           'fprintf', '__deregister_frame_info', 'read', '__cxa_type_match',
           'realloc', 'memcmp', '_init_libc', 'fopen', 'getopt', 'memset',
           'open64', '_fini_array', 'strcmp', '__gnu_Unwind_Find_exidx',
           'atexit', 'fputc', 'fwrite', 'exit', 'strlen', '__register_frame_info', 'free']


class DigestEmulator:
    def __init__(self, iso):
        binary = BINARY.read_bytes()
        if hashlib.sha256(binary).hexdigest() != PIN:
            raise ValueError('isodigest binary does not match pinned addresses')
        self.iso = iso
        self.position = 0
        self.output = bytearray()
        self.stderr = bytearray()
        self.heap = 0x1000000
        self.allocations = {}
        self.calls = collections.Counter()
        self.entries = []
        self.reads = []
        self.options = iter([ord('d'), -1])
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.u.mem_map(0x100000, 0x10000)
        phoff = struct.unpack_from('<I', binary, 28)[0]
        phsize, phnum = struct.unpack_from('<HH', binary, 42)
        for i in range(phnum):
            kind, offset, address, _, size, _, _, _ = struct.unpack_from('<8I', binary, phoff + i * phsize)
            if kind == 1:
                self.u.mem_write(address, binary[offset:offset+size])
        self.u.mem_map(0x200000, 0x1000)
        self.u.mem_map(0x1000000, 0x4000000)
        self.u.mem_map(0x7000000, 0x100000)
        for i in range(len(IMPORTS)):
            self.write32(0x10b828 + i * 4, 0x200000 + i * 4)
            self.u.mem_write(0x200000+i*4, bytes.fromhex('1eff2fe1'))
        self.u.hook_add(UC_HOOK_CODE, self.import_call, begin=0x200000, end=0x200000+4*len(IMPORTS)-1)
        self.u.hook_add(UC_HOOK_CODE, self.record_entry, begin=0x102728, end=0x102728)
        self.u.hook_add(UC_HOOK_INTR, self.reject_interrupt)
        args = [self.string(x) for x in ['isodigest', '-d', 'input.iso']]
        argv = self.allocate(16)
        for i, a in enumerate(args):
            self.write32(argv + i*4, a)
        self.write32(0x10b910, 2)  # optind, following the mocked -d option
        self.u.reg_write(UC_ARM_REG_R0, 3)
        self.u.reg_write(UC_ARM_REG_R0+1, argv)
        self.u.reg_write(UC_ARM_REG_SP, 0x70ff000)
        self.u.reg_write(UC_ARM_REG_LR, 0x200800)

    def write32(self, p, n):
        self.u.mem_write(p, struct.pack('<I', n & 0xffffffff))

    def uint(self, p, size=4):
        return int.from_bytes(self.u.mem_read(p, size), 'little')

    def allocate(self, size):
        if size > 0x1000000 or self.heap+size >= 0x5000000:
            raise ValueError('Emulated allocation limit exceeded')
        p = self.heap
        self.heap += (max(size, 1)+15) & ~15
        self.allocations[p] = size
        return p

    def string(self, s):
        b = s.encode()+b'\0'
        p = self.allocate(len(b))
        self.u.mem_write(p, b)
        return p

    def cstring(self, p):
        result = bytearray()
        for i in range(65536):
            b = self.uint(p+i, 1)
            if not b:
                return bytes(result)
            result.append(b)
        raise ValueError('Unterminated guest string')

    def reg(self, i):
        if i < 4:
            return self.u.reg_read(UC_ARM_REG_R0+i)
        return self.uint(self.u.reg_read(UC_ARM_REG_SP)+(i-4)*4)

    def format(self, pointer, index):
        fmt = self.cstring(pointer).decode('ascii')
        def subst(m):
            nonlocal index
            token = m.group()
            if token == '%%':
                return '%'
            wide = 'll' in token or 'j' in token
            if wide:
                index = (index+1) & ~1
            value = self.reg(index)
            index += 1
            bits = 32
            if wide:
                value |= self.reg(index) << 32
                index += 1
                bits = 64
            kind = token[-1]
            if kind == 's':
                return self.cstring(value).decode('latin1')
            if kind == 'c':
                return chr(value & 255)
            if kind in 'di' and value & (1 << (bits-1)):
                value -= 1 << bits
            converted = re.sub(r'll|[ljz]', '', token)
            if kind == 'u':
                converted = converted[:-1]+'d'
            return converted % value
        return re.sub(r'%(?:%|[-+ #0]*\d*(?:\.\d+)?(?:ll|[ljz])?[diuxXosc])', subst, fmt).encode('latin1')

    def record_entry(self, uc, address, size, user):
        p = self.reg(2)
        self.entries.append(dict(path=self.cstring(self.uint(p+124)).decode('latin1'),
                                 offset=self.uint(p+24,8), size=self.uint(p+32,8)))

    def reject_interrupt(self, uc, number, user):
        raise RuntimeError(f'Guest syscall/interrupt rejected: {number}')

    def import_call(self, uc, address, size, user):
        name = IMPORTS[(address-0x200000)//4]
        self.calls[name] += 1
        a,b,c,d = [self.reg(i) for i in range(4)]
        result = 0
        if name == 'getopt':
            result = next(self.options)
        elif name == 'open64':
            if self.cstring(a) != b'input.iso' or b != 0:
                raise ValueError('Guest attempted an unexpected open')
            result = 3
        elif name == 'read':
            if a != 3 or c > 0x100000:
                raise ValueError('Unexpected read')
            data = bytes(self.iso[self.position:self.position+c])
            self.reads.append([self.position, len(data)])
            self.position += len(data)
            if data:
                uc.mem_write(b, data)
            result = len(data)
        elif name == 'lseek':
            if a != 3 or c not in (0,1,2):
                raise ValueError('Unexpected seek')
            signed = b if b < 0x80000000 else b-0x100000000
            self.position = [0, self.position, len(self.iso)][c]+signed
            if not 0 <= self.position <= len(self.iso):
                raise ValueError('Seek outside ISO')
            result = self.position
        elif name in ('malloc','realloc'):
            result = self.allocate(a if name == 'malloc' else b)
            if name == 'realloc' and a:
                uc.mem_write(result, bytes(uc.mem_read(a, min(b,self.allocations[a]))))
        elif name == 'free':
            if a and a not in self.allocations:
                raise ValueError('Unexpected free')
        elif name == 'memcpy':
            uc.mem_write(a, bytes(uc.mem_read(b,c)))
            result = a
        elif name == 'memset':
            uc.mem_write(a, bytes([b & 255])*c)
            result = a
        elif name == 'strlen':
            result = len(self.cstring(a))
        elif name in ('strcmp','memcmp'):
            left, right = ((self.cstring(a),self.cstring(b)) if name == 'strcmp'
                           else (bytes(uc.mem_read(a,c)),bytes(uc.mem_read(b,c))))
            result = (left > right)-(left < right)
        elif name in ('fprintf','printf','puts','fputc','fwrite'):
            stream = a if name == 'fprintf' else b if name == 'fputc' else d if name == 'fwrite' else 0x10b8b8
            if name == 'fprintf':
                data = self.format(b,2)
            elif name == 'printf':
                data = self.format(a,1)
            elif name == 'puts':
                data = self.cstring(a)+b'\n'
            elif name == 'fputc':
                data = bytes([a & 255])
            else:
                data = bytes(uc.mem_read(a,b*c))
            if stream not in (0x10b8b8,0x10b914):
                raise ValueError(f'Unexpected output stream {stream:x}')
            (self.output if stream == 0x10b8b8 else self.stderr).extend(data)
            result = c if name == 'fwrite' else len(data)
        elif name == 'exit':
            raise RuntimeError(f'Guest exited early: {a}: {self.stderr.decode(errors="replace")}')
        else:
            raise RuntimeError(f'Unimplemented guest import: {name}')
        uc.reg_write(UC_ARM_REG_R0, result & 0xffffffff)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def run(self):
        self.u.emu_start(0x102bf4, 0x200800, timeout=45_000_000, count=100_000_000)
        if self.u.reg_read(UC_ARM_REG_PC) != 0x200800 or self.reg(0) != 0:
            raise RuntimeError('Digest emulation failed or exceeded limits')
        return bytes(self.output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('iso',type=Path)
    parser.add_argument('output',type=Path,help='New directory for digest and metadata')
    args = parser.parse_args()
    model = DigestEmulator(args.iso.read_bytes())
    digest = model.run()
    args.output.mkdir()  # Never replace previous evidence.
    (args.output/'digest.txt').write_bytes(digest)
    (args.output/'signature.bin').write_bytes(model.iso[:64])
    result = dict(binary_sha256=PIN,iso_sha256=hashlib.sha256(model.iso).hexdigest(),
                  digest_sha256=hashlib.sha256(digest).hexdigest(),entries=model.entries,
                  imported_calls=dict(model.calls),reads=model.reads,
                  stderr=model.stderr.decode(errors='replace'))
    (args.output/'trace.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(f'Emulated digest: {len(model.entries)} entries, {len(digest)} bytes; {args.output}')


if __name__ == '__main__':
    main()
