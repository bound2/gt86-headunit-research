"""Read-only inspection of SHA256-pinned Toyota Apple-authentication/media modules.

No vendor program is loaded by the host OS. Optional LLVM disassembly receives
an in-memory copy with the stripped section-directory fields cleared, allowing
LLVM to use PT_LOAD segments. All original code/data and files are unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "extracted/qnx-system-v3/image-380000"
PINS = {
    "i2c": ("lib/dll/iofs-i2c-ipod.so", "f7791854a0fd94a9eaa85159291007ffb49c07ea49a7e66253c5aa07df8919e6"),
    "ipod": ("lib/dll/iofs-ipod.so", "f0598ab13b10ad77fca2a309a484453512c0c9094ff726de77d54416c74cf629"),
    "media": ("usr/sbin/io-fs-media", "92c92ef5a41c1a4ed15ab7bc89167b94def45a31d526afe5ca6c6f4214f4a6c5"),
}
LLVM = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin/llvm-objdump.exe")


class PinnedElf:
    def __init__(self, module):
        name, self.sha256 = PINS[module]
        self.path = DIRECTORY / name
        self.data = self.path.read_bytes()
        if hashlib.sha256(self.data).hexdigest() != self.sha256:
            raise ValueError(f"Not the pinned research input: {self.path}")
        if self.data[:7] != b"\x7fELF\x01\x01\x01":
            raise ValueError("Expected little-endian ELF32")
        phoff = struct.unpack_from("<I", self.data, 28)[0]
        phsize, phnum = struct.unpack_from("<HH", self.data, 42)
        if phsize != 32 or phnum > 16:
            raise ValueError("Unexpected program headers")
        self.segments = [struct.unpack_from("<8I", self.data, phoff + i * phsize)
                         for i in range(phnum)]
        self.dynamic = {}
        for kind, offset, _, _, size, _, _, _ in self.segments:
            if kind == 2:
                for pos in range(offset, offset + size, 8):
                    tag, value = struct.unpack_from("<II", self.data, pos)
                    if tag == 0:
                        break
                    self.dynamic[tag] = value

    def offset(self, address, size=1):
        for kind, offset, start, _, length, _, _, _ in self.segments:
            if kind == 1 and start <= address and address + size <= start + length:
                return offset + address - start
        raise ValueError(f"Address outside file-backed segments: {address:#x}+{size}")

    def uint(self, address):
        return struct.unpack_from("<I", self.data, self.offset(address, 4))[0]

    def string(self, address):
        offset = self.offset(address)
        end = self.data.index(0, offset, min(offset + 4096, len(self.data)))
        return self.data[offset:end].decode("ascii")

    def symbol(self, index):
        address = self.dynamic[6] + index * 16
        name, value, size, info, _, section = struct.unpack_from(
            "<IIIBBH", self.data, self.offset(address, 16))
        return dict(name=self.string(self.dynamic[5] + name), value=value,
                    size=size, info=info, section=section)

    def relocations(self):
        for addr_tag, size_tag in ((17, 18), (23, 2)):
            for address in range(self.dynamic[addr_tag],
                                 self.dynamic[addr_tag] + self.dynamic[size_tag], 8):
                target, info = struct.unpack_from("<II", self.data, self.offset(address, 8))
                yield target, info & 255, self.symbol(info >> 8)

    def metadata(self):
        return dict(path=self.path.relative_to(ROOT).as_posix(), sha256=self.sha256,
                    plt_got=hex(self.dynamic[3]), imports=[
                        dict(slot=hex(target), symbol=symbol["name"])
                        for target, kind, symbol in self.relocations() if kind == 22])

    def disassemble(self, llvm, start, stop):
        if start < 0 or start >= stop or stop - start > 0x10000:
            raise ValueError("Choose a nonempty range of at most 64 KiB")
        self.offset(start, stop - start)
        adapted = bytearray(self.data)
        struct.pack_into("<I", adapted, 32, 0)  # e_shoff
        struct.pack_into("<HH", adapted, 48, 0, 0)  # e_shnum, e_shstrndx
        result = subprocess.run(
            [str(llvm), "-D", "--mcpu=cortex-a8", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", "-"], input=adapted, capture_output=True,
            timeout=20, check=True)
        return ("# Analysis-only header adaptation in memory; original input unchanged.\n"
                f"# {self.path.name} SHA256 {self.sha256}\n"
                + result.stderr.decode("utf-8", errors="replace")
                + result.stdout.decode("utf-8", errors="replace"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=PINS, default="i2c")
    parser.add_argument("--disassemble", action="store_true")
    parser.add_argument("--llvm", type=Path, default=LLVM)
    parser.add_argument("--start", type=lambda s: int(s, 0))
    parser.add_argument("--stop", type=lambda s: int(s, 0))
    parser.add_argument("--output", type=Path, help="New evidence file; never overwritten")
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise FileExistsError(args.output)
    elf = PinnedElf(args.module)
    if args.disassemble:
        defaults = {"i2c": (0x600, 0xABC), "ipod": (0x2F58, 0x41A0),
                    "media": (0x115870, 0x115930)}[args.module]
        rendered = elf.disassemble(args.llvm, defaults[0] if args.start is None else args.start,
                                  defaults[1] if args.stop is None else args.stop)
    else:
        evidence = elf.metadata()
        if args.module == "i2c":
            evidence["descriptor"] = {
                "address": "0x1c28", "name": elf.string(elf.uint(0x1C28)),
                "constant_value": elf.uint(0x1C2C),
                "next_name": elf.string(elf.uint(0x1C30)),
                "context_size": elf.uint(0x1C34),
            }
            evidence["callbacks"] = {
                name: hex(elf.uint(address)) for name, address in (
                    ("initialize", 0x1D98), ("control_lock", 0x1D9C),
                    ("read_register", 0x1DA0), ("write_register", 0x1DA4),
                    ("ready_unsupported", 0x1DA8), ("describe", 0x1DAC))}
        elif args.module == "ipod":
            evidence["driver_description"] = {
                "module": "0x356f8", "interface": hex(elf.uint(0x3571C)),
                "interface_name": elf.string(elf.uint(0x38A20)),
                "describe_slot": "0x38a5c", "describe": hex(elf.uint(0x38A5C)),
                "cached_auth_description": "0x2f90",
            }
        elif args.module == "media":
            names = {"mount_create", "mount_info_io", "node_get", "hier_build", "iface_find", "attr_attach"}
            evidence["exports"] = {
                symbol["name"]: dict(address=hex(symbol["value"]), size=symbol["size"])
                for symbol in (elf.symbol(i) for i in range(elf.uint(elf.dynamic[4] + 4)))
                if symbol["section"] and symbol["name"] in names}
            evidence["information_path_components"] = [elf.string(a) for a in (0x120D64, 0x120D70)]
        rendered = json.dumps(evidence, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            output.write(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
