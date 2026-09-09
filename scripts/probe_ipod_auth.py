"""Exercise pinned ARM iPod authentication routines with a synthetic I2C bus.

All imports, register transfers, timing, logging and outbound iPod messages are
intercepted. No guest operation reaches a host device, process, network or file.
The synthetic certificate and signature are arbitrary bytes, not credentials.
Requires the existing build/python-libs Unicorn 2.1.4 analysis dependency.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from inspect_ipod_auth import PinnedElf, ROOT
sys.path.insert(0, str(ROOT / "build/python-libs"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

BASES = {"i2c": 0x100000, "ipod": 0x200000}
RETURN = 0x40FFFC


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class AuthProbe:
    def __init__(self, identity=b"\x03\x05\x02\x00", certificate_size=257,
                 signature_size=64, fail_register=None, status=0x10,
                 bus_error=0, open_error=0, options="speed=40000", fail_read_register=None):
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.imports = {}
        self.events = []
        self.time = 0
        self.heap = 0x500100
        self.errno = 0x500000
        self.identity = identity
        self.certificate_size = certificate_size
        self.certificate = bytes((i * 17 + 3) % 256 for i in range(certificate_size))
        self.signature = bytes((i * 7 + 9) % 256 for i in range(signature_size))
        self.fail_register = fail_register
        self.fail_read_register = fail_read_register
        self.status = status
        self.bus_error = bus_error
        self.open_error = open_error
        self.options = iter(options.split(",") if options else [])
        self.signed_challenge = None
        self.sent = []
        self.u.mem_map(0x400000, 0x10000)
        self.u.mem_map(0x500000, 0x100000)
        self.u.mem_map(0x700000, 0x10000)
        self.inputs = {}
        for module, base in BASES.items():
            elf = PinnedElf(module)
            self.inputs[elf.path.name] = elf.sha256
            self.u.mem_map(base, 0x100000)
            for kind, offset, address, _, size, _, _, _ in elf.segments:
                if kind == 1:
                    self.u.mem_write(base + address, elf.data[offset:offset + size])
            for target, kind, symbol in elf.relocations():
                if kind == 23:  # R_ARM_RELATIVE
                    value = base + self.uint(base + target)
                elif kind in (2, 21, 22):  # ABS32 / GLOB_DAT / JUMP_SLOT
                    if symbol["name"] == "ipod_log":
                        value = self.stub(symbol["name"])  # Intercept internal logger too.
                    elif symbol["section"]:
                        value = base + symbol["value"]
                    else:
                        value = self.stub(symbol["name"])
                    if kind == 2:
                        value += self.uint(base + target)
                else:
                    raise ValueError(f"Unexpected relocation {kind}")
                self.write32(base + target, value)
        self.context = self.allocate(0x880)
        self.owner = self.allocate(0x300)
        self.device = self.allocate(0x300)
        self.options_pointer = self.allocate_bytes(options.encode() + b"\0")
        self.write32(self.context + 0x14, self.owner)
        self.write32(self.owner + 0x54, self.context)
        self.write32(self.device + 4, self.owner)
        self.write32(self.context + 0x0C, BASES["i2c"] + 0x1BE4)
        for field, callback in ((0x30, 0x8D4), (0x34, 0x840), (0x38, 0x798),
                                (0x3C, 0x6E4), (0x40, 0x6CC), (0x44, 0x600)):
            self.write32(self.context + field, BASES["i2c"] + callback)
        self.u.hook_add(UC_HOOK_CODE, self.on_code)
        self.u.hook_add(UC_HOOK_INTR, self.on_interrupt)

    def allocate(self, size):
        require(0 <= size <= 0x10000 and self.heap + size < 0x600000, "Guest allocation bound")
        address = self.heap
        self.heap += (max(size, 1) + 15) & ~15
        return address

    def allocate_bytes(self, data):
        address = self.allocate(len(data))
        if data:
            self.u.mem_write(address, data)
        return address

    def read(self, address, size):
        require(0 <= size <= 8192, "Guest read size bound")
        return bytes(self.u.mem_read(address, size)) if size else b""

    def uint(self, address):
        return int.from_bytes(self.read(address, 4), "little")

    def write32(self, address, value):
        self.u.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def string(self, address):
        for size in range(4096):
            if self.read(address + size, 1) == b"\0":
                return self.read(address, size).decode("ascii")
        raise ValueError("Unterminated guest string")

    def arg(self, index):
        return (self.u.reg_read(UC_ARM_REG_R0 + index) if index < 4 else
                self.uint(self.u.reg_read(UC_ARM_REG_SP) + (index - 4) * 4))

    def stub(self, name):
        for address, existing in self.imports.items():
            if name == existing:
                return address
        address = 0x400000 + len(self.imports) * 4
        require(address < RETURN, "Import stub bound")
        self.imports[address] = name
        return address

    def on_interrupt(self, uc, number, user):
        raise RuntimeError(f"Guest syscall/interrupt forbidden: {number}")

    def call(self, module, offset, *args):
        require(len(args) <= 4, "Only register arguments allowed at entry")
        for i in range(4):
            self.u.reg_write(UC_ARM_REG_R0 + i, args[i] if i < len(args) else 0)
        self.u.reg_write(UC_ARM_REG_SP, 0x70FFF0)
        self.u.reg_write(UC_ARM_REG_LR, RETURN)
        self.u.emu_start(BASES[module] + offset, RETURN, timeout=5_000_000, count=300_000)
        require(self.u.reg_read(UC_ARM_REG_PC) == RETURN, "Guest instruction/time budget exceeded")
        return self.u.reg_read(UC_ARM_REG_R0)

    def register_read(self, register, size):
        require(0 <= size <= 2048, "Synthetic register read bound")
        if register in (self.fail_register, self.fail_read_register):
            return None
        if register == 0:
            data = self.identity
        elif register == 0x30:
            data = self.certificate_size.to_bytes(2, "big")
        elif 0x31 <= register <= 0x40:
            offset = (register - 0x31) * 128
            data = self.certificate[offset:offset + 128]
        elif register in (4, 6):
            data = b"\x12\x34\x56\x78"
        elif register == 0x10:
            data = bytes([self.status])
        elif register == 0x11:
            data = len(self.signature).to_bytes(2, "big")
        elif register == 0x12:
            data = self.signature
        elif register == 5:
            data = b"\x07"
        else:
            raise RuntimeError(f"Unexpected synthetic register: {register:#x}")
        require(len(data) >= size, f"Insufficient synthetic data for {register:#x}: {size}")
        return data[:size]

    def vector(self, address, index):
        base, size = struct.unpack("<II", self.read(address + 8 * index, 8))
        return base, size

    def devctlv(self):
        fd, command, send_count, recv_count = [self.arg(i) for i in range(4)]
        send, receive, info = [self.arg(i) for i in range(4, 7)]
        require(fd == 7, "Unexpected synthetic fd")
        header, header_size = self.vector(send, 0)
        register_ptr, register_size = self.vector(send, 1)
        require(register_size == 1, "Expected one-byte register selector")
        register = self.read(register_ptr, 1)[0]
        if command == 0xC0140507:
            require((send_count, recv_count, header_size) == (2, 2, 20), "SENDRECV IOV layout")
            address, fmt, slen, rlen, stop = struct.unpack("<5I", self.read(header, 20))
            out, capacity = self.vector(receive, 1)
            require((fmt, slen, stop, capacity) == (2, 1, 1, rlen), "SENDRECV header")
            self.events.append(dict(op="read", address=address, register=register, size=rlen))
            data = self.register_read(register, rlen)
            if data is None:
                return 5
            if data:
                self.u.mem_write(out, data)
            self.write32(info, len(data))
        elif command == 0x80100505:
            require((send_count, recv_count, header_size) == (3, 1, 16), "SEND IOV layout")
            address, fmt, length, stop = struct.unpack("<4I", self.read(header, 16))
            pointer, size = self.vector(send, 2)
            require((fmt, length, stop) == (2, size + 1, 1), "SEND header")
            data = self.read(pointer, size)
            self.events.append(dict(op="write", address=address, register=register, data=data.hex()))
            if register == self.fail_register:
                return 5
            if register == 0x20:
                require(len(data) >= 2 and int.from_bytes(data[:2], "big") == len(data) - 2,
                        "Expected combined challenge length/data write")
                self.signed_challenge = data[2:]
            elif register == 0x10:
                require(data == b"\x01", "Expected start-signature command")
            else:
                raise RuntimeError(f"Unexpected synthetic register write: {register:#x}")
            self.write32(info, length)
        else:
            raise RuntimeError(f"Unexpected devctlv: {command:#x}")
        return 0

    def on_code(self, uc, address, size, user):
        if address == BASES["ipod"] + 0x1AE20:
            count = self.arg(4)
            require(self.arg(1) == 0x18, "Only the intercepted legacy signature message is expected")
            payload = self.read(self.arg(3) + 10, count)
            self.sent.append(payload)
            self.events.append(dict(op="legacy_message", command=0x18, size=count,
                                    synthetic_payload_sha256=hashlib.sha256(payload).hexdigest()))
            result = 0
        elif address in self.imports:
            name = self.imports[address]
            a, b, c, d = [self.arg(i) for i in range(4)]
            result = 0
            if name == "__get_errno_ptr":
                result = self.errno
            elif name == "getsubopt":
                option = next(self.options, None)
                if option is None:
                    result = -1
                else:
                    key, value = option.split("=", 1)
                    keys = [self.string(self.uint(b + i * 4)) for i in range(4)]
                    result = keys.index(key)
                    self.write32(c, self.allocate_bytes(value.encode() + b"\0"))
            elif name == "strtol":
                require(b == c == 0, "Unexpected strtol arguments")
                token = self.string(a)
                result = int(token, 16 if token.startswith("0x") else 10)
            elif name == "open":
                require(self.string(a) == "/dev/i2c0" and b == 2, "Unexpected guest open")
                self.events.append(dict(op="mock_open", path="/dev/i2c0"))
                self.write32(self.errno, self.open_error)
                result = -1 if self.open_error else 7
            elif name == "close":
                require(a == 7, "Unexpected close")
                self.events.append(dict(op="mock_close"))
            elif name == "devctl":
                require(a == 7 and self.arg(4) == 0, "Unexpected devctl arguments")
                if b == 0x80040502:
                    require(d == 4, "Bus-speed parameter size")
                    self.events.append(dict(op="bus_speed", value=self.uint(c)))
                    result = self.bus_error
                elif b in (0x508, 0x509):
                    require(c == d == 0, "Lock command parameters")
                    self.events.append(dict(op="lock" if b == 0x508 else "unlock"))
                else:
                    raise RuntimeError(f"Unexpected devctl: {b:#x}")
            elif name == "devctlv":
                result = self.devctlv()
            elif name in ("fs_log", "ipod_log"):
                self.events.append(dict(op="log", format=self.string(c)))
            elif name == "systime_ms":
                self.time += 1
                result = self.time
            elif name == "delay":
                require(a <= 1000, "Unexpected delay")
                self.time += a
                self.events.append(dict(op="mock_delay", milliseconds=a))
            elif name == "xmlbuf_add":
                self.events.append(dict(op="xml", key=self.string(b) if b else None,
                                        value=self.string(c) if c else None))
            elif name == "xmlbuf_addf":
                fmt = self.string(c)
                values = [d, self.arg(4)] if fmt == "%u.%02u" else [d]
                self.events.append(dict(op="xml_field", key=self.string(b), format=fmt,
                                        value=self.string(d) if fmt == "%s" else values))
            else:
                raise RuntimeError(f"Unexpected guest import: {name}")
        else:
            allowed = (BASES["i2c"] + 0x448 <= address < BASES["i2c"] + 0xABC or
                       BASES["ipod"] + 0x280C <= address < BASES["ipod"] + 0x41A0)
            require(allowed, f"Execution outside audited routines: {address:#x}")
            return
        self.u.reg_write(UC_ARM_REG_R0, result & 0xFFFFFFFF)
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def initialize(self):
        return self.call("ipod", 0x3DB8, self.context, self.options_pointer)

    def describe(self):
        self.call("ipod", 0x2F90, self.owner, self.allocate(0x200))

    def sign(self, challenge=b"synthetic challenge"):
        require(1 <= len(challenge) <= 128, "Synthetic challenge bound")
        self.write32(self.device + 0x1D0,
                     self.allocate_bytes(len(challenge).to_bytes(2, "big") + challenge))
        return self.call("ipod", 0x3944, self.device)

    def result(self, name, result):
        return dict(name=name, result=result, events=self.events)


def run_checks():
    evidence = []
    p = AuthProbe()
    require(p.initialize() == 0, "Protocol-2 initialization failed")
    require(p.read(p.context + 0x58, 257) == p.certificate, "Certificate copy/paging differs")
    reads = [(e["register"], e["size"]) for e in p.events if e["op"] == "read"]
    require(reads == [(0, 4), (0x30, 2), (0x31, 128), (0x32, 128), (0x33, 1), (4, 4)],
            "Unexpected identity/certificate register sequence")
    before = len(p.events)
    p.describe()
    description = p.events[before:]
    require(all(e["op"] in ("xml", "xml_field") for e in description), "Metadata performed I/O")
    fields = {e["key"]: e["value"] for e in description if e["op"] == "xml_field"}
    require(fields == dict(device=[3], firmware=[5], protocol=[2, 0], devno=[0x12345678],
                           size=[257], addr=[16], path="/dev/i2c0", speed=[40000]),
            "Metadata fields are not the cached synthetic values")
    require(p.sign() == 0 and p.sent == [p.signature], "Synthetic signature not dispatched")
    require(p.signed_challenge == b"synthetic challenge", "Challenge altered")
    require(p.call("ipod", 0x371C, p.device) == 0 and
            not p.uint(p.context + 0x85C), "Caller cleanup failed to release synthetic lock")
    evidence.append(p.result("protocol2_certificate_metadata_and_signature", 0))
    for length in (1, 128, 1920):
        p = AuthProbe(certificate_size=length)
        require(p.initialize() == 0 and p.read(p.context + 0x58, length) == p.certificate,
                "Certificate boundary copy failed")
        before = len(p.events)
        require(p.initialize() == 0 and len(p.events) == before, "Cached init repeated bus I/O")
        evidence.append(p.result(f"certificate_{length}_and_cached_init", 0))
    p = AuthProbe(identity=b"\x03\x05\x01\x00")
    require(p.initialize() == 0, "Legacy protocol-1 identity branch failed")
    require([(e["register"], e["size"]) for e in p.events if e["op"] == "read"] == [(0, 4), (6, 4)],
            "Legacy protocol-1 branch incorrectly fetched certificate")
    evidence.append(p.result("protocol1_identity_no_certificate", 0))
    for identity, name in ((b"\x04\x05\x02\x00", "unknown_device_version"),
                           (b"\x03\x05\x03\x00", "unsupported_protocol_major")):
        p = AuthProbe(identity=identity)
        result = p.initialize()
        require(result == 48 and not p.uint(p.context + 0x18) & 1, name)
        require([e["register"] for e in p.events if e["op"] == "read"] == [0], name + " read past identity")
        evidence.append(p.result(name, result))
    for length in (0, 2049):
        p = AuthProbe(certificate_size=length)
        result = p.initialize()
        require(result == 240, "Invalid certificate length accepted")
        evidence.append(p.result(f"certificate_length_{length}_rejected", result))
    p = AuthProbe(certificate_size=2048)
    require(p.initialize() == 0, "Stock maximum-length behavior changed")
    reads = [e for e in p.events if e["op"] == "read" and 0x31 <= e["register"] <= 0x40]
    require(sum(e["size"] for e in reads) == 1920, "Expected stock 1920-byte paging limit")
    require(p.read(p.context + 0x58 + 1920, 128) == bytes(128), "Unexpected certificate tail")
    evidence.append(p.result("stock_2048_length_reads_only_1920", 0))
    for register, name in ((0x31, "certificate_bus_failure"), (0, "identity_bus_timeout")):
        p = AuthProbe(fail_register=register)
        result = p.initialize()
        require(result != 0 and not p.uint(p.context + 0x18) & 1, name)
        evidence.append(p.result(name, result))
    for kwargs, name in ((dict(open_error=2), "open_failure"),
                         (dict(bus_error=5), "bus_speed_failure")):
        p = AuthProbe(**kwargs)
        result = p.initialize()
        require(result != 0 and not any(e["op"] == "read" for e in p.events), name)
        evidence.append(p.result(name, result))
    for kwargs, expected, name in ((dict(status=0x80), 22, "signature_chip_error"),
                                  (dict(signature_size=1025), 240, "signature_oversized"),
                                  (dict(fail_read_register=0x10), 16, "signature_bus_busy")):
        p = AuthProbe(**kwargs)
        require(p.initialize() == 0, "Signature scenario setup")
        result = p.sign()
        require(result == expected and not p.sent, name)
        evidence.append(p.result(name, result))
    return dict(input_sha256=p.inputs, checks=evidence, scope={
        "firmware": "6.17.0WL, not the installed 6.9.0WL",
        "bus": "Synthetic register bytes and intercepted devctl/devctlv only",
        "timing": "Virtual milliseconds; no physical bus timing tested",
        "native_routines": "Pinned legacy iPod core plus pinned I2C callbacks",
        "phone_messages": "Intercepted before serialization/transport",
        "real_certificate_or_signature": False, "car_tested": False,
        "carplay_authenticated": False, "vendor_file_modified": False,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New JSON evidence file; never overwritten")
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise FileExistsError(args.output)
    evidence = run_checks()
    rendered = json.dumps(evidence, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            output.write(rendered)
    print(f"PASS: {len(evidence['checks'])} pinned ARM authentication checks; synthetic bus only.")
    if not args.output:
        print(rendered, end="")


if __name__ == "__main__":
    main()
