"""Bounded ARM replay of selected network query, index and address helpers.

Socket, ioctl, strings and vector validation are synthetic. No native socket,
USB operation, factory service, route event thread or actual phone is exercised.
"""
import json
import struct

from inspect_network_identity import ROOT, PINS, PinnedElf
from probe_ipod_auth import AuthProbe, RETURN, require
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

BASE = 0x200000
ENTRIES = dict(query=0x7A07C, find=0x8061C, address=0xCC9D0)


class NetworkProbe:
    allocate = AuthProbe.allocate
    allocate_bytes = AuthProbe.allocate_bytes
    read = AuthProbe.read
    uint = AuthProbe.uint
    write32 = AuthProbe.write32
    arg = AuthProbe.arg
    stub = AuthProbe.stub
    on_interrupt = AuthProbe.on_interrupt
    string = AuthProbe.string

    def __init__(self, *, socket_failure=False, ioctl_failure=False, iftype=6, link=2, mtu=1500):
        self.elf = PinnedElf("network", pins=PINS, directory=ROOT)
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.imports, self.events = {}, []
        self.heap = 0x500100
        self.socket_failure, self.ioctl_failure = socket_failure, ioctl_failure
        require(0 <= iftype <= 255 and 0 <= link <= 0xFFFFFFFF and 0 <= mtu <= 0xFFFFFFFF,
                "Mock ioctl value bounds")
        self.iftype, self.link, self.mtu = iftype, link, mtu
        for address, size in ((BASE, 0x170000), (0x400000, 0x10000), (0x500000, 0x100000), (0x700000, 0x10000)):
            self.u.mem_map(address, size)
        for kind, offset, address, _, size, memory, _, _ in self.elf.segments:
            if kind == 1:
                require(size <= memory and address + memory <= 0x170000, "ELF mapping bounds")
                self.u.mem_write(BASE + address, self.elf.data[offset:offset + size])
        for target, kind, symbol in self.elf.relocations():
            if kind == 23:
                value = BASE + self.uint(BASE + target)
            elif kind in (2, 21, 22):
                value = BASE + symbol["value"] if symbol["section"] else self.stub(symbol["name"])
                if kind == 2:
                    value += self.uint(BASE + target)
            else:
                raise ValueError(f"Unexpected selected relocation: {kind}")
            self.write32(BASE + target, value)
        # Intercept these statically linked helpers, never enter the real socket
        # implementation or pretend to implement PAL reference-counted strings.
        self.imports[BASE + 0x116EC4] = "mock_socket"
        self.imports[BASE + 0xE980] = "mock_string_assignment"
        self.interface = self.allocate_bytes(bytes(132) + b"\xA5" * 16)
        self.owner = self.allocate(0x80)
        self.vector = self.owner + 0x64
        self.entries = []
        self.name = self.allocate(4)
        name_data = self.allocate_bytes(bytes(17) + b"ncm0\0")
        self.write32(self.name, name_data)
        self.address_source = self.allocate_bytes(bytes(28) + b"\xA5" * 16)
        self.address_output = self.allocate_bytes(bytes(32) + b"\xA5" * 16)
        self.u.hook_add(UC_HOOK_CODE, self.on_code)
        self.u.hook_add(UC_HOOK_INTR, self.on_interrupt)

    def call(self, entry, *args):
        require(entry in ENTRIES and len(args) <= 4, "Selected network entry/argument bound")
        for i in range(4):
            self.u.reg_write(UC_ARM_REG_R0 + i, (args[i] if i < len(args) else 0) & 0xFFFFFFFF)
        self.u.reg_write(UC_ARM_REG_SP, 0x70FFF0)
        self.u.reg_write(UC_ARM_REG_LR, RETURN)
        self.u.emu_start(BASE + ENTRIES[entry], RETURN, timeout=1_000_000, count=10_000)
        require(self.u.reg_read(UC_ARM_REG_PC) == RETURN, "Guest instruction/time budget exceeded")
        require(self.read(self.interface + 132, 16) == b"\xA5" * 16 and
                self.read(self.address_output + 32, 16) == b"\xA5" * 16, "Output canary changed")
        return self.u.reg_read(UC_ARM_REG_R0)

    def on_code(self, uc, address, size, user):
        if address not in self.imports:
            ranges = ((0xD980, 0xE8C8), (0x7A07C, 0x7A324), (0x7A464, 0x7A488),
                      (0x7D5C8, 0x7D5DC), (0x7D61C, 0x7D62C), (0x7D674, 0x7D67C),
                      (0x7D774, 0x7D77C), (0x8061C, 0x80674), (0xCC9D0, 0xCCA14))
            require(any(a <= address - BASE < b for a, b in ranges), "Execution outside selected network helpers")
            return
        require(len(self.events) < 64, "Mock event bound")
        name = self.imports[address]
        a, b, c = [self.arg(i) for i in range(3)]
        event, result = dict(op=name), 0
        if name == "mock_socket":
            require((a, b, c) == (2, 2, 0), "Only mock IPv4 query socket allowed")
            result = -1 if self.socket_failure else 7
        elif name == "StarRec_PAL_memset":
            require(0x700000 <= a <= 0x710000 - c and b == 0 and c == 144, "Mock ifreq bounds")
            self.u.mem_write(a, bytes(c))
            result = a
        elif name == "StarRec_PAL_strcpy":
            data = self.string(b).encode("ascii")
            require(b == self.uint(self.name) + 17 and len(data) <= 15 and
                    0x700000 <= a <= 0x710000 - 144, "Mock interface-name copy")
            self.u.mem_write(a, data + b"\0")
            result = a
        elif name == "ioctl":
            require(a == 7 and b == 0xC0906980 and 0x700000 <= c <= 0x710000 - 144,
                    "Only mock interface-data ioctl allowed")
            event["interface"] = self.string(c)
            if self.ioctl_failure:
                result = -1
            else:
                self.u.mem_write(c + 16, bytes([self.iftype]))
                self.write32(c + 20, self.link)
                self.write32(c + 24, self.mtu)
        elif name == "mock_string_assignment":
            require(a == self.interface + 0x58 and b == self.name, "Mock string ownership")
            self.write32(a, self.uint(b))
            result = a
        elif name == "close":
            require(a == 7, "Mock socket close identity")
        elif name == "StarRec_TraceOut_trace":
            pass  # Record only, no logger or formatting call reaches the host.
        elif name == "_ZNK3PAL11CVectorBase8checkGetEij":
            require(a == self.vector and 0 <= b < len(self.entries) <= 8 and c == 0x3AF,
                    "Synthetic vector access bound")
            result = 1
        elif name == "memcpy":
            require(a == self.address_output and b == self.address_source and c in (16, 28),
                    "Selected sockaddr copy bounds")
            self.u.mem_write(a, self.read(b, c))
            event["bytes"] = c
            result = a
        else:
            raise RuntimeError(f"Unexpected guest import: {name}")
        self.events.append(event)
        self.u.reg_write(UC_ARM_REG_R0, result & 0xFFFFFFFF)
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def make_interfaces(self, indices):
        require(not self.entries and len(indices) <= 8, "Synthetic interface bound")
        for index in indices:
            require(index is None or 0 <= index <= 0xFFFFFFFF, "Synthetic index bound")
            item = 0 if index is None else self.allocate(132)
            if item:
                self.write32(item + 0x5C, index)
            self.entries.append(item)
        pairs = self.allocate_bytes(b"".join(struct.pack("<II", 0, item) for item in self.entries))
        for offset, value in ((0, len(indices)), (4, len(indices)), (8, pairs)):
            self.write32(self.vector + offset, value)


def scenarios():
    p = NetworkProbe()
    require(p.call("query", p.owner, p.name, p.interface) == 1, "Mock query succeeds")
    query = dict(events=p.events, iftype=p.uint(p.interface + 0x60),
                 link=p.read(p.interface + 0x79, 1).hex(), mtu=p.uint(p.interface + 0x80),
                 address_count=p.uint(p.interface + 0x6C), index=p.uint(p.interface + 0x5C))
    p = NetworkProbe()
    p.make_interfaces([None, 7, 7])
    require(p.call("find", p.owner, 7) == p.entries[1], "First matching cached index")
    return dict(query=query, duplicate_index="first match; no USB generation or session comparison",
                actual_phone_or_target_verified=False)


if __name__ == "__main__":
    print(json.dumps(scenarios(), indent=2))
