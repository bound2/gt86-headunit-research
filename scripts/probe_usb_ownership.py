"""Bounded ARM replay of selected USB ownership and lifetime routines.

Runs the library/server conflict routines and library counter/abort/close/detach
boundaries with synthetic objects. No actual server dispatcher, kernel, USB I/O,
thread, hardware cancellation, descriptor resolver or host wait is executed.
"""
import json

from inspect_usb_ownership import PINS, ROOT, PinnedElf, inspect
from probe_ipod_auth import AuthProbe, RETURN, require
from probe_ncm_lifecycle import instance
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

LIB_BASE = 0x200000
ENTRIES = dict(conflict=0x371C, synchronise=0x5A0C, abort=0x5E5C, close=0x58B0, detach=0x5F38)


class OwnershipProbe:
    allocate = AuthProbe.allocate
    allocate_bytes = AuthProbe.allocate_bytes
    read = AuthProbe.read
    uint = AuthProbe.uint
    write32 = AuthProbe.write32
    arg = AuthProbe.arg
    stub = AuthProbe.stub
    on_interrupt = AuthProbe.on_interrupt

    def __init__(self, module="usb", command_error=0):
        require(module in ("usb", "server"), "Selected module bound")
        self.elf = PinnedElf(module, pins=PINS, directory=ROOT)
        self.module, self.base = module, LIB_BASE if module == "usb" else 0
        self.globals = LIB_BASE + 0xBAB0 if module == "usb" else 0x121870
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.imports, self.events, self.locks, self.clients = {}, [], set(), []
        self.freed, self.callback_count = [], 0
        self.heap, self.command_error = 0x500100, command_error
        self.device = self.pipe = self.connection = 0
        self.removal_callback = self.stub("mock_removal_callback")
        region = (LIB_BASE, 0x10000) if module == "usb" else (0x100000, 0x30000)
        for address, size in (region, (0x400000, 0x10000), (0x500000, 0x100000), (0x700000, 0x10000)):
            self.u.mem_map(address, size)
        for kind, offset, address, _, size, memory_size, _, _ in self.elf.segments:
            if kind == 1:
                require(size <= memory_size and region[0] <= self.base + address and
                        self.base + address + memory_size <= sum(region), "ELF mapping bound")
                self.u.mem_write(self.base + address, self.elf.data[offset:offset + size])
        for target, kind, symbol in self.elf.relocations():
            if kind == 20 and module == "server":
                # Zero-backed COPY imports are not needed by selected conflict code.
                continue
            if kind == 23:
                value = self.base + self.uint(self.base + target)
            elif kind in (2, 21, 22):
                value = (self.stub(symbol["name"]) if not symbol["section"] or
                         symbol["name"] == "usbdi_sendcmd" else self.base + symbol["value"])
                if kind == 2:
                    value += self.uint(self.base + target)
            else:
                raise ValueError(f"Unexpected selected relocation: {kind}")
            self.write32(self.base + target, value)
        self.u.hook_add(UC_HOOK_CODE, self.on_code)
        self.u.hook_add(UC_HOOK_INTR, self.on_interrupt)

    def call(self, entry, *args):
        require(entry in ENTRIES and len(args) <= 4, "Selected entry/argument bound")
        require(self.module == "usb" or entry == "conflict", "Server replay is conflict-only")
        address = LIB_BASE + ENTRIES[entry] if self.module == "usb" else 0x11661C
        for i in range(4):
            self.u.reg_write(UC_ARM_REG_R0 + i, (args[i] if i < len(args) else 0) & 0xFFFFFFFF)
        self.u.reg_write(UC_ARM_REG_SP, 0x70FFF0)
        self.u.reg_write(UC_ARM_REG_LR, RETURN)
        self.u.emu_start(address, RETURN, timeout=1_000_000, count=10_000)
        require(self.u.reg_read(UC_ARM_REG_PC) == RETURN, "Guest instruction/time budget exceeded")
        require(not self.locks, "Mock lock leaked")
        return self.u.reg_read(UC_ARM_REG_R0)

    def on_code(self, uc, address, size, user):
        if address not in self.imports:
            ranges = ((0x2DB0, 0x34E8), (0x371C, 0x3860), (0x58B0, 0x591C),
                      (0x5A0C, 0x5B28), (0x5E5C, 0x5EFC), (0x5F38, 0x6040))
            allowed = (any(a <= address - LIB_BASE < b for a, b in ranges) if self.module == "usb"
                       else 0x11661C <= address < 0x116758 or 0x102180 <= address < 0x1029CC)
            require(allowed, f"Execution outside selected USB routines: {address:#x}")
            return
        require(len(self.events) < 128, "Guest event budget exceeded")
        name = self.imports[address]
        a, b, c, d = [self.arg(i) for i in range(4)]
        event, result = dict(op=name), 0
        if name in ("pthread_mutex_lock", "pthread_mutex_unlock"):
            require(a == self.globals or any(a == client + 8 for client in self.clients), "Mock mutex identity")
            if name == "pthread_mutex_lock":
                require(a not in self.locks, "Recursive mock lock")
                self.locks.add(a)
            else:
                require(a in self.locks, "Unbalanced mock unlock")
                self.locks.remove(a)
        elif name in ("atomic_add", "atomic_sub", "atomic_set"):
            require(a in (self.device + 0x14, self.pipe + 0xC) and b == 1, "Mock atomic target")
            old = self.uint(a)
            value = old | b if name == "atomic_set" else old + (b if name == "atomic_add" else -b)
            require(0 <= value <= 0xFFFFFFFF, "Mock counter underflow/overflow")
            self.write32(a, value)
            event.update(offset=hex(a - (self.pipe if a == self.pipe + 0xC else self.device)), value=value)
        elif name == "usbdi_sendcmd":
            require(a == 7 and b in (4, 6) and d == 0, "Only mock detach/abort command allowed")
            event.update(command=b, pipe_pending=self.uint(self.pipe + 0xC), device_pending=self.uint(self.device + 0x18))
            if b == 6:
                event.update(identity=self.read(c + 40, 4).hex(), config=self.uint(c + 44),
                             iface=self.uint(c + 48), alternate=self.uint(c + 52), endpoint=self.uint(c + 56))
            result = self.command_error
        elif name == "mock_removal_callback":
            require(a == self.connection and b == self.device + 0x1C and not self.locks, "Removal callback ownership")
            self.callback_count += 1
            event.update(device_pending=self.uint(self.device + 0x18), instance=self.read(b, 36).hex())
        elif name == "free":
            require(a in (self.device, self.pipe) and a not in self.freed, "Mock free ownership")
            self.freed.append(a)
            event["object"] = "device" if a == self.device else "pipe"
        elif name == "delay":
            require(a == 100, "Unexpected native retry delay")
            event["milliseconds_not_slept"] = a
        else:
            raise RuntimeError(f"Unexpected guest import: {name}")
        self.events.append(event)
        self.u.reg_write(UC_ARM_REG_R0, result)
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def client(self, exclusive=True):
        require(len(self.clients) < 8, "Synthetic client bound")
        client = self.allocate(0x80)
        self.write32(client + 0x10, 2 if exclusive else 0)
        self.write32(self.clients[-1] if self.clients else self.globals + 0x24, client)
        self.clients.append(client)
        return client

    def claim(self, client, data):
        require(client in self.clients and len(data) == 36, "Resolved synthetic claim")
        node = self.allocate_bytes(bytes(8) + data + b"\xA5" * 16)
        result = self.call("conflict", node, client)
        require(self.read(node + 8, 36) == data and self.read(node + 44, 16) == b"\xA5" * 16, "Claim bounds")
        return result

    def make_device(self, pending=1, pipe_pending=1):
        require(self.module == "usb" and not self.device, "One synthetic device per library probe")
        self.connection = self.allocate(0x68)
        callbacks = self.allocate(16)
        self.write32(callbacks + 8, self.removal_callback)
        self.write32(self.connection + 0x1C, callbacks)
        self.write32(self.connection + 0x30, 7)
        self.device = self.allocate(72)
        self.pipe = self.allocate(24)
        self.write32(self.connection + 0x38, self.device)
        self.write32(self.connection + 0x3C, self.device)
        for offset, value in ((4, self.connection + 0x38), (8, self.connection),
                              (0xC, self.pipe), (0x10, self.pipe), (0x18, pending)):
            self.write32(self.device + offset, value)
        self.u.mem_write(self.device + 0x1C, instance())
        for offset, value in ((4, self.device + 0xC), (8, self.device), (0xC, pipe_pending), (0x14, 0x81)):
            self.write32(self.pipe + offset, value)


def scenarios():
    cases = []
    for module in ("usb", "server"):
        p = OwnershipProbe(module)
        owner, other = p.client(), p.client()
        require(p.claim(owner, instance()) == 0, "Initial claim")
        same = p.claim(other, instance())
        distinct = p.claim(other, instance(iface=5))
        require((same, distinct) == (16, 0), "Interface-granular conflict")
        cases.append(dict(module=module, same_interface=same, different_interface=distinct))
    p = OwnershipProbe()
    p.make_device()
    require(p.call("synchronise", p.device, 0, 0) == 16 and p.callback_count == 0, "Deferred removal")
    require(p.call("abort", p.pipe) == 0, "Mock abort command")
    require(p.call("detach", p.device) == 16 and not p.freed, "Abort is not a drain")
    # Explicitly simulate retirement; this is NOT real event-thread execution.
    p.write32(p.pipe + 0xC, 0)
    require(p.call("synchronise", p.device, 1, -1) == 0 and p.callback_count == 1, "Last retirement callback")
    require(p.call("detach", p.device) == 0 and p.freed == [p.pipe, p.device], "Retired ownership cleanup")
    cases.append(dict(name="mock_abort_then_explicit_retirement", events=p.events))
    return dict(static=inspect(), cases=cases, live_usb_or_phone_verified=False,
                scope="Selected ARM replay with synthetic claims/counters; no hardware or actual callback race")


if __name__ == "__main__":
    print(json.dumps(scenarios(), indent=2))
