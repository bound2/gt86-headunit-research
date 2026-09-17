"""Bounded PC-only replay of two pinned ARM NCM USB event callbacks.

Only insertion selection/queueing and removal selection/handoff are executed.
All imports and logging are intercepted. No USB device, QNX thread, real lock,
interface, kernel driver, network socket or vendor process is used. Worker,
attach, detach and callback-framework execution remain outside this experiment.
Requires the existing build/python-libs Unicorn analysis dependency.
"""
import json
import struct

from inspect_ncm_lifecycle import (
    CONTROL, INSERTIONS, REMOVALS, DEVICE_LIST, PINS, ROOT, PinnedElf, inspect)
from probe_ipod_auth import AuthProbe, RETURN, require
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

BASE = 0x100000


def instance(path=1, devno=7, generation=3, vendor=0x5AC, product=0x1234,
             dclass=2, subclass=13, protocol=0, config=1, iface=4, alternate=0):
    """QNX 6.5's documented 36-byte instance, with explicitly synthetic values."""
    return struct.pack("<BBH8I", path, devno, generation, vendor, product,
                       dclass, subclass, protocol, config, iface, alternate)


class NcmProbe:
    allocate = AuthProbe.allocate
    allocate_bytes = AuthProbe.allocate_bytes
    read = AuthProbe.read
    uint = AuthProbe.uint
    write32 = AuthProbe.write32
    arg = AuthProbe.arg
    stub = AuthProbe.stub
    on_interrupt = AuthProbe.on_interrupt

    def __init__(self, flags=0, malloc_fail=False, verbose=False):
        self.elf = PinnedElf("ncm", pins=PINS, directory=ROOT)
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.imports, self.events, self.contexts, self.nodes = {}, [], [], []
        self.heap, self.locked = 0x500100, False
        self.malloc_fail = malloc_fail
        self.connection = 0x123400  # Token only: no host handle.
        self.pending, self.removed = [], []
        for address, size in ((BASE, 0x10000), (0x400000, 0x10000),
                              (0x500000, 0x100000), (0x700000, 0x10000)):
            self.u.mem_map(address, size)
        for kind, offset, address, _, size, memory_size, _, _ in self.elf.segments:
            if kind == 1:
                require(size <= memory_size and address + memory_size <= 0x10000, "ELF mapping bound")
                self.u.mem_write(BASE + address, self.elf.data[offset:offset + size])
        for target, kind, symbol in self.elf.relocations():
            if kind == 23:
                value = BASE + self.uint(BASE + target)
            elif kind in (2, 21, 22):
                value = BASE + symbol["value"] if symbol["section"] else self.stub(symbol["name"])
                if kind == 2:
                    value += self.uint(BASE + target)
            else:
                raise ValueError(f"Unexpected NCM relocation: {kind}")
            self.write32(BASE + target, value)
        self.write32(BASE + CONTROL + 4, flags)
        self.write32(BASE + CONTROL + 0xBC, int(verbose))
        self.u.hook_add(UC_HOOK_CODE, self.on_code)
        self.u.hook_add(UC_HOOK_INTR, self.on_interrupt)

    def add_device(self, path, devno):
        """Append a synthetic node in known order; do not run native attachment."""
        require(len(self.nodes) < 16, "Synthetic device-list bound")
        context = self.allocate(0xC40)
        node = self.allocate_bytes(struct.pack("<IIBBH", 0, context, path, devno, 0))
        self.write32(self.nodes[-1] if self.nodes else BASE + DEVICE_LIST, node)
        self.nodes.append(node)
        self.contexts.append(context)
        return context

    def call(self, offset, data):
        require(offset in (0x4F50, 0x515C), "Entry outside audited NCM callbacks")
        require(len(data) == 36, "USB instance size")
        pointer = self.allocate_bytes(data)
        for i, value in enumerate((self.connection, pointer, 0, 0)):
            self.u.reg_write(UC_ARM_REG_R0 + i, value)
        self.u.reg_write(UC_ARM_REG_SP, 0x70FFF0)
        self.u.reg_write(UC_ARM_REG_LR, RETURN)
        self.u.emu_start(BASE + offset, RETURN, timeout=1_000_000, count=10_000)
        require(self.u.reg_read(UC_ARM_REG_PC) == RETURN, "Guest instruction/time budget exceeded")
        require(not self.locked, "Callback returned with mock lock held")
        require(self.read(pointer, 36) == data, "Callback altered input instance")

    def on_code(self, uc, address, size, user):
        if address == BASE + 0xBAB4:
            name = "intercepted_log"
        elif address in self.imports:
            name = self.imports[address]
        else:
            offset = address - BASE
            require(any(start <= offset < stop for start, stop in (
                (0x274C, 0x2D58), (0x4F50, 0x5130), (0x515C, 0x52E8), (0x5424, 0x5448))),
                f"Execution outside audited NCM callbacks: {address:#x}")
            return
        require(len(self.events) < 128, "Guest event budget exceeded")
        a, b, c = [self.arg(i) for i in range(3)]
        event, result = dict(op=name), 0
        if name in ("pthread_mutex_lock", "pthread_mutex_unlock"):
            require(a == BASE + CONTROL + 0x348, "Unexpected mock mutex")
            acquiring = name == "pthread_mutex_lock"
            require(self.locked != acquiring, "Unbalanced mock mutex")
            self.locked = acquiring
        elif name == "malloc":
            require(a == 52, "Unexpected insertion allocation")
            result = 0 if self.malloc_fail else self.allocate_bytes(b"\xA5" * a)
            event.update(size=a, pointer=result)
        elif name == "atomic_add":
            require(a in (BASE + INSERTIONS, BASE + REMOVALS) and b == 1, "Unexpected mock counter")
            self.write32(a, self.uint(a) + b)
            event.update(counter=hex(a - BASE), value=self.uint(a))
        elif name == "stk_context_callback_2":
            require(a == BASE + 0x5310 and c == BASE + CONTROL, "Unexpected queued callback")
            require(not self.locked, "Queued callback under list lock")
            payload = self.read(b, 52)
            require(payload[:8] == b"\xA5" * 8 and payload[44:] == b"\xA5" * 8,
                    "Insertion copy exceeded its 36-byte field")
            self.pending.append(dict(callback=hex(a - BASE), instance=payload[8:44].hex()))
            event.update(self.pending[-1])
        elif name == "dev_remove":
            require(a in self.contexts and not self.locked, "Unexpected removal owner/lock")
            self.removed.append(self.contexts.index(a))
            event["context_index"] = self.removed[-1]
        elif name != "intercepted_log":
            raise RuntimeError(f"Unexpected guest import: {name}")
        self.events.append(event)
        self.u.reg_write(UC_ARM_REG_R0, result)
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def evidence(self):
        return dict(events=self.events, queued=self.pending, removed_context_indices=self.removed,
                    insertion_counter=self.uint(BASE + INSERTIONS), removal_counter=self.uint(BASE + REMOVALS))


def scenarios():
    p = NcmProbe()
    data = instance()
    p.call(0x515C, data)
    require(p.pending == [dict(callback="0x5310", instance=data.hex())], "Insertion copy/queue")
    cases = [dict(name="insertion_copy_and_queue", **p.evidence())]
    for name, options, data in (
        ("scanning_skips", dict(flags=2), instance()),
        ("wrong_class_skips", {}, instance(dclass=3)),
        ("wrong_subclass_skips", {}, instance(subclass=12)),
        ("allocation_failure_skips", dict(malloc_fail=True), instance())):
        p = NcmProbe(**options)
        p.call(0x515C, data)
        require(not p.pending and p.uint(BASE + INSERTIONS) == 0, name)
        cases.append(dict(name=name, **p.evidence()))
    p = NcmProbe()
    p.add_device(2, 8)
    p.add_device(1, 7)
    p.call(0x4F50, instance())
    require(p.removed == [1] and p.uint(BASE + REMOVALS) == 1, "Non-head removal selection")
    cases.append(dict(name="second_node_selection", **p.evidence()))
    p = NcmProbe()
    p.add_device(1, 7)
    p.add_device(1, 7)
    p.call(0x4F50, instance(generation=99, iface=42, config=2))
    require(p.removed == [0], "First bus/address match; generation/interface are not selectors")
    cases.append(dict(name="same_address_first_match_despite_other_identity_fields", **p.evidence()))
    return dict(scope="Synthetic callback replay only; no worker, attach, detach or real USB execution",
                static=inspect(), cases=cases, phone_or_live_lifecycle_verified=False)


if __name__ == "__main__":
    print(json.dumps(scenarios(), indent=2))
