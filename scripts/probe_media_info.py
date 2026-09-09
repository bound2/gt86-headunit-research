"""Bounded PC-only probes of the pinned media-information export.

Executes selected ARM routines with synthetic mount/node/cache structures.
Imports are intercepted; no guest device, filesystem, process or network access
is possible. The mount-description dispatch check executes a named slice, not
mount_create as a whole. It mocks XML emission and the driver callback. A
separate auth probe exercises the actual driver-description callback.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from inspect_ipod_auth import PinnedElf
from probe_ipod_auth import AuthProbe, BASES, RETURN, require
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R4, UC_ARM_REG_R6, UC_ARM_REG_R10
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC


class DriverDescriptionProbe(AuthProbe):
    def on_code(self, uc, address, size, user):
        if BASES["ipod"] + 0x29008 <= address < BASES["ipod"] + 0x290A8:
            return
        super().on_code(uc, address, size, user)


class MediaInfoProbe:
    # These helpers operate on bounded guest memory only.
    allocate = AuthProbe.allocate
    allocate_bytes = AuthProbe.allocate_bytes
    read = AuthProbe.read
    uint = AuthProbe.uint
    write32 = AuthProbe.write32
    string = AuthProbe.string
    arg = AuthProbe.arg
    stub = AuthProbe.stub
    on_interrupt = AuthProbe.on_interrupt

    def __init__(self, cached=b"synthetic cached bytes"):
        require(len(cached) <= 4096, "Synthetic cache bound")
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.imports = {}
        self.events = []
        self.heap = 0x500100
        self.slice_mode = False
        self.elf = PinnedElf("media")
        for address, size in ((0x100000, 0x100000), (0x400000, 0x10000),
                              (0x500000, 0x100000), (0x700000, 0x10000)):
            self.u.mem_map(address, size)
        for kind, offset, address, _, size, _, _, _ in self.elf.segments:
            if kind == 1:
                self.u.mem_write(address, self.elf.data[offset:offset + size])
        for target, kind, symbol in self.elf.relocations():
            if kind in (21, 22):  # GLOB_DAT / JUMP_SLOT: intercept all external functions.
                self.write32(target, self.stub(symbol["name"]))
            elif kind == 20:  # COPY: libc data is unused by the selected paths.
                self.u.mem_write(target, bytes(symbol["size"]))
            else:
                raise ValueError(f"Unexpected executable relocation {kind}")
        self.mount = self.allocate(0x700)
        self.cache = self.allocate_bytes(cached)
        self.write32(self.mount + 0x80, self.cache)
        self.write32(self.mount + 0x88, len(cached))
        self.write32(self.mount + 0x11C, 100)
        self.write32(self.mount + 0x5C, 512)
        self.u.hook_add(UC_HOOK_CODE, self.on_code)
        self.u.hook_add(UC_HOOK_INTR, self.on_interrupt)

    def call(self, address, *args):
        require(len(args) <= 5, "Entry argument bound")
        self.u.reg_write(UC_ARM_REG_SP, 0x70FFE0)
        for i in range(4):
            self.u.reg_write(UC_ARM_REG_R0 + i, args[i] if i < len(args) else 0)
        self.write32(0x70FFE0, args[4] if len(args) == 5 else 0)
        self.u.reg_write(UC_ARM_REG_LR, RETURN)
        self.u.emu_start(address, RETURN, timeout=5_000_000, count=300_000)
        require(self.u.reg_read(UC_ARM_REG_PC) == RETURN, "Guest instruction/time budget exceeded")
        return self.u.reg_read(UC_ARM_REG_R0)

    def on_code(self, uc, address, size, user):
        if self.slice_mode and address == 0x116984:
            # The disassembled driver-description block ends here; do not mount anything.
            self.u.reg_write(UC_ARM_REG_PC, RETURN)
            return
        if address == 0x11B628 and self.slice_mode:
            self.events.append(dict(op="xml", key=self.string(self.arg(1)),
                                    value=self.string(self.arg(2)) if self.arg(2) else None))
            result = 0
        elif address == 0x11783C:
            # Mock path_sum rather than using an uninitialized QNX libc locale table.
            name = self.string(self.arg(0))
            require(name in (".FS_info.", "info.xml"), "Unexpected hierarchy name")
            result = sum(name.lower().encode("ascii")) % 256
            result = result if result not in (0, 255) else 1
            self.events.append(dict(op="mock_path_sum", name=name))
        elif address in self.imports:
            name = self.imports[address]
            a, b, c = [self.arg(i) for i in range(3)]
            if name == "memcpy":
                data = self.read(b, c)
                if data:
                    self.u.mem_write(a, data)
                self.events.append(dict(op="memcpy", size=c))
                result = a
            elif name in ("strcmp", "stricmp"):
                left, right = self.string(a), self.string(b)
                if name == "stricmp":
                    left, right = left.lower(), right.lower()
                result = (left > right) - (left < right)
                self.events.append(dict(op=name, left=left, right=right))
            elif name == "synthetic_driver_description" and self.slice_mode:
                require(a == self.device and b == self.mount, "Driver callback arguments")
                self.events.append(dict(op="mock_driver_description", arguments="device,mount"))
                result = 0
            else:
                raise RuntimeError(f"Unexpected guest import: {name}")
        else:
            allowed = (0x1038E0 <= address < 0x103FB0 or  # PLT; imports still fail closed.
                       0x110534 <= address < 0x1107C8 or
                       0x115870 <= address < 0x115930 or
                       0x1170AC <= address < 0x117588 or
                       self.slice_mode and 0x116938 <= address < 0x116984)
            require(allowed, f"Execution outside audited routines: {address:#x}")
            return
        self.u.reg_write(UC_ARM_REG_R0, result & 0xFFFFFFFF)
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def node(self, slot, name=None, flags=0):
        node = self.allocate(0x100)
        self.write32(node, 100 + slot)
        self.write32(self.mount + 0x44, flags)
        name_ptr = self.allocate_bytes(name.encode() + b"\0") if name is not None else 0
        result = self.call(0x1170AC, self.mount, node, 0, name_ptr)
        return result, node

    def cached_read(self, blocks, flags=1):
        # Each tuple is (512-byte offset index, 512-byte count, signed special-node tag).
        require(0 < len(blocks) <= 4, "Descriptor count bound")
        descriptors, buffers = [], []
        for offset, count, tag in blocks:
            require(0 <= count <= 4, "Descriptor byte-count bound")
            buffer = self.allocate_bytes(b"\xA5" * 2048)
            descriptor = self.allocate(0x30)
            self.write32(descriptor + 0x1C, offset)
            self.write32(descriptor + 0x20, count)
            self.u.mem_write(descriptor + 0x2A, struct.pack("<h", tag))
            self.write32(descriptor + 0x2C, buffer)
            descriptors.append(descriptor)
            buffers.append(buffer)
        array = self.allocate_bytes(struct.pack("<" + "I" * len(descriptors), *descriptors))
        owner = self.allocate(4)
        self.write32(owner, self.mount)
        require(self.call(0x115870, owner, flags, array, 0, len(descriptors)) == 0, "Cache callback failed")
        return [self.read(buffer, 2048) for buffer in buffers]

    def dispatch_slice(self):
        self.device = self.allocate(0x100)
        driver = self.allocate(0x80)
        module = self.allocate(0x44)
        self.write32(self.device + 4, driver)
        self.write32(driver + 0x0C, module)
        self.write32(module, self.allocate_bytes(b"synthetic_ipod\0"))
        self.write32(driver + 0x3C, self.stub("synthetic_driver_description"))
        for register, value in ((UC_ARM_REG_R4, self.mount), (UC_ARM_REG_R6, self.mount + 0x80),
                                (UC_ARM_REG_R10, self.device)):
            self.u.reg_write(register, value)
        self.slice_mode = True
        try:
            self.call(0x116938)
        finally:
            self.slice_mode = False


def run_checks():
    evidence = []
    p = DriverDescriptionProbe()
    require(p.initialize() == 0, "Synthetic chip initialization")
    before = len(p.events)
    callback = p.uint(BASES["ipod"] + 0x38A5C) - BASES["ipod"]
    require(callback == 0x29008, "Pinned driver callback table differs")
    p.call("ipod", callback, p.device, p.allocate(0x200))
    events = p.events[before:]
    require(all(e["op"] in ("xml", "xml_field") for e in events), "Description performed I/O")
    require(any(e.get("key") == "authcoproc" for e in events), "Missing auth subtree")
    require(any(e.get("key") == "protocol" and e.get("value") == [2, 0] for e in events),
            "Cached synthetic chip protocol not forwarded")
    evidence.append(dict(name="actual_driver_callback_cached_auth", events=events))
    p = MediaInfoProbe()
    p.dispatch_slice()
    require([e["op"] for e in p.events] == ["xml", "xml", "mock_driver_description"],
            "Unexpected mount-description dispatch")
    evidence.append(dict(name="mount_description_slice", events=p.events))
    p = MediaInfoProbe()
    directory = p.allocate(0x100)
    head = p.allocate(0x10)
    nodes = p.allocate(0x400)
    device = p.allocate(0x100)
    p.write32(p.mount + 0x110, nodes)
    p.write32(p.mount + 0x124, 1)  # Synthetic node-cache stride: 8 bytes.
    p.write32(p.mount + 0x20, device)
    p.write32(directory + 0x64, head)
    p.write32(directory + 0x70, 101)  # .FS_info. node (N+1).
    require(p.call(0x110534, p.mount, directory, 0, 0) == 0, "Hierarchy build")
    require(p.uint(head + 8) & 0xFFFFFF == 102 and
            p.uint(nodes + 102 * 8) & 0xFFFFFF == 103 and
            p.uint(nodes + 103 * 8) & 0xFFFFFF == 0, "Information-file child chain")
    evidence.append(dict(name="information_directory_child_chain", events=p.events,
                         child_slots=[102, 103], info_xml_slot=103))
    for slot, expected_name, expected_mode in ((1, ".FS_info.", 0x436D), (3, "info.xml", 0x8124)):
        p = MediaInfoProbe()
        result, node = p.node(slot)
        require(result == 0 and p.string(node + 0x46) == expected_name and
                p.uint(node + 0x14) == expected_mode, "Builtin name/mode")
        if slot == 3:
            require(p.uint(node + 0x20) == p.uint(p.mount + 0x88), "Info file length")
        evidence.append(dict(name=f"node_{expected_name}", mode=hex(expected_mode), events=p.events))
    for name, flags, expected in (("info.xml", 0, 0), ("INFO.XML", 0, 2), ("INFO.XML", 8, 0)):
        p = MediaInfoProbe()
        require(p.node(3, name, flags)[0] == expected, "Name matching branch")
        evidence.append(dict(name=f"match_{name}_flags_{flags}", result=expected, events=p.events))
    p = MediaInfoProbe(b"")
    require(p.node(3)[0] == 2, "Empty cache should omit information-file node")
    evidence.append(dict(name="empty_cache_no_file", result=2, events=p.events))
    cached = bytes((i * 7 + 1) % 256 for i in range(700))
    for offset, count, tag, flags in ((0, 1, -3, 1), (0, 2, -3, 1), (1, 1, -3, 1),
                                     (2, 1, -3, 1), (0x800000, 1, -3, 1),
                                     (0, 1, -3, 0), (0, 1, 3, 1), (0, 0, -3, 1)):
        p = MediaInfoProbe(cached)
        actual = p.cached_read([(offset, count, tag)], flags)[0]
        expected = cached[offset * 512:(offset + count) * 512] if flags & 1 and tag < 0 else b""
        require(actual == expected + b"\xA5" * (2048 - len(expected)), "Cached read bytes/tail")
        evidence.append(dict(name=f"read_block_{offset}_count_{count}_tag_{tag}_flags_{flags}",
                             copied=len(expected), events=p.events))
    p = MediaInfoProbe(cached)
    buffers = p.cached_read([(0, 1, -3), (1, 1, -3)])
    require(buffers[0][:512] + buffers[1][:188] == cached and
            buffers[0][512:] == b"\xA5" * 1536 and buffers[1][188:] == b"\xA5" * 1860,
            "Multiple descriptors do not reconstruct cache")
    evidence.append(dict(name="multiple_descriptors", events=p.events,
                         synthetic_cache_sha256=hashlib.sha256(cached).hexdigest()))
    p = MediaInfoProbe(b"")
    require(p.cached_read([(0, 1, -3)])[0] == b"\xA5" * 2048, "Empty cache read")
    evidence.append(dict(name="empty_cache_read", events=p.events))
    return dict(input_sha256={PinnedElf(m).path.name: PinnedElf(m).sha256 for m in ("media", "ipod", "i2c")},
                checks=evidence, scope={
                    "firmware": "6.17.0WL; installed 6.9.0WL not available",
                    "mount_create": "Driver-description slice only; callback and XML emission mocked",
                    "driver_description": "Separate native callback check with synthetic chip identity",
                    "hierarchy": "Special directory branch; path_sum mocked; not complete path resolution",
                    "read": "Native node/cache callbacks; not a QNX resource-manager process",
                    "actual_mountpoint_known": False, "actual_chip_identity_known": False,
                    "car_tested": False, "carplay_authenticated": False, "vendor_file_modified": False})


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
    print(f"PASS: {len(evidence['checks'])} pinned ARM media-information checks; synthetic state only.")
    if not args.output:
        print(rendered, end="")


if __name__ == "__main__":
    main()
