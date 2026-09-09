"""Bounded PC-only replay of pinned stock ARM iPod USB read/write routines.

USB requests, status, locks, logging and delays are synthetic host callbacks.
No USB library is loaded, device opened, initializer run or stock service changed.
This is an observation harness for the later corpus, not an iAP2 USB adapter.
Requires the existing build/python-libs Unicorn analysis dependency.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from inspect_ipod_auth import PinnedElf, ROOT
from probe_ipod_auth import AuthProbe, RETURN, require
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

BASE = 0x100000
CORPUS = ROOT / "extracted/qnx-system-v3"
PINS = {
    "image-8.imagefs": "faa1e4928340da1b1b97cebd504a514d53a180a4528417900fb41f534cd3fc4c",
    "image-120000/lib/dll/devu-dm816x-mg.so": "d0cd1bbe177f84dc0e547e68d1ba48096531ce1173c3f97047667236ab04a8e4",
    "image-120000/etc/enum-usb.conf": "3a748b8fffadfd9bf8239ba02b331f440253b0b78e29e11bcb7853c33c14bfd9",
    "image-120000/etc/system/enum/common": "fb5539f10b48525f5aac13d35a0b9d04cb4c9007aca07422e2591bc6ad99b507",
    "image-120000/etc/system/enum/devices/usb/ipod": "ce92d120be27fb8f8c1c5a6f5231e4321dcf2f97e4fdc6958a95ff5c7aea76e0",
    "image-380000/boot/scripts/secondary-boot.sh": "581665a0ef5f18b80d2e8cc0203bfd8a476fc5b9130a75c9efbfac4cc39505f8",
    "image-380000/boot/scripts/pre-media.sh": "8b444fe857974b460885db5e5de376f76cb3dda6062953b50b3634a09e447b5b",
    "image-380000/boot/scripts/early_services.sh": "b9d822060b1739ea99adfa01e4316a0f26b7f876a81cbfd4870027d7a7f54f76",
    "image-380000/etc/ipod.cfg": "041b6e860359cdbdbf18e6d650d3148d67931ba2e13432cb08a290c0df521162",
    "image-380000/etc/system/config/connmgr_r0.json": "4471bc0da810fa7aab42e7ccfd58ff53135a4e7e4b834da3a16d7a6bb3619c6a",
    "image-380000/etc/system/config/connmgr_r1.json": "2e4300755a6b1571935abc047cbf32998078958b9969bbea69cab721f4226150",
}


def static_evidence():
    """Hash all selected inputs before interpreting any of them; execute none."""
    data = {}
    for name, digest in PINS.items():
        content = (CORPUS / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError(f"Not the pinned research input: {name}")
        data[name] = content
    elf = PinnedElf("usb")
    tokens = data["image-8.imagefs"][0x90A18:0x90A69].split(b"\0")[:-1]
    require(tokens == [b"io-usb", b"io-usb", b"-vvv", b"-c", b"-d", b"dm816x-mg",
                       b"ioport=0x47401400,irq=18,ctrl_noping,in_rndis"], "Boot token pin")
    host = data["image-120000/lib/dll/devu-dm816x-mg.so"]
    description = b"DESCRIPTION=DM816x USB OTG controller driver (Host Only)"
    require(description in host, "Host driver description pin")
    return dict(inputs={**PINS, elf.path.relative_to(CORPUS).as_posix(): elf.sha256},
                boot_tokens=dict(file_offset="0x90a18", strings=[t.decode() for t in tokens]),
                host_driver_description=description.decode(), usb_module=elf.metadata(),
                descriptor=dict(module="0x4920", interface=hex(elf.uint(0x4944)),
                                name=elf.string(elf.uint(0x4BF0)),
                                write=hex(elf.uint(0x4C1C)), read=hex(elf.uint(0x4C20))),
                limits="Later 6.17.0WL corpus only; no physical USB ownership or installed-version proof")


class UsbProbe:
    # Shared helpers are bounded guest-memory operations, never host I/O.
    allocate = AuthProbe.allocate
    allocate_bytes = AuthProbe.allocate_bytes
    read = AuthProbe.read
    uint = AuthProbe.uint
    write32 = AuthProbe.write32
    arg = AuthProbe.arg
    stub = AuthProbe.stub
    on_interrupt = AuthProbe.on_interrupt

    def __init__(self, active=True, submit_errors=(), statuses=(), always_busy=False):
        self.elf = PinnedElf("usb")  # Refuse modified input before guest setup.
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.imports, self.events = {}, []
        self.heap, self.errno = 0x500100, 0x500000
        self.submit_errors, self.statuses = list(submit_errors), list(statuses)
        self.always_busy = always_busy
        self.tx, self.rx = None, None
        self.received_size = 0
        for address, size in ((BASE, 0x10000), (0x400000, 0x10000),
                              (0x500000, 0x100000), (0x700000, 0x10000)):
            self.u.mem_map(address, size)
        for kind, offset, address, _, size, _, _, _ in self.elf.segments:
            if kind == 1:
                self.u.mem_write(BASE + address, self.elf.data[offset:offset + size])
        for target, kind, symbol in self.elf.relocations():
            if kind == 23:
                value = BASE + self.uint(BASE + target)
            elif kind in (2, 21, 22):
                value = (BASE + symbol["value"] if symbol["section"] else self.stub(symbol["name"]))
                if kind == 2:
                    value += self.uint(BASE + target)
            else:
                raise ValueError(f"Unexpected USB relocation: {kind}")
            self.write32(BASE + target, value)
        self.context = self.allocate(0x200)
        self.device = self.allocate(0x80)
        owner, logger = self.allocate(0x40), self.allocate(0x80)
        self.write32(self.device + 0x44, self.context)
        self.write32(self.context + 4, owner)
        self.write32(owner + 0x14, logger)
        self.write32(self.context + 8, int(active))
        self.u.mem_write(self.context + 0x28, struct.pack("<H", 3))  # Synthetic interface.
        self.out_buffer, self.in_buffer = self.allocate(1024), self.allocate(1024)
        for field, value in ((0x30, 0xA0), (0x34, 0xA1), (0x38, self.out_buffer),
                             (0x40, 0xB0), (0x44, 0xB1), (0x48, self.in_buffer), (0x4C, 64)):
            self.write32(self.context + field, value)
        # One input report ID=6, one output ID=7. Size includes flags, excludes ID.
        self.u.mem_write(self.context + 0x60, struct.pack("<BBHBBH", 6, 1, 9, 7, 2, 9))
        self.u.mem_write(self.context + 0x160, struct.pack("<HH", 1, 2))
        self.u.hook_add(UC_HOOK_CODE, self.on_code)
        self.u.hook_add(UC_HOOK_INTR, self.on_interrupt)

    def call(self, offset, *args):
        require(offset in (0x11CC, 0x1674), "Entry outside audited USB routines")
        require(len(args) <= 4, "Entry argument bound")
        for i in range(4):
            self.u.reg_write(UC_ARM_REG_R0 + i, args[i] if i < len(args) else 0)
        self.u.reg_write(UC_ARM_REG_SP, 0x70FFF0)
        self.u.reg_write(UC_ARM_REG_LR, RETURN)
        self.u.emu_start(BASE + offset, RETURN, timeout=5_000_000, count=100_000)
        require(self.u.reg_read(UC_ARM_REG_PC) == RETURN, "Guest instruction/time budget exceeded")
        result = self.u.reg_read(UC_ARM_REG_R0)
        return result if result < 0x80000000 else result - 0x100000000

    def on_code(self, uc, address, size, user):
        if address not in self.imports:
            offset = address - BASE
            require(0xDF4 <= offset < 0x10D0 or 0x11CC <= offset < 0x1618 or
                    0x1674 <= offset < 0x1918, f"Execution outside audited USB routines: {address:#x}")
            return
        require(len(self.events) < 256, "Guest event budget exceeded")
        name = self.imports[address]
        a, b, c, d = [self.arg(i) for i in range(4)]
        event, result = dict(op=name), 0
        if name in ("memcpy", "memmove"):
            value = self.read(b, c)
            if value:
                self.u.mem_write(a, value)
            event["size"], result = c, a
        elif name == "memset":
            require(c <= 8192, "Guest fill size bound")
            if c:
                self.u.mem_write(a, bytes([b & 255]) * c)
            event["size"], result = c, a
        elif name == "__get_errno_ptr":
            result = self.errno
        elif name == "strerror":
            result = self.allocate_bytes(b"synthetic error\0")
        elif name in ("pthread_sleepon_lock", "pthread_sleepon_unlock", "ipod_log"):
            pass
        elif name == "delay":
            event["milliseconds"] = a  # Recorded only: no wall-clock sleep.
        elif name == "pthread_sleepon_timedwait":
            require(a == self.context, "Wait context")
            event["nanoseconds"] = c | (d << 32)
            result = 260  # Observed native timeout-to-empty-read branch.
        elif name == "usbd_setup_vendor":
            value, index, buffer, length = [self.arg(i) for i in range(4, 8)]
            require(a == 0xA1 and buffer == self.out_buffer and length <= 1024, "Output URB bound")
            self.tx = dict(flags=b, request=c, request_type=d, value=value, index=index,
                           length=length, data=self.read(buffer, length).hex())
            event.update(self.tx)
        elif name == "usbd_setup_interrupt":
            require(a == 0xB1 and c == self.in_buffer and d <= 1024, "Input URB bound")
            self.rx = dict(flags=b, length=d)
            event.update(self.rx)
        elif name == "usbd_io":
            require((a, b) in ((0xA1, 0xA0), (0xB1, 0xB0)), "Synthetic URB/pipe pair")
            require(d == self.context, "I/O context")
            require(c == (0 if a == 0xA1 else BASE + 0x1630), "I/O callback pin")
            result = self.submit_errors.pop(0) if self.submit_errors else 0
            event.update(urb=a, pipe=b, callback=hex(c), timeout=self.arg(4), result=result)
            # Never invoke the callback or host USB; input remains pending.
        elif name == "usbd_urb_status":
            require(a in (0xA1, 0xB1), "Status URB")
            actual = self.tx["length"] if a == 0xA1 else self.received_size
            result, status, actual = (self.statuses.pop(0) if self.statuses else
                                     (16 if self.always_busy else 0, 0x01000000, actual))
            require(0 <= actual <= 1024, "Synthetic completion size bound")
            self.write32(b, status)
            self.write32(c, actual)
            event.update(result=result, status=hex(status), actual_length=actual)
        elif name == "usbd_reset_pipe":
            require(a in (0xA0, 0xB0), "Reset mock pipe")
            event["pipe"] = a  # In-memory record, never a real reset.
        else:
            raise RuntimeError(f"Unexpected guest import: {name}")
        self.events.append(event)
        self.u.reg_write(UC_ARM_REG_R0, result & 0xFFFFFFFF)
        self.u.reg_write(UC_ARM_REG_PC, self.u.reg_read(UC_ARM_REG_LR))

    def write(self, payload):
        require(len(payload) <= 1024, "Synthetic write bound")
        return self.call(0x1674, self.device, self.allocate_bytes(payload), len(payload))

    def complete_input(self, data):
        require(len(data) <= 64, "Synthetic interrupt bound")
        self.u.mem_write(self.in_buffer, bytes(64))
        if data:
            self.u.mem_write(self.in_buffer, data)
        self.received_size = len(data)
        self.write32(self.context + 0x164, 2)

    def read_payload(self, size, timeout=0):
        require(1 <= size <= 1024 and 0 <= timeout <= 1000, "Synthetic read bound")
        out = self.allocate_bytes(bytes([0xA5]) * (size + 16))
        result = self.call(0x11CC, self.device, out, size, timeout)
        require(self.read(out + size, 16) == bytes([0xA5]) * 16, "Read output canary")
        return result, self.read(out, max(result, 0))

    def evidence(self, name, result):
        return dict(name=name, result=result, errno=self.uint(self.errno), events=self.events)


def scenarios():
    cases = []
    p = UsbProbe()
    result = p.write(b"abc")
    require(result == 3 and p.tx == dict(flags=2, request=9, request_type=0x21, value=0x207,
            index=3, length=10, data="07006162630000000000"), "Single output report")
    cases.append(p.evidence("write_padding_and_setup", result))

    p = UsbProbe()
    result = p.write(bytes(range(17)))
    reports = [bytes.fromhex(e["data"]) for e in p.events if e["op"] == "usbd_setup_vendor"]
    require(result == 17 and [r[1] for r in reports] == [2, 3, 1], "Fragment flags")
    require(reports == [b"\x07\x02" + bytes(range(8)), b"\x07\x03" + bytes(range(8, 16)),
                        b"\x07\x01\x10" + bytes(7)], "Fragment payloads and padding")
    cases.append(p.evidence("write_fragmentation", result))

    for name, options, payload, expected, error in (
            ("write_empty", {}, b"", 0, 0),
            ("write_disconnected", dict(active=False), b"abc", -1, 9),
            ("write_submission_error", dict(submit_errors=[19]), b"abc", -1, 19),
            ("write_partial_then_disconnect", dict(submit_errors=[0, 19]), bytes(17), 8, 0),
            ("write_stall", dict(statuses=[(5, 4, 0)]), b"abc", -1, 5),
            ("write_short_success", dict(statuses=[(0, 0x01000000, 2)]), b"abc", 3, 0),
            ("write_busy_then_success", dict(statuses=[(16, 0, 0)]), b"abc", 3, 0)):
        p = UsbProbe(**options)
        result = p.write(payload)
        require(result == expected and p.uint(p.errno) == error, name)
        if name == "write_stall":
            require([e["pipe"] for e in p.events if e["op"] == "usbd_reset_pipe"] == [0xA0], name)
        cases.append(p.evidence(name, result))

    p = UsbProbe(always_busy=True)
    try:
        p.write(b"abc")
    except AssertionError as error:
        require("budget exceeded" in str(error), "Expected only a bounded busy-loop stop")
        cases.append(p.evidence("write_busy_budget", str(error)))
    else:
        raise AssertionError("Busy loop unexpectedly completed")

    p = UsbProbe()
    p.complete_input(b"\x06\x00abcdefgh")
    first, a = p.read_payload(3)
    second, b = p.read_payload(8)
    require((first, a, second, b) == (3, b"abc", 5, b"defgh"), "Read header stripping and cache")
    require(p.rx == dict(flags=5, length=64), "Interrupt setup pin")
    cases.append(p.evidence("read_report_and_partial_cache", [first, a.hex(), second, b.hex()]))

    p = UsbProbe()
    p.complete_input(b"\x06\x00abcd")
    first, a = p.read_payload(8)
    require(p.uint(p.context + 0x5C) == 4, "Input continuation count")
    p.complete_input(b"efgh")
    second, b = p.read_payload(8)
    require((first, a, second, b) == (4, b"abcd", 4, b"efgh"), "Input continuation")
    require(p.uint(p.context + 0x5C) == 0, "Input continuation complete")
    cases.append(p.evidence("read_split_interrupt_completion", [first, a.hex(), second, b.hex()]))

    for name, options, data, timeout, expected in (
            ("read_unknown_report", {}, b"\x55\x00abcdefgh", 0, 0),
            ("read_header_only", {}, b"\x06\x00", 0, 0),
            ("read_disconnected", dict(active=False), None, 0, -1),
            ("read_wait_timeout", {}, None, 7, 0),
            ("read_stall_requeues", dict(statuses=[(5, 4, 0)]), b"\x06\x00abc", 0, 0)):
        p = UsbProbe(**options)
        if data is not None:
            p.complete_input(data)
        result, payload = p.read_payload(8, timeout)
        require(result == expected and not payload, name)
        if name == "read_wait_timeout":
            require([e["nanoseconds"] for e in p.events if e["op"] == "pthread_sleepon_timedwait"]
                    == [7_000_000], "Milliseconds converted to nanoseconds")
        if name == "read_stall_requeues":
            require([e["pipe"] for e in p.events if e["op"] == "usbd_reset_pipe"] == [0xB0], name)
            require(p.rx == dict(flags=5, length=64), "Read stall requeues interrupt request")
        cases.append(p.evidence(name, result))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New evidence file; never overwritten")
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise FileExistsError(args.output)
    evidence = static_evidence()
    evidence["scenarios"] = scenarios()
    evidence["scenario_count"] = len(evidence["scenarios"])
    evidence["scope"] = "Synthetic USB only; no attachment, hardware query, credentials or CarPlay session"
    rendered = json.dumps(evidence, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            output.write(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
