"""Read-only pinned factory USB library/server ownership analysis.

No USB operation or vendor process is executed. Optional bounded disassembly
uses the existing in-memory ELF header adapter and host LLVM.
"""
import argparse
import json
import struct

from inspect_factory_network import PINS as NETWORK_PINS, dynamic_symbols, metadata, check_words, check_local_calls
from inspect_ipod_auth import LLVM, ROOT, PinnedElf
from inspect_mirrorlink_graphics import selected_calls

CORPUS = "extracted/qnx-system-v3/image-120000/"
PINS = {
    "usb": (CORPUS + "lib/libusbdi.so.2", "bb57492945edf721bfc1677e7827b56018a81cea9a740790ffba63030f7775c0"),
    "alias": (CORPUS + "lib/libusbdi.so", "cca264fa0088e55c66e9ccca0377b75292ea3e53c462719d5c3936d1a60f2c6b"),
    "server": (CORPUS + "sbin/io-usb", "9128ef23a002c4523fdaad4e1941c97397535524d13c54c28e1b62c353b3b7ec"),
    "ncm": NETWORK_PINS["ncm"],
}
LIB_WORDS = {
    0x3730: 0xE5913010, 0x3734: 0xE3130002,
    0x3774: 0xE2022002, 0x3780: 0xE5930008, 0x3784: 0xE5941008,
    0x3790: 0xE5930024, 0x3794: 0xE5941024, 0x37B4: 0xE3A00010,
    0x58C0: 0xE590300C, 0x58C8: 0x13A00010, 0x58CC: 0x18BD8070,
    0x5E68: 0xE5943018, 0x5ED0: 0xE3A01006,
    0x5F4C: 0xE5903018, 0x5F54: 0x13A07010, 0x5FC4: 0xE3A01004,
    0x60AC: 0xE3A01003, 0x5A44: 0xE5953018, 0x5A5C: 0xE3A00010,
    0x5A84: 0xE3A00013, 0x5AA0: 0xE3A0000B, 0x5AC0: 0xE5856018,
    0x5B08: 0xE12FFF33, 0x5738: 0xE1A02006, 0x572C: 0xE3A06024,
    0x7F64: 0xEBFFED53, 0x7F68: 0xE3500000, 0x7F6C: 0x1A000031,
    0x7F84: 0xE12FFF33, 0x7FF4: 0xE12FFF33,
    0x800C: 0xE3A01001, 0x8010: 0xE3E02000,
    0x8700: 0x13A01007, 0x8704: 0x03A01000,
    0x4100: 0xE5847010,
}
LIB_CALLS = {
    0x39B8: "conflict", 0x573C: "memcmp", 0x5EDC: "usbdi_sendcmd",
    0x5EC4: "atomic_add", 0x5EEC: "atomic_sub", 0x5FD0: "usbdi_sendcmd",
    0x5FF8: "delay", 0x6000: "usbd_close_pipe", 0x6030: "free",
    0x5910: "free", 0x60B8: "usbdi_sendcmd", 0x5A40: "atomic_set",
    0x5AF4: "pthread_mutex_unlock", 0x7F50: "usbd_device_lookup",
    0x7F64: "usbdi_synchronise", 0x8004: "atomic_sub", 0x8014: "usbdi_synchronise",
    0x906C: "usbdi_synchronise", 0x914C: "usbdi_synchronise", 0x9180: "usbdi_synchronise",
    0x8754: "usbdi_sendcmd",
}
SERVER_WORDS = {
    0x117B14: 0x117C34, 0x117B18: 0x117CC8, 0x117B20: 0x117D7C,
    0x1060F4: 0xE1D430B2, 0x106104: 0xE1D620BE, 0x106108: 0xE1520003,
    0x106434: 0xE1D630BE, 0x106438: 0xE1C430B2,
    0x106478: 0xE5D0300A, 0x10647C: 0xE584301C,
    0x116628: 0xE5913010, 0x11662C: 0xE3130002,
    0x11666C: 0xE2022002, 0x116678: 0xE5930008, 0x11667C: 0xE5941008,
    0x116688: 0xE5930024, 0x11668C: 0xE5941024, 0x1166AC: 0xE3A00010,
    0x116844: 0xE3A0102C, 0x116858: 0xE285E008,
    0x117B78: 0xE5980000, 0x116F60: 0xE5846010,
}
SERVER_LOCAL = {
    0x117C6C: 0x105F88, 0x117C80: 0x11682C, 0x116880: 0x11661C,
    0x117CD0: 0x116758, 0x117CE8: 0x1093C4,
    0x117B80: 0x116F20, 0x117D84: 0x109C24,
}


def compare_library_copies(first, second):
    """The two pinned ELF files differ only in two PT_LOAD p_paddr fields."""
    if len(first.data) != len(second.data):
        raise ValueError("Library-copy sizes differ")
    differences = [i for i, (a, b) in enumerate(zip(first.data, second.data)) if a != b]
    phoff = struct.unpack_from("<I", first.data, 28)[0]
    allowed = {phoff + i * 32 + 12 + j for i in (0, 1) for j in range(4)}
    if not differences or not set(differences) <= allowed:
        raise ValueError("Library copies differ outside selected physical-address metadata")
    return [hex(i) for i in differences]


def needed_libraries(elf):
    names = []
    for kind, offset, _, _, size, _, _, _ in elf.segments:
        if kind == 2:
            for pos in range(offset, offset + size, 8):
                tag, value = struct.unpack_from("<II", elf.data, pos)
                if tag == 0:
                    break
                if tag == 1:
                    names.append(elf.string(elf.dynamic[5] + value))
    return names


def inspect():
    elfs = {key: PinnedElf(key, pins=PINS, directory=ROOT) for key in PINS}
    usb, server = elfs["usb"], elfs["server"]
    check_words(usb, LIB_WORDS)
    check_words(server, SERVER_WORDS)
    needed = needed_libraries(elfs["ncm"])
    if "libusbdi.so.2" not in needed:
        raise ValueError("NCM dependency changed")
    return dict(inputs={key: dict(sha256=elf.sha256, metadata=metadata(elf.data))
                        for key, elf in elfs.items()},
                library_exports=[s for s in dynamic_symbols(usb) if s["section"]],
                library_copy_differences=compare_library_copies(usb, elfs["alias"]),
                ncm_needed=needed, library_calls=selected_calls(usb, LIB_CALLS),
                server_local_calls=check_local_calls(server, SERVER_LOCAL),
                library_words={hex(a): hex(v) for a, v in LIB_WORDS.items()},
                server_words={hex(a): hex(v) for a, v in SERVER_WORDS.items()},
                conflict=dict(library="0x371c", server="0x11661c", client_flag_mask=2,
                    key=["32-bit path/devno/generation tuple", "32-bit interface"],
                    limit="Resolved synthetic instances; not full server configuration arbitration"),
                lifecycle=dict(device_pending_offset="0x18", pipe_pending_offset="0xc",
                    removal="mark removed; defer callback while library I/O count is nonzero",
                    completion="transfer callback, pipe decrement, device decrement, possible removal callback",
                    abort="command return does not retire device I/O count",
                    detach="early EBUSY preserves handle; command-path error still frees local handle"),
                live_ownership_verified=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassemble", choices=PINS)
    parser.add_argument("--start", type=lambda s: int(s, 0))
    parser.add_argument("--stop", type=lambda s: int(s, 0))
    args = parser.parse_args()
    if args.disassemble:
        if args.start is None or args.stop is None:
            parser.error("--disassemble requires --start and --stop")
        print(PinnedElf(args.disassemble, pins=PINS, directory=ROOT).disassemble(LLVM, args.start, args.stop))
    else:
        if args.start is not None or args.stop is not None:
            parser.error("address options require --disassemble")
        print(json.dumps(inspect(), indent=2))
