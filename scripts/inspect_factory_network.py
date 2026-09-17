"""Read-only, pinned later-firmware NCM and built-in network-domain evidence.

The default inspection executes no program and opens no device. Optional bounded
LLVM disassembly uses the existing in-memory ELF-header adapter, never loading
the vendor library. Selected instructions are assertions, not emulation or a
whole-driver/installed-unit compatibility test.
"""
import argparse
import csv
import hashlib
import io
import json
import re
import struct

from inspect_ipod_auth import LLVM, ROOT, PinnedElf, arm_call_target
from inspect_mirrorlink_graphics import selected_calls

CORPUS = "extracted/qnx-system-v3/"
PINS = {
    "ncm": (CORPUS + "image-380000/lib/dll/devnp-ncm.so",
            "bdabe7a1b29cd4070c03e0cb5c98403c632a0147c8d5da1686d2b41b834ff996"),
    "stack": (CORPUS + "image-380000/sbin/io-pkt-v4-hc",
              "f0f0624759c6d06e77dcd459dcd2d95bb3577d0f94730a9c031382bdab27b13b"),
    "boot": (CORPUS + "image-380000/boot/scripts/secondary-boot.sh",
             "581665a0ef5f18b80d2e8cc0203bfd8a476fc5b9130a75c9efbfac4cc39505f8"),
    "connectivity": (CORPUS + "image-16e0000/boot/scripts/connectivity.sh",
                     "fc3c55dd500aa60c790e07e667a0b568d795d932cff1af504d38deba3499c3ef"),
    "recovery": (CORPUS + "image-16e0000/boot/scripts/dbservice_recovery.sh",
                 "d44e5f3eff33d55b00964f37beb36366b76434889425ee65e2ac0c56568c6243"),
    "inventory": (CORPUS + "inventory.tsv",
                  "9296d45028a16d62ae0a77e8b9eff35e3719b874eb7bd565efd2003b24a52cbf"),
}

# The entire small support predicate, followed by selected descriptor/parameter
# instructions. Raw words deliberately remain separate from the interpretations.
NCM_WORDS = {
    0x5424: 0xE590300C, 0x5428: 0xE3530002, 0x542C: 0x1A000003,
    0x5430: 0xE5903010, 0x5434: 0xE353000D, 0x5438: 0x03A00000,
    0x543C: 0x012FFF1E, 0x5440: 0xE3A00013, 0x5444: 0xE12FFF1E,
    0x4020: 0xE5D03005, 0x4024: 0xE3530002, 0x402C: 0xE5D03006,
    0x4030: 0xE353000D, 0x403C: 0x03A0A024,
    0x4048: 0xE5D03002, 0x404C: 0xE3530006,
    0x4050: 0x05D03003, 0x4054: 0x0585302C,
    0x4058: 0x05D03004, 0x405C: 0x05853030,
    0x4084: 0xE595302C, 0x4088: 0xE3730001, 0x408C: 0x0A000002,
    0x4090: 0xE5952030, 0x4094: 0xE3720001, 0x4098: 0x1A000008,
    0x40E4: 0xE5D03005, 0x40E8: 0xE353000A,
    0x5FAC: 0xE353000F, 0x5FB4: 0xE1D620B8,
    0x6098: 0xE353001A, 0x60D0: 0xE5D63005, 0x60D4: 0xE5C53B58,
    0x6238: 0xE3A03021,
    0x63F8: 0xE3A0301C, 0x6400: 0xE3A01001, 0x6404: 0xE3A02080,
    0x6408: 0xE3A03000, 0x6410: 0xE5D53002,
    0x66C4: 0xE3A03004, 0x66D0: 0xE3A01002, 0x66D4: 0xE3A02086,
    0x66D8: 0xE3A03000,
    0x67F8: 0xE3130002, 0x680C: 0xE3A03000, 0x6820: 0xE3A02084,
    0x682C: 0xE3130010, 0x6840: 0xE3A03000, 0x6854: 0xE3A0208A,
    0x6928: 0xE3130008, 0x6940: 0xE3A03002, 0x6950: 0xE3A02087,
    0x6954: 0xE3A03000,
    0x6378: 0xE3120008, 0x63AC: 0xE3A01002, 0x63B0: 0xE58D1008,
    0x63B8: 0xE3A02088, 0x63BC: 0xE3A03000,
    0x6B50: 0xE3A03009, 0x6B58: 0xE3A03000,
    0x6B9C: 0xE3A02000, 0x6BF4: 0xE3A02001,
    0x6C2C: 0xE3A03006, 0x6C38: 0xE3A03001,
}
NCM_CALLS = {
    0x4014: "usbd_interface_descriptor", 0x4078: "usbd_parse_descriptors",
    0x40D8: "usbd_interface_descriptor", 0x4150: "dev_attach",
    0x5D00: "usbd_interface_descriptor", 0x5DC8: "usbd_open_pipe",
    0x5E08: "usbd_open_pipe", 0x5E30: "usbd_open_pipe",
    0x5E84: "usbd_open_pipe", 0x5EA8: "usbd_parse_descriptors",
    0x5FEC: "usbd_string", 0x623C: "usbd_setup_vendor",
    0x6BA0: "usbd_select_interface", 0x6BF8: "usbd_select_interface",
}
NCM_LOCAL_CALLS = {
    0x4B64: 0x3FE0, 0x4D80: 0x3FE0,
    0x63C0: 0x61D8, 0x640C: 0x61D8, 0x66DC: 0x61D8, 0x6824: 0x61D8,
    0x6858: 0x61D8, 0x6958: 0x61D8,
    0x6994: 0x6358,
    0x6B5C: 0x5CB8, 0x6BE0: 0x5CB8, 0x6BE8: 0x63D4, 0x6C3C: 0x5CB8,
}


def read_inputs(directory=ROOT):
    result = {}
    for key, (name, digest) in PINS.items():
        data = (directory / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"Not the pinned research input: {name}")
        result[key] = data
    return result


def dynamic_symbols(elf):
    count = elf.uint(elf.dynamic[4] + 4)
    if not 0 < count <= 65536:
        raise ValueError("Unexpected dynamic symbol count")
    return [elf.symbol(i) for i in range(count)]


def check_words(elf, expected):
    for address, word in expected.items():
        if elf.uint(address) != word:
            raise ValueError(f"Selected instruction changed at {address:#x}")


def check_local_calls(elf, expected):
    result = {}
    for address, target in expected.items():
        actual = arm_call_target(elf, address)
        if actual != target:
            raise ValueError(f"Selected local call changed at {address:#x}")
        result[hex(address)] = hex(actual)
    return result


def built_in_domains(elf):
    """Read the actual linker set consumed by the reviewed domaininit routine.

    This does not enumerate domains dynamically installed by any other module.
    """
    symbols = dynamic_symbols(elf)
    named = {s["name"]: s for s in symbols if s["section"]}
    start = named["__start_link_set_domains"]["value"]
    stop = named["__stop_link_set_domains"]["value"]
    if start % 4 or stop <= start or (stop - start) % 4 or stop - start > 256:
        raise ValueError("Unexpected built-in domain table bounds")
    check_words(elf, {0x1C7100: 0xE59F4084, 0x1C7104: 0xE59F6084,
                      0x1C7114: 0xE5943000, 0x1C7118: 0xE2844004,
                      0x1C718C: start, 0x1C7190: stop})
    check_local_calls(elf, {0x1C712C: named["domain_attach"]["value"],
                            0x1C714C: named["domain_attach"]["value"]})
    result = []
    for slot in range(start, stop, 4):
        address = elf.uint(slot)
        matches = [s for s in symbols if s["value"] == address and s["size"] == 148
                   and s["section"] and s["info"] & 15 == 1]
        if len(matches) != 1:
            raise ValueError("Ambiguous built-in domain object")
        result.append(dict(slot=hex(slot), address=hex(address), symbol=matches[0]["name"],
                           family=elf.uint(address), name=elf.string(elf.uint(address + 4))))
    return result


def matching_lines(data, marker):
    return [dict(line=i, text=line) for i, line in enumerate(data.decode("ascii").splitlines(), 1)
            if marker in line and not line.lstrip().startswith("#")]


def metadata(data):
    prefixes = (b"NAME=", b"DESCRIPTION=", b"DATE=", b"STATE=", b"VERSION=", b"TAGID=")
    return [s.decode("ascii") for s in re.findall(rb"[ -~]{5,}", data) if s.startswith(prefixes)]


def inspect(directory=ROOT):
    inputs = read_inputs(directory)  # Check all pins before interpreting any input.
    elfs = {k: PinnedElf(k, pins=PINS, directory=directory) for k in ("ncm", "stack")}
    for key, elf in elfs.items():
        if elf.data != inputs[key] or struct.unpack_from("<H", elf.data, 18)[0] != 40:
            raise ValueError("Expected unchanged pinned ARM ELF")
    ncm, stack = elfs["ncm"], elfs["stack"]
    check_words(ncm, NCM_WORDS)
    rows = list(csv.DictReader(io.StringIO(inputs["inventory"].decode("ascii")), delimiter="\t"))
    network_rows = [r for r in rows if any(token in r["path"] or token in r["target"]
                                         for token in ("io-pkt", "devnp-ncm", "lsm-ipv6"))]
    return {
        "scope": "Static selected 6.17.0WL IFS corpus; not installed 6.9.0WL or phone acceptance",
        "input_sha256": {name: digest for name, digest in PINS.values()},
        "metadata": {k: metadata(elf.data) for k, elf in elfs.items()},
        "startup": {
            "stack": matching_lines(inputs["boot"], "io-pkt-v4-hc"),
            "ncm": {k: matching_lines(inputs[k], "mount -T io-pkt")
                    for k in ("connectivity", "recovery")},
            "runtime_execution_verified": False,
        },
        "ifs_network_inventory": network_rows,
        "ncm_calls": selected_calls(ncm, NCM_CALLS),
        "ncm_local_calls": check_local_calls(ncm, NCM_LOCAL_CALLS),
        "ncm_selected_words": {hex(a): hex(v) for a, v in NCM_WORDS.items()},
        "ncm_descriptor_path": {
            "candidate": "0x3fe0", "control_class": 2, "control_subclass": 13,
            "association": "CDC Union descriptor subtype 6, first subordinate interface",
            "data_class": 10, "data_alt_sequence": [0, 1],
            "control_pipe_mask": 9, "data_pipe_mask": 6,
            "mask_meaning": {"1": "control", "2": "bulk IN", "4": "bulk OUT", "8": "interrupt IN"},
            "leaf_support_predicate": {"address": "0x5424", "accept": 0, "reject": 19},
        },
        "ncm_control_requests": [
            {"site": "0x640c", "request": 128, "name": "GET_NTB_PARAMETERS", "length": 28},
            {"site": "0x66dc", "request": 134, "name": "SET_NTB_INPUT_SIZE", "length": 4,
             "condition": "selected receive NTB size differs"},
            {"site": "0x6824", "request": 132, "name": "SET_NTB_FORMAT", "value": 0,
             "condition": "reported formats bit 1"},
            {"site": "0x6858", "request": 138, "name": "SET_CRC_MODE", "value": 0,
             "condition": "NCM capabilities bit 4"},
            {"site": "0x6958", "request": 135, "name": "GET_MAX_DATAGRAM_SIZE", "length": 2,
             "condition": "NCM capabilities bit 3"},
            {"site": "0x63c0", "request": 136, "name": "SET_MAX_DATAGRAM_SIZE", "length": 2,
             "condition": "NCM capabilities bit 3 and selected datagram size differs"},
        ],
        "stack_built_in_domains": built_in_domains(stack),
        "stack_raw_marker_counts": {s: stack.data.count(s.encode("ascii"))
                                    for s in ("inet6", "ip6_input", "IPv6")},
        "factory_or_phone_acceptance_verified": False,
        "limits": [
            "IFS inventory includes symlinks but is not a search of all MMC files or the installed unit",
            "Built-in domains do not enumerate dynamically attached modules",
            "Selected calls/words do not prove whole-driver safety or live USB ownership",
            "No phone descriptors, IPv6 interface/listener or native CarPlay executable are supplied",
            "No vendor process, USB API, interface configuration or firmware update is executed",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassemble", choices=("ncm", "stack"))
    parser.add_argument("--start", type=lambda s: int(s, 0))
    parser.add_argument("--stop", type=lambda s: int(s, 0))
    args = parser.parse_args()
    if args.disassemble:
        if args.start is None or args.stop is None:
            parser.error("--disassemble requires --start and --stop")
        read_inputs()
        elf = PinnedElf(args.disassemble, pins=PINS, directory=ROOT)
        print(elf.disassemble(LLVM, args.start, args.stop))
    else:
        if args.start is not None or args.stop is not None:
            parser.error("address options require --disassemble")
        print(json.dumps(inspect(), indent=2))
