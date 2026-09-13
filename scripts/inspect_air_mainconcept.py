"""Check pinned AIR decoder evidence without loading or executing vendor code.

Addresses describe selected observations in the later research corpus, not a
callable decoder API. Interval labels are analytical, not recovered symbols.
"""
import argparse
import bisect
import json

from inspect_air_video import DIRECTORY, LLVM, PINS, PinnedElf, unwind_starts
from inspect_ipod_auth import arm_call_target
from inspect_mirrorlink_graphics import selected_calls

RANGES = {
    "factory": (0x260710, 0x2607FC),
    "constructor": (0x39FEB4, 0x39FF98),
    "label": (0x39BE10, 0x39BE4C),
    "instance_setup": (0x39DE6C, 0x39DF98),
    "packet_dispatch": (0x39FB38, 0x39FC08),
    "configure_record": (0x39EE54, 0x39F1C8),
    "configure_backend": (0x39DF98, 0x39EE54),
    "submit_record": (0x39D2D8, 0x39D754),
    "collect_frames": (0x39CCD0, 0x39D11C),
    "render_planes": (0x39C258, 0x39C380),
    "backend_factory": (0x574280, 0x5743D8),
    "backend_submit": (0x573E74, 0x573FE0),
}
RELATIVE_SLOTS = {
    0xA5D0BC: 0xA5D16C, 0xA5D170: 0x931D38,  # instance RTTI
    0xA5D0E4: 0xA5D160, 0xA5D164: 0x931D20,  # decompressor RTTI
    0xA5D0F4: 0x39FC08, 0xA5D104: 0x39BE08,  # dispatch/current instance
    0xA5D12C: 0x39C258, 0xA5D140: 0x39BE10,  # rendering/label
}
DIRECT_CALLS = {
    0x2607C4: 0x4400C0, 0x2607D8: 0x39FEB4, 0x39FEC8: 0x260CD8,
    0x39FC2C: 0x39FB38, 0x39FC58: 0x39DC64,
    0x39FB54: 0x39EE54, 0x39FB68: 0x39F1C8, 0x39FB8C: 0x39D11C,
    0x39F0D0: 0x39DF98, 0x39E184: 0x39DE6C,
    0x39DF38: 0x4400C0, 0x39DF40: 0x39CB88,
    0x39DF80: 0x5FFEFC, 0x39DF88: 0x574280,
    0x574384: 0x576644, 0x39F86C: 0x39D2D8,
    0x39D52C: 0x39CCD0, 0x39D6DC: 0x39CCD0,
    0x39DAB4: 0x574250, 0x39DAC4: 0x5FFEF8,
}
IMPORT_CALLS = {
    0x574290: "_Znaj", 0x5742A4: "memset", 0x574324: "_Znaj",
    0x574338: "memset", 0x39F07C: "memcpy", 0x39F0BC: "memcpy",
    0x39CEB4: "memset", 0x39CF14: "memcpy",
}
# The first two function pointers installed in the 44-byte backend object.
BACKEND_POINTERS = {0x5743B0: 0x573E74, 0x5743B4: 0x574440}
# Command identifiers are deliberately numeric: no unverified SDK prototypes.
COMMAND_LITERALS = {
    0x39D0F8: 0x10003, 0x39D0FC: 0x10010, 0x39D100: 0x10014,
    0x39D104: 0x10009, 0x39D108: 0x10091, 0x39D10C: 0x10027,
    0x39D110: 0x1008B, 0x39D118: 0x10007,
}
WORDS = {
    0x260710: 0xE2400002, 0x260724: 0xE3500005,
    0x260728: 0x908FF100, 0x260744: 0xEA00001C,
    0x2607BC: 0xE30103F0, 0x39FED0: 0xE08F5005,
    0x39FEE4: 0xE2833030, 0x39FEE8: 0xE5843000,
    0x39BE10: 0xE5900170, 0x39BE20: 0xE08F3003,
    0x39BE24: 0x1A000002, 0x39BE2C: 0xE0830000,
    0x39DF1C: 0xE3530000, 0x39DF20: 0x18BD8070,
    0x39DF48: 0xE5845178, 0x39DF84: 0xE5850008,
    0x39DF90: 0xE5830004, 0x57428C: 0xE08F5005,
    0x5742E4: 0xE5843000, 0x5742FC: 0xE5848004,
    0x574390: 0x15845028,
    0x39FC1C: 0xE5D25018, 0x39FC20: 0xE3550009,
    0x39FC4C: 0xE3550017, 0x39FB3C: 0xE5926024,
    0x39FB48: 0xE5D65001, 0x39FB4C: 0xE3550000,
    0x39FB5C: 0xE3550001, 0x39FB74: 0xE3550002,
    0x39F048: 0xE2433005, 0x39F04C: 0xE5843188,
    0x39F06C: 0xE5840180, 0x39F078: 0xE2811005,
    0x39E0B8: 0xE2033003, 0x39E0BC: 0xE2833001,
    0x39E0C4: 0xE5843194,
    0x39D2F0: 0xE08F9009, 0x39D398: 0xE7B71051,
    0x39D414: 0xE2577005, 0x39D418: 0x12866005,
    0x39D4FC: 0xE5953000, 0x39D504: 0xE12FFF33,
    0x39D61C: 0xE1A02006, 0x39D620: 0xE5953000,
    0x39D628: 0xE1A01008, 0x39D62C: 0xE12FFF33,
    0x573F00: 0xE12FFF3C, 0x573F04: 0xE59D3004,
    0x573F0C: 0xE0636006, 0x573F10: 0xE0855003,
    0x39CEF0: 0xE12FFF3C, 0x39D0E4: 0xE12FFF3C,
    0x39D114: 0x59563132,
    0x39BE08: 0xE590017C, 0x39BE0C: 0xE12FFF1E,
    0x39C2E8: 0xE596802C, 0x39C2EC: 0xE5967030,
    0x39C344: 0xE5961028, 0x39C34C: 0xE59CC018,
    0x39C350: 0xE12FFF3C,
}


def inspect(directory=DIRECTORY):
    elf = PinnedElf("air", pins=PINS, directory=directory)
    starts = unwind_starts(elf)
    intervals = {}
    for name, (start, stop) in RANGES.items():
        i = bisect.bisect_left(starts, start)
        if i + 1 >= len(starts) or (starts[i], starts[i + 1]) != (start, stop):
            raise ValueError(f"Selected decoder unwind interval changed: {name}")
        intervals[name] = dict(start=hex(start), stop=hex(stop))
    for address, word in {**WORDS, **COMMAND_LITERALS}.items():
        if elf.uint(address) != word:
            raise ValueError(f"Selected decoder instruction/literal changed at {address:#x}")
    bases = [(pc + 8 + elf.uint(slot)) & 0xFFFFFFFF for pc, slot in (
        (0x39FED0, 0x39FF90), (0x39BE20, 0x39BE44),
        (0x57428C, 0x5743AC), (0x39D2F0, 0x39D744))]
    if set(bases) != {0xA66654}:
        raise ValueError("Selected decoder GOT base changed")
    base = bases[0]
    if (base + elf.uint(0x39FF94) + 0x30) & 0xFFFFFFFF != 0xA5D0E8:
        raise ValueError("Selected decoder constructor vtable changed")
    label_address = (base + elf.uint(0x39BE48)) & 0xFFFFFFFF
    if label_address != 0x931D54 or elf.string(label_address) != "H264 - MainConcept":
        raise ValueError("Selected decoder label changed")
    prefix_address = (base + elf.uint(0x39D750)) & 0xFFFFFFFF
    prefix = elf.data[elf.offset(prefix_address, 4):elf.offset(prefix_address, 4) + 4]
    if prefix_address != 0x931D08 or prefix != b"\0\0\0\1":
        raise ValueError("Selected decoder start-code prefix changed")
    rels = {a: (kind, symbol) for a, kind, symbol in elf.relocations()}
    for slot, target in RELATIVE_SLOTS.items():
        kind, symbol = rels.get(slot, (None, {}))
        if kind != 23 or symbol.get("name") or elf.uint(slot) != target:
            raise ValueError(f"Selected decoder relative relocation changed at {slot:#x}")
    if (elf.string(0x931D20) != "21H264VideoDecompressor"
            or elf.string(0x931D38) != "24H264DecompressorInstance"):
        raise ValueError("Selected decoder RTTI changed")
    for site, target in DIRECT_CALLS.items():
        if arm_call_target(elf, site) != target:
            raise ValueError(f"Selected decoder direct call changed at {site:#x}")
    for slot, target in BACKEND_POINTERS.items():
        if (base + elf.uint(slot)) & 0xFFFFFFFF != target:
            raise ValueError("Selected backend function pointer changed")
    count = elf.uint(elf.dynamic[4] + 4)  # SysV DT_HASH nchain
    if count != 1272:
        raise ValueError("Selected decoder dynamic-symbol count changed")
    selected = {0x260710, 0x39FEB4, 0x39DE6C, 0x574280, 0x573E74,
                0x574440, 0x39FC08, 0x39BE08, 0x39C258}
    exports = [s for s in (elf.symbol(i) for i in range(count))
               if s["section"] and s["value"] in selected]
    if exports:
        raise ValueError("Selected decoder addresses now have defined dynamic symbols")
    calls = selected_calls(elf, IMPORT_CALLS)
    if elf.data != (directory / PINS["air"][0]).read_bytes():
        raise ValueError("Input changed during inspection")
    return dict(
        scope="Static AIR MainConcept-associated path; no decoder execution or target writes",
        input_sha256=PINS["air"][1], selected_unwind_intervals=intervals,
        relative_slots={hex(a): hex(t) for a, t in RELATIVE_SLOTS.items()},
        direct_calls={hex(a): hex(t) for a, t in DIRECT_CALLS.items()},
        native_calls=calls, label=dict(address=hex(label_address), text=elf.string(label_address)),
        backend_pointer_literals={hex(a): hex(t) for a, t in BACKEND_POINTERS.items()},
        input_prefix=dict(address=hex(prefix_address), bytes_hex=prefix.hex()),
        command_literals={hex(a): hex(t) for a, t in COMMAND_LITERALS.items()},
        fallback_output_marker="0x59563132", selected_defined_dynamic_symbols=exports,
        limits=["Selected outer input uses AIR records, not a standalone CarPlay packet API",
                "Backend command layouts, frame ownership and outside-AIR initialization are incomplete",
                "YV12 marker and frame-plane paths do not prove real decoded pixels or speed",
                "Later corpus evidence does not establish installed 6.9.0WL behavior"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassemble", choices=RANGES,
                        help="Read one bounded interval with host LLVM, never the QNX loader")
    args = parser.parse_args()
    print(json.dumps(inspect(), indent=2))
    if args.disassemble:
        elf = PinnedElf("air", pins=PINS, directory=DIRECTORY)
        print(elf.disassemble(LLVM, *RANGES[args.disassemble]))


if __name__ == "__main__":
    main()
