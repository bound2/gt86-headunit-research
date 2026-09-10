"""Read pinned AIR media-graph evidence without loading or running vendor code.

The exception index supplies bounded unwind intervals, not recovered C++ names
or guaranteed one-function-per-entry sizes. Default mode launches no subprocess.
"""
import argparse
import bisect
import json

from inspect_factory_graphics import DIRECTORY, LLVM, PINS as GRAPHICS_PINS
from inspect_ipod_auth import PinnedElf, arm_call_target
from inspect_mirrorlink_graphics import selected_calls

PINS = {"air": GRAPHICS_PINS["air"]}
RANGES = {
    "initialize": (0x35940C, 0x3595B4),
    "graph": (0x3595B4, 0x35A3E8),
    "plane_setup": (0x35AD74, 0x35B264),
    "push": (0x354204, 0x35430C),
    "consume": (0x3556F8, 0x355A00),
}
CALLS = {
    0x359434: "getenv", 0x359438: "MmInitialize",
    0x35948C: "AoFindName", 0x3594C8: "AoFindName",
    0x359508: "AoFindName", 0x359544: "AoFindName",
    0x3596C0: "MmCreateGraph", 0x3596D4: "MmFindFilter",
    0x359730: "MmGetResourceValue", 0x3597B0: "MmSetResourceValue",
    0x3597C4: "MmSetResourceValue", 0x35980C: "MmAcquireOutputChannel",
    0x359820: "MmFindChannelsFilter", 0x359830: "MmAcquireOutputChannel",
    0x359878: "MmFindFilter", 0x35990C: "MmAcquireInputChannel",
    0x35991C: "MmAttachChannels", 0x3599F0: "MmFindFilter",
    0x359A30: "MmSetResourceValue", 0x359D3C: "MmAcquireInputChannel",
    0x359D4C: "MmAttachChannels", 0x35A0E8: "MmFinalizeGraph",
    0x35A118: "MmDestroyGraph", 0x35A164: "MmStart",
    0x35A1F8: "MmDestroyGraph",
}
# Each is an observed literal-pool offset relative to the selected GOT base.
LITERALS = {
    0x359584: "MM_INIT", 0x359594: "queue_filter",
    0x35959C: "flash_reader", 0x3595A4: "screen_writer", 0x3595AC: "frame_writer",
    0x35A2F8: "AIRMediaOut", 0x35A2FC: "flash_reader",
    0x35A308: "MM_FLASH_READER_STANDALONE",
    0x35A30C: "MM_FLASH_READER_QUEUE_SIZE",
    0x35A310: "MM_FLASH_READER_PUSH_ENTRY_PT",
    0x35A31C: "MM_FLASH_READER_VIDEO_FOURCC",
    0x35A320: "MM_FLASH_READER_VIDEO_WIDTH",
    0x35A324: "MM_FLASH_READER_VIDEO_HEIGHT",
    0x35A33C: "queue_filter", 0x35A36C: "SCREEN_WRITER_EXT_CONTEXT",
    0x35A378: "SCREEN_WRITER_EXT_BACK_WINDOW",
    0x35A390: "SCREEN_WRITER_POST_BUFFER_NOSYNC",
    0x35A394: "SCREEN_WRITER_DISABLE_MEDIACLOCK",
    0x35A3E0: "VideoDecoderLowLatencyMode", 0x35B254: "screen_writer",
}
WORDS = {
    0x359420: 0xE08F5005, 0x3595E0: 0xE08F5005, 0x35ADAC: 0xE08F6006,
    0x359738: 0x15900000, 0x359740: 0xE5840020,  # resource pointer dereference/store
    0x3542A8: 0xE59C3020, 0x3542C0: 0xE12FFF33,  # callback reload/indirect call
    0x359768: 0x0A00017D,  # non-video branch skips selected video graph path
    0x359808: 0xE3A0110A, 0x359818: 0xE5841074,  # selected compressed channel/store
    0x35982C: 0xE3A01002,  # selected raw video output channel request
    0x35A0EC: 0xE3500000, 0x35A0F0: 0x0A00000A,  # finalize result test
    0x35A1FC: 0xE3A06000, 0x35A200: 0xE5846044,  # backlog failure graph cleared
    0x35AFA8: 0xE5943014, 0x35AFAC: 0xE3530007,
    0x35AFB0: 0x059F5290, 0x35B248: 0x48323634,  # selected H264 marker
    0x35AFEC: 0xE583504C, 0x35AFFC: 0xE583206C,  # codec/writer in helper state
}


def prel31(address, word):
    """Decode an index entry's signed place-relative 31-bit first word."""
    if not 0 <= address <= 0xFFFFFFFF or not 0 <= word < 0x80000000:
        raise ValueError("Invalid exception-index PREL31 input")
    signed = word - (0x80000000 if word & 0x40000000 else 0)
    return (address + signed) & 0xFFFFFFFF


def unwind_starts(elf):
    entries = [s for s in elf.segments if s[0] == 0x70000001]
    if len(entries) != 1:
        raise ValueError("Expected one ARM exception-index segment")
    _, offset, address, _, length, *_ = entries[0]
    if (address % 4 or length % 8 or not 0 < length // 8 <= 65536
            or elf.offset(address, length) != offset):
        raise ValueError("Invalid exception-index bounds")
    result = []
    for pos in range(address, address + length, 8):
        target = prel31(pos, elf.uint(pos)) & ~1  # normalize a Thumb-state bit
        if not any(k == 1 and flags & 1 and start <= target < start + size
                   for k, _, start, _, size, _, flags, _ in elf.segments):
            raise ValueError("Exception-index target outside file-backed executable segments")
        if result and target <= result[-1]:
            raise ValueError("Exception-index targets are not strictly ordered")
        result.append(target)
    return result


def inspect(directory=DIRECTORY):
    elf = PinnedElf("air", pins=PINS, directory=directory)
    starts = unwind_starts(elf)
    intervals = {}
    for name, (start, stop) in RANGES.items():
        i = bisect.bisect_left(starts, start)
        if i + 1 >= len(starts) or (starts[i], starts[i + 1]) != (start, stop):
            raise ValueError(f"Selected unwind interval changed: {name}")
        intervals[name] = dict(start=hex(start), stop=hex(stop), bytes=stop - start)
    for address, word in WORDS.items():
        if elf.uint(address) != word:
            raise ValueError(f"Selected AIR instruction/literal changed at {address:#x}")
    bases = [(pc + 8 + elf.uint(slot)) & 0xFFFFFFFF
             for pc, slot in ((0x359420, 0x359580), (0x3595E0, 0x35A2E0),
                              (0x35ADAC, 0x35B228))]
    if set(bases) != {0xA66654}:
        raise ValueError("Selected AIR GOT base changed")
    literals = {}
    for slot, expected in LITERALS.items():
        address = (bases[0] + elf.uint(slot)) & 0xFFFFFFFF
        if elf.string(address) != expected:
            raise ValueError(f"Selected AIR resource literal changed at {slot:#x}")
        literals[hex(slot)] = dict(address=hex(address), text=expected)
    rels = {a: (kind, symbol) for a, kind, symbol in elf.relocations()}
    # RTTI name and selected vtable method, not exported decoder function names.
    relative_slots = {}
    for slot, expected in ((0xA59B1C, 0xA5A2A0), (0xA5A2A4, 0x92E5B8),
                            (0xA59B38, 0x35AD74), (0xA5D164, 0x931D20)):
        kind, symbol = rels[slot]
        if kind != 23 or symbol["name"] or elf.uint(slot) != expected:
            raise ValueError("Selected AIR relative relocation changed")
        relative_slots[hex(slot)] = hex(expected)
    if (elf.string(0x92E5B8) != "17H264MMFPlaneCodec"
            or elf.string(0x931D20) != "21H264VideoDecompressor"):
        raise ValueError("Selected AIR RTTI name changed")
    direct = {}
    for site, target in ((0x359608, 0x35940C), (0x35B120, 0x3595B4), (0x355808, 0x354204),
                          (0x355858, 0x354204), (0x35A1D4, 0x3556F8)):
        if arm_call_target(elf, site) != target:
            raise ValueError("Selected AIR direct call changed")
        direct[hex(site)] = hex(target)
    if elf.data != (directory / PINS["air"][0]).read_bytes():
        raise ValueError("Input changed during inspection")
    return dict(scope="Static AIR MMF graph; no decoder or target process is executed",
                input_sha256=PINS["air"][1], unwind_entry_count=len(starts),
                selected_unwind_intervals=intervals, native_calls=selected_calls(elf, CALLS),
                literals=literals, relative_slots=relative_slots, direct_calls=direct,
                limits=["Graph construction does not prove its filters exist or decode on this unit",
                        "Callback signature, ownership and compressed-frame framing remain incomplete",
                        "The selected screen-writer path does not return CPU RGBA frames",
                        "Separate MainConcept decompressor and external API remain unresolved"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassemble", choices=RANGES,
                        help="List one bounded interval using host LLVM, never the QNX loader")
    args = parser.parse_args()
    print(json.dumps(inspect(), indent=2))
    if args.disassemble:
        elf = PinnedElf("air", pins=PINS, directory=DIRECTORY)
        print(elf.disassemble(LLVM, *RANGES[args.disassemble]))


if __name__ == "__main__":
    main()
