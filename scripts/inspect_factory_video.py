"""Pinned PC-only RAW-pixel/WFD boundary inspection, never a video decoder.

Default inspection reads metadata/instructions only. Optional bounded host LLVM
listing never loads the QNX library. Inputs were recovered in research Step 82.
"""
import argparse
import hashlib
import json

from inspect_mirrorlink_graphics import (
    ROOT, LLVM, PINS as GRAPHICS_PINS, PinnedElf, arm_call_target,
    selected_calls, static_symbols,
)

PINS = {key: GRAPHICS_PINS[key] for key in ("remote", "graphics")}
RANGES = {
    "raw": (0x173028, 0x1732AC),
    "raw_base": (0x172744, 0x172D58),
    "wfd_factory": (0x1050FC, 0x1051B0),
    "wfd_caller": (0x73000, 0x73064),
}
FUNCTIONS = {
    "raw": (0x173028, 644, "_ZN3Rfb12CRfbCodecRaw16decodeFromBufferEPKhRKjRjRb"),
    "raw_base": (0x172744, 1556, "_ZN3Rfb20CRfbGraphicCodecBase10FromBufferEPKhRKjRjRb"),
    "wfd_factory": (0x1050FC, 180,
                    "_ZN10MirrorLink3Wfd6Client20IMirrorLinkWfdClient6CreateERKN3PAL7CStringERNS2_9IReceiverE"),
}
WORDS = {
    0x1728B8: 0xE5933014,  # window GetBufferPixelFormat slot
    0x1729E0: 0xE59CC024, 0x1729E4: 0xE12FFF3C,  # window LockBuffer
    0x172AAC: 0xE59CC01C, 0x172AB0: 0xE12FFF3C,  # codec decodeFromBuffer
    0x172BDC: 0xE5933028, 0x172BE0: 0xE12FFF33,  # window UnlockBuffer
    0x173194: 0xE594C014,  # owned destination pointer saved by lock
    0x173198: 0xE020E390, 0x17319C: 0xE08C0000,  # row/stride/offset destination
    0x17341C: 0xE2833018, 0x173420: 0xE5853000,  # RAW vtable address point
    0x73014: 0xE3500000, 0x7301C: 0xE586012C,  # test/store factory pointer
    0x73020: 0x1A00000F,  # nonnull branch past the failure path
    0x73058: 0xE3A03001, 0x7305C: 0xE58D3224,  # selected failure result = 1
}


def read_inputs(directory=ROOT):
    inputs = {}
    for key, (name, expected) in PINS.items():
        data = (directory / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Not the pinned research input: {name}")
        inputs[key] = data
    return inputs


def wfd_factory(elf):
    """Check the complete manually audited factory, including its literal pool.

This is not an emulator or a general null-return detector. The whole-function
hash binds the straight-line/r5-preservation interpretation to the audited body.
"""
    start, stop = RANGES["wfd_factory"]
    offset = elf.offset(start, stop - start)
    digest = hashlib.sha256(elf.data[offset:offset + stop - start]).hexdigest()
    if digest != "533750574eae1612fcbd99cfd1d85386d540708173dd9ebee22e7c6a66fc3b1f":
        raise ValueError("Selected WFD factory body changed")
    for address, expected in ((0x105118, 0xE3A05000),  # r5 = 0
                              (0x10518C, 0xE1A00005),  # r0 = r5
                              (0x105194, 0xE8BD81F0)):  # return; r0 not restored
        if elf.uint(address) != expected:
            raise ValueError("Selected WFD return changed")
    branches = [address for address in range(start, 0x105198, 4)
                if elf.uint(address) & 0x0E000000 == 0x0A000000]
    if branches != [0x105158, 0x105188]:
        raise ValueError("Selected WFD branch inventory changed")
    calls = selected_calls(elf, {site: "StarRec_TraceOut_trace" for site in branches})
    return dict(address=hex(start), bytes=stop - start, body_sha256=digest,
                calls=calls, normal_return_value=0,
                interpretation="Null factory on ordinary return under the native calling convention; not an operational WFD client")


def inspect(directory=ROOT):
    inputs = read_inputs(directory)  # Pin both inputs before parsing either.
    remote, graphics = (PinnedElf(key, pins=PINS, directory=directory)
                        for key in ("remote", "graphics"))
    if remote.data != inputs["remote"] or graphics.data != inputs["graphics"]:
        raise ValueError("Input changed during inspection")
    for address, expected in WORDS.items():
        if remote.uint(address) != expected:
            raise ValueError(f"Selected video-boundary word changed at {address:#x}")
    symbols = static_symbols(remote)
    functions = {}
    for key, (address, size, name) in FUNCTIONS.items():
        matches = [s for s in symbols if s["name"] == name and s["info"] & 15 == 2]
        if len(matches) != 1 or (matches[0]["value"], matches[0]["size"]) != (address, size):
            raise ValueError(f"Selected function boundary changed: {key}")
        functions[key] = matches[0]
    remote_rels = {a: (kind, symbol) for a, kind, symbol in remote.relocations()}
    relative_slots = {}
    # Constructor GOT -> RAW vtable, and that vtable's +0x1c decoding slot.
    for slot, target in ((0x1E17D8, 0x1E0628), (0x1E065C, 0x173028)):
        kind, symbol = remote_rels[slot]
        if kind != 23 or symbol["name"] or remote.uint(slot) != target:
            raise ValueError("Selected RAW relative relocation changed")
        relative_slots[hex(slot)] = hex(target)
    graphics_rels = {a: (kind, symbol) for a, kind, symbol in graphics.relocations()}
    window_slots = {}
    for slot, target, method in ((0x1D42C, 0x17880, "20GetBufferPixelFormat"),
                                 (0x1D43C, 0x16CA0, "10LockBuffer"),
                                 (0x1D440, 0x16AC4, "12UnlockBuffer")):
        kind, symbol = graphics_rels[slot]
        if (kind != 2 or graphics.uint(slot) != 0 or symbol["value"] != target
                or method not in symbol["name"]):
            raise ValueError("Selected graphic-window virtual relocation changed")
        window_slots[hex(slot)] = symbol
    if arm_call_target(remote, 0x73010) != 0x1050FC:
        raise ValueError("Selected WFD factory caller changed")
    return dict(scope="Static later-corpus evidence; no decoding, device access or vendor execution",
                input_sha256={name: digest for name, digest in PINS.values()},
                functions=functions, raw_relative_slots=relative_slots,
                window_virtual_slots=window_slots,
                raw_copy_call=selected_calls(remote, {0x1731A0: "memcpy"}),
                wfd_factory=wfd_factory(remote), wfd_factory_caller="0x73010",
                limits=["RAW pixel copying is not H.264 decompression",
                        "Selected null factory does not prove absence of all decoders",
                        "AIR decoder availability and external ABI remain unresolved",
                        "The installed 6.9.0WL version and real CarPlay remain untested"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassemble", choices=RANGES,
                        help="Print one bounded host LLVM listing; never run the vendor code")
    args = parser.parse_args()
    print(json.dumps(inspect(), indent=2))
    if args.disassemble:
        elf = PinnedElf("remote", pins=PINS, directory=ROOT)
        print(elf.disassemble(LLVM, *RANGES[args.disassemble]))


if __name__ == "__main__":
    main()
