"""Pinned, PC-only inspection of the factory MirrorLink graphics boundary.

This reads ELF metadata and selected ARM instructions. It never loads a vendor
library, opens a QNX device, or submits a frame. See the report for extraction.
"""
import argparse
import hashlib
import json
import struct

from inspect_ipod_auth import ROOT, LLVM, PinnedElf, arm_call_target

WICOME = "extracted/factory-wicome-617-step82/usr/share/MMC_PROG_DATA/wicome/"
PINS = {
    "graphics": (WICOME + "libpal_graphic.so", "e86a25975368a5bddf9ea55c365dacb54e2ce2bfab0a25d7cf015ed6118f1c98"),
    "remote": (WICOME + "libremoteuiservice.so", "b4cd37a07ddefeea4949f0044cfa88309f515beeaf443f11927062ea450c579e"),
    "service": ("extracted/qnx-system-v3/image-16e0000/usr/bin/mirrorLinkSvc", "193a5013c302b81b66c4c7967ea63218fdfd05f592700d9ca8bb58621272d3e9"),
    "boot": ("extracted/qnx-system-v3/image-16e0000/boot/scripts/bluetooth.sh", "048349c0e6a85a7bf19a5033490feaca7e5e11b1e89c9c690fc4a8109f2f3b0a"),
}
RANGES = {
    "create_window": (0xAA5C, 0xB028),
    "egl_init": (0xD52C, 0xDD14),
    "lock_buffer": (0x120F8, 0x1227C),
    "upload_buffer": (0x134F4, 0x138D4),
    "configure_buffer": (0x138D4, 0x143B4),
    "render_buffer": (0xFFC0, 0x10AD0),
    "redraw": (0x16854, 0x16AC4),
    "swap": (0xC05C, 0xC24C),
    "destroy_window": (0x9F98, 0xA168),
    "destroy_egl": (0xC254, 0xC60C),
    "delete_buffers": (0x143B4, 0x144D8),
}
CALLS = {
    0xABA0: "screen_create_context", 0xAC08: "screen_create_window_type",
    0xAC80: "screen_set_window_property_cv", 0xACF8: "screen_set_window_property_cv",
    0xAD64: "screen_set_window_property_iv", 0xADD0: "screen_set_window_property_iv",
    0xAE3C: "screen_set_window_property_iv", 0xAEA4: "screen_create_window_buffers",
    0xAF10: "screen_set_window_property_iv",
    0xD984: "eglCreateWindowSurface", 0xDA08: "eglCreateContext",
    0x140AC: "glTexImage2D", 0x14360: "_Znaj",
    0x136A0: "glTexSubImage2D", 0x10724: "glDrawElements", 0xC13C: "eglSwapBuffers",
    0xC33C: "eglDestroyContext", 0xC3AC: "eglDestroySurface",
    0xC448: "eglTerminate", 0xC544: "eglReleaseThread",
    0x9FF8: "screen_destroy_window", 0xA060: "screen_destroy_context",
    0x14414: "glDeleteTextures", 0x14420: "glDeleteFramebuffers",
    0x1442C: "glDeleteFramebuffers", 0x1443C: "_ZdaPv",
}
# Selected raw instruction assertions; these do not constitute dataflow emulation.
WORDS = {
    0xAAE8: 0xE3A0C000,
    0xAB08: 0xE3A0E020,  # local usage value = 32
    0xAB18: 0xE58DC034,  # local visibility value receives the earlier zero
    0xAC6C: 0xE3A01007,  # class property
    0xACE4: 0xE3A01014,  # ID string property
    0xAD60: 0xE3A0100E,  # format property
    0xADC8: 0xE3A01030,  # usage property
    0xAE34: 0xE3A01028,  # size property
    0xAEA0: 0xE3A01002,  # two Screen window buffers
    0xAF0C: 0xE3A01033,  # visibility property
    0x121A0: 0xE596300C,  # stored CPU buffer pointer
    0x121D0: 0xE58A3000,  # pointer returned through caller reference
    0x1436C: 0xE585000C,  # allocated CPU buffer saved at +0xc
    0x13680: 0xE595800C, 0x1369C: 0xE58D8010,  # same pointer supplied to GL upload
    0x168F8: 0xE5933020, 0x168FC: 0xE12FFF33,  # renderer virtual slot +0x20
    0x1698C: 0xE5933004, 0x16990: 0xE12FFF33,  # control virtual slot +4
    0xC0B8: 0xE5933030, 0xC1B0: 0xE5933034,  # Bind/UnBind slots
}


def read_inputs(directory=ROOT):
    result = {}
    for key, (name, digest) in PINS.items():
        data = (directory / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"Not the pinned research input: {name}")
        result[key] = data
    return result


def static_symbols(elf):
    """Read the intact ELF32 static table in the pinned remote-UI library."""
    data = elf.data
    if len(data) < 52:
        raise ValueError("Truncated ELF32 header")
    def bounded(offset, length):
        if offset < 0 or length < 0 or offset + length > len(data):
            raise ValueError("Static symbol metadata exceeds file bounds")
    shoff = struct.unpack_from("<I", data, 32)[0]
    shsize, shnum = struct.unpack_from("<HH", data, 46)
    if shsize != 40 or not 0 < shnum <= 128:
        raise ValueError("Unexpected ELF32 section directory")
    bounded(shoff, shsize * shnum)
    sections = [struct.unpack_from("<10I", data, shoff + 40 * i) for i in range(shnum)]
    tables = [s for s in sections if s[1] == 2]
    if len(tables) != 1:
        raise ValueError("Expected one static symbol table")
    table = tables[0]
    if table[9] != 16 or table[5] % 16 or not 0 < table[5] // 16 <= 65536 or table[6] >= shnum:
        raise ValueError("Unexpected static symbol table layout")
    strings = sections[table[6]]
    if strings[1] != 3:
        raise ValueError("Static table does not link to a string table")
    bounded(table[4], table[5])
    bounded(strings[4], strings[5])
    result = []
    for offset in range(table[4], table[4] + table[5], 16):
        name, value, size, info, _, section = struct.unpack_from("<IIIBBH", data, offset)
        if name >= strings[5]:
            raise ValueError("Static symbol name outside string table")
        start = strings[4] + name
        end = data.find(b"\0", start, strings[4] + strings[5])
        if end < 0:
            raise ValueError("Unterminated static symbol name")
        result.append(dict(name=data[start:end].decode("ascii"), value=value,
                           size=size, info=info, section=section))
    return result


def rotated_immediate(word):
    value, rotation = word & 255, ((word >> 8) & 15) * 2
    return ((value >> rotation) | (value << (32 - rotation))) & 0xFFFFFFFF if rotation else value


def resolve_plt(elf, address, jump_slots):
    """Resolve only the observed ARM ADD/ADD/LDR three-word PLT form."""
    if address < 0 or address % 4:
        raise ValueError("Expected an aligned ARM PLT address")
    first, second, third = (elf.uint(address + i) for i in (0, 4, 8))
    if (first & 0xFFFFF000 != 0xE28FC000 or second & 0xFFFFF000 != 0xE28CC000
            or third & 0xFFFFF000 != 0xE5BCF000):
        raise ValueError("Unsupported selected ARM PLT form")
    slot = (address + 8 + rotated_immediate(first) + rotated_immediate(second)
            + (third & 4095)) & 0xFFFFFFFF
    if slot not in jump_slots:
        raise ValueError("Selected PLT has no matching jump-slot relocation")
    return dict(plt=hex(address), got=hex(slot), symbol=jump_slots[slot]["name"])


def selected_calls(elf, expected):
    slots = {address: symbol for address, kind, symbol in elf.relocations() if kind == 22}
    result = {}
    for site, name in expected.items():
        resolved = resolve_plt(elf, arm_call_target(elf, site), slots)
        if resolved["symbol"] != name:
            raise ValueError(f"Selected native call changed at {site:#x}")
        result[hex(site)] = resolved
    return result


def inspect(directory=ROOT):
    inputs = read_inputs(directory)  # Validate every input before ELF analysis.
    elfs = {key: PinnedElf(key, pins=PINS, directory=directory)
            for key in ("graphics", "remote", "service")}
    if any(elf.data != inputs[key] for key, elf in elfs.items()):
        raise ValueError("Input changed during inspection")
    graphics, remote, service = (elfs[k] for k in ("graphics", "remote", "service"))
    for address, word in WORDS.items():
        if graphics.uint(address) != word:
            raise ValueError(f"Selected graphics instruction changed at {address:#x}")
    symbols = static_symbols(remote)
    callers = {}
    for site in (0x58C0C, 0x59624):
        enclosing = [s for s in symbols if s["info"] & 15 == 2
                     and s["value"] <= site < s["value"] + s["size"]]
        if len(enclosing) != 1:
            raise ValueError("Ambiguous selected remote-UI function")
        callers[hex(site)] = enclosing[0]
    relocations = {a: (k, s) for a, k, s in graphics.relocations()}
    virtuals = {}
    for slot, value in ((0x1D370, 0xFFC0), (0x1D14C, 0xC05C),
                        (0x1D178, 0xBD48), (0x1D17C, 0xBC3C)):
        kind, symbol = relocations[slot]
        if kind != 2 or graphics.uint(slot) != 0 or symbol["value"] != value:
            raise ValueError("Selected virtual-method relocation changed")
        virtuals[hex(slot)] = symbol
    service_calls = {hex(a): hex(arm_call_target(service, a)) for a in (0x1136A4, 0x11379C)}
    if set(service_calls.values()) != {"0x11b5a0"}:
        raise ValueError("Selected service writer changed")
    boot = inputs["boot"].decode("ascii")
    return dict(
        scope="Static 6.17.0WL factory graphics, not a CarPlay renderer or installed-unit test",
        input_sha256={name: digest for name, digest in PINS.values()},
        graphics_calls=selected_calls(graphics, CALLS),
        virtual_method_relocations=virtuals,
        remote_factory_calls=selected_calls(remote, {
            0x58C0C: "_ZN3PAL7Graphic14IGraphicWindow6CreateEv",
            0x59624: "_ZN3PAL7Graphic14IGraphicWindow6CreateEv",
            0x582E0: "_ZN3PAL7Graphic14IGraphicWindow7DestroyERPS1_"}),
        remote_factory_callers=callers,
        frame_update_command_literals={hex(slot): service.string(service.uint(slot))
                                       for slot in (0x1136F0, 0x1137E8)},
        service_writer_calls=service_calls,
        boot_links_wicome_libraries="qln -sP /fs/mmc0/ifs/wicome /usr/lib/wicome" in boot,
        limits=["Selected callsites/relocations are not a complete dynamic dispatch proof",
                "CPU pixel upload and EGL presentation do not establish H.264 decoding",
                "Window buffers and visibility are not physical display ownership",
                "No vendor binary, graphics driver, phone session or car operation runs"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassemble", choices=RANGES,
                        help="List a selected routine with host LLVM; never execute it")
    args = parser.parse_args()
    print(json.dumps(inspect(), indent=2))
    if args.disassemble:
        elf = PinnedElf("graphics", pins=PINS, directory=ROOT)
        print(elf.disassemble(LLVM, *RANGES[args.disassemble]))


if __name__ == "__main__":
    main()
