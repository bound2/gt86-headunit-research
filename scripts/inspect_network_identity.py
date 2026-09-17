"""Pinned factory networking identity/readiness evidence, without native I/O.

Default inspection reads files only. Optional LLVM disassembly uses the existing
bounded in-memory header adapter; it never starts a factory service.
"""
import argparse
import hashlib
import json

from inspect_ipod_auth import ROOT, LLVM, PinnedElf
from inspect_factory_network import check_words, check_local_calls
from inspect_mirrorlink_graphics import static_symbols, selected_calls

PINS = {
    "network": ("extracted/factory-network-617-step99/usr/share/MMC_PROG_DATA/wicome/libnetworkingservice.so",
                "30ac5eb41a56be89e252c52af4e52c16791742977966d3d8e418822cd6d5d55c"),
    "config": ("extracted/qnx-system-v3/image-16e0000/etc/wicome/wicome.cfg",
               "b56af8f9393fd8ebe97b118c221b34b1a6a047369012ca564884476b23123fb3"),
}
SYMBOLS = {
    "query_interface": (0x7A07C, 708, "_ZNK3CIP19createNewIfInstanceERKN3PAL7CStringER10CInterface"),
    "find_index": (0x8061C, 88, "_ZNK3CIP23findInterfaceByIfNumberEi"),
    "create_event": (0x83A60, 1260, "_ZN3CIP20handleCreateEventMsgERKN3PAL7CStringEN12CIpMsgThread13IpEventType_tEi"),
    "info_event": (0x84050, 1616, "_ZN3CIP18handleInfoEventMsgEiN12CIpMsgThread12IfInfoBits_tE"),
    "initial_snapshot": (0x7C0F8, 1284, "_ZN3CIP10initializeEv"),
    "route_socket": (0xC9828, 544, "_ZN12CIpMsgThread15initIpMsgThreadEv"),
    "route_events": (0xCA4FC, 3388, "_ZN12CIpMsgThread16receiveSockEventEv"),
    "copy_address": (0xCC9D0, 68, "_ZN7CIpAddr11setSockAddrERK11sockaddr_in"),
    "configuration": (0x83080, 2528, "_ZN3CIP17readServiceConfigERKN3PAL7CStringE"),
    "get_cached_config": (0x82178, 704, "_ZNK3CIP11getIfConfigERKN3PAL7CStringERNS0_7TVectorI9CIfConfigEE"),
    "copy_cached_config": (0x866B4, 140, "_ZN9CIfConfig15convertIfConfigERK10CInterface"),
    "ethernet_carplay_enable": (0x70348, 8, "_ZN9CEthernet17p2p_enableCarplayERKN3PAL7CStringEiS3_S3_S3_S3_iS3_S3_"),
    "ethernet_carplay_disable": (0x70350, 8, "_ZN9CEthernet18p2p_disableCarplayERKN3PAL7CStringE"),
}
WORDS = {
    0x7A07C: 0xE3A00002, 0x7A090: 0xE1A01000, 0x7A094: 0xE3A02000,
    0x7A0F4: 0xE3A02090, 0x7A338: 0xC0906980,
    0x7A174: 0xE3560006, 0x7A1B8: 0xE3560017, 0x7A1FC: 0xE3560047,
    0x7A240: 0xE3560018, 0x7A270: 0xE3A06001,
    0x7A2DC: 0xE3530002, 0x7A2E8: 0xE3A01001, 0x7A2F8: 0xE3A01000,
    0x80628: 0xE2806064, 0x80638: 0xE5908004, 0x80648: 0xE1500007,
    0x7D5C8: 0xE590005C, 0x7D614: 0xE5D00078, 0x7D624: 0xE5D00079,
    0x83AD0: 0xE2858064, 0x83BFC: 0xEBFFE66F, 0x83C04: 0xE3A01000,
    0x83CD0: 0xE5953044, 0x83D20: 0xE12FFF33,
    0x83D28: 0xE3500000, 0x83D2C: 0xA3570001,
    0x83E0C: 0xE12FFF33, 0x83EB8: 0xE12FFF33,
    0xC98F4: 0xE3A01003, 0xC98F8: 0xE3A00011, 0xC9908: 0xE586004C,
    0xCA698: 0xE5D5C003, 0xCA69C: 0xE24C300C, 0xCA6A0: 0xE3530005,
    0xCA6A4: 0x908FF103, 0xCA6B4: 0xEA0002BD, 0xCA6B8: 0xEA00007F,
    0xCA93C: 0xE00EE003, 0xCA954: 0xE15C0002, 0xCA984: 0xE1D510BC,
    0xCA990: 0xE12FFF33, 0xCAADC: 0xE3530002, 0xCAAE0: 0x13530018,
    0x7C30C: 0xE3530002, 0x7C310: 0x13530018,
    0x7C4A0: 0xE2111001, 0x7C4C8: 0xE3530012, 0x7C4E0: 0xE1D510B2,
    0xCC9DC: 0xE3530002, 0xCC9E4: 0xE3A02010,
    0xCC9F8: 0xE3530018, 0xCC9FC: 0x18BD8010, 0xCCA00: 0xE3A0201C,
    0xCCA0C: 0xE5C4301C,
    0x70348: 0xE3A00004, 0x7034C: 0xE12FFF1E,
    0x70350: 0xE3A00004, 0x70354: 0xE12FFF1E,
}
LOCAL = {
    0x7A098: 0x116EC4, 0x7A2C8: 0x7D774, 0x7A2D4: 0x7D5D0,
    0x7A2EC: 0x7D61C, 0x7A2FC: 0x7D61C, 0x7A308: 0x7D674,
    0x80634: 0x7A464, 0x80644: 0x7D5C8,
    0x83AE4: 0x7A590, 0x83B44: 0x7A07C, 0x83BFC: 0x7D5C0,
    0x83C08: 0x7D61C, 0x83C48: 0x7C0B0, 0x83CCC: 0x83080,
    0x83DFC: 0x7F744, 0x840D4: 0x8061C,
    0x84154: 0x7D60C, 0x8417C: 0x7D61C, 0x84228: 0x82718,
    0xC98FC: 0x116EC4, 0x7C25C: 0x10AD70,
    0x7C33C: 0xCC9D0, 0x7C348: 0xCC9D0, 0x7C4E4: 0x7D5C0,
    0xCAAF0: 0xCC9D0,
    0x8228C: 0x866B4, 0x8238C: 0x866B4,
    0x866D8: 0x7D5C8, 0x8671C: 0x7D614, 0x86728: 0x7D624,
}
IMPORTS = {
    0x7A100: "StarRec_PAL_memset", 0x7A110: "StarRec_PAL_strcpy",
    0x7A120: "ioctl", 0x7A314: "close", 0x83C18: "StarRec_PAL_GetMACAdress",
    0x8310C: "ConfigMgr_GetNumValueElems", 0xC996C: "StarRec_PAL_IOWatch_CallbackAdd",
    0xCA570: "read", 0xCC9E8: "memcpy", 0xCCA04: "memcpy",
}


def inspect(directory=ROOT):
    inputs = {key: (directory / path).read_bytes() for key, (path, _) in PINS.items()}
    for key, data in inputs.items():
        if hashlib.sha256(data).hexdigest() != PINS[key][1]:
            raise ValueError(f"Not the pinned network identity input: {key}")
    elf = PinnedElf("network", pins=PINS, directory=directory)
    if elf.data != inputs["network"]:
        raise ValueError("Network input changed during inspection")
    symbols = static_symbols(elf)
    for address, size, name in SYMBOLS.values():
        matches = [s for s in symbols if s["name"] == name and s["section"]]
        if len(matches) != 1 or (matches[0]["value"], matches[0]["size"]) != (address, size):
            raise ValueError(f"Selected network symbol changed: {name}")
    check_words(elf, WORDS)
    base = (0x83090 + 8 + elf.uint(0x83A10)) & 0xFFFFFFFF
    strings = {hex(slot): elf.string((base + elf.uint(slot)) & 0xFFFFFFFF)
               for slot in (0x83A18, 0x83A1C, 0x83A24, 0x83A28)}
    if list(strings.values()) != ["NetworkingService", "ipmode", "dhcp", "dhcp6"]:
        raise ValueError("Selected per-name configuration keys changed")
    lines = [dict(line=n, text=line) for n, line in enumerate(inputs["config"].decode("latin1").splitlines(), 1)
             if line.startswith(("NetworkingService_5.", "NetworkingService_ncm0.", "UPnPService.InterfaceName"))]
    return dict(inputs={key: dict(path=path, sha256=digest) for key, (path, digest) in PINS.items()},
                config=lines, symbols={key: dict(address=hex(a), size=n, name=s) for key, (a, n, s) in SYMBOLS.items()},
                words={hex(a): hex(w) for a, w in WORDS.items()}, local_calls=check_local_calls(elf, LOCAL),
                imports=selected_calls(elf, IMPORTS), config_literals=strings,
                identity="Cached map by interface name; info-event lookup by numeric interface index, not USB identity",
                readiness="Interface/link flags and addresses are distinct observations; no phone/listener proof",
                ipv6="Client accepts family 24 and copies 28-byte sockaddr; this does not provide an IPv6 stack",
                actual_phone_or_target_verified=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassemble", action="store_true")
    parser.add_argument("--start", type=lambda s: int(s, 0))
    parser.add_argument("--stop", type=lambda s: int(s, 0))
    args = parser.parse_args()
    if args.disassemble:
        if args.start is None or args.stop is None:
            parser.error("--disassemble requires --start and --stop")
        print(PinnedElf("network", pins=PINS, directory=ROOT).disassemble(LLVM, args.start, args.stop))
    elif args.start is not None or args.stop is not None:
        parser.error("address options require --disassemble")
    else:
        print(json.dumps(inspect(), indent=2))
