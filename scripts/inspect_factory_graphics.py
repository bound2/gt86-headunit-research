"""Read pinned factory window-manager/configuration evidence on the PC only.

No QNX process, shell fragment, service or display command is executed. The
optional --disassemble operation uses the existing bounded LLVM helper on an
in-memory copy. Default output is selected static metadata, not a renderer.
"""
import argparse
import hashlib
import json
import re
import struct

from inspect_ipod_auth import DIRECTORY, LLVM, PinnedElf, arm_call_target

PINS = {
    "manager": ("usr/bin/DisplayManager", "a4375cb0ecaa9d7c117d2c15210fa6a674bcd555539c901409675dda7028ecf3"),
    "air": ("lib/air/runtimeSDK/Adobe AIR/Versions/1.0/libCore.so", "9f8a7dea6c168cd3c71d4db93885ced8b2a696ab26c403bf27c8bf3b2254f12d"),
    "graphics": ("usr/lib/graphics/jacinto5/graphics.conf", "7bb0b363e9a5d1d09321a8e10ebe5c0256515585ea1353fa0cf44a56a4239b23"),
    "start": ("usr/bin/start_screen.sh", "558affa60925c073820b06c9a3ea326fd46c61a4efefaa92b3986aaf780f9542"),
    "boot": ("boot/scripts/secondary-boot.sh", "581665a0ef5f18b80d2e8cc0203bfd8a476fc5b9130a75c9efbfac4cc39505f8"),
}


def read_inputs(directory=DIRECTORY):
    inputs = {}
    for key, (name, expected) in PINS.items():
        data = (directory / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Not the pinned research input: {name}")
        inputs[key] = data
    return inputs


def class_properties(text, name):
    """Selected flat class blocks only, not a general graphics.conf parser."""
    matches = re.findall(r"^\s*begin class " + re.escape(name)
                         + r"\s*$([\s\S]*?)^\s*end class\s*$", text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"Expected one class block: {name}")
    properties = {}
    for line in matches[0].splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not key or not value or key in properties:
            raise ValueError(f"Malformed selected class: {name}")
        properties[key] = value
    return properties


def manager_metadata(elf):
    """Read two selected descriptors and validate their native callsites."""
    descriptors = {}
    for address, expected in ((0x1285D8, ("v", "Visibility", 0x109694, 51)),
                              (0x128778, ("o", "z-Order", 0x1097A8, 54))):
        words = struct.unpack_from("<8I", elf.data, elf.offset(address, 32))
        command, label, setter, _, parameters, prop, reader, cache_offset = words
        decoded = (chr(command), elf.string(label), setter, prop)
        if decoded != expected or parameters != 1:
            raise ValueError("Selected DisplayManager descriptor changed")
        descriptors[decoded[0]] = dict(address=hex(address), label=decoded[1],
                                       setter=hex(setter), property_id=prop,
                                       parameter_count=parameters,
                                       readback_function=hex(reader),
                                       cached_field_offset=hex(cache_offset))
    count = elf.uint(elf.dynamic[4] + 4)
    if not 0 < count < 4096:
        raise ValueError("Unexpected native symbol count")
    symbols = [elf.symbol(i) for i in range(count)]
    by_address = {s["value"]: s["name"] for s in symbols if not s["section"] and s["value"]}
    expected_calls = {
        0x109760: "screen_set_window_property_iv",
        0x109864: "screen_set_window_property_iv",
        0x108DC4: "screen_get_window_property_iv",
        0x108F20: "screen_get_window_property_iv",
        0x1098E4: "screen_flush_context",
    }
    calls = {}
    for address, expected_name in expected_calls.items():
        target = arm_call_target(elf, address)
        if by_address.get(target) != expected_name:
            raise ValueError("Selected native Screen call changed")
        calls[hex(address)] = dict(target=hex(target), symbol=expected_name)
    if elf.uint(0x1098DC) != 0xE3A01000:
        raise ValueError("Selected flush argument is no longer zero")
    usage = elf.data[0x32CA8:0x337C0]
    cache_phrase = b"disables the cache used for storing the visible states"
    if cache_phrase not in usage:
        raise ValueError("Expected visibility-cache usage text")
    return dict(descriptors=descriptors, selected_calls=calls,
                flush_argument=0,
                visibility_cache_described_in_usage=True,
                imports=sorted(s["name"] for s in symbols
                               if not s["section"] and s["name"].startswith("screen_")))


def inspect(directory=DIRECTORY):
    inputs = read_inputs(directory)
    manager = PinnedElf("manager", pins=PINS, directory=directory)
    if manager.data != inputs["manager"]:
        raise ValueError("Manager changed during inspection")
    graphics = inputs["graphics"].decode("ascii")
    boot = inputs["boot"].decode("ascii")
    start = inputs["start"].decode("ascii")
    if "DisplayManager &" not in boot or "screen &" not in start:
        raise ValueError("Expected stock graphics startup")
    # Exact strings are only evidence of potential API/Flash concepts. In
    # particular generic AIR displayState strings do not link to ToyotaMGR.
    air = inputs["air"]
    air_tokens = (b"displayState", b"flash.display:StageDisplayState",
                  b"NativeWindowDisplayState", b"com.harman.service.ToyotaMGR",
                  b"screen_create_window_type", b"screen_post_window")
    return {
        "scope": "Static later 6.17.0WL corpus, not the running GT86 or a CarPlay renderer",
        "input_sha256": {name: digest for name, digest in PINS.values()},
        "manager": manager_metadata(manager),
        "window_classes": {name: class_properties(graphics, name)
                           for name in ("FlashWindow", "mlc", "framebuffer1")},
        "boot_starts_manager_without_disable_cache":
            re.search(r"^DisplayManager &$", boot, re.MULTILINE) is not None,
        "air_literal_counts": {token.decode(): air.count(token) for token in air_tokens},
        "limits": [
            "Descriptor and callsite checks do not execute the manager's command parser",
            "Visibility/order/readback are not proof of posting a frame or physical screen ownership",
            "AIR literals alone do not establish a Toyota displayState consumer or external decoder API",
            "No SDK ABI, window permissions, rendering throughput or on-car recovery is verified",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassemble", action="store_true",
                        help="List selected setter/flush code with host LLVM; never execute it")
    args = parser.parse_args()
    print(json.dumps(inspect(), indent=2))
    if args.disassemble:
        elf = PinnedElf("manager", pins=PINS)
        print(elf.disassemble(LLVM, 0x109694, 0x109914))


if __name__ == "__main__":
    main()
