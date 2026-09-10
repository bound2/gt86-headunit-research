"""List selected factory display-control routines without executing vendor code.

Only the pinned later 6.17.0WL corpus is accepted. The existing host Lua 5.1
compiler reads verified files with -l -p (list, parse only). No
firmware, USB medium, QNX service or vehicle state is changed. Instruction
listings are evidence for manual analysis, not a hardware ownership test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = Path("extracted/qnx-system-v3/image-380000/usr/share/lua/service/toyotamanager")
LUAC = ROOT / "build/lua-host/Release/luac.exe"
PINS = {
    "toyotamanager.lua": "af611ebdbbff9e5bfb4dfcb2464a1a2b514bb30688d90b5912af4d9d5e4232d2",
    "modemanager.lua": "dc8f8437a02153f5e36ab2bb3a8a39a291b6b1e23a537f116d6e69d4a62c1ed5",
    "avclan.lua": "2a0fa72645758ebcac0f92544a2408a3c41567c42794349138f22ff3e27ae1e6",
    "properties.lua": "34aeacac5faae28cacbdafb1b7a2f28272fd4ff7fc66e7694bdc832060cc9b7b",
    "hmiClient.lua": "d9baa99d7c4bfaa43c41313f14b2d3e8798457c7e5812629736bf85fb0066dec",
}
# Source spans and complete instruction counts verified in the pinned listings.
SECTIONS = {
    "toyotamanager.lua": {
        "signal_forwarder": (82, 85, 13),
        "request_wrapper": (303, 307, 7),
        "release_wrapper": (312, 316, 7),
    },
    "modemanager.lua": {
        "rgb_status": (317, 359, 110),
        "display_callback": (469, 539, 181),
        "local_restore": (1436, 1464, 71),
        "request_control": (2085, 2090, 13),
        "release_control": (2095, 2103, 22),
    },
    "avclan.lua": {
        "ipc_writer": (186, 196, 27),
        "bus_request": (648, 656, 21),
        "bus_confirmation": (659, 661, 6),
        "bus_callback": (663, 667, 10),
        "device_start": (2060, 2081, 67),
    },
    "properties.lua": {"defaults": (0, 0, 105)},
    "hmiClient.lua": {
        "current_screen": (53, 90, 78),
        "first_map_ready": (93, 95, 5),
        "service_available": (97, 117, 72),
        "service_init": (119, 124, 20),
    },
}
HEADER = re.compile(
    r"^(?:main|function) <(.+\.lua):(\d+),(\d+)> \((\d+) instructions?,")
INSTRUCTION = re.compile(r"^\s*(\d+)\s+\[(\d+)\]\s+([A-Z][A-Z0-9]*)\s+(.+?)\s*$")


def read_inputs(root=ROOT):
    """Validate every input before starting even the parse-only host compiler."""
    inputs = {}
    for name, expected in PINS.items():
        data = (root / DIRECTORY / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Not the pinned research input: {name}")
        inputs[name] = data
    return inputs


def select_sections(listing, filename):
    """Parse only selected function bodies; never infer control flow from names."""
    requested = SECTIONS[filename]
    by_span = {(start, end): (name, count)
               for name, (start, end, count) in requested.items()}
    found = {}
    current = None
    for line in listing.splitlines():
        header = HEADER.match(line)
        if header:
            current = None
            source, start, end, count = header.groups()
            source_name = source.replace("\\", "/").rsplit("/", 1)[-1]
            span = (int(start), int(end))
            if source_name == filename and span in by_span:
                name, expected_count = by_span[span]
                if name in found or int(count) != expected_count:
                    raise ValueError(f"Duplicate or changed section: {filename}:{name}")
                current = dict(source=filename, source_start=span[0],
                               source_end=span[1], instructions=[])
                found[name] = current
            continue
        instruction = INSTRUCTION.match(line)
        if current is not None and instruction:
            pc, source_line, opcode, tail = instruction.groups()
            operands, separator, comment = tail.partition(";")
            row = dict(pc=int(pc), line=int(source_line), opcode=opcode,
                       operands=" ".join(operands.split()))
            if separator:
                # Preserve literal spacing. Only closure host addresses vary.
                row["comment"] = "<host address>" if opcode == "CLOSURE" else comment.strip()
            current["instructions"].append(row)
    if set(found) != set(requested):
        raise ValueError(f"Missing selected sections: {filename}")
    for name, section in found.items():
        rows = section["instructions"]
        count = requested[name][2]
        if [row["pc"] for row in rows] != list(range(1, count + 1)):
            raise ValueError(f"Incomplete or malformed listing: {filename}:{name}")
        section["instruction_count"] = count
    return found


def inspect(root=ROOT, luac=LUAC, include_instructions=False):
    inputs = read_inputs(root)
    sections = {}
    for filename, data in inputs.items():
        # -p suppresses compiler output files. No Lua chunk is run. This Win32
        # Lua host reads stdin in text mode, so binary chunks use their paths.
        path = root / DIRECTORY / filename
        result = subprocess.run([str(luac), "-l", "-p", str(path)],
                                capture_output=True, timeout=20, check=True)
        if path.read_bytes() != data:
            raise ValueError(f"Research input changed during inspection: {filename}")
        selected = select_sections(result.stdout.decode("utf-8"), filename)
        for name, section in selected.items():
            normalized = json.dumps(section["instructions"], sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")
            section["listing_sha256"] = hashlib.sha256(normalized).hexdigest()
            if not include_instructions:
                del section["instructions"]
            sections[f"{filename}:{name}"] = section
    return {
        "scope": "Selected static 6.17.0WL listings; installed 6.9.0WL and hardware NOT tested",
        "input_sha256": PINS.copy(),
        "sections": sections,
        "limits": [
            "Parse-only host luac is used; vendor Lua functions are not executed",
            "Names, source spans and instruction counts are not a proof of dataflow",
            "allowed=true and displayState signals alone do not prove physical ownership",
            "No display/video/touch backend, native deployment or CarPlay session is supplied",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instructions", action="store_true",
                        help="Include complete selected normalized instruction listings")
    args = parser.parse_args()
    print(json.dumps(inspect(include_instructions=args.instructions), indent=2))


if __name__ == "__main__":
    main()
