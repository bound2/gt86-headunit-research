"""Replay pinned Toyota Lua update entry points using host-only mocks.

No firmware is changed. Guest shell commands, services and files are simulated;
native QNX executables, installers and hardware are never invoked. This is a
control-flow test, not full-system emulation or an installation procedure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {
    "extracted/swdl/etc/manifest.lua":
        "f6f54e4148e7fd66930cd1318e916700185dd596e14ed07c9e4b5074f45287f1",
    "extracted/install/etc/manifest.lua":
        "062922eae11e43c6d971fd130af64d484d6e69a791c36c4806192deaa3f278bf",
    "extracted/qnx-system-v3/image-380000/usr/share/lua/service/swdlMediaDetect/loader.lua":
        "3fcfa1ff457b99d4cb28f6a589ccf8666716feccc849e9bdc134b474651dd214",
    "extracted/qnx-system-v3/image-380000/usr/share/lua/service/swdlMediaDetect/swdlMediaDetect.lua":
        "17c75b43b2deb30c2aabbea9f582ac181d5ff4752aee863ff9b03832c6759a02",
    "extracted/install/usr/share/scripts/update/authISO.lua":
        "a798d89d640e38a06662248a731de9b9bfd06949e00317af343dd148b9590c17",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional new JSON evidence file")
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise FileExistsError(args.output)
    for name, expected in INPUTS.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Not the pinned research input: {name}")
    lua = ROOT / "build/lua-host/Release/lua.exe"
    if not lua.is_file():
        raise FileNotFoundError("Build the Win32 Lua 5.1.5 host; see README.md")
    result = subprocess.run(
        [str(lua), str(ROOT / "tests/update_path_probe.lua"),
         *(str(ROOT / name) for name in INPUTS)],
        capture_output=True, text=True, timeout=20,
    )
    if result.returncode:
        raise RuntimeError(f"Lua harness failed ({result.returncode}):\n{result.stderr}")
    evidence = json.loads(result.stdout)
    evidence["input_sha256"] = INPUTS
    evidence["scope"] = {
        "firmware": "6.17.0WL corpus; owner's 6.9.0WL not tested",
        "guest_io": "Mocks only; unexpected operations fail",
        "manifest": "Complete stock manifests evaluated",
        "native_installers_executed": False,
        "sam_hardware_emulated": False,
        "modified_iso_written": False,
        "car_tested": False,
        "carplay_implemented": False,
    }
    rendered = json.dumps(evidence, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            output.write(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
