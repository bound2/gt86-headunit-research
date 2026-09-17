"""Build only the native diagnostic with a user-supplied QNX ARMv7 SDK.

No SDK downloads, license activation, target execution, image creation or vehicle
connection. Missing SDK inputs fail before output creation or compiler invocation.
--check-sdk performs file checks only; it does not claim SDK/runtime compatibility.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from inspect_qnx_runtime_candidate import ROOT, FACTORY, profile

SOURCE = ROOT / "src/carplay/qnx_network_diagnostic.c"
HEADERS = ("stdio.h", "stdlib.h", "string.h", "errno.h", "sys/types.h", "sys/socket.h",
           "net/if.h", "netinet/in.h", "ifaddrs.h", "unistd.h")
RUNTIME = ("armle-v7/lib/crt1.o", "armle-v7/lib/libc.so.3", "armle-v7/lib/libsocket.so.3")
REQUIRED = {"socket", "close", "getifaddrs", "freeifaddrs", "if_nametoindex"}
FORBIDDEN = {"bind", "listen", "connect", "send", "sendto", "sendmsg", "setsockopt", "ioctl",
             "system", "popen", "execve", "spawn", "mount", "umount"}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sdk_inputs(host, target):
    if not host or not target:
        raise ValueError("Supply --qnx-host and --qnx-target, or configure QNX_HOST/QNX_TARGET with a usable SDK")
    host, target = Path(host).resolve(), Path(target).resolve()
    compiler = host / "usr/bin" / ("qcc.exe" if os.name == "nt" else "qcc")
    config = host / "etc/qcc"
    files = [compiler, SOURCE] + [target / "usr/include" / name for name in HEADERS] + [target / name for name in RUNTIME]
    missing = [str(p) for p in files if not p.is_file()]
    if not config.is_dir():
        missing.append(str(config))
    if missing:
        raise ValueError("Missing QNX ARMv7 development inputs: " + ", ".join(missing))
    return dict(host=str(host), target=str(target), compiler=str(compiler), config=str(config),
                hashes={str(p): digest(p) for p in files}, sdk_compatibility_verified=False)


def factory_exports():
    result = set()
    for key in ("libc", "socket"):
        path, expected = FACTORY[key]
        data = (ROOT / "extracted/qnx-system-v3" / path).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Not the pinned factory library: " + key)
        result.update(profile(data)["exports"])
    return result


def verify_executable(data, exports):
    info = profile(data)
    flags = int(info["flags"], 16)
    if (info["elf_type"] != 2 or flags >> 24 != 5 or flags & 0x400 or
            info["interpreters"] != ["/usr/lib/ldqnx.so.2"]):
        raise ValueError("Not the selected QNX ARM EABI executable form")
    if sorted(info["needed"]) != ["libc.so.3", "libsocket.so.3"]:
        raise ValueError("Unexpected diagnostic runtime dependencies")
    entry, phoff = struct.unpack_from("<II", data, 24)
    count = struct.unpack_from("<H", data, 44)[0]
    segments = [struct.unpack_from("<8I", data, phoff + i * 32) for i in range(count)]
    if not entry or not any(tag == 1 and flags & 1 and base <= entry < base + size
                            for tag, _, base, _, size, _, flags, _ in segments):
        raise ValueError("Entry point is not in file-backed executable memory")
    imports = set(info["imports"])
    if not REQUIRED <= imports:
        raise ValueError("Missing diagnostic query imports")
    all_imports = imports | set(info["weak_imports"])
    if (all_imports & FORBIDDEN or any(s.startswith("usbd_") for s in all_imports)):
        raise ValueError("Unexpected mutating/device API import")
    missing = sorted(imports - exports)
    if missing:
        raise ValueError("Imports absent from pinned factory libraries: " + ", ".join(missing))
    return dict(sha256=info["sha256"], bytes=info["bytes"], flags=info["flags"],
                entry=hex(entry), interpreter=info["interpreters"][0], needed=info["needed"],
                imports=info["imports"], weak_imports=info["weak_imports"],
                selected_elf_checks_passed=True, target_execution_verified=False,
                installed_version_compatibility_verified=False)


def build(host, target, check_only=False):
    inputs = sdk_inputs(host, target)
    exports = factory_exports()
    if check_only:
        return dict(sdk=inputs, native_executable_built=False)
    build_root = ROOT / "build"
    # A fresh directory preserves earlier artifacts and failed compiler output.
    build_root.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="qnx-network-diagnostic-", dir=build_root))
    output = directory / "qnx-network-diagnostic"
    command = [inputs["compiler"], "-Vgcc_ntoarmv7le", "-Wc,-std=c99,-Wall,-Wextra,-Werror",
               "-O2", str(SOURCE), "-o", str(output), "-lsocket"]
    environment = os.environ.copy()
    environment.update(QNX_HOST=inputs["host"], QNX_TARGET=inputs["target"], QCC_CONF_PATH=inputs["config"])
    environment["PATH"] = str(Path(inputs["compiler"]).parent) + os.pathsep + environment.get("PATH", "")
    result = subprocess.run(command, cwd=directory, env=environment, capture_output=True,
                            text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError(f"QNX compiler failed ({result.returncode}); artifacts retained at {directory}\n"
                           + result.stdout[-8192:] + result.stderr[-8192:])
    if any(digest(Path(path)) != expected for path, expected in inputs["hashes"].items()):
        raise ValueError("SDK/source input changed during build; output is unverified")
    verification = verify_executable(output.read_bytes(), exports)
    record = dict(sdk=inputs, command=command, output=str(output), verification=verification,
                  native_executable_built=True, target_executed=False,
                  warning="Not an installer or a CarPlay receiver; no installed-unit execution/recovery established")
    (directory / "build-record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qnx-host", default=os.environ.get("QNX_HOST"))
    parser.add_argument("--qnx-target", default=os.environ.get("QNX_TARGET"))
    parser.add_argument("--check-sdk", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.qnx_host, args.qnx_target, args.check_sdk), indent=2))
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(2, str(error) + "\n")
