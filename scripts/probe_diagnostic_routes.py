"""Inspect pinned diagnostic candidates and replay two stock Lua consumers safely.

This PC-only tool neither prepares USB trigger files nor executes vendor shell
scripts. MCD decisions are modeled with synthetic callout results, not hardware.
The snapshot member is read to memory from the pinned ISO using Windows tar.
"""
import argparse
import configparser
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "extracted/qnx-system-v3"
PINS = {
    "image-380000/usr/share/lua/service/insightDetect/insightDetect.lua":
        "ab45932003b4b68040b8718b8705176be6eb14db303a9cc29c33ce6ea3712eac",
    "image-380000/usr/share/connmgr/AppleAppIns.lua":
        "e03f5a3c2f6a18120dc1368b02644fad5261c1e64610927b8a2eccd6542257ae",
    "image-120000/etc/mcd.conf": "c51251069a8efdbfb67f9182f62efea8a2f95f51b0ba7330ebbec815dfc7e8b4",
    "image-120000/etc/mcdLossless.conf": "4b0fdcc42a25f556e6bf94daf56df861e7ec0a4e07d9a786eb88466323187480",
    "image-16e0000/boot/scripts/runacpclient.sh": "7acfd2f2354d947a9c6e1d7191d81e9b290a95de3905748192319363f674c543",
    "image-380000/etc/acp-toyota.conf": "7131d5a471d470ff9f26895396bf97517dc267727c98eef8569bc9b898c57191",
    "image-16e0000/boot/scripts/dumper.sh": "b1bb196c3144a5826705cfbd738345f7df4a1bc96df2039bd0549ce9b1b38e6d",
    "image-16e0000/boot/scripts/misc.sh": "7b6d8c01e2ebcad4818f18dd6972779dfcfdb4825401e91eb28997e66659a547",
    "image-380000/boot/scripts/pre-hmi.sh": "26d2fed3ba6ae4db444e7c0a53666605217ca50f5f1aaead46f25dfbb09d5a8d",
    "image-380000/boot/scripts/secondary-boot.sh": "581665a0ef5f18b80d2e8cc0203bfd8a476fc5b9130a75c9efbfac4cc39505f8",
    "image-16e0000/etc/system/config/pgetty.cfg": "1384c73485c8401b6a0693db949479178681df857172365985763d003db4e490",
}
ISO = ROOT / "downloads/6.17.0L/swdlInstall.iso"
ISO_SHA256 = "06bdc5c05b889ae68bd372dd060502226ea911fc0715a646072c59b1832bf30d"
SNAPSHOT = "usr/share/MMC_PROG_DATA/usr/share/scripts/snapshot.sh"
TAR = Path("C:/Windows/System32/tar.exe")


def read_inputs():
    inputs = {}
    for name, expected in PINS.items():
        data = (CORPUS / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Not the pinned research input: {name}")
        inputs[name] = data
    return inputs


def mcd_trace(source, matches):
    """Follow the stock USB decision graph using explicitly mocked callouts."""
    config = configparser.ConfigParser(interpolation=None, delimiters=("=",))
    config.read_string(source)
    rule = config["/fs/usb*"]["start rule"]
    trace = []
    while rule:
        if len(trace) >= 16 or any(item["rule"] == rule for item in trace):
            raise ValueError("Cyclic or oversized rule chain")
        entry = config[rule]
        if "callout" not in entry:
            trace.append(dict(rule=rule, terminal=True))
            break
        if rule not in matches:
            raise ValueError(f"No synthetic callout result: {rule}")
        matched = matches[rule]
        trace.append(dict(rule=rule, matched=matched))
        rule = entry.get("match rule" if matched else "fail rule")
    return trace


def snapshot_bytes():
    with ISO.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != ISO_SHA256:
        raise ValueError("Not the pinned installation ISO")
    result = subprocess.run([str(TAR), "-xOf", str(ISO), SNAPSHOT],
                            capture_output=True, timeout=20, check=True)
    if not 0 < len(result.stdout) <= 4096:
        raise ValueError("Unexpected snapshot script size")
    return result.stdout


def run_checks():
    inputs = read_inputs()
    model_checks = []
    scenarios = (("marker_only", {}, True), ("no_marker", {"ACPClient_ON": False}, False),
                 ("audio_preempts", {"AUDIO": True}, False),
                 ("pictures_preempt", {"PICTURES": True}, False),
                 ("application_preempts", {"APP_INSTALL": True}, False))
    for filename in ("mcd.conf", "mcdLossless.conf"):
        for name, overrides, expected in scenarios:
            matches = dict(APP_INSTALL=False, SWDL=False, AUDIO=False,
                           PICTURES=False, ACPClient_ON=True, OTHER=True)
            matches.update(overrides)
            trace = mcd_trace(inputs["image-120000/etc/" + filename].decode(), matches)
            notified = any(t["rule"] == "ACPClient_ON" and t.get("matched") for t in trace)
            if notified != expected:
                raise AssertionError("Unexpected synthetic notification result")
            model_checks.append(dict(name=filename + ":" + name, trace=trace,
                                     logging_rule_matched=notified))
    lua_paths = list(PINS)[:2]
    result = subprocess.run([str(ROOT / "build/lua-host/Release/lua.exe"),
                             str(ROOT / "tests/diagnostic_routes_probe.lua"),
                             *(str(CORPUS / name) for name in lua_paths)],
                            capture_output=True, text=True, timeout=20, check=True)
    lua_checks = json.loads(result.stdout)
    snapshot = snapshot_bytes()
    config = json.loads(inputs["image-380000/etc/acp-toyota.conf"])
    dam = config["DAM"]
    return dict(input_sha256=PINS, iso_sha256=ISO_SHA256,
                snapshot=dict(member=SNAPSHOT, sha256=hashlib.sha256(snapshot).hexdigest(),
                              source=snapshot.decode("ascii")),
                configuration=dict(snapshot=dam["Snapshot"],
                                   upload_configured=dam["Upload"]["CurlSender"]["serverUrl"].startswith("https://"),
                                   periodic_event_names=[e["reqIDs"] for e in dam["PeriodicEvents"]]),
                modeled_mcd_checks=model_checks, stock_lua_checks=lua_checks,
                scope=dict(firmware="6.17.0WL; installed 6.9.0WL not tested",
                           mcd="Configuration graph with synthetic callout results; not native MCD",
                           lua="Stock scripts with mocked I/O, XML/JSON conversion, services and time",
                           snapshot="Static source inspection only; not executed",
                           guest_commands_executed=False, usb_marker_created=False,
                           external_services_contacted=False, car_tested=False,
                           chip_information_collected=False, read_only_export_established=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New JSON evidence file; never overwritten")
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise FileExistsError(args.output)
    evidence = run_checks()
    rendered = json.dumps(evidence, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            output.write(rendered)
    print(f"PASS: {len(evidence['modeled_mcd_checks'])} modeled MCD and "
          f"{len(evidence['stock_lua_checks'])} mocked stock Lua diagnostic checks.")
    if not args.output:
        print(rendered, end="")


if __name__ == "__main__":
    main()
