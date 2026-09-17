"""Pinned, read-only native NCM ownership evidence; no vendor code execution.

The optional ISO check lists the outer archive and reads one pinned library into
memory using host tar. It neither extracts files nor searches nested archives.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from inspect_factory_network import PINS, ROOT, PinnedElf, check_local_calls, check_words
from inspect_mirrorlink_graphics import selected_calls

CONTROL = 0xE608
INSERTIONS, REMOVALS, DEVICE_LIST = 0xE5FC, 0xE600, 0xE604
RELATIVE_SLOTS = {
    0xE0B8: 0x4F50, 0xE418: INSERTIONS, 0xE420: REMOVALS,
    0xE430: DEVICE_LIST, 0xE434: CONTROL, 0xE4A0: 0x358C, 0xE4A4: 0x3050,
}
WORDS = {
    # pnp option dispatch/flag; retained module-handle behavior during detach.
    0x42B8: 0xEA00004D, 0x43FC: 0xE3822004, 0x4400: 0xE5832004,
    0x344C: 0xE5853044, 0x345C: 0xE3130004, 0x3464: 0x15853044,
    # Two connect outputs; second connection receives no callback table.
    0x47C8: 0xE58D3280, 0x48D4: 0xE2811014,
    0x4948: 0xE3A03000, 0x494C: 0xE58D3280, 0x4960: 0xE2811018,
    # Control/data attachment on the first connection. r2 is EXTRA BYTES.
    0x37A8: 0xE5930014, 0x37B0: 0xE3A02004,
    0x38FC: 0xE5930014, 0x3904: 0xE3A02004,
    0x324C: 0xE5950B20, 0x3270: 0xE5950B1C,
    0x3C30: 0xE5940B1C, 0x3C38: 0xE5940B20,
    # List identity is two bytes, not the complete USB instance.
    0x3B98: 0xE5C82008, 0x3BA0: 0xE5C82009,
    0x4FD0: 0xE1D610B0, 0x4FD4: 0xE1D320B8, 0x4FE4: 0xE1D320B8,
    # Insertion skip bit, allocation/copy, and shared worker attachment.
    0x5180: 0xE3130002, 0x5274: 0xE3A00034, 0x529C: 0xE286C008,
    0x52A0: 0xE8B5000F, 0x52A4: 0xE8AC000F, 0x52A8: 0xE8B5000F,
    0x52AC: 0xE8AC000F, 0x52B0: 0xE5953000, 0x52B4: 0xE58C3000,
    0x53A0: 0xE5930018, 0x53A8: 0xE3A02000,
    # Abort waits can force pending counters to zero; zero is not a drain proof.
    0x72D0: 0xE2855005, 0x72DC: 0xE3A03000, 0x72E0: 0xE5843C14,
    0x7328: 0xE3007FA5, 0x732C: 0xE5943C14,
    0x736C: 0xE2855005, 0x7378: 0xE3A03000, 0x737C: 0xE5843BE0,
    0x73C4: 0xE3007FA5, 0x73C8: 0xE5943BE0,
    0x7408: 0xE285500A, 0x7414: 0xE3A03000, 0x7418: 0xE5843B90,
    0x7440: 0xE3007FAA, 0x7444: 0xE5943B90,
    0x7458: 0xE3A02000, 0x7488: 0xE3A00000,
    0xE0B0: 3, 0xE0B4: 0, 0xE0BC: 0, 0xE498: 0xC40,
}
CALLS = {
    0x48D8: "usbd_connect", 0x4964: "usbd_connect",
    0x37B8: "usbd_attach", 0x3910: "usbd_attach",
    0x3AD0: "snprintf", 0x3AF0: "strcpy", 0x3B4C: "if_attach",
    0x3B58: "ether_ifattach", 0x3B68: "shutdownhook_establish",
    0x3C34: "usbd_detach", 0x3C3C: "usbd_detach", 0x3C44: "free",
    0x4FB8: "pthread_mutex_lock", 0x5000: "pthread_mutex_unlock",
    0x50C0: "atomic_add", 0x50F0: "dev_remove", 0x5104: "pthread_mutex_unlock",
    0x5278: "malloc", 0x52C4: "atomic_add", 0x52DC: "stk_context_callback_2",
    0x5330: "proc0_getprivs", 0x5364: "kthread_create1", 0x536C: "proc0_remprivs",
    0x53B0: "usbd_attach", 0x53EC: "usbd_detach", 0x53FC: "atomic_sub",
    0x5404: "free", 0x540C: "kthread_exit",
    0x3118: "free", 0x318C: "atomic_sub", 0x3220: "quiesce_all",
    0x3228: "ether_ifdetach", 0x3230: "if_detach", 0x3234: "unquiesce_all",
    0x323C: "shutdownhook_disestablish", 0x3250: "usbd_detach", 0x3274: "usbd_detach",
    0x349C: "usbd_disconnect", 0x34A4: "usbd_disconnect",
    0x34AC: "stk_context_callback_2_clean",
    0x7228: "usbd_abort_pipe", 0x725C: "usbd_abort_pipe", 0x7290: "usbd_abort_pipe",
    0x745C: "usbd_select_interface",
}
LOCAL_CALLS = {
    0x4F68: 0x5424, 0x518C: 0x5424, 0x53C8: 0x3FE0,
    0x3938: 0x714C, 0x3940: 0x5548, 0x3968: 0x6120,
    0x3990: 0x6B34, 0x39B8: 0x5820, 0x39E0: 0x5AA8,
    0x3BEC: 0x9920, 0x3C2C: 0x74C0,
    0x321C: 0x2E58, 0x3248: 0x71D8, 0x3298: 0x97E0, 0x33AC: 0x74C0,
    0x71F4: 0xB6E4, 0x72CC: 0xB6E4, 0x7368: 0xB6E4, 0x7404: 0xB6E4,
}
ISO = ROOT / "downloads/6.17.0L/swdlInstall.iso"
ISO_SHA256 = "06bdc5c05b889ae68bd372dd060502226ea911fc0715a646072c59b1832bf30d"
TAR = Path("C:/Windows/System32/tar.exe")
NETWORK_MEMBER = "usr/share/MMC_PROG_DATA/wicome/libnetworkingservice.so"
NETWORK_SHA256 = "30ac5eb41a56be89e252c52af4e52c16791742977966d3d8e418822cd6d5d55c"


def inspect():
    elf = PinnedElf("ncm", pins=PINS, directory=ROOT)
    check_words(elf, {**WORDS, **RELATIVE_SLOTS})
    relocations = {target: kind for target, kind, _ in elf.relocations()}
    if any(relocations.get(slot) != 23 for slot in RELATIVE_SLOTS):
        raise ValueError("Expected R_ARM_RELATIVE ownership slot")
    options = [elf.string(elf.uint(0xE44C + 4 * i)) for i in range(15)]
    if options[6] != "pnp":
        raise ValueError("pnp option dispatch changed")
    got = 0x5168 + 8 + elf.uint(0x52E8)
    callback = (got + elf.uint(0x530C)) & 0xFFFFFFFF
    worker = (0x5318 + 8 + elf.uint(0x5374) + elf.uint(0x5380)) & 0xFFFFFFFF
    name_address = (0x3598 + 8 + elf.uint(0x3C54) + elf.uint(0x3CA0)) & 0xFFFFFFFF
    if (got, callback, worker, name_address) != (0xE1A0, 0x5310, 0x5384, 0xBF9C):
        raise ValueError("PIC ownership target changed")
    return dict(
        scope="Selected 6.17.0WL native code; not installed-unit or phone verification",
        input_sha256=elf.sha256, calls=selected_calls(elf, CALLS),
        local_calls=check_local_calls(elf, LOCAL_CALLS),
        selected_words={hex(a): hex(v) for a, v in WORDS.items()},
        relative_slots={hex(a): hex(v) for a, v in RELATIVE_SLOTS.items()},
        options=options, pnp_flag=4,
        connections={"callback_io_offset": "0x14", "shared_inspection_offset": "0x18"},
        insertion={"entry": "0x515c", "queued_callback": hex(callback), "worker": hex(worker),
                   "payload_bytes": 52, "copied_instance_bytes": 36},
        removal={"entry": "0x4f50", "match": "first list node matching path/devno only",
                 "handoff": "dev_remove; actual cleanup is not executed by the replay"},
        attachment={"entry": "0x358c", "context_bytes": elf.uint(0xE498),
                    "control_handle_offset": "0xb20", "data_handle_offset": "0xb1c",
                    "extra_allocation_bytes": 4, "extended_name_format": elf.string(name_address),
                    "default_name": "copied from framework device name; not a phone identity"},
        detach={"entry": "0x3050", "pnp": "clears module handle and skips connection disconnect"},
        abort={"entry": "0x71d8", "forced_zero_counter_offsets": ["0xc14", "0xbe0", "0xb90"],
               "final_data_alternate": 0, "return": 0,
               "limit": "Selected timeout branches reset counters; no actual transfer-drain proof"},
        whole_driver_or_live_ownership_verified=False)


def inspect_iso():
    """No extraction to disk, installation, vendor execution, or nested traversal."""
    with ISO.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != ISO_SHA256:
        raise ValueError("Not the pinned installation ISO")
    listing = subprocess.run([str(TAR), "-tvf", str(ISO)], capture_output=True,
                             timeout=20, check=True).stdout
    if not 0 < len(listing) <= 4 * 1024 * 1024:
        raise ValueError("Unexpected ISO listing size")
    lines = listing.decode("utf-8", errors="strict").splitlines()
    matches = [line for line in lines if re.search(
        r"io-pkt|devnp-|lsm-|libsocket|netinet|ipv6|tcpip|ncm|libnetworking", line, re.I)]
    data = subprocess.run([str(TAR), "-xOf", str(ISO), NETWORK_MEMBER],
                          capture_output=True, timeout=20, check=True).stdout
    if len(data) != 1976933 or hashlib.sha256(data).hexdigest() != NETWORK_SHA256:
        raise ValueError("Not the pinned networking client library")
    return dict(iso_sha256=digest, outer_listing_entries=len(lines), network_named_entries=matches,
                nested_archive_entries=[line for line in lines if re.search(r"\.(zip|tar|tgz)$", line, re.I)],
                client_library=dict(member=NETWORK_MEMBER, sha256=NETWORK_SHA256, bytes=len(data),
                    raw_marker_counts={s: data.count(s.encode()) for s in ("AF_INET6", "inet6", "IPv6")}),
                limits=["Outer filenames and symlink descriptions only; no nested archive or renamed ELF audit",
                        "Client IPv6 diagnostic strings do not supply an IPv6 network stack",
                        "Later distribution package only; not a dump of the installed unit"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", action="store_true", help="also inspect the pinned outer ISO directory")
    args = parser.parse_args()
    result = inspect()
    if args.iso:
        result["iso"] = inspect_iso()
    print(json.dumps(result, indent=2))
