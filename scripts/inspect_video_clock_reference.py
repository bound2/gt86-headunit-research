"""Offline, pinned-source check of screen-clock and configuration evidence.

Reads Git objects only; no checked-out source, receiver, build, hook, phone or
vendor executable is run. Lazy fetching and network protocols are disabled.
This audits selected reference code, NOT a phone timestamp/packet capture.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

LIVI = "a76553fc941dcf378dd55c04da56aaf3d6911e08"
UXPLAY = "2c7b63ee9c36edfb121186db928397c582852133"
PINS = {
    "livi_ts": ("livi", LIVI, "src/main/services/projection/driver/cp/stack/screenStream.ts", "c02d2385a0fb2fb1be2dfe214ec4456420cfa3a2"),
    "livi_screen": ("livi", LIVI, "native/livi-gst-video/rust/screen/src/lib.rs", "249c8af60ff20f5ffa411ac95046a686bfa2336e"),
    "livi_addon": ("livi", LIVI, "native/livi-gst-video/rust/addon/src/screen_recv.rs", "e73033cc7722acc45ff90e3a808806f9884ef61f"),
    "livi_nal": ("livi", LIVI, "native/livi-gst-video/rust/nal/src/lib.rs", "b8e8744e5a5256bced4aa3a73628121b7d84f623"),
    "livi_player": ("livi", LIVI, "native/livi-gst-video/rust/player/src/lib.rs", "f9c763418cb1af4bd9e7340b08aa4cb243ffac31"),
    "livi_timing": ("livi", LIVI, "src/main/services/projection/driver/cp/stack/timingServer.ts", "2eb385de51fd3ceda2e720bfa4687d277b467d70"),
    "ux_mirror": ("uxplay", UXPLAY, "lib/raop_rtp_mirror.c", "3c1dcabe5175551a9a2b7dc3b5b13ff80cb11060"),
    "ux_bytes": ("uxplay", UXPLAY, "lib/byteutils.c", "095020881258a95eb2a33995653868c73a24ac2d"),
    "ux_ntp": ("uxplay", UXPLAY, "lib/raop_ntp.c", "892de9c407746ac13e3b10539b8cca0f40ff96db"),
    "ux_cipher": ("uxplay", UXPLAY, "lib/mirror_buffer.c", "95492e81ecd67277d11e850f2ac5a65cc7b0a5e2"),
}
LIMIT = 512 * 1024


def git(repo: Path, *args: str) -> bytes:
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["git", "--no-pager", "-c", "protocol.allow=never", "-C", str(repo), *args],
                          check=True, capture_output=True, timeout=30, env=env).stdout


def verify_blob(data: bytes, expected: str) -> str:
    if not data or len(data) > LIMIT:
        raise ValueError("Reference blob exceeds bounds or is empty")
    digest = hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()
    if digest != expected:
        raise ValueError("Pinned Git blob mismatch")
    return data.decode("utf-8")


def read_blob(repo: Path, commit: str, path: str, expected: str) -> str:
    identity = f"{commit}:{path}"
    size = int(git(repo, "cat-file", "-s", identity))
    if not 0 < size <= LIMIT:
        raise ValueError("Reference object exceeds bounds or is empty")
    data = git(repo, "cat-file", "blob", identity)
    if len(data) != size:
        raise ValueError("Reference object length mismatch")
    return verify_blob(data, expected)


def inspect(livi: Path, uxplay: Path) -> dict:
    roots = {"livi": livi, "uxplay": uxplay}
    sources = {name: read_blob(roots[repo], commit, path, sha) for name, (repo, commit, path, sha) in PINS.items()}
    checks = {
        "livi_ts": ["this.emit('frame', payload)", "chachaOpen(this.key, nonce64(this._counter), body, header)"],
        "livi_screen": ["fn on_frame(&mut self, nal: &[u8]);", "self.sink.on_frame(frame);"],
        "livi_addon": ["if atom.is_empty()", "*c == codec && a == atom", "feed::push_video(self.id, nal);", "fn a_keepalive_config_is_not_reported()"],
        "livi_nal": ["let mut p = vec![0u8; 4];", 'p.extend_from_slice(b"avcC");', "CpCodec::H264, 8"],
        "livi_player": ['element.set_property("sync", false);', "force_sinks_realtime(&player.pipeline);", "src.push_buffer(gst::Buffer::from_slice(data.to_vec()))"],
        "ux_mirror": ["byteutils_get_long(packet, 8)", "ntp_timestamp_raw", "mirror_buffer_decrypt", "video_data.ntp_time_local = ntp_timestamp_local;"],
        "ux_bytes": ["uint64_t byteutils_get_long", "return *((uint64_t*)(b + offset));"],
        "ux_ntp": ["raop_ntp_adjust_remote_timestamp_offset", "if (add_secs_1900_to_1970)", "2208988800ULL"],
        "ux_cipher": ["aes_ctr_init(aeskey_video, aesiv_video)", "aes_ctr_decrypt"],
    }
    for name, tokens in checks.items():
        for token in tokens:
            if token not in sources[name]:
                raise ValueError(f"Reviewed evidence marker missing: {name}: {token}")
    return {
        "verified_blobs": len(sources), "livi_commit": LIVI, "uxplay_commit": UXPLAY,
        "livi_screen_callback": "payload only; no sender-time argument",
        "livi_player": "selected pipeline sinks disable clock synchronization",
        "configuration": "native addon ignores empty/repeated codec data; NAL tests use four reserved zero bytes + avcC",
        "uxplay_comparison": "header offset 8, raw host uint64 load, NTP/epoch adjustment, AES-CTR media",
        "carplay_sender_timestamp_mapping_verified": False,
        "phone_or_factory_execution": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--livi", type=Path, default=Path("build/livi-reference"))
    parser.add_argument("--uxplay", type=Path, default=Path("build/uxplay-reference"))
    args = parser.parse_args()
    print(json.dumps(inspect(args.livi, args.uxplay), indent=2))
