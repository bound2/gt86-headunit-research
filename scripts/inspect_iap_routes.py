# SPDX-License-Identifier: GPL-3.0-only
"""Offline pinned iAP route/profile evidence; no helper, USB or phone execution.

Reuses the bounded immutable Git reader with lazy fetch/network disabled.
Marker checks make the reviewed inputs reproducible, not a whole-program proof.
"""
import argparse
import json
from pathlib import Path

from inspect_video_clock_reference import LIVI, read_blob

BASE = "native/livi-helperd/"
PINS = {
    "socket": (BASE + "crates/livi-runtime/src/livi_sock.rs", "08b8e25070b47b5cb0aaea08f10a98ef6fa6aae2"),
    "driver": (BASE + "crates/livi-runtime/src/driver.rs", "4c36c1fe6520047c1ab9c24d921e4ddf907aa9c4"),
    "state": (BASE + "crates/livi-runtime/src/state.rs", "a3deff4221693f9d2e77554b9cacf06fe5ca266d"),
    "wired": (BASE + "bin/livi-helperd/src/wired.rs", "bf2900569464e3fd99c3d62874ae749d30b4287a"),
    "link": (BASE + "crates/iap2-link/src/lib.rs", "c64c8949718bdcd20e96d77b59fd70293bcc7a1e"),
    "bringup": (BASE + "crates/livi-runtime/src/bringup.rs", "84dbb71e485d60b0d6805e6705f6bf38a5df4ca7"),
    "carkit": (BASE + "crates/iap2-wired/src/carkit.rs", "58bd611ffdc984d55eacb0bcf6f8128ed0c9b8bc"),
    "stack": ("src/main/services/projection/driver/cp/stack/cpStack.ts", "d7b7511321a9da61d63a3c23a8e34cdd5523d7b9"),
}
MARKERS = {
    "socket": ['"tunnel" =>', "state.carkit_blocks(bt_mac)", "spawn_link(fd, link_cfg, true)",
               "control_version: 2, zero_ack: true", "run_accessory(channel, auth"],
    "driver": ["let mut engine = LinkEngine::new(cfg);", "engine.start(initiate_negotiate, now());",
               "Ok(n) => engine.feed(&buf[..n], now())", "Event::Control(bytes)"],
    "state": ["pub fn carkit_blocks", "if bt_mac.is_empty()", "return !sessions.is_empty();",
              "eq_ignore_ascii_case(bt_mac)"],
    "wired": ["control_version: 2, zero_ack: true", "spawn_link_stream(stream, link, true)",
              "ctx.state.carkit_started(ident.clone());", "ctx.state.carkit_ended(&ident);", "start_ncm_bridge"],
    "link": ["retransmission_timeout: if z { 0 } else { 4000 }", "max_ack: if z { 0 } else { 3 }",
             "if self.lsp.max_retransmissions > 0", "if self.lsp.max_ack == 0", "self.enter_negotiate(now);"],
    "bringup": ["run_identification", "run_auth", "cp.transport == Transport::Wired", "cp.av_iface.as_deref()?"],
    "carkit": ['"com.apple.carkit.service"', "pub fn into_stream", "self.idevice.get_socket()"],
    "stack": ["if (req.method === 'RECORD')", "this._openIapMessageRelay(session)",
              "tunnel.on('iap', (iap: Buffer) => session.iapRelay?.write(iap))",
              "encodeBplist({ type: 'iAPSendMessage', params: { data } })"],
}


def inspect(repo: Path) -> dict:
    sources = {name: read_blob(repo, LIVI, path, sha) for name, (path, sha) in PINS.items()}
    for name, markers in MARKERS.items():
        for marker in markers:
            if marker not in sources[name]:
                raise ValueError(f"Reviewed evidence marker missing: {name}: {marker}")
    return {
        "commit": LIVI, "verified_blobs": len(sources),
        "tunnel_bytes": "iAP2 link framing before CSM assembly; not raw CSM",
        "wireless_tunnel": "new separately owned link/accessory session, opened at RECORD",
        "wired_carkit": "existing stream link kept separately; helper blocks a matching tunnel",
        "unknown_mac_guard": "any active carkit session blocks an unspecified phone",
        "both_reference_profiles": {"control_version": 2, "zero_ack": True, "initiate_negotiate": True},
        "wired_av": "separate phone USB network function; not the carkit TLS byte stream",
        "factory_or_phone_acceptance_verified": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--livi", type=Path, default=Path("build/livi-reference"))
    args = parser.parse_args()
    print(json.dumps(inspect(args.livi), indent=2))
