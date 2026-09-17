"""Selected factory network evidence, not live networking/phone acceptance."""
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_network_identity as trace
from probe_network_identity import BASE, NetworkProbe, scenarios


class NetworkIdentityTests(unittest.TestCase):
    def test_pinned_name_configuration_and_native_boundaries(self):
        result = trace.inspect()
        self.assertEqual([v["line"] for v in result["config"]], [210, 211, 212, 213, 370])
        self.assertIn("ncm0", result["config"][1]["text"])
        self.assertTrue(result["config"][2]["text"].endswith("dhcp"))
        self.assertEqual(result["local_calls"]["0x840d4"], "0x8061c")
        self.assertEqual(result["imports"]["0x7a120"]["symbol"], "ioctl")
        self.assertEqual(result["config_literals"]["0x83a28"], "dhcp6")
        self.assertEqual(result["words"]["0x70348"], "0xe3a00004")
        self.assertEqual(result["words"]["0xca6b8"], "0xea00007f")  # Type 15 -> information branch.
        self.assertFalse(result["actual_phone_or_target_verified"])

    def test_query_supported_types_maps_type_24(self):
        for iftype, expected in ((6, 6), (23, 23), (71, 71), (24, 1)):
            p = NetworkProbe(iftype=iftype)
            self.assertEqual(p.call("query", p.owner, p.name, p.interface), 1)
            self.assertEqual(p.uint(p.interface + 0x60), expected)
            self.assertEqual(p.uint(p.interface + 0x58), p.uint(p.name))
            self.assertEqual(p.uint(p.interface + 0x80), 1500)
            self.assertEqual([e["op"] for e in p.events].count("close"), 1)

    def test_query_unknown_type_preserves_output_and_closes_socket(self):
        for iftype in (0, 1, 255):
            p = NetworkProbe(iftype=iftype)
            before = p.read(p.interface, 132)
            self.assertEqual(p.call("query", p.owner, p.name, p.interface), 0)
            self.assertEqual(p.read(p.interface, 132), before)
            self.assertEqual(p.events[-1]["op"], "close")

    def test_socket_and_ioctl_failure_preserve_output(self):
        for socket_failure in (True, False):
            p = NetworkProbe(socket_failure=socket_failure, ioctl_failure=not socket_failure)
            before = p.read(p.interface, 132)
            self.assertEqual(p.call("query", p.owner, p.name, p.interface), 0)
            self.assertEqual(p.read(p.interface, 132), before)
            names = [e["op"] for e in p.events]
            self.assertEqual(names.count("close"), 0 if socket_failure else 1)
            self.assertEqual(names.count("ioctl"), 0 if socket_failure else 1)

    def test_link_state_is_only_exact_two_and_query_does_not_supply_identity_or_address(self):
        for link in (0, 1, 2, 3, 0xFFFFFFFF):
            p = NetworkProbe(link=link)
            self.assertEqual(p.call("query", p.owner, p.name, p.interface), 1)
            self.assertEqual(p.read(p.interface + 0x79, 1), bytes([int(link == 2)]))
            self.assertEqual(p.uint(p.interface + 0x5C), 0)  # No ifindex supplied by this helper.
            self.assertEqual(p.uint(p.interface + 0x6C), 0)  # No address supplied.
            self.assertEqual(p.read(p.interface + 0x78, 1), b"\0")  # Administrative state separate.

    def test_index_search_empty_missing_null_and_later_entry(self):
        for indices, query, position in (([], 7, None), ([1, 2], 7, None), ([None, 3, 7], 7, 2)):
            p = NetworkProbe()
            p.make_interfaces(indices)
            self.assertEqual(p.call("find", p.owner, query), 0 if position is None else p.entries[position])
            self.assertFalse(any(e["op"] in ("ioctl", "mock_socket") for e in p.events))

    def test_duplicate_index_selects_first_without_other_identity_checks(self):
        p = NetworkProbe()
        p.make_interfaces([7, 7])
        p.u.mem_write(p.entries[0] + 0x64, bytes(range(7)))
        p.u.mem_write(p.entries[1] + 0x64, bytes(reversed(range(7))))
        p.write32(p.entries[0] + 0x58, 0x11111111)  # Not dereferenced by selected helper.
        p.write32(p.entries[1] + 0x58, 0x22222222)
        self.assertEqual(p.call("find", p.owner, 7), p.entries[0])
        # These synthetic duplicates are not a claim that the live OS emits them.

    def test_address_copy_preserves_ipv4_and_complete_ipv6_scope_bytes(self):
        for family, length in ((2, 16), (24, 28)):
            p = NetworkProbe()
            data = bytes([length, family]) + bytes(range(2, length))
            if family == 24:
                data = data[:24] + struct.pack("<I", 7)
            p.u.mem_write(p.address_source, data)
            p.u.mem_write(p.address_output, b"\xCC" * 32)
            p.call("address", p.address_output, p.address_source)
            actual = p.read(p.address_output, 32)
            self.assertEqual(actual[:length], data)
            self.assertEqual(actual[length:28], b"\xCC" * (28 - length))
            self.assertEqual(actual[28], 1)
            self.assertEqual(actual[29:], b"\xCC" * 3)
            self.assertEqual(p.events, [dict(op="memcpy", bytes=length)])

    def test_address_helper_does_not_validate_length_or_scope_and_unsupported_family_keeps_old_value(self):
        p = NetworkProbe()
        data = bytes([0, 24]) + bytes(26)  # Family selects copy, even with zero length/scope.
        p.u.mem_write(p.address_source, data)
        p.call("address", p.address_output, p.address_source)
        before = p.read(p.address_output, 32)
        self.assertEqual(before[:28], data)
        self.assertEqual(before[28], 1)
        p.u.mem_write(p.address_source, bytes([28, 99]) + bytes(26))
        p.call("address", p.address_output, p.address_source)
        self.assertEqual(p.read(p.address_output, 32), before)
        self.assertEqual(len(p.events), 1)
        # Valid flag means copied supported family here, not verified network readiness.

    def test_changed_inputs_rejected_before_interpretation_or_emulation(self):
        original = Path.read_bytes
        for key, (name, _) in trace.PINS.items():
            target = ROOT / name
            def changed(path):
                return original(path) + b"changed" if path == target else original(path)
            with patch.object(Path, "read_bytes", changed), patch("inspect_network_identity.static_symbols") as symbols:
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    trace.inspect()
                symbols.assert_not_called()
            if key == "network":
                with patch.object(Path, "read_bytes", changed), patch("probe_network_identity.Uc") as emulator:
                    with self.assertRaisesRegex(ValueError, "Not the pinned"):
                        NetworkProbe()
                    emulator.assert_not_called()

    def test_changed_selected_instruction_and_symbol_are_rejected(self):
        original = trace.PinnedElf.uint
        with patch.object(trace.PinnedElf, "uint", lambda e, a: original(e, a) ^ (1 if a == 0x7A338 else 0)):
            with self.assertRaisesRegex(ValueError, "Selected instruction changed"):
                trace.inspect()
        with patch.object(trace, "static_symbols", return_value=[]):
            with self.assertRaisesRegex(ValueError, "Selected network symbol changed"):
                trace.inspect()

    def test_probe_guards(self):
        p = NetworkProbe()
        with self.assertRaisesRegex(AssertionError, "entry/argument"):
            p.call("route_event")
        with self.assertRaisesRegex(AssertionError, "outside selected"):
            p.on_code(p.u, BASE + 0xCA4FC, 4, None)
        with self.assertRaisesRegex(RuntimeError, "interrupt forbidden"):
            p.on_interrupt(p.u, 2, None)
        address = next(a for a, name in p.imports.items() if name == "mount")
        with self.assertRaisesRegex(RuntimeError, "Unexpected guest import"):
            p.on_code(p.u, address, 4, None)
        with self.assertRaisesRegex(AssertionError, "interface bound"):
            p.make_interfaces([1] * 9)

    def test_repeatable_without_subprocesses_or_input_changes(self):
        before = {k: (ROOT / path).read_bytes() for k, (path, _) in trace.PINS.items()}
        with patch.object(subprocess, "run") as run:
            self.assertEqual(trace.inspect(), trace.inspect())
            self.assertEqual(scenarios(), scenarios())
            run.assert_not_called()
        self.assertEqual(before, {k: (ROOT / path).read_bytes() for k, (path, _) in trace.PINS.items()})


if __name__ == "__main__":
    unittest.main()
