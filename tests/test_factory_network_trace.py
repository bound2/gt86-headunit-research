"""Offline factory-network evidence tests, not USB or on-unit integration."""
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_factory_network as network


class FactoryNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = network.inspect()

    def elf(self, key="ncm"):
        return network.PinnedElf(key, pins=network.PINS, directory=ROOT)

    @staticmethod
    def edit_word(elf, address, value):
        data = bytearray(elf.data)
        struct.pack_into("<I", data, elf.offset(address, 4), value)
        elf.data = bytes(data)

    def test_boot_text_and_complete_ifs_inventory_include_ncm_not_a_v6_alias(self):
        startup = self.evidence["startup"]
        self.assertEqual(startup["stack"][0]["line"], 35)
        self.assertIn("io-pkt-v4-hc -S -ptcpip", startup["stack"][0]["text"])
        for key, line in (("connectivity", 21), ("recovery", 107)):
            self.assertEqual(startup["ncm"][key], [dict(
                line=line, text="mount -T io-pkt -o pnp /lib/dll/devnp-ncm.so")])
        self.assertFalse(startup["runtime_execution_verified"])
        rows = self.evidence["ifs_network_inventory"]
        self.assertEqual([(r["type"], r["path"], r["target"]) for r in rows], [
            ("file", "lib/dll/devnp-ncm.so", ""), ("file", "sbin/io-pkt-v4-hc", "")])
        self.assertTrue(any("not a search of all MMC" in s for s in self.evidence["limits"]))

    def test_descriptor_association_and_separate_control_and_data_pipes(self):
        path = self.evidence["ncm_descriptor_path"]
        self.assertEqual((path["control_class"], path["control_subclass"], path["data_class"]),
                         (2, 13, 10))
        self.assertIn("Union", path["association"])
        self.assertEqual(path["data_alt_sequence"], [0, 1])
        self.assertEqual((path["control_pipe_mask"], path["data_pipe_mask"]), (9, 6))
        calls = self.evidence["ncm_calls"]
        self.assertEqual(len(calls), 14)
        self.assertEqual(calls["0x4150"]["symbol"], "dev_attach")
        for address in ("0x6ba0", "0x6bf8"):
            self.assertEqual(calls[address]["symbol"], "usbd_select_interface")
        local = self.evidence["ncm_local_calls"]
        self.assertEqual(local["0x4b64"], "0x3fe0")
        self.assertEqual(local["0x4d80"], "0x3fe0")

    def test_six_selected_ncm_control_requests_and_ignored_parameter_status(self):
        requests = self.evidence["ncm_control_requests"]
        self.assertEqual([r["request"] for r in requests], [0x80, 0x86, 0x84, 0x8A, 0x87, 0x88])
        self.assertEqual([r["length"] for r in requests if "length" in r], [28, 4, 2, 2])
        for row in requests:
            self.assertEqual(self.evidence["ncm_local_calls"][row["site"]], "0x61d8")
        self.assertEqual(self.elf().uint(0x6238), 0xE3A03021)
        # Immediately following GET_NTB_PARAMETERS, the caller reads the buffer,
        # not r0's error return. This is selected static evidence, not fault replay.
        self.assertEqual(self.elf().uint(0x6410), 0xE5D53002)

    def test_domaininit_consumes_six_real_domain_objects_without_inet6(self):
        domains = self.evidence["stack_built_in_domains"]
        self.assertEqual([(d["symbol"], d["family"], d["name"]) for d in domains], [
            ("arpdomain", 28, "arp"), ("inetdomain", 2, "internet"),
            ("keydomain", 29, "key"), ("linkdomain", 18, "link"),
            ("routedomain", 17, "route"), ("unixdomain", 1, "unix")])
        self.assertEqual([int(d["slot"], 16) for d in domains], list(range(0x1FFD18, 0x1FFD30, 4)))
        self.assertEqual(self.evidence["stack_raw_marker_counts"],
                         {"inet6": 0, "ip6_input": 0, "IPv6": 0})
        self.assertIn("NAME=io-pkt-v4-hc", self.evidence["metadata"]["stack"])
        self.assertIn("STATE=experimental", self.evidence["metadata"]["ncm"])
        self.assertFalse(self.evidence["factory_or_phone_acceptance_verified"])

    def test_changed_inputs_are_rejected_before_any_elf_interpretation(self):
        original = Path.read_bytes
        for name, _ in network.PINS.values():
            target = ROOT / name
            def changed(path):
                data = original(path)
                return data + b"changed" if path == target else data
            with self.subTest(name=name), patch.object(Path, "read_bytes", changed), \
                    patch.object(network, "PinnedElf") as elf:
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    network.inspect()
                elf.assert_not_called()

    def test_default_inspection_is_repeatable_without_subprocesses_or_writes(self):
        before = network.read_inputs()
        with patch.object(subprocess, "run") as run:
            self.assertEqual(network.inspect(), self.evidence)
            run.assert_not_called()
        self.assertEqual(network.read_inputs(), before)

    def test_instruction_and_call_checks_reject_altered_selected_semantics(self):
        elf = self.elf()
        self.edit_word(elf, 0x4024, 0xE35300FF)
        with self.assertRaisesRegex(ValueError, "instruction changed"):
            network.check_words(elf, network.NCM_WORDS)
        with self.assertRaisesRegex(ValueError, "local call changed"):
            network.check_local_calls(self.elf(), {0x640C: 0x6358})
        with self.assertRaisesRegex(ValueError, "call changed"):
            network.selected_calls(self.elf(), {0x6BA0: "usbd_open_pipe"})

    def test_domain_table_consumer_objects_and_names_are_checked(self):
        for address, value, message in (
                (0x1C718C, 0x1FFD1C, "instruction changed"),
                (0x1C712C, 0xEB000000, "local call changed"),
                (0x1FFD18, 0, "Ambiguous"),
                (0x201CCC, 0xFFFFFFFF, "outside file-backed")):
            elf = self.elf("stack")
            self.edit_word(elf, address, value)
            with self.subTest(address=hex(address)), self.assertRaisesRegex(ValueError, message):
                network.built_in_domains(elf)

    def test_dynamic_symbol_and_domain_table_bounds_are_rejected(self):
        elf = self.elf("stack")
        for count in (0, 65537):
            self.edit_word(elf, elf.dynamic[4] + 4, count)
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "symbol count"):
                network.dynamic_symbols(elf)
        elf = self.elf("stack")
        original = network.dynamic_symbols(elf)
        for value in (0x1FFD18, 0x1FFD31, 0x200018):
            symbols = [dict(s, value=value) if s["name"] == "__stop_link_set_domains" else s
                       for s in original]
            with self.subTest(stop=hex(value)), patch.object(network, "dynamic_symbols", return_value=symbols):
                with self.assertRaisesRegex(ValueError, "table bounds"):
                    network.built_in_domains(elf)


if __name__ == "__main__":
    unittest.main()
