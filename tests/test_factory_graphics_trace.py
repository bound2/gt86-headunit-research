"""Pinned static evidence checks, not QNX graphics or on-car validation."""
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_factory_graphics as graphics


class GraphicsClassParserTests(unittest.TestCase):
    def test_reads_selected_flat_block_and_ignores_comments(self):
        text = "begin class mlc\nvisible = false # initial state\n# pipeline=2\nend class\n"
        self.assertEqual(graphics.class_properties(text, "mlc"), {"visible": "false"})

    def test_rejects_missing_duplicate_and_malformed_blocks(self):
        valid = "begin class mlc\nvisible=false\nend class\n"
        for text in ("", valid + valid, valid.replace("visible=false", "visible"),
                     valid.replace("visible=false", "visible="),
                     valid.replace("visible=false", "=false"),
                     valid.replace("visible=false", "visible=false\nvisible=true")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                graphics.class_properties(text, "mlc")


class FactoryGraphicsTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = graphics.inspect()

    def test_selected_property_descriptors_and_native_calls(self):
        manager = self.evidence["manager"]
        for command, label, prop, setter, reader, cache in (
                ("v", "Visibility", 51, "0x109694", "0x108d7c", "0x40"),
                ("o", "z-Order", 54, "0x1097a8", "0x108ed4", "0x3c")):
            row = manager["descriptors"][command]
            self.assertEqual((row["label"], row["property_id"], row["setter"],
                              row["readback_function"], row["cached_field_offset"]),
                             (label, prop, setter, reader, cache))
            self.assertEqual(row["parameter_count"], 1)
        calls = manager["selected_calls"]
        for address in ("0x109760", "0x109864"):
            self.assertEqual(calls[address]["symbol"], "screen_set_window_property_iv")
        for address in ("0x108dc4", "0x108f20"):
            self.assertEqual(calls[address]["symbol"], "screen_get_window_property_iv")
        self.assertEqual(calls["0x1098e4"]["symbol"], "screen_flush_context")
        self.assertEqual(manager["flush_argument"], 0)
        self.assertTrue(manager["visibility_cache_described_in_usage"])
        self.assertNotIn("screen_post_window", manager["imports"])

    def test_stock_window_configuration_and_cache_startup(self):
        classes = self.evidence["window_classes"]
        self.assertEqual(classes["FlashWindow"]["order"], "4")
        self.assertEqual(classes["FlashWindow"]["visible"], "false")
        mlc = classes["mlc"]
        self.assertEqual(mlc["visible"], "false")
        self.assertEqual(mlc["format"], "rgba8888")
        for key in ("source-size", "window-size", "surface-size"):
            self.assertEqual(mlc[key], "800x480")
        self.assertNotIn("pipeline", mlc)  # The pipeline assignment is a comment.
        self.assertEqual(classes["framebuffer1"]["pipeline"], "3")
        self.assertTrue(self.evidence["boot_starts_manager_without_disable_cache"])

    def test_air_matches_do_not_establish_toyota_signal_consumption(self):
        self.assertEqual(self.evidence["air_literal_counts"], {
            "displayState": 43,
            "flash.display:StageDisplayState": 5,
            "NativeWindowDisplayState": 25,
            "com.harman.service.ToyotaMGR": 0,
            "screen_create_window_type": 1,
            "screen_post_window": 2,
        })
        self.assertTrue(any("alone do not establish" in limit
                            for limit in self.evidence["limits"]))

    def test_changed_input_is_rejected_before_elf_parsing(self):
        original_read = Path.read_bytes
        for name, _ in graphics.PINS.values():
            target = graphics.DIRECTORY / name
            def changed(path):
                data = original_read(path)
                return data + b"changed" if path == target else data
            with self.subTest(name=name), patch.object(Path, "read_bytes", changed), \
                    patch.object(graphics, "PinnedElf") as elf:
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    graphics.inspect()
                elf.assert_not_called()

    def test_default_inspection_launches_nothing_and_leaves_inputs_unchanged(self):
        before = graphics.read_inputs()
        with patch.object(subprocess, "run") as run:
            self.assertEqual(graphics.inspect(), self.evidence)
            run.assert_not_called()
        self.assertEqual(before, graphics.read_inputs())

    def test_descriptor_call_and_flush_changes_are_rejected(self):
        # Mutate only an in-memory copy after pin validation to exercise guards.
        for address, word, message in ((0x1285D8 + 20, 52, "descriptor changed"),
                                       (0x109760, 0xEB000000, "Screen call changed"),
                                       (0x1098DC, 0xE3A01001, "no longer zero")):
            elf = graphics.PinnedElf("manager", pins=graphics.PINS)
            changed = bytearray(elf.data)
            struct.pack_into("<I", changed, elf.offset(address, 4), word)
            elf.data = bytes(changed)
            with self.subTest(address=hex(address)), self.assertRaisesRegex(ValueError, message):
                graphics.manager_metadata(elf)


if __name__ == "__main__":
    unittest.main()
