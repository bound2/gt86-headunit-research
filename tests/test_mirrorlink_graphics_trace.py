"""Offline evidence checks; no vendor execution or rendering is tested."""
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_mirrorlink_graphics as mirror


class MirrorLinkGraphicsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = mirror.inspect()

    def elf(self, key="graphics"):
        return mirror.PinnedElf(key, pins=mirror.PINS, directory=ROOT)

    def test_screen_creation_upload_presentation_and_cleanup_are_separate(self):
        calls = self.evidence["graphics_calls"]
        self.assertEqual(len(calls), 26)
        for address, symbol in (("0xaea4", "screen_create_window_buffers"),
                                ("0x14360", "_Znaj"),
                                ("0x136a0", "glTexSubImage2D"),
                                ("0x10724", "glDrawElements"),
                                ("0xc13c", "eglSwapBuffers"),
                                ("0x9ff8", "screen_destroy_window"),
                                ("0x1443c", "_ZdaPv")):
            self.assertEqual(calls[address]["symbol"], symbol)
        self.assertFalse(any(row["symbol"] == "screen_post_window" for row in calls.values()))
        # This is the selected path, not a claim about all rendering paths.
        self.assertTrue(any("H.264" in limit for limit in self.evidence["limits"]))

    def test_static_symbols_identify_the_remote_ui_factory_callers(self):
        callers = self.evidence["remote_factory_callers"]
        self.assertIn("24initDefaultGraphicWindowEv", callers["0x58c0c"]["name"])
        self.assertIn("16GetGraphicWindow", callers["0x59624"]["name"])
        self.assertEqual(callers["0x58c0c"]["value"], 0x58628)
        self.assertEqual(callers["0x59624"]["value"], 0x592E4)
        self.assertEqual(self.evidence["remote_factory_calls"]["0x58c0c"]["got"], "0x1e1240")

    def test_redraw_and_control_virtual_slots_resolve_via_relocations(self):
        slots = self.evidence["virtual_method_relocations"]
        for address, method in (("0x1d370", "12RenderBufferEv"),
                                ("0x1d14c", "12UpdateWindowEv"),
                                ("0x1d178", "4BindEv"), ("0x1d17c", "6UnBindEv")):
            self.assertTrue(slots[address]["name"].endswith(method))
        elf = self.elf()
        self.assertEqual(elf.uint(0xAEA0), 0xE3A01002)
        self.assertEqual(elf.uint(0xAF0C), 0xE3A01033)

    def test_frame_update_commands_are_forwarded_not_graphics_calls(self):
        self.assertEqual(self.evidence["frame_update_command_literals"], {
            "0x1136f0": "MirrorLinkClient_StopFrameBufferUpdate",
            "0x1137e8": "MirrorLinkClient_StartFrameBufferUpdate"})
        self.assertEqual(set(self.evidence["service_writer_calls"].values()), {"0x11b5a0"})
        self.assertTrue(self.evidence["boot_links_wicome_libraries"])

    def test_changed_inputs_are_rejected_before_elf_analysis(self):
        original = Path.read_bytes
        for name, _ in mirror.PINS.values():
            target = ROOT / name
            def changed(path):
                data = original(path)
                return data + b"changed" if path == target else data
            with self.subTest(name=name), patch.object(Path, "read_bytes", changed), \
                    patch.object(mirror, "PinnedElf") as elf:
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    mirror.inspect()
                elf.assert_not_called()

    def test_default_output_is_repeatable_without_processes_or_input_changes(self):
        before = mirror.read_inputs()
        with patch.object(subprocess, "run") as run:
            self.assertEqual(mirror.inspect(), self.evidence)
            run.assert_not_called()
        self.assertEqual(before, mirror.read_inputs())

    def test_selected_plt_form_and_relocation_are_required(self):
        elf = self.elf()
        slots = {a: s for a, k, s in elf.relocations() if k == 22}
        result = mirror.resolve_plt(elf, 0x7BD8, slots)
        self.assertEqual(result, dict(plt="0x7bd8", got="0x1d674", symbol="screen_create_context"))
        for address in (-4, 1, 0xAA5C, 0xFFFFFFFC):
            with self.subTest(address=address), self.assertRaises(ValueError):
                mirror.resolve_plt(elf, address, slots)
        with self.assertRaisesRegex(ValueError, "no matching"):
            mirror.resolve_plt(elf, 0x7BD8, {})
        for offset in (0, 4, 8):
            altered = self.elf()
            data = bytearray(altered.data)
            struct.pack_into("<I", data, altered.offset(0x7BD8 + offset, 4), 0xE1A00000)
            altered.data = bytes(data)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "PLT form"):
                mirror.resolve_plt(altered, 0x7BD8, slots)
        with self.assertRaisesRegex(ValueError, "call changed"):
            mirror.selected_calls(elf, {0xC13C: "screen_post_window"})
        with self.assertRaises(ValueError):
            mirror.selected_calls(elf, {0xAA5C: "screen_create_context"})

    def test_arm_immediates_apply_rotation(self):
        self.assertEqual(mirror.rotated_immediate(0xE28FC600), 0)
        self.assertEqual(mirror.rotated_immediate(0xE28CCA15), 86016)
        self.assertEqual(mirror.rotated_immediate(0xE3A004FF), 0xFF000000)
        self.assertEqual(mirror.rotated_immediate(0xE3A000A5), 165)

    def test_static_symbol_parser_rejects_invalid_sections_and_names(self):
        original = self.elf("remote")
        self.assertEqual(len(mirror.static_symbols(original)), 33803)
        shoff = struct.unpack_from("<I", original.data, 32)[0]
        shnum = struct.unpack_from("<H", original.data, 48)[0]
        sections = [struct.unpack_from("<10I", original.data, shoff + 40*i) for i in range(shnum)]
        table_index = next(i for i,s in enumerate(sections) if s[1] == 2)
        table = sections[table_index]
        strings = sections[table[6]]
        edits = [(32, len(original.data)), (shoff + 40*table_index + 36, 8),
                 (shoff + 40*table_index + 24, shnum), (table[4], strings[5])]
        for offset, value in edits:
            elf = self.elf("remote")
            data = bytearray(elf.data)
            struct.pack_into("<I", data, offset, value)
            elf.data = bytes(data)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                mirror.static_symbols(elf)
        original.data = original.data[:12]
        with self.assertRaisesRegex(ValueError, "Truncated"):
            mirror.static_symbols(original)


if __name__ == "__main__":
    unittest.main()
