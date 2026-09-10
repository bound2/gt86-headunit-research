"""Static evidence regression checks, not tests of a decoder or a vehicle."""
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_factory_video as video


class FactoryVideoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = video.inspect()

    def test_raw_decoder_is_a_named_pixel_copy_boundary(self):
        raw = self.evidence["functions"]["raw"]
        self.assertEqual((raw["value"], raw["size"]), (0x173028, 644))
        self.assertEqual(self.evidence["raw_copy_call"]["0x1731a0"],
                         dict(plt="0x1b604", got="0x1e1078", symbol="memcpy"))
        self.assertIn("RAW pixel copying is not H.264 decompression", self.evidence["limits"])

    def test_raw_and_window_slots_are_separate_relocation_types(self):
        self.assertEqual(self.evidence["raw_relative_slots"],
                         {"0x1e17d8": "0x1e0628", "0x1e065c": "0x173028"})
        slots = self.evidence["window_virtual_slots"]
        self.assertIn("20GetBufferPixelFormat", slots["0x1d42c"]["name"])
        self.assertIn("10LockBuffer", slots["0x1d43c"]["name"])
        self.assertIn("12UnlockBuffer", slots["0x1d440"]["name"])

    def test_wfd_factory_returns_null_after_only_two_logging_calls(self):
        factory = self.evidence["wfd_factory"]
        self.assertEqual(factory["normal_return_value"], 0)
        self.assertEqual(factory["bytes"], 180)
        self.assertEqual(set(factory["calls"]), {"0x105158", "0x105188"})
        self.assertEqual({row["symbol"] for row in factory["calls"].values()},
                         {"StarRec_TraceOut_trace"})
        self.assertEqual(self.evidence["wfd_factory_caller"], "0x73010")

    def test_changed_factory_body_is_rejected_not_reinterpreted(self):
        for address, word in ((0x105118, 0xE3A05001),  # nonnull result
                              (0x105120, 0xEA000000),  # extra branch
                              (0x105158, 0xE1A00000),  # removed logging call
                              (0x105194, 0xE8BD81FF)):  # changed return registers
            elf = video.PinnedElf("remote", pins=video.PINS, directory=ROOT)
            data = bytearray(elf.data)
            struct.pack_into("<I", data, elf.offset(address, 4), word)
            elf.data = bytes(data)
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, "body changed"):
                video.wfd_factory(elf)

    def test_changed_input_is_rejected_before_any_elf_analysis(self):
        original = Path.read_bytes
        for name, _ in video.PINS.values():
            target = ROOT / name
            def changed(path):
                data = original(path)
                return data + b"changed" if path == target else data
            with self.subTest(name=name), patch.object(Path, "read_bytes", changed), \
                    patch.object(video, "PinnedElf") as elf:
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    video.inspect()
                elf.assert_not_called()

    def test_default_is_repeatable_without_subprocess_or_file_writes(self):
        before = video.read_inputs()
        with patch.object(subprocess, "run") as run, \
                patch.object(Path, "write_bytes") as write_bytes, \
                patch.object(Path, "write_text") as write_text:
            self.assertEqual(video.inspect(), self.evidence)
            run.assert_not_called()
            write_bytes.assert_not_called()
            write_text.assert_not_called()
        self.assertEqual(before, video.read_inputs())


if __name__ == "__main__":
    unittest.main()
