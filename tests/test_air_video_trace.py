"""Static AIR evidence checks; no media filter or vendor code is executed."""
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_air_video as air


class AirVideoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = air.inspect()

    def elf(self):
        return air.PinnedElf("air", pins=air.PINS, directory=air.DIRECTORY)

    def test_media_calls_are_graph_and_callback_acquisition_not_decoder_exports(self):
        calls = self.evidence["native_calls"]
        self.assertEqual(len(calls), 25)
        self.assertEqual(calls["0x359730"]["symbol"], "MmGetResourceValue")
        self.assertEqual(calls["0x359820"]["symbol"], "MmFindChannelsFilter")
        self.assertEqual(calls["0x3599f0"]["symbol"], "MmFindFilter")
        self.assertEqual(calls["0x35a118"]["symbol"], "MmDestroyGraph")
        self.assertEqual(calls["0x35a1f8"]["symbol"], "MmDestroyGraph")
        self.assertEqual(self.evidence["direct_calls"]["0x35b120"], "0x3595b4")
        self.assertEqual(self.evidence["direct_calls"]["0x355808"], "0x354204")

    def test_selected_resources_keep_input_output_and_filter_selection_separate(self):
        literals = self.evidence["literals"]
        self.assertEqual(literals["0x35a310"]["text"], "MM_FLASH_READER_PUSH_ENTRY_PT")
        self.assertEqual(literals["0x35a36c"]["text"], "SCREEN_WRITER_EXT_CONTEXT")
        self.assertEqual(literals["0x35b254"]["text"], "screen_writer")
        self.assertEqual(literals["0x359584"]["text"], "MM_INIT")
        self.assertIn("not return CPU RGBA", " ".join(self.evidence["limits"]))

    def test_rtti_and_unwind_intervals_identify_a_bounded_local_candidate(self):
        self.assertEqual(self.evidence["unwind_entry_count"], 27240)
        self.assertEqual(self.evidence["selected_unwind_intervals"]["graph"],
                         dict(start="0x3595b4", stop="0x35a3e8", bytes=3636))
        self.assertEqual(self.evidence["relative_slots"]["0xa59b38"], "0x35ad74")
        self.assertEqual(self.evidence["relative_slots"]["0xa5a2a4"], "0x92e5b8")

    def test_prel31_decodes_signed_offsets_and_rejects_invalid_first_words(self):
        self.assertEqual(air.prel31(0x1000, 8), 0x1008)
        self.assertEqual(air.prel31(0x1000, 0x7FFFFFF8), 0xFF8)
        self.assertEqual(air.prel31(0xFFFFFFFC, 4), 0)
        for address, word in ((-1, 0), (0x100000000, 0), (0, -1), (0, 0x80000000)):
            with self.subTest(address=address, word=word), self.assertRaises(ValueError):
                air.prel31(address, word)

    def test_unwind_parser_rejects_bad_directory_order_and_targets(self):
        elf = self.elf()
        elf.segments = [s for s in elf.segments if s[0] != 0x70000001]
        with self.assertRaisesRegex(ValueError, "one ARM"):
            air.unwind_starts(elf)
        elf = self.elf()
        elf.segments[0] = (*elf.segments[0][:4], 9, *elf.segments[0][5:])
        with self.assertRaisesRegex(ValueError, "bounds"):
            air.unwind_starts(elf)
        for index, word, message in ((0, 0x80000000, "PREL31"),
                                     (0, (0xFFFFFFFF - 0xA05904) & 0x7FFFFFFF, "outside"),
                                     (1, (0x6CBF4 - (0xA05904 + 8)) & 0x7FFFFFFF, "ordered")):
            elf = self.elf()
            data = bytearray(elf.data)
            struct.pack_into("<I", data, elf.segments[0][1] + index * 8, word)
            elf.data = bytes(data)
            with self.subTest(index=index, word=word), self.assertRaisesRegex(ValueError, message):
                air.unwind_starts(elf)

    def test_changed_input_is_refused_before_unwind_inspection(self):
        original = Path.read_bytes
        with patch.object(Path, "read_bytes", lambda p: original(p) + b"changed"), \
                patch.object(air, "unwind_starts") as unwind:
            with self.assertRaisesRegex(ValueError, "Not the pinned"):
                air.inspect()
            unwind.assert_not_called()

    def test_default_is_repeatable_and_leaves_input_unchanged_without_processes(self):
        original = self.elf().data
        with patch.object(subprocess, "run") as run, \
                patch.object(Path, "write_bytes") as write_bytes, \
                patch.object(Path, "write_text") as write_text:
            self.assertEqual(air.inspect(), self.evidence)
            run.assert_not_called()
            write_bytes.assert_not_called()
            write_text.assert_not_called()
        self.assertEqual(self.elf().data, original)


if __name__ == "__main__":
    unittest.main()
