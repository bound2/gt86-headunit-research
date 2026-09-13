"""Selected static decoder relationships, not decoding/interoperability tests."""
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_air_mainconcept as decoder


class AirMainConceptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = decoder.inspect()

    def elf(self):
        return decoder.PinnedElf("air", pins=decoder.PINS, directory=decoder.DIRECTORY)

    def test_factory_constructor_and_rtti_connect_the_label_to_the_class(self):
        self.assertEqual(self.evidence["direct_calls"]["0x2607d8"], "0x39feb4")
        self.assertEqual(self.evidence["relative_slots"]["0xa5d140"], "0x39be10")
        self.assertEqual(self.evidence["relative_slots"]["0xa5d164"], "0x931d20")
        self.assertEqual(self.evidence["label"]["text"], "H264 - MainConcept")
        self.assertEqual(len(self.evidence["selected_unwind_intervals"]), 12)

    def test_instance_initializes_two_distinct_internal_objects(self):
        calls = self.evidence["direct_calls"]
        self.assertEqual(calls["0x39df80"], "0x5ffefc")
        self.assertEqual(calls["0x39df88"], "0x574280")
        self.assertEqual(calls["0x39dab4"], "0x574250")
        self.assertEqual(calls["0x39dac4"], "0x5ffef8")
        self.assertEqual(self.evidence["backend_pointer_literals"],
                         {"0x5743b0": "0x573e74", "0x5743b4": "0x574440"})
        self.assertEqual(self.evidence["native_calls"]["0x574290"]["symbol"], "_Znaj")

    def test_record_dispatch_and_start_code_submission_remain_separate(self):
        calls = self.evidence["direct_calls"]
        self.assertEqual(calls["0x39fb54"], "0x39ee54")
        self.assertEqual(calls["0x39fb68"], "0x39f1c8")
        self.assertEqual(calls["0x39f86c"], "0x39d2d8")
        self.assertEqual(self.evidence["input_prefix"]["bytes_hex"], "00000001")
        self.assertEqual(self.evidence["native_calls"]["0x39f07c"]["symbol"], "memcpy")

    def test_output_evidence_is_numeric_commands_and_planes_not_an_exported_api(self):
        self.assertEqual(self.evidence["command_literals"]["0x39d10c"], "0x10027")
        self.assertEqual(self.evidence["command_literals"]["0x39d118"], "0x10007")
        self.assertEqual(self.evidence["fallback_output_marker"], "0x59563132")
        self.assertEqual(self.evidence["selected_defined_dynamic_symbols"], [])
        self.assertIn("ownership", " ".join(self.evidence["limits"]))

    def test_changed_whole_input_is_refused_before_inspection(self):
        original = Path.read_bytes
        with patch.object(Path, "read_bytes", lambda p: original(p) + b"changed"), \
                patch.object(decoder, "unwind_starts") as unwind:
            with self.assertRaisesRegex(ValueError, "Not the pinned"):
                decoder.inspect()
            unwind.assert_not_called()

    def test_selected_semantic_anchors_are_checked_after_whole_file_pin(self):
        # Inject an already-open object to exercise relationship checks separately
        # from the earlier whole-input SHA refusal. No actual corpus file changes.
        for address, message in ((0x39D62C, "instruction/literal"),
                                 (0xA5D140, "relative relocation"),
                                 (0x5743B0, "function pointer")):
            elf = self.elf()
            changed = bytearray(elf.data)
            struct.pack_into("<I", changed, elf.offset(address, 4), 0)
            elf.data = bytes(changed)
            with self.subTest(address=hex(address)), \
                    patch.object(decoder, "PinnedElf", return_value=elf), \
                    self.assertRaisesRegex(ValueError, message):
                decoder.inspect()

    def test_default_is_repeatable_and_does_not_launch_processes_or_write(self):
        before = self.elf().data
        with patch.object(subprocess, "run") as run, \
                patch.object(Path, "write_bytes") as write_bytes, \
                patch.object(Path, "write_text") as write_text:
            self.assertEqual(decoder.inspect(), self.evidence)
            run.assert_not_called()
            write_bytes.assert_not_called()
            write_text.assert_not_called()
        self.assertEqual(self.elf().data, before)


if __name__ == "__main__":
    unittest.main()
