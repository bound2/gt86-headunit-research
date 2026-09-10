"""Corpus-dependent static trace checks; no guest/target execution."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from inspect_ipod_auth import PinnedElf, arm_call_target, media_service_metadata


class MediaServiceTraceTests(unittest.TestCase):
    def test_selected_consumer_path_and_callbacks(self):
        elf = PinnedElf("service")
        facts = media_service_metadata(elf)
        self.assertEqual(facts["path_suffix"], "/.FS_info./info.xml")
        self.assertEqual(facts["consumer_call"], {"site": "0x17bd20", "target": "0x178238"})
        self.assertEqual(facts["parser_callbacks"], {
            "start": "0x1780a0", "end": "0x177c3c", "text": "0x177f8c", "processing_instruction": "0x177c40"})
        self.assertEqual(facts["start_tag_comparison_literals"], ["model", "id", "productid", "product"])
        self.assertEqual(facts["storage_result_literals"], ["flash", "harddrive"])
        self.assertEqual(facts["model_configuration_string"], "/etc/ipodModels.cfg")
        self.assertEqual(facts["authcoproc_ascii_occurrences"], 0)
        for address in (0x177C3C, 0x177C40):
            self.assertEqual(elf.uint(address), 0xE12FFF1E)  # Selected handlers return immediately.

    def test_read_only_file_and_parser_import_calls(self):
        facts = media_service_metadata(PinnedElf("service"))
        self.assertEqual(facts["open_flags"], 0)
        self.assertEqual(facts["selected_import_calls"], {
            "0x178260": "XML_ParserCreate", "0x17826c": "XML_UseParserAsHandlerArg",
            "0x17827c": "XML_SetElementHandler", "0x178288": "XML_SetCharacterDataHandler",
            "0x178294": "XML_SetProcessingInstructionHandler", "0x1782ac": "open",
            "0x1782c0": "fstat", "0x1782dc": "read", "0x17830c": "XML_Parse", "0x178348": "close"})

    def test_call_decoder_rejects_non_calls_and_invalid_ranges(self):
        elf = PinnedElf("service")
        for address in (0x178238, 0x17829C, 0x17BD21, -4, 0, 0xFFFFFFFF):
            with self.subTest(address=address), self.assertRaises(ValueError):
                arm_call_target(elf, address)

    def test_static_inspection_never_launches_vendor_or_changes_input(self):
        with patch("inspect_ipod_auth.subprocess.run") as run:
            elf = PinnedElf("service")
            original = elf.data
            facts = media_service_metadata(elf)
            self.assertIn("Static", facts["scope"])
            self.assertEqual(elf.data, original)
            self.assertEqual(elf.path.read_bytes(), original)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
