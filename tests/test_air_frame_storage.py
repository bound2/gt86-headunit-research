"""Static frame lifetime and copy observations; not an AIR or video emulator."""
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_air_mainconcept as air


class AirFrameStorageTests(unittest.TestCase):
    def setUp(self):
        self.elf = air.PinnedElf("air", pins=air.PINS, directory=air.DIRECTORY)

    def test_selected_commands_distinguish_descriptor_and_pixel_copy(self):
        result = air.frame_storage_evidence(self.elf)
        self.assertEqual(result["selected_command_cases"],
                         {"0x10027": "0x5750e0", "0x10007": "0x575490"})
        self.assertEqual(result["descriptor_fields"]["0x10"], "plane query 0")
        self.assertEqual(result["descriptor_fields"]["0x28"], "stride query 5")
        self.assertEqual(result["native_calls"]["0x575adc"]["symbol"], "memcpy")
        self.assertEqual(result["native_calls"]["0x575d58"]["symbol"], "memcpy")

    def test_frame_release_is_not_an_owned_pixel_transfer(self):
        result = air.frame_storage_evidence(self.elf)
        self.assertEqual(result["current_frame_release"],
                         dict(call="0x573eb8", frame_slot="0x0c", clear="0x573ec0"))
        self.assertEqual(result["direct_calls"]["0x573ec8"], "0x573900")
        self.assertIn("transferred reference", " ".join(result["limits"]))
        self.assertIn("without copying", " ".join(result["limits"]))

    def test_core_and_companion_creation_do_not_prove_runtime_readiness(self):
        result = air.frame_storage_evidence(self.elf)
        self.assertEqual(result["core_allocation_bytes"], 0xFDAD0)
        self.assertEqual(result["core_callback_literals"]["0x576820"], "0x576624")
        self.assertEqual(result["core_callback_literals"]["0x57681c"], "0x5765fc")
        self.assertEqual(result["core_initialization"]["call"], "0x5746b0")
        self.assertEqual(result["direct_calls"]["0x5fff30"], "0x5fef60")
        self.assertIn("not total decoder memory", " ".join(result["limits"]))

    def test_changed_dispatch_copy_release_and_constructor_anchors_are_refused(self):
        for address in (0x5744F8, 0x574564, 0x575170, 0x573EB8, 0x5767F4):
            original = self.elf.data
            changed = bytearray(original)
            struct.pack_into("<I", changed, self.elf.offset(address, 4), 0)
            self.elf.data = bytes(changed)
            with self.subTest(address=hex(address)), \
                    self.assertRaisesRegex(ValueError, "frame-storage anchor"):
                air.frame_storage_evidence(self.elf)
            self.elf.data = original

    def test_changed_core_function_pointer_is_refused(self):
        changed = bytearray(self.elf.data)
        struct.pack_into("<I", changed, self.elf.offset(0x576820, 4), 0)
        self.elf.data = bytes(changed)
        with self.assertRaisesRegex(ValueError, "Core callback literal"):
            air.frame_storage_evidence(self.elf)


if __name__ == "__main__":
    unittest.main()
