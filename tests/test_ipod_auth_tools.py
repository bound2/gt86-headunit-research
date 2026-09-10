"""Corpus-dependent safety checks for the read-only auth/media analysis tools."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from inspect_ipod_auth import PinnedElf


class AnalysisToolTests(unittest.TestCase):
    def test_pinned_descriptor_is_constant(self):
        elf = PinnedElf("i2c")
        self.assertEqual(elf.string(elf.uint(0x1C28)), "=Iacp_ver")
        self.assertEqual(elf.uint(0x1C2C), 1)
        self.assertEqual(elf.metadata()["sha256"], hashlib.sha256(elf.data).hexdigest())

    def test_changed_vendor_input_refused(self):
        for module in ("i2c", "ipod", "media", "usb", "service"):
            original = PinnedElf(module).data
            changed = original[:-1] + bytes([original[-1] ^ 1])
            with self.subTest(module=module), patch.object(Path, "read_bytes", return_value=changed):
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    PinnedElf(module)

    def test_analysis_header_adaptation_only(self):
        elf = PinnedElf("i2c")
        original = elf.data
        response = subprocess.CompletedProcess([], 0, b"synthetic listing", b"")
        with patch("inspect_ipod_auth.subprocess.run", return_value=response) as run:
            elf.disassemble(Path("unused-llvm"), 0x600, 0xABC)
        adapted = run.call_args.kwargs["input"]
        expected = bytearray(original)
        struct.pack_into("<I", expected, 32, 0)
        struct.pack_into("<HH", expected, 48, 0, 0)
        self.assertEqual(adapted, expected)
        self.assertEqual(elf.data, original)
        self.assertEqual(elf.path.read_bytes(), original)
        self.assertEqual(run.call_args.kwargs["timeout"], 20)

    def test_invalid_ranges_refused_before_tool_launch(self):
        elf = PinnedElf("i2c")
        with patch("inspect_ipod_auth.subprocess.run") as run:
            for start, stop in ((-1, 10), (10, 10), (20, 10), (0, 65537), (0x100000, 0x100004)):
                with self.subTest(start=start, stop=stop), self.assertRaises(ValueError):
                    elf.disassemble(Path("unused-llvm"), start, stop)
            run.assert_not_called()

    def test_existing_output_refused(self):
        target = ROOT / "README.md"
        original = target.read_bytes()
        for name in ("inspect_ipod_auth.py", "probe_ipod_auth.py", "probe_media_info.py"):
            result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / name),
                                     "--output", str(target)], capture_output=True, timeout=20)
            with self.subTest(script=name):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"FileExistsError", result.stderr)
                self.assertEqual(target.read_bytes(), original)

    def test_media_export_and_driver_callback_pins(self):
        elf = PinnedElf("media")
        self.assertEqual([elf.string(a) for a in (0x120D64, 0x120D70)], [".FS_info.", "info.xml"])
        symbols = {s["name"]: s["value"] for s in
                   (elf.symbol(i) for i in range(elf.uint(elf.dynamic[4] + 4))) if s["section"]}
        self.assertEqual(symbols["mount_info_io"], 0x115870)
        self.assertEqual(symbols["node_get"], 0x1170AC)
        self.assertEqual(elf.uint(0x10CAA4), symbols["mount_info_io"])
        driver = PinnedElf("ipod")
        self.assertEqual(driver.uint(0x356F8 + 0x24), 0x38A20)
        self.assertEqual(driver.string(driver.uint(0x38A20)), "drvr")
        self.assertEqual(driver.uint(0x38A20 + 0x3C), 0x29008)

    def test_media_probe_fails_closed(self):
        from probe_media_info import MediaInfoProbe
        p = MediaInfoProbe()
        with self.assertRaisesRegex(AssertionError, "outside audited"):
            p.call(0x1038B8)  # Executable initializer is outside this probe's scope.
        with self.assertRaisesRegex(RuntimeError, "Unexpected guest import: open"):
            p.call(p.stub("open"))
        with self.assertRaisesRegex(RuntimeError, "syscall/interrupt forbidden"):
            p.on_interrupt(p.u, 2, None)

    def test_media_description_slice_requires_explicit_mode(self):
        from probe_media_info import MediaInfoProbe
        p = MediaInfoProbe()
        with self.assertRaisesRegex(AssertionError, "outside audited"):
            p.call(0x116938)
        p.dispatch_slice()
        self.assertFalse(p.slice_mode)


if __name__ == "__main__":
    unittest.main()
