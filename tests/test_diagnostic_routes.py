"""Safety and regression checks for the PC-only diagnostic-route investigation."""
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import probe_diagnostic_routes as probe


class DiagnosticRouteTests(unittest.TestCase):
    def test_all_pins_and_route_checks(self):
        evidence = probe.run_checks()
        self.assertEqual(len(evidence["modeled_mcd_checks"]), 10)
        self.assertEqual(len(evidence["stock_lua_checks"]), 7)
        self.assertIn("/tmp/ScreenShot.bmp", evidence["snapshot"]["source"])
        self.assertNotIn("info.xml", evidence["snapshot"]["source"])
        self.assertTrue(evidence["configuration"]["upload_configured"])
        self.assertFalse(evidence["scope"]["guest_commands_executed"])

    def test_changed_input_refused(self):
        with patch.object(Path, "read_bytes", return_value=b"changed"):
            with self.assertRaisesRegex(ValueError, "Not the pinned research input"):
                probe.read_inputs()

    def test_changed_iso_refused_before_archive_reader(self):
        with patch.object(Path, "open", return_value=io.BytesIO(b"changed ISO")), \
                patch.object(probe.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "Not the pinned installation ISO"):
                probe.snapshot_bytes()
            run.assert_not_called()

    def test_existing_output_refused(self):
        target = ROOT / "README.md"
        original = target.read_bytes()
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/probe_diagnostic_routes.py"),
                                 "--output", str(target)], capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"FileExistsError", result.stderr)
        self.assertEqual(target.read_bytes(), original)

    def test_cycle_and_missing_mock_fail(self):
        source = "[/fs/usb*]\nStart Rule=A\n[A]\nCallout=FNAME_MATCH\nMatch Rule=A\n"
        with self.assertRaisesRegex(ValueError, "Cyclic"):
            probe.mcd_trace(source, {"A": True})
        with self.assertRaisesRegex(ValueError, "No synthetic callout"):
            probe.mcd_trace(source, {})


if __name__ == "__main__":
    unittest.main()
