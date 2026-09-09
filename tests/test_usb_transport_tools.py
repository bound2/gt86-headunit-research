"""Corpus-dependent USB replay safety and behavior regressions; no real USB."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from probe_usb_transport import BASE, PINS, UsbProbe, scenarios, static_evidence
from unicorn.arm_const import UC_ARM_REG_SP


class UsbTransportToolTests(unittest.TestCase):
    def test_static_pins_and_descriptor(self):
        evidence = static_evidence()
        self.assertEqual(len(evidence["inputs"]), 12)
        self.assertEqual(evidence["descriptor"], dict(module="0x4920", interface="0x4bf0",
                         name="ipod_transport", write="0x1674", read="0x11cc"))
        self.assertIn("Host Only", evidence["host_driver_description"])
        self.assertEqual(evidence["boot_tokens"]["strings"][2:6], ["-vvv", "-c", "-d", "dm816x-mg"])

    def test_changed_inputs_fail_before_replay(self):
        original_read = Path.read_bytes
        for name in (*PINS, "image-380000/lib/dll/iofs-usb-ipod.so"):
            def changed(path):
                data = original_read(path)
                return data[:-1] + bytes([data[-1] ^ 1]) if path.as_posix().endswith(name) else data
            with self.subTest(name=name), patch.object(Path, "read_bytes", changed):
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    static_evidence()
        with patch.object(Path, "read_bytes", return_value=b"changed"), patch("probe_usb_transport.Uc") as guest:
            with self.assertRaisesRegex(ValueError, "Not the pinned"):
                UsbProbe()
            guest.assert_not_called()

    def test_audited_execution_and_imports_only(self):
        p = UsbProbe()
        with self.assertRaisesRegex(AssertionError, "Entry outside audited"):
            p.call(0x2E3C)  # No transport initialization/attach.
        with self.assertRaisesRegex(AssertionError, "Execution outside audited"):
            p.on_code(p.u, BASE + 0x1630, 4, None)  # Callback is recorded, not run.
        p.u.reg_write(UC_ARM_REG_SP, 0x70FFF0)
        with self.assertRaisesRegex(RuntimeError, "Unexpected guest import: open"):
            p.on_code(p.u, p.stub("open"), 4, None)
        with self.assertRaisesRegex(RuntimeError, "syscall/interrupt forbidden"):
            p.on_interrupt(p.u, 2, None)

    def test_bounds(self):
        p = UsbProbe()
        for action in (lambda: p.write(bytes(1025)), lambda: p.complete_input(bytes(65)),
                       lambda: p.read_payload(0), lambda: p.read_payload(1025),
                       lambda: p.read_payload(8, 1001), lambda: p.allocate(65537)):
            with self.subTest(action=action), self.assertRaises(AssertionError):
                action()
        p.events = [{}] * 256
        with self.assertRaisesRegex(AssertionError, "event budget exceeded"):
            p.write(b"a")

    def test_native_scenarios(self):
        cases = {case["name"]: case for case in scenarios()}
        self.assertEqual(len(cases), 17)
        self.assertEqual(cases["write_partial_then_disconnect"]["result"], 8)
        short = cases["write_short_success"]
        self.assertEqual(short["result"], 3)
        self.assertEqual([e["actual_length"] for e in short["events"] if e["op"] == "usbd_urb_status"], [2])
        self.assertIn("budget exceeded", cases["write_busy_budget"]["result"])
        self.assertEqual(cases["read_stall_requeues"]["result"], 0)

    def test_existing_output_refused(self):
        target = ROOT / "README.md"
        original = target.read_bytes()
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/probe_usb_transport.py"),
                                 "--output", str(target)], capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"FileExistsError", result.stderr)
        self.assertEqual(target.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
