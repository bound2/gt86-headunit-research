"""Selected native USB ownership evidence; no actual phone/server integration."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_usb_ownership as trace
from probe_usb_ownership import LIB_BASE, OwnershipProbe, instance, scenarios


class UsbOwnershipTests(unittest.TestCase):
    def test_static_dependency_aliases_dispatch_and_callback_order(self):
        result = trace.inspect()
        self.assertIn("libusbdi.so.2", result["ncm_needed"])
        self.assertEqual(result["library_copy_differences"], ["0x41", "0x42", "0x61", "0x62"])
        self.assertEqual(result["server_local_calls"]["0x117c6c"], "0x105f88")
        self.assertEqual(result["server_local_calls"]["0x117c80"], "0x11682c")
        self.assertEqual(result["server_local_calls"]["0x116880"], "0x11661c")
        for site in ("0x7f64", "0x8014"):
            self.assertEqual(result["library_calls"][site]["symbol"], "usbdi_synchronise")
        self.assertEqual(result["library_words"]["0x7ff4"], "0xe12fff33")
        self.assertEqual(result["library_calls"]["0x8004"]["symbol"], "atomic_sub")
        self.assertFalse(result["live_ownership_verified"])

    def test_alias_comparison_refuses_code_difference(self):
        first = trace.PinnedElf("usb", pins=trace.PINS, directory=ROOT)
        second = trace.PinnedElf("alias", pins=trace.PINS, directory=ROOT)
        data = bytearray(second.data)
        data[second.offset(0x371C)] ^= 1
        second.data = bytes(data)
        with self.assertRaisesRegex(ValueError, "outside selected physical-address"):
            trace.compare_library_copies(first, second)

    def test_same_resolved_interface_conflicts_across_exclusive_clients(self):
        for module in ("usb", "server"):
            p = OwnershipProbe(module)
            owner, other = p.client(), p.client()
            self.assertEqual(p.claim(owner, instance()), 0)
            old = p.uint(owner + 0x1C)
            self.assertEqual(p.claim(other, instance()), 16)
            self.assertEqual(p.uint(owner + 0x1C), old)
            self.assertEqual(p.uint(other + 0x1C), 0)
            self.assertFalse(p.locks)

    def test_distinct_interface_bus_address_and_generation_do_not_conflict_in_selector(self):
        for module in ("usb", "server"):
            for fields in (dict(iface=5), dict(path=2), dict(devno=8), dict(generation=4)):
                with self.subTest(module=module, fields=fields):
                    p = OwnershipProbe(module)
                    owner, other = p.client(), p.client()
                    self.assertEqual(p.claim(owner, instance()), 0)
                    self.assertEqual(p.claim(other, instance(**fields)), 0)
                    self.assertNotEqual(p.uint(other + 0x1C), 0)

    def test_selector_does_not_use_vid_pid_class_config_or_alternate(self):
        for module in ("usb", "server"):
            for fields in (dict(vendor=99, product=77), dict(config=7), dict(alternate=1),
                           dict(dclass=3, subclass=0, protocol=9)):
                with self.subTest(module=module, fields=fields):
                    p = OwnershipProbe(module)
                    owner, other = p.client(), p.client()
                    self.assertEqual(p.claim(owner, instance()), 0)
                    self.assertEqual(p.claim(other, instance(**fields)), 16)
        # These are synthetic resolved nodes, not accepted server attach requests.

    def test_shared_inspection_records_do_not_exclude_io_claims(self):
        for module in ("usb", "server"):
            for shared_first in (True, False):
                p = OwnershipProbe(module)
                shared, owner = p.client(False), p.client(True)
                order = (shared, owner) if shared_first else (owner, shared)
                self.assertEqual([p.claim(c, instance()) for c in order], [0, 0])

    def test_same_client_duplicate_conflicts_and_search_finds_later_claim(self):
        for module in ("usb", "server"):
            p = OwnershipProbe(module)
            first, second, third = p.client(), p.client(), p.client()
            self.assertEqual(p.claim(first, instance(iface=2)), 0)
            self.assertEqual(p.claim(second, instance(iface=4)), 0)
            self.assertEqual(p.claim(second, instance(iface=5)), 0)
            self.assertEqual(p.claim(second, instance(iface=5)), 16)
            self.assertEqual(p.claim(third, instance(iface=4)), 16)

    def test_removal_is_deferred_until_last_explicit_retirement(self):
        p = OwnershipProbe()
        p.make_device(pending=2, pipe_pending=2)
        self.assertEqual(p.call("synchronise", p.device, 0, 0), 16)
        self.assertEqual(p.uint(p.device + 0x14) & 1, 1)
        self.assertEqual(p.call("synchronise", p.device, 1, -1), 0)
        self.assertEqual(p.callback_count, 0)
        self.assertEqual(p.call("synchronise", p.device, 1, -1), 0)
        self.assertEqual(p.callback_count, 1)
        event = [e for e in p.events if e["op"] == "mock_removal_callback"]
        self.assertEqual(event[0]["device_pending"], 0)
        self.assertEqual(event[0]["instance"], instance().hex())
        self.assertFalse(p.locks)

    def test_removal_without_pending_returns_ready_without_helper_callback(self):
        p = OwnershipProbe()
        p.make_device(pending=0, pipe_pending=0)
        self.assertEqual(p.call("synchronise", p.device, 0, 0), 0)
        self.assertEqual(p.callback_count, 0)
        # Static event-loop trace shows that its caller invokes removal in this case.

    def test_new_io_is_rejected_after_removal_or_while_suspended(self):
        for flags, expected in ((1, 19), (2, 11)):
            p = OwnershipProbe()
            p.make_device()
            p.write32(p.device + 0x14, flags)
            self.assertEqual(p.call("synchronise", p.device, 1, 1), expected)
            self.assertEqual(p.uint(p.device + 0x18), 1)
            self.assertFalse(p.callback_count)

    def test_abort_balances_its_pipe_reference_without_retiring_io(self):
        for error in (0, 5, 19):
            p = OwnershipProbe(command_error=error)
            p.make_device()
            self.assertEqual(p.call("abort", p.pipe), error)
            self.assertEqual(p.uint(p.pipe + 0xC), 1)
            self.assertEqual(p.uint(p.device + 0x18), 1)
            self.assertFalse(p.callback_count)
            event = [e for e in p.events if e["op"] == "usbdi_sendcmd"][0]
            self.assertEqual(event, dict(op="usbdi_sendcmd", command=6, pipe_pending=2,
                device_pending=1, identity=instance()[:4].hex(), config=1, iface=4, alternate=0, endpoint=0x81))

    def test_abort_without_pending_sends_no_command(self):
        p = OwnershipProbe()
        p.make_device(pending=0, pipe_pending=0)
        self.assertEqual(p.call("abort", p.pipe), 0)
        self.assertEqual(p.events, [])

    def test_busy_close_and_detach_preserve_local_objects(self):
        p = OwnershipProbe()
        p.make_device()
        before = p.read(p.device, 72), p.read(p.pipe, 24)
        self.assertEqual(p.call("close", p.pipe), 16)
        self.assertEqual(p.call("detach", p.device), 16)
        self.assertEqual((p.read(p.device, 72), p.read(p.pipe, 24)), before)
        self.assertFalse(p.events)
        self.assertFalse(p.freed)

    def test_detach_command_error_still_disposes_local_handles(self):
        for error in (0, 5, 19):
            p = OwnershipProbe(command_error=error)
            p.make_device(pending=0, pipe_pending=0)
            self.assertEqual(p.call("detach", p.device), error)
            self.assertEqual(p.freed, [p.pipe, p.device])
            self.assertEqual(p.uint(p.connection + 0x38), 0)
            self.assertFalse(p.callback_count)

    def test_detach_busy_status_alone_does_not_identify_handle_lifetime(self):
        pending = OwnershipProbe()
        pending.make_device()
        command_busy = OwnershipProbe(command_error=16)
        command_busy.make_device(pending=0, pipe_pending=0)
        self.assertEqual(pending.call("detach", pending.device), 16)
        self.assertEqual(command_busy.call("detach", command_busy.device), 16)
        self.assertEqual(pending.freed, [])
        self.assertEqual(command_busy.freed, [command_busy.pipe, command_busy.device])
        # Injected RPC status, not proof that the real server returns EBUSY here.
        # A backend cannot infer pointer validity from the integer alone.

    def test_selected_replay_is_repeatable_without_subprocesses_or_input_changes(self):
        before = {key: (ROOT / name).read_bytes() for key, (name, _) in trace.PINS.items()}
        with patch.object(subprocess, "run") as run:
            self.assertEqual(scenarios(), scenarios())
            run.assert_not_called()
        self.assertEqual(before, {key: (ROOT / name).read_bytes() for key, (name, _) in trace.PINS.items()})

    def test_changed_input_rejected_before_emulator_creation(self):
        original = Path.read_bytes
        for module in ("usb", "server"):
            target = ROOT / trace.PINS[module][0]
            def changed(path):
                return original(path) + b"changed" if path == target else original(path)
            with patch.object(Path, "read_bytes", changed), patch("probe_usb_ownership.Uc") as emulator:
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    OwnershipProbe(module)
                emulator.assert_not_called()

    def test_entry_import_and_interrupt_guards(self):
        p = OwnershipProbe()
        with self.assertRaisesRegex(AssertionError, "entry/argument bound"):
            p.call("attach")
        address = next(a for a, name in p.imports.items() if name == "MsgSendv_r")
        with self.assertRaisesRegex(RuntimeError, "Unexpected guest import"):
            p.on_code(p.u, address, 4, None)
        with self.assertRaisesRegex(AssertionError, "Execution outside"):
            p.on_code(p.u, LIB_BASE + 0x7E44, 4, None)
        with self.assertRaisesRegex(RuntimeError, "interrupt forbidden"):
            p.on_interrupt(p.u, 2, None)
        with self.assertRaisesRegex(AssertionError, "conflict-only"):
            OwnershipProbe("server").call("detach", 0)

    def test_cyclic_claim_list_hits_instruction_budget(self):
        p = OwnershipProbe()
        owner, other = p.client(), p.client()
        self.assertEqual(p.claim(owner, instance(iface=2)), 0)
        node = p.uint(owner + 0x1C)
        p.write32(node, node)
        with self.assertRaisesRegex(AssertionError, "instruction/time budget"):
            p.claim(other, instance(iface=4))


if __name__ == "__main__":
    unittest.main()
