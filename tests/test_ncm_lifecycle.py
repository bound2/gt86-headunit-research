"""Synthetic native callback evidence, not a real USB lifecycle acceptance test."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_ncm_lifecycle as trace
from probe_ncm_lifecycle import BASE, NcmProbe, instance, scenarios


class NcmLifecycleTests(unittest.TestCase):
    def test_static_connection_attach_detach_and_worker_boundaries(self):
        result = trace.inspect()
        self.assertEqual(result["connections"], dict(callback_io_offset="0x14", shared_inspection_offset="0x18"))
        for site in ("0x48d8", "0x4964"):
            self.assertEqual(result["calls"][site]["symbol"], "usbd_connect")
        for site in ("0x37b8", "0x3910", "0x53b0"):
            self.assertEqual(result["calls"][site]["symbol"], "usbd_attach")
        for site in ("0x3c34", "0x3c3c", "0x3250", "0x3274"):
            self.assertEqual(result["calls"][site]["symbol"], "usbd_detach")
        self.assertEqual(result["relative_slots"]["0xe4a0"], "0x358c")
        self.assertEqual(result["relative_slots"]["0xe4a4"], "0x3050")
        self.assertEqual(result["insertion"]["worker"], "0x5384")
        self.assertEqual(result["options"][6], "pnp")
        self.assertEqual(result["pnp_flag"], 4)
        self.assertEqual(result["attachment"]["extended_name_format"], "ncm_%d_%d")
        self.assertEqual(result["attachment"]["extra_allocation_bytes"], 4)
        self.assertFalse(result["whole_driver_or_live_ownership_verified"])

    def test_static_relocation_type_is_not_inferred_from_raw_pointer(self):
        original = trace.PinnedElf.relocations
        def changed(elf):
            for target, kind, symbol in original(elf):
                yield target, 2 if target == 0xE4A4 else kind, symbol
        with patch.object(trace.PinnedElf, "relocations", changed):
            with self.assertRaisesRegex(ValueError, "R_ARM_RELATIVE"):
                trace.inspect()

    def test_abort_trace_records_forced_counter_zero_not_transfer_completion(self):
        result = trace.inspect()
        for site in ("0x7228", "0x725c", "0x7290"):
            self.assertEqual(result["calls"][site]["symbol"], "usbd_abort_pipe")
        self.assertEqual(result["calls"]["0x745c"]["symbol"], "usbd_select_interface")
        self.assertEqual(result["abort"]["forced_zero_counter_offsets"], ["0xc14", "0xbe0", "0xb90"])
        self.assertEqual(result["abort"]["return"], 0)
        self.assertIn("no actual transfer-drain proof", result["abort"]["limit"])

    def test_insertion_copies_all_fields_and_does_not_run_queued_work(self):
        for data in (instance(), instance(path=9, devno=42, generation=0xABCD, vendor=123,
                product=456, config=7, iface=11, alternate=3, protocol=9)):
            p = NcmProbe(verbose=True)
            p.call(0x515C, data)
            self.assertEqual(p.pending, [dict(callback="0x5310", instance=data.hex())])
            self.assertEqual(p.uint(BASE + trace.INSERTIONS), 1)
            self.assertFalse(p.removed)
            ops = [e["op"] for e in p.events if e["op"] != "intercepted_log"]
            self.assertEqual(ops, ["malloc", "atomic_add", "stk_context_callback_2"])

    def test_insertion_rejects_wrong_class_subclass_and_skips_scan(self):
        for flags, data in ((0, instance(dclass=10)), (0, instance(subclass=12)),
                            (2, instance()), (6, instance())):
            p = NcmProbe(flags=flags, verbose=True)
            p.call(0x515C, data)
            self.assertFalse(p.pending)
            self.assertEqual(p.uint(BASE + trace.INSERTIONS), 0)
            self.assertTrue(all(e["op"] == "intercepted_log" for e in p.events))

    def test_pnp_flag_does_not_itself_suppress_insertion(self):
        p = NcmProbe(flags=4)
        p.call(0x515C, instance())
        self.assertEqual(len(p.pending), 1)

    def test_allocation_failure_neither_queues_nor_increments(self):
        p = NcmProbe(malloc_fail=True)
        p.call(0x515C, instance())
        self.assertFalse(p.pending)
        self.assertEqual(p.uint(BASE + trace.INSERTIONS), 0)
        self.assertEqual(p.events[0], dict(op="malloc", size=52, pointer=0))

    def test_removal_traverses_list_and_unlocks_before_handoff(self):
        p = NcmProbe()
        p.add_device(2, 7)
        p.add_device(1, 8)
        p.add_device(1, 7)
        before = [p.read(node, 12) for node in p.nodes]
        p.call(0x4F50, instance())
        self.assertEqual(p.removed, [2])
        self.assertEqual(p.uint(BASE + trace.REMOVALS), 1)
        self.assertEqual([e["op"] for e in p.events], ["pthread_mutex_lock", "pthread_mutex_unlock",
                         "atomic_add", "intercepted_log", "dev_remove"])
        # The external dev_remove mock records only: native detach was not run.
        self.assertEqual([p.read(node, 12) for node in p.nodes], before)

    def test_removal_first_address_match_ignores_other_identity_fields(self):
        for fields in ({}, dict(generation=0xFFFF), dict(iface=99), dict(config=4),
                       dict(vendor=99, product=17), dict(alternate=8, protocol=255)):
            with self.subTest(fields=fields):
                p = NcmProbe(verbose=True)
                p.add_device(1, 7)
                p.add_device(1, 7)
                p.call(0x4F50, instance(**fields))
                self.assertEqual(p.removed, [0])

    def test_removal_no_match_or_empty_list_balances_lock_without_counter(self):
        for empty, data in ((True, instance()), (False, instance(path=2)),
                            (False, instance(devno=8))):
            p = NcmProbe()
            if not empty:
                p.add_device(1, 7)
            p.call(0x4F50, data)
            self.assertFalse(p.removed)
            self.assertEqual(p.uint(BASE + trace.REMOVALS), 0)
            self.assertEqual([e["op"] for e in p.events],
                             ["pthread_mutex_lock", "pthread_mutex_unlock", "intercepted_log"])

    def test_removal_wrong_class_or_subclass_skips_list_lock(self):
        for data in (instance(dclass=10), instance(subclass=12)):
            p = NcmProbe(verbose=True)
            p.add_device(1, 7)
            p.call(0x4F50, data)
            self.assertFalse(p.removed)
            self.assertEqual(p.uint(BASE + trace.REMOVALS), 0)
            self.assertTrue(all(e["op"] == "intercepted_log" for e in p.events))

    def test_replay_rejects_worker_entry_unexpected_import_and_interrupt(self):
        p = NcmProbe()
        with self.assertRaisesRegex(AssertionError, "Entry outside"):
            p.call(0x5384, instance())
        with self.assertRaisesRegex(AssertionError, "instance size"):
            p.call(0x515C, instance()[:-1])
        address = next(a for a, name in p.imports.items() if name == "usbd_attach")
        with self.assertRaisesRegex(RuntimeError, "Unexpected guest import: usbd_attach"):
            p.on_code(p.u, address, 4, None)
        with self.assertRaisesRegex(RuntimeError, "interrupt forbidden"):
            p.on_interrupt(p.u, 2, None)
        with self.assertRaisesRegex(AssertionError, "Execution outside"):
            p.on_code(p.u, BASE + 0x5384, 4, None)

    def test_cyclic_synthetic_list_hits_instruction_budget(self):
        p = NcmProbe()
        p.add_device(2, 8)
        p.write32(p.nodes[0], p.nodes[0])
        with self.assertRaisesRegex(AssertionError, "instruction/time budget"):
            p.call(0x4F50, instance())

    def test_changed_driver_is_rejected_before_emulator_creation(self):
        original = Path.read_bytes
        target = ROOT / trace.PINS["ncm"][0]
        def changed(path):
            data = original(path)
            return data + b"changed" if path == target else data
        with patch.object(Path, "read_bytes", changed), patch("probe_ncm_lifecycle.Uc") as emulator:
            with self.assertRaisesRegex(ValueError, "Not the pinned"):
                NcmProbe()
            emulator.assert_not_called()

    def test_repeatable_replay_without_subprocesses_or_input_changes(self):
        target = ROOT / trace.PINS["ncm"][0]
        before = target.read_bytes()
        with patch.object(subprocess, "run") as run:
            self.assertEqual(scenarios(), scenarios())
            run.assert_not_called()
        self.assertEqual(target.read_bytes(), before)

    def test_pinned_iso_outer_directory_and_client_strings_are_scoped(self):
        result = trace.inspect_iso()
        self.assertEqual(result["outer_listing_entries"], 842)
        self.assertEqual([line.split()[-1] for line in result["network_named_entries"]], [
            "usr/share/MMC_PROG_DATA/wicome/devnp-pan.so", trace.NETWORK_MEMBER])
        self.assertEqual(len(result["nested_archive_entries"]), 7)
        self.assertEqual(result["client_library"]["raw_marker_counts"],
                         dict(AF_INET6=1, inet6=1, IPv6=5))
        self.assertIn("no nested archive", result["limits"][0])

    def test_iso_pin_mismatch_refuses_tar_and_member_pin_mismatch_refuses_result(self):
        with patch.object(trace, "ISO_SHA256", "0" * 64), patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "pinned installation ISO"):
                trace.inspect_iso()
            run.assert_not_called()
        with patch.object(trace, "NETWORK_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "pinned networking client"):
                trace.inspect_iso()


if __name__ == "__main__":
    unittest.main()
