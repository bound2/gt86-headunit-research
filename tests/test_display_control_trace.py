"""Static evidence/parser checks, not display emulation or on-car validation."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_display_control as display


TINY = """function <C:/synthetic/tiny.lua:1,2> (3 instructions, 12 bytes at 12345678)
0 params, 2 slots, 0 upvalues, 0 locals, 0 constants, 0 functions
  1 [1] CLOSURE 0 0 ; 12345678
  2 [1] LOADK 1 -1 ; "two  spaces"
  3 [2] RETURN 0 1
"""


class DisplayListingParserTests(unittest.TestCase):
    def parse(self, text):
        with patch.dict(display.SECTIONS, {"tiny.lua": {"tiny": (1, 2, 3)}}):
            return display.select_sections(text, "tiny.lua")["tiny"]

    def test_normalizes_host_addresses_but_preserves_literal_spacing(self):
        first = self.parse(TINY)
        second = self.parse(TINY.replace("12345678", "87654321"))
        self.assertEqual(first, second)
        self.assertEqual(first["instructions"][1]["comment"], '"two  spaces"')

    def test_rejects_missing_duplicate_truncated_or_changed_sections(self):
        for text in ("", TINY + TINY, TINY.replace("3 instructions", "4 instructions"),
                     TINY.replace("  3 [2] RETURN 0 1\n", ""),
                     TINY.replace("  2 [1]", "  1 [1]"),
                     TINY.replace("tiny.lua", "unrelated.lua")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.parse(text)


class DisplayControlTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = display.inspect(include_instructions=True)

    def section(self, key):
        return self.evidence["sections"][key]["instructions"]

    def test_wrapper_returns_literal_allowed_without_ownership_result(self):
        for name, method in (("request_wrapper", "requestDisplayCtrl"),
                             ("release_wrapper", "releaseDisplayCtrl")):
            rows = self.section("toyotamanager.lua:" + name)
            self.assertEqual(rows[1]["comment"], '"' + method + '"')
            # CALL C=1 discards results; the following table is a literal reply.
            self.assertEqual((rows[2]["opcode"], rows[2]["operands"]), ("CALL", "1 1 1"))
            self.assertEqual(rows[4]["comment"], '"allowed" true')
            self.assertEqual(rows[5]["opcode"], "RETURN")

    def test_request_release_and_cancellation_instruction_anchors(self):
        request = self.section("modemanager.lua:request_control")
        self.assertEqual(request[3]["comment"], "- 0")
        self.assertEqual(request[6]["comment"], "displayRequest")
        self.assertEqual(request[8]["comment"], '"requestDisplay"')
        self.assertEqual([request[i]["comment"] for i in (9, 10)], ["1", "1"])
        release = self.section("modemanager.lua:release_control")
        self.assertEqual(release[6]["comment"], '- "DA"')
        self.assertEqual([release[i]["comment"] for i in (12, 13)], ["0", "1"])
        self.assertEqual(release[20]["comment"], "cancelDisplayRequest")

    def test_bus_callback_and_local_restore_both_emit_display_state(self):
        callback = self.section("modemanager.lua:display_callback")
        self.assertEqual(callback[10]["comment"], '"confirmDisplay"')
        self.assertEqual(callback[16]["comment"], '"state" -')
        self.assertEqual(callback[18]["comment"], '"displayState"')
        restore = self.section("modemanager.lua:local_restore")
        self.assertEqual(restore[10]["comment"], '"state" 1')
        self.assertEqual(restore[14]["comment"], '"displayState"')
        # Both paths pass the same property table; this is not bus provenance.
        self.assertEqual(callback[20]["comment"], restore[16]["comment"])

    def test_avclan_simulator_branch_and_real_device_path_are_distinct(self):
        request = self.section("avclan.lua:bus_request")
        self.assertEqual(request[7]["comment"], "REQUEST_DISPLAY")
        self.assertEqual(request[12]["comment"], '"simulator"')
        self.assertEqual(request[16]["comment"], '"requestDisplay"')
        confirmation = self.section("avclan.lua:bus_confirmation")
        self.assertEqual(confirmation[1]["comment"], "CONFIRM_DISPLAY")
        callback = self.section("avclan.lua:bus_callback")
        self.assertEqual(callback[1]["comment"], "lastDisplayState")
        self.assertEqual(callback[3]["comment"], "lastModeflag")
        self.assertEqual(callback[5]["comment"], '"requestDisplay"')
        device = self.section("avclan.lua:device_start")
        self.assertEqual(device[3]["comment"], '"/dev/avclan/tm"')
        self.assertEqual(device[4]["comment"], '"rw"')

    def test_selected_listings_are_complete_and_repeatable(self):
        second = display.inspect()
        self.assertEqual(len(second["sections"]), 18)
        for key, section in second["sections"].items():
            self.assertNotIn("instructions", section)
            first = self.evidence["sections"][key]
            self.assertEqual(first["listing_sha256"], section["listing_sha256"])
            self.assertEqual(len(first["instructions"]), section["instruction_count"])
        defaults = self.section("properties.lua:defaults")
        self.assertEqual(defaults[54]["comment"], '"state" 0')
        self.assertEqual(defaults[55]["comment"], "displayState")

    def test_changed_input_is_rejected_before_compiler_launch(self):
        original_read = Path.read_bytes
        for name in display.PINS:
            def changed(path):
                data = original_read(path)
                return data + b"changed" if path.name == name else data
            with self.subTest(name=name), patch.object(Path, "read_bytes", changed), \
                    patch.object(display.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "Not the pinned"):
                    display.inspect()
                run.assert_not_called()

    def test_input_change_during_listing_is_rejected(self):
        original_read = Path.read_bytes
        calls = {}
        def changed(path):
            calls[path] = calls.get(path, 0) + 1
            data = original_read(path)
            return data + b"changed" if calls[path] > 1 else data
        with patch.object(Path, "read_bytes", changed), \
                patch.object(display.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "changed during"):
                display.inspect()
            self.assertEqual(run.call_count, 1)

    def test_only_parse_only_host_commands_are_launched_and_inputs_unchanged(self):
        before = display.read_inputs()
        real_run = subprocess.run
        with patch.object(display.subprocess, "run", wraps=real_run) as run:
            display.inspect()
        self.assertEqual(before, display.read_inputs())
        self.assertEqual(run.call_count, len(display.PINS))
        for call, name in zip(run.call_args_list, display.PINS):
            self.assertEqual(call.args[0], [str(display.LUAC), "-l", "-p",
                                           str(ROOT / display.DIRECTORY / name)])
            self.assertEqual(call.kwargs, dict(capture_output=True, timeout=20, check=True))

    def test_compiler_failure_and_timeout_are_not_reported_as_success(self):
        for error in (subprocess.CalledProcessError(1, "luac"),
                      subprocess.TimeoutExpired("luac", 20)):
            with patch.object(display.subprocess, "run", side_effect=error), \
                    self.assertRaises(type(error)):
                display.inspect()

    def test_hmi_current_screen_controls_named_windows_not_frame_buffers(self):
        rows = self.section("hmiClient.lua:current_screen")
        self.assertEqual(rows[22]["comment"], '- "com.harman.screen.apps.extApps.AppTemplate"')
        self.assertEqual(rows[52]["comment"], '- "com.harman.screen.apps.mirrorlinkApps.MirrorLinkApps"')
        commands = [row["comment"] for row in rows
                    if row["opcode"] == "LOADK" and "DisplayManager:0" in row.get("comment", "")]
        self.assertEqual(len(commands), 7)
        for index, row in enumerate(rows):
            if row["opcode"] == "LOADK" and "DisplayManager:0" in row.get("comment", ""):
                following = rows[index + 1]
                self.assertEqual((following["opcode"], following["operands"]), ("CALL", "2 2 1"))
        self.assertEqual([rows[i]["comment"] for i in (36, 50, 66, 76)],
                         ["AMS_visible", "AMS_visible", "ML_visible", "ML_visible"])
        for token in ("FlashWindow:AMS,v,1;", ":map,v,0;", "mlc,o,1;", "mlc,v,1;", "mlc,v,0;"):
            self.assertTrue(any(token in command for command in commands))
        available = self.section("hmiClient.lua:service_available")
        self.assertEqual(available[17]["comment"], '"currentScreen"')
        self.assertEqual(available[18]["comment"], "hmiCurrentScreenHandler")
        self.assertIn("flashHMILoaded", available[2]["comment"])
        ready = self.section("hmiClient.lua:first_map_ready")
        self.assertIn("/tmp/firstMapReady", ready[2]["comment"])


if __name__ == "__main__":
    unittest.main()
