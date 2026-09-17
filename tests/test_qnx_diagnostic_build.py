"""Build refusal and selected ELF gates, NOT a successful native build test."""
import copy
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_qnx_network_diagnostic as build
from inspect_qnx_runtime_candidate import FACTORY


def selected_fixture():
    # Deliberately not an executable: profile is mocked in tests of the gates.
    # Real ELF parsing has separate tests; this fixture must never be built/run.
    data = bytearray(84)
    struct.pack_into("<II", data, 24, 0x1010, 52)
    struct.pack_into("<H", data, 44, 1)
    struct.pack_into("<8I", data, 52, 1, 0, 0x1000, 0, 84, 84, 5, 4096)
    info = dict(elf_type=2, flags="0x5000002", interpreters=["/usr/lib/ldqnx.so.2"],
                needed=["libsocket.so.3", "libc.so.3"], imports=sorted(build.REQUIRED),
                weak_imports=["optional"], sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    return data, info


class DiagnosticBuildTests(unittest.TestCase):
    def test_missing_sdk_fails_before_compiler_or_directory_creation(self):
        with patch.object(build.subprocess, "run") as run, patch.object(build.tempfile, "mkdtemp") as mkdir:
            with self.assertRaisesRegex(ValueError, "Supply --qnx-host"):
                build.build(None, None)
            run.assert_not_called()
            mkdir.assert_not_called()

    def test_incomplete_sdk_refused_without_running_compiler(self):
        with patch.object(Path, "is_file", return_value=False), patch.object(Path, "is_dir", return_value=False), \
                patch.object(build.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "Missing QNX ARMv7 development inputs"):
                build.build(ROOT / "missing-sdk/host", ROOT / "missing-sdk/target", True)
            run.assert_not_called()

    def test_check_only_never_compiles_or_marks_native_build(self):
        inputs = dict(hashes={}, sdk_compatibility_verified=False)
        with patch.object(build, "sdk_inputs", return_value=inputs), patch.object(build, "factory_exports", return_value=set()), \
                patch.object(build.subprocess, "run") as run, patch.object(build.tempfile, "mkdtemp") as mkdir:
            result = build.build("host", "target", True)
            self.assertFalse(result["native_executable_built"])
            run.assert_not_called()
            mkdir.assert_not_called()

    def test_factory_exports_cover_selected_source_api(self):
        exports = build.factory_exports()
        self.assertTrue(build.REQUIRED <= exports)
        self.assertTrue({"printf", "puts", "fflush", "ferror", "strcmp", "getenv", "__get_errno_ptr"} <= exports)
        self.assertTrue({"_init_libc", "_preinit_array", "_init_array", "_fini_array", "atexit", "exit"} <= exports)

    def test_changed_factory_library_rejected(self):
        original = Path.read_bytes
        target = ROOT / "extracted/qnx-system-v3" / FACTORY["libc"][0]
        def changed(path):
            return b"changed" if path == target else original(path)
        with patch.object(Path, "read_bytes", changed), patch.object(build, "profile") as profile:
            with self.assertRaisesRegex(ValueError, "Not the pinned factory library"):
                build.factory_exports()
            profile.assert_not_called()

    def test_selected_checks_do_not_claim_target_execution(self):
        data, info = selected_fixture()
        with patch.object(build, "profile", return_value=info):
            result = build.verify_executable(data, build.REQUIRED)
        self.assertTrue(result["selected_elf_checks_passed"])
        self.assertFalse(result["target_execution_verified"])
        self.assertFalse(result["installed_version_compatibility_verified"])

    def test_wrong_executable_family_and_dependencies_rejected(self):
        data, original = selected_fixture()
        for field, value, message in (("elf_type", 3, "executable form"),
                ("flags", "0x5000402", "executable form"), ("flags", "0x4000002", "executable form"),
                ("interpreters", ["/lib/ld-linux.so.3"], "executable form"),
                ("needed", ["libc.so.3", "libsocket.so.3", "libstdc++.so.6"], "dependencies")):
            info = copy.deepcopy(original); info[field] = value
            with self.subTest(field=field, value=value), patch.object(build, "profile", return_value=info):
                with self.assertRaisesRegex(ValueError, message):
                    build.verify_executable(data, build.REQUIRED)

    def test_missing_mutating_and_unresolved_imports_rejected(self):
        data, original = selected_fixture()
        for imports, exports, message in (([], build.REQUIRED, "query imports"),
                (sorted(build.REQUIRED | {"bind"}), build.REQUIRED | {"bind"}, "mutating/device"),
                (sorted(build.REQUIRED | {"usbd_attach"}), build.REQUIRED | {"usbd_attach"}, "mutating/device"),
                (sorted(build.REQUIRED | {"unknown"}), build.REQUIRED, "Imports absent")):
            info = copy.deepcopy(original); info["imports"] = imports
            with patch.object(build, "profile", return_value=info), self.assertRaisesRegex(ValueError, message):
                build.verify_executable(data, exports)
        info = copy.deepcopy(original); info["weak_imports"] = ["bind"]
        with patch.object(build, "profile", return_value=info), self.assertRaisesRegex(ValueError, "mutating/device"):
            build.verify_executable(data, build.REQUIRED)

    def test_invalid_entry_refused(self):
        original, info = selected_fixture()
        for entry, flags in ((0, 5), (0x2000, 5), (0x1010, 4)):
            data = bytearray(original)
            struct.pack_into("<I", data, 24, entry)
            struct.pack_into("<I", data, 76, flags)
            with patch.object(build, "profile", return_value=info), self.assertRaisesRegex(ValueError, "Entry point"):
                build.verify_executable(data, build.REQUIRED)


if __name__ == "__main__":
    unittest.main()
