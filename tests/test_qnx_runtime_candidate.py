"""Offline ABI evidence checks; online candidate comparison is an explicit CLI action."""
import hashlib
import io
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_qnx_runtime_candidate as audit


def factory_bytes(key):
    return (ROOT / "extracted/qnx-system-v3" / audit.FACTORY[key][0]).read_bytes()


class RuntimeCandidateTests(unittest.TestCase):
    def test_pinned_factory_profiles_without_network(self):
        with patch.object(audit, "urlopen") as opened:
            result = audit.inspect()
            opened.assert_not_called()
        self.assertFalse(result["abi_compatibility_verified"])
        self.assertFalse(result["native_executable_built"])
        for item in result["factory"].values():
            self.assertEqual(item["machine"], 40)
            self.assertEqual(item["flags"], "0x5000002")
            self.assertFalse(item["ipv6_domain_exported"])
        self.assertEqual(result["factory"]["stack"]["interpreters"], ["/usr/lib/ldqnx.so.2"])
        self.assertIn("TAGID=PSP_networking_br650_be650SP1", result["factory"]["stack"]["metadata"])

    def test_native_driver_imports_include_both_callback_boundaries(self):
        ncm = audit.profile(factory_bytes("ncm"))
        stack = audit.profile(factory_bytes("stack"))
        for name in ("stk_context_callback_2", "stk_context_callback_2_clean"):
            self.assertIn(name, ncm["imports"])
            self.assertIn(name, stack["exports"])
        self.assertEqual(ncm["needed"], ["libusbdi.so.2", "libc.so.3"])
        self.assertEqual(len(ncm["imports"]), 141)

    def test_changed_factory_input_rejected_before_parse_or_network(self):
        original = Path.read_bytes
        target = ROOT / "extracted/qnx-system-v3" / audit.FACTORY["libc"][0]
        def changed(path):
            return original(path) + b"changed" if path == target else original(path)
        with patch.object(Path, "read_bytes", changed), patch.object(audit, "profile") as profile, \
                patch.object(audit, "urlopen") as opened:
            with self.assertRaisesRegex(ValueError, "Not the pinned factory"):
                audit.inspect(True)
            profile.assert_not_called()
            opened.assert_not_called()

    def test_remote_length_sha256_and_git_blob_pins(self):
        data = b"synthetic reference"
        size = len(data)
        blob = hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest()
        digest = hashlib.sha256(data).hexdigest()
        for length, expected_blob, expected_digest in ((size, blob, digest), (size + 1, blob, digest),
                (size, "0" * 40, digest), (size, blob, "0" * 64)):
            with patch.dict(audit.CANDIDATE, x=("test", length, expected_blob, expected_digest)), \
                    patch.object(audit, "urlopen", return_value=io.BytesIO(data)) as opened:
                if (length, expected_blob, expected_digest) == (size, blob, digest):
                    self.assertEqual(audit.fetch("x"), data)
                else:
                    with self.assertRaisesRegex(ValueError, "Not the pinned runtime"):
                        audit.fetch("x")
                opened.assert_called_once_with(audit.URL + "test", timeout=20)

    def test_wrong_architecture_and_header_bounds_rejected(self):
        original = factory_bytes("ncm")
        for offset, fmt, value, message in ((18, "<H", 3, "Expected ARM"),
                (42, "<H", 31, "Program header"), (44, "<H", 33, "Program header"),
                (28, "<I", len(original), "Program header")):
            data = bytearray(original)
            struct.pack_into(fmt, data, offset, value)
            with self.assertRaisesRegex(ValueError, message):
                audit.profile(data)
        with self.assertRaisesRegex(ValueError, "Expected bounded ELF32"):
            audit.profile(b"\x7fELF")

    def test_dynamic_and_load_bounds_rejected(self):
        original = factory_bytes("ncm")
        phoff = struct.unpack_from("<I", original, 28)[0]
        data = bytearray(original)
        struct.pack_into("<I", data, phoff + 16, len(data) + 1)
        with self.assertRaisesRegex(ValueError, "Segment file"):
            audit.profile(data)
        data = bytearray(original)
        count = struct.unpack_from("<H", data, 44)[0]
        for i in range(count):
            start = phoff + i * 32
            if struct.unpack_from("<I", data, start)[0] == 2:
                struct.pack_into("<I", data, start, 0)
        with self.assertRaisesRegex(ValueError, "Expected one aligned dynamic"):
            audit.profile(data)

    def test_comparison_keeps_symbol_name_evidence_separate_from_abi_success(self):
        # The same stack on both sides removes name differences, but must never
        # turn that observation into a compatibility or native-build claim.
        with patch.object(audit, "fetch", side_effect=lambda key: factory_bytes(key)):
            result = audit.inspect(True)
        self.assertEqual(result["ncm_stack_imports_missing_in_candidate"], [])
        self.assertFalse(result["abi_compatibility_verified"])
        self.assertFalse(result["native_executable_built"])

    def test_repeatability_and_unchanged_inputs(self):
        before = {key: factory_bytes(key) for key in audit.FACTORY}
        self.assertEqual(audit.inspect(), audit.inspect())
        self.assertEqual(before, {key: factory_bytes(key) for key in audit.FACTORY})


if __name__ == "__main__":
    unittest.main()
