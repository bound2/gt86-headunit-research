"""ZIP coverage and refusal tests; never execute packaged content."""
import io
from pathlib import Path
import stat
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_packaged_runtime as audit


def fixture(entries, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=compression) as archive:
            for name, data in entries:
                archive.writestr(name, data)
    return stream.getvalue()


class PackagedRuntimeTests(unittest.TestCase):
    def test_complete_pinned_iso_audit(self):
        result = audit.inspect()
        archives = list(result["archives"].values())
        self.assertEqual([v["entries"] for v in archives], [3131, 3131, 2117, 69, 69, 56, 140])
        self.assertEqual([v["files"] for v in archives], [3101, 3101, 2076, 60, 60, 39, 114])
        self.assertEqual(sum(v["expanded_bytes"] for v in archives), 69771325)
        self.assertEqual(archives[0]["inventory_sha256"], archives[1]["inventory_sha256"])
        binaries = [b for v in archives for b in v["binary_signature_members"]]
        self.assertEqual(binaries, [dict(member="shaders/building/converter.exe", bytes=892928,
            sha256="14197db035cb96f70be5504f2bea729b0a7ee7e8f2dbe9dadc97ecf92f9b4237",
            elf_magic_offset=-1, pe_machine="0x14c")])
        for item in archives:
            self.assertTrue(item["all_members_crc_checked"])
            for key in ("network_or_sdk_names", "nested_archive_candidates", "runtime_marker_members"):
                self.assertEqual(item[key], [])
        self.assertFalse(result["target_runtime_or_sdk_supplied"])

    def test_renamed_elf_and_runtime_markers_are_detected(self):
        result = audit.inspect_zip(fixture([("picture.dat", b"prefix\x7fELFbytes"),
            ("notes.txt", b"inet6domain\0ip6_input\0"), ("sbin/io-pkt-v6-hc", b"plain")]))
        self.assertEqual(result["binary_signature_members"][0]["elf_magic_offset"], 6)
        self.assertEqual(result["network_or_sdk_names"], ["sbin/io-pkt-v6-hc"])
        self.assertEqual(result["runtime_marker_members"][0]["markers"], ["inet6domain", "ip6_input"])

    def test_nested_archive_is_reported_not_silently_covered(self):
        result = audit.inspect_zip(fixture([("renamed.bin", fixture([("a", b"x")])),
                                            ("empty.zip", b"opaque")]))
        self.assertEqual(result["nested_archive_candidates"], ["renamed.bin", "empty.zip"])
        self.assertEqual(result["files"], 2)

    def test_stored_and_deflated_crc_checked_and_repeatable(self):
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            data = fixture([("assets/", b""), ("assets/a.txt", b"asset" * 100)], method)
            with patch.object(subprocess, "run") as run, patch.object(Path, "open") as opened:
                a = audit.inspect_zip(data)
                self.assertEqual(a, audit.inspect_zip(data))
                run.assert_not_called()
                opened.assert_not_called()
            self.assertEqual((a["files"], a["directories"], a["expanded_bytes"]), (1, 1, 500))

    def test_invalid_member_names_rejected(self):
        for name in ("../a", "/a", "C:/a", "a\\b", "a//b", "./a", "a/../b", "a\nb", ""):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Noncanonical"):
                audit.safe_name(name)

    def test_duplicate_and_symlink_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            audit.inspect_zip(fixture([("a", b"x"), ("a", b"y")]))
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(ValueError, "Nonregular"):
            audit.inspect_zip(fixture([(link, b"target")]))

    def test_encrypted_unsupported_and_corrupt_payload_rejected(self):
        original = fixture([("a", b"payload")])
        encrypted = bytearray(original)
        central = encrypted.index(b"PK\x01\x02")
        struct.pack_into("<H", encrypted, 6, 1)
        struct.pack_into("<H", encrypted, central + 8, 1)
        with self.assertRaisesRegex(ValueError, "Encrypted"):
            audit.inspect_zip(encrypted)
        unsupported = bytearray(original)
        struct.pack_into("<H", unsupported, 8, 99)
        struct.pack_into("<H", unsupported, central + 10, 99)
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            audit.inspect_zip(unsupported)
        corrupted = original.replace(b"payload", b"PAYLOAD", 1)
        with self.assertRaises(zipfile.BadZipFile):
            audit.inspect_zip(corrupted)

    def test_metadata_bounds_before_payload_read(self):
        data = fixture([("a", b"1234"), ("b", b"1234")])
        for bound, value, error in (("MAX_ARCHIVE", 1, "Archive byte"),
                ("MAX_ENTRIES", 1, "entry"), ("MAX_MEMBER", 2, "Member byte"),
                ("MAX_TOTAL", 7, "Total expanded")):
            with patch.object(audit, bound, value), patch.object(zipfile.ZipFile, "open") as opened:
                with self.assertRaisesRegex(ValueError, error):
                    audit.inspect_zip(data)
                opened.assert_not_called()
        with self.assertRaisesRegex(ValueError, "Directory has payload"):
            audit.inspect_zip(fixture([("dir/", b"x")]))

    def test_changed_iso_rejected_before_host_tar(self):
        with patch.object(Path, "open", return_value=io.BytesIO(b"changed")), patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "Not the pinned installation"):
                audit.inspect()
            run.assert_not_called()

    def test_changed_listing_and_member_rejected_before_zip(self):
        def host_result(data):
            return subprocess.CompletedProcess([], 0, stdout=data)
        with patch.object(audit.hashlib, "file_digest") as digest:
            digest.return_value.hexdigest.return_value = audit.ISO_SHA256
            with patch.object(subprocess, "run", return_value=host_result(b"different.zip\n")):
                with self.assertRaisesRegex(ValueError, "Outer archive inventory"):
                    audit.inspect()
            names = list(audit.ARCHIVES) + [f"plain/{i}" for i in range(835)]
            with patch.object(subprocess, "run", side_effect=[host_result("\n".join(names).encode()),
                                                               host_result(b"changed")]), \
                    patch.object(audit, "inspect_zip") as inspect_zip:
                with self.assertRaisesRegex(ValueError, "Not the pinned nested"):
                    audit.inspect()
                inspect_zip.assert_not_called()

    def test_truncated_and_false_pe_header_do_not_claim_pe_machine(self):
        for payload in (b"MZ", b"MZ" + bytes(58) + struct.pack("<I", 0xFFFFFFFF)):
            item = audit.inspect_zip(fixture([("a", payload)]))["binary_signature_members"][0]
            self.assertNotIn("pe_machine", item)


if __name__ == "__main__":
    unittest.main()
