# SPDX-License-Identifier: GPL-3.0-only
"""Reference audit contract tests, not a phone or native helper test."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inspect_iap_routes as ref


class IapRoutesTests(unittest.TestCase):
    def test_every_source_is_pinned_and_reviewed(self):
        self.assertEqual(set(ref.PINS), set(ref.MARKERS))
        self.assertEqual(len(ref.PINS), 8)
        for path, sha in ref.PINS.values():
            self.assertNotIn("..", path.split("/"))
            self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_missing_marker_rejected(self):
        with patch.object(ref, "read_blob", return_value="unrelated"):
            with self.assertRaisesRegex(ValueError, "marker missing"):
                ref.inspect(Path("unused"))

    def test_pin_failure_propagates(self):
        with patch.object(ref, "read_blob", side_effect=ValueError("Pinned Git blob mismatch")) as read:
            with self.assertRaisesRegex(ValueError, "blob mismatch"):
                ref.inspect(Path("unused"))
            self.assertEqual(read.call_count, 1)

    def test_complete_review_keeps_hardware_claim_false(self):
        by_path = {path: "\n".join(ref.MARKERS[name]) for name, (path, _) in ref.PINS.items()}
        with patch.object(ref, "read_blob", side_effect=lambda root, commit, path, sha: by_path[path]) as read:
            result = ref.inspect(Path("unused"))
        self.assertEqual(read.call_count, 8)
        self.assertFalse(result["factory_or_phone_acceptance_verified"])
        self.assertEqual(result["both_reference_profiles"]["control_version"], 2)
        self.assertTrue(result["both_reference_profiles"]["zero_ack"])


if __name__ == "__main__":
    unittest.main()
