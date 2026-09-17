"""Checks reference-reader pin/bound/network restrictions, not phone timing."""
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inspect_video_clock_reference as ref


class VideoClockReferenceTests(unittest.TestCase):
    def test_blob_identity(self):
        data = b"reviewed source\n"
        sha = hashlib.sha1(b"blob 16\0" + data).hexdigest()
        self.assertEqual(ref.verify_blob(data, sha), data.decode())
        with self.assertRaises(ValueError):
            ref.verify_blob(data + b"\n", sha)

    def test_bounds_before_decode(self):
        for data in (b"", b"x" * (ref.LIMIT + 1)):
            with self.assertRaises(ValueError):
                ref.verify_blob(data, "0" * 40)

    def test_object_size_before_read(self):
        with patch.object(ref, "git", return_value=str(ref.LIMIT + 1).encode()) as run:
            with self.assertRaises(ValueError):
                ref.read_blob(Path("unused"), ref.LIVI, "path", "0" * 40)
            self.assertEqual(run.call_count, 1)

    def test_network_disabled_and_no_shell(self):
        with patch.object(ref.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"ok")) as run:
            self.assertEqual(ref.git(Path("space in path"), "cat-file", "-s", "pinned:path"), b"ok")
            args, kw = run.call_args
            self.assertIn("protocol.allow=never", args[0])
            self.assertIn("space in path", args[0])
            self.assertEqual(kw["env"]["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(kw["env"]["GIT_OPTIONAL_LOCKS"], "0")
            self.assertLessEqual(kw["timeout"], 30)
            self.assertNotIn("shell", kw)

    def test_review_markers_not_silently_skipped(self):
        with patch.object(ref, "read_blob", return_value="unrelated"):
            with self.assertRaisesRegex(ValueError, "marker missing"):
                ref.inspect(Path("unused"), Path("unused"))


if __name__ == "__main__":
    unittest.main()
