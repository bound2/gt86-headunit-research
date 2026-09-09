# SPDX-License-Identifier: GPL-3.0-only
"""Independent standard-library checks of synthetic plist fixture semantics."""
import pathlib
import plistlib
import unittest

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "lockdown"


class LockdownFixtures(unittest.TestCase):
    def read(self, name):
        raw = (FIXTURES / name).read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"\n"))
        return plistlib.loads(raw)

    def test_get_value(self):
        self.assertEqual(self.read("get-product-type.xml"), {
            "Label": "gt86-research", "Request": "GetValue", "Key": "ProductType"})

    def test_synthetic_response(self):
        self.assertEqual(self.read("product-type.xml"), {
            "Request": "GetValue", "Value": "iPhone17,1"})

    def test_error_is_not_a_value(self):
        self.assertEqual(self.read("error.xml"), {
            "Request": "GetValue", "Error": "InvalidHostID"})

    def test_all_xml_entities(self):
        self.assertEqual(self.read("escaped.xml"), {
            "Label": "&<>\"'", "Request": "GetValue", "Key": "K&<>\"'",
            "Domain": "D&<>\"'"})


if __name__ == "__main__":
    unittest.main()
