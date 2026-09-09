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

    def test_binary_vectors(self):
        expected = {
            "product": {"Request": "GetValue", "Value": "iPhone17,1"},
            "error": {"Request": "GetValue", "Error": -7,
                      "ErrorString": "InvalidHostID", "ErrorDescription": "synthetic refusal"},
            "session": {"Request": "StartSession", "SessionID": "synthetic-session",
                        "EnableSessionSSL": True},
            "service_tls": {"Request": "StartService", "Port": 62079, "EnableServiceSSL": True},
            "service_plain": {"Request": "StartService", "Port": 1},
            "pair": {"Request": "Pair", "EscrowBag": bytes([0, 255, 1, 2])},
            "mixed": {"Request": "GetValue", "Value": [
                "same", "same", 0, -1, -(1 << 63), 1 << 63, (1 << 64) - 1,
                True, False, bytes([0, 255]), "\u00c4\U0001f600", {"nested": []}]},
        }
        found = {}
        for line in (FIXTURES / "plist-binary-vectors.txt").read_text(encoding="ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            name, value = line.split()
            self.assertNotIn(name, found)
            raw = bytes.fromhex(value)
            found[name] = plistlib.loads(raw)
            self.assertEqual(raw, plistlib.dumps(expected[name], fmt=plistlib.FMT_BINARY, sort_keys=False))
        self.assertEqual(found, expected)


if __name__ == "__main__":
    unittest.main()
