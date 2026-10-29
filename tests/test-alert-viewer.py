#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("evw_alert_viewer", ROOT / "evw-alert-viewer.py")
VIEWER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VIEWER)


class AlertDetailsTests(unittest.TestCase):
    def test_unlocked_details_include_metadata_body_and_raw_json(self):
        record = {
            "id": "stored-id",
            "real_id": "alert-123",
            "ts": 1793280000,
            "severity": "WARNING",
            "source": "test",
            "title": "summary",
            "body": "full body",
            "raw": '{"id":"alert-123"}\n',
        }
        text = VIEWER.alert_details_text(record)
        self.assertIn("WARNING", text)
        self.assertIn("source=test", text)
        self.assertIn("id=alert-123", text)
        self.assertIn("full body", text)
        self.assertIn("full alert file", text)
        self.assertIn('{"id":"alert-123"}', text)

    def test_locked_details_explain_sudo_without_body(self):
        record = {
            "id": "locked:secret.json",
            "ts": 1793280000,
            "severity": "LOCKED",
            "title": "locked",
            "body": "must not leak",
            "source": "root-owned alert file",
            "path": "/var/db/evw-security-system/alerts/secret.json",
            "locked": True,
        }
        text = VIEWER.alert_details_text(record)
        self.assertIn("LOCKED", text)
        self.assertIn(record["path"], text)
        self.assertIn("sudo", text)
        self.assertNotIn("must not leak", text)

    def test_double_click_opens_detail_popup(self):
        source = (ROOT / "evw-alert-viewer.py").read_text()
        self.assertIn('tree.bind("<Double-Button-1>", row_double_clicked)', source)
        self.assertIn("def detail_popup", source)
        self.assertIn("alert_details_text(r)", source)


if __name__ == "__main__":
    unittest.main()
