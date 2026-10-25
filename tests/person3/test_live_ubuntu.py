"""Smoke tests for bounded read-only Ubuntu log ingestion."""
import tempfile
import unittest
from pathlib import Path
from src.ui.live import read_auth_events, monitor_snapshot


class UbuntuLiveTests(unittest.TestCase):
    def test_three_failed_ssh_logins_trigger_existing_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("".join(
                f"2026-10-25T10:00:0{i}+00:00 ubuntu sshd[101]: "
                f"Failed password for invalid user test from 127.0.0.1 port 55000 ssh2\n"
                for i in range(3)
            ), encoding="utf-8")
            result = monitor_snapshot(path)
            self.assertEqual(len(result["events"]), 3)
            self.assertGreaterEqual(len(result["alerts"]), 1)
            self.assertEqual(result["events"][0].source_type, "authentication_log")

    def test_missing_file_is_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            result = monitor_snapshot(Path(directory) / "missing.log")
            self.assertEqual(result["events"], [])
            self.assertEqual(result["alerts"], [])
            self.assertFalse(result["path_exists"])


if __name__ == "__main__":
    unittest.main()
