"""Behavioral integration tests over actual engines and Streamlit reruns."""
import json
import unittest
import tempfile
from unittest.mock import patch
from pathlib import Path

from streamlit.testing.v1 import AppTest
from src.common.models import ContractError, SelectionStrategy
from src.readiness.assessment import assess_readiness_details, simulate_readiness_improvement
from src.ui.live import monitor_snapshot
from src.ui.service import (SCENARIOS, build_workspace, case_outputs, load_research_records,
                            preserve_selected)

APP = Path(__file__).resolve().parents[2] / "app.py"


class DashboardServiceTests(unittest.TestCase):
    def test_all_scenarios_match_actual_assessment(self):
        for scenario in SCENARIOS:
            ws = build_workspace(scenario)
            expected = assess_readiness_details(ws["profile"], ws["statuses"])
            self.assertEqual(ws["details"], expected)
            self.assertAlmostEqual(ws["readiness"].score * 100, expected["readiness_percentage"])
            self.assertTrue(all(event.scenario_id == scenario for event in ws["events"]))

    def test_unavailable_and_zero_budget(self):
        ws = build_workspace("suspicious_authentication")
        ids = tuple(item.evidence_id for item in ws["candidates"])
        filtered = build_workspace("suspicious_authentication", unavailable_ids=ids)
        self.assertTrue(all(not result.selected_evidence_ids for result in filtered["comparisons"]))
        self.assertEqual(filtered["details"]["readiness_percentage"], 0)
        self.assertIn("authentication_log", filtered["details"]["missing_evidence"])
        zero = build_workspace("suspicious_authentication", budget=0)
        self.assertTrue(all(result.selected_cost == 0 for result in zero["comparisons"]))
        with self.assertRaises(ContractError):
            build_workspace("suspicious_authentication", unavailable_ids=("unknown",))

    def test_preserve_verify_export_report(self):
        ws = build_workspace("suspicious_file_modification")
        preserved = preserve_selected(ws, SelectionStrategy.ADAPTIVE)
        try:
            summary = preserved.verify()
            self.assertEqual(summary["valid"], len(preserved.manifests))
            self.assertTrue(preserved.archive().startswith(b"PK"))
            record, markdown = case_outputs(ws, preserved, summary)
            self.assertEqual(record["evidence_verification_status"], summary)
            self.assertIn("Evidence verification status", markdown)
            artifact = Path(preserved.manifests[0].source_path)
            artifact.write_bytes(b"changed")
            self.assertEqual(preserved.verify()["modified"], 1)
        finally:
            preserved.close()

    def test_research_rejects_invalid_and_preserves_null(self):
        self.assertEqual(load_research_records(b""), [])
        with self.assertRaises(ContractError):
            load_research_records(b'{"fake_metrics":100}')
        raw = {"run_id": "saved-1", "strategy": "adaptive", "scenario_id": "potential_exfiltration",
               "selected_evidence_ids": [], "evidence_recall": None, "evidence_precision": None,
               "collection_cost": 0, "budget_utilization": 0}
        self.assertIsNone(load_research_records(json.dumps(raw).encode())[0]["evidence_recall"])


class DashboardInteractionTests(unittest.TestCase):
    """Exercise the six operational pages with actual parsed Ubuntu log fixtures."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ubuntu-auth.log"

    def write_failures(self, count=3):
        self.path.write_text("".join(
            f"2026-10-25T10:00:{i:02d}+00:00 ubuntu sshd[101]: "
            f"Failed password for invalid user lab from 127.0.0.1 port 55000 ssh2\n"
            for i in range(count)
        ), encoding="utf-8")

    def app(self):
        with patch("src.ui.application.monitor_snapshot", side_effect=lambda: monitor_snapshot(self.path)):
            return AppTest.from_file(str(APP), default_timeout=30).run()

    def navigate(self, app, page):
        with patch("src.ui.application.monitor_snapshot", side_effect=lambda: monitor_snapshot(self.path)):
            return app.radio(key="navigation").set_value(page).run()

    def assert_clean(self, app):
        self.assertFalse(list(app.exception), str(list(app.exception)))
        self.assertFalse(list(app.error), str(list(app.error)))

    def test_waiting_state_has_no_fabricated_score(self):
        app = self.app()
        self.assert_clean(app)
        self.assertEqual(app.radio(key="navigation").value, "Command Center")
        self.assertTrue(any("No Ubuntu SSH failure records" in item.message for item in app.info))

    def test_six_operational_pages_render_from_real_log_fixture(self):
        self.write_failures()
        app = self.app()
        self.assert_clean(app)
        pages = ["Command Center", "Forensic Readiness", "Threat Detection",
                 "Evidence Prioritization", "Incident Investigation", "Evidence Vault"]
        self.assertEqual(list(app.radio(key="navigation").options), pages)
        for page in pages:
            app = self.navigate(app, page)
            self.assert_clean(app)

    def test_evidence_budget_and_exclusions(self):
        self.write_failures()
        app = self.navigate(self.app(), "Evidence Prioritization")
        self.assert_clean(app)
        with patch("src.ui.application.monitor_snapshot", side_effect=lambda: monitor_snapshot(self.path)):
            app.number_input(key="_budget").set_value(0).run()
        self.assert_clean(app)
        self.assertEqual(app.number_input(key="_budget").value, 0)
        app = self.navigate(app, "Evidence Vault")
        self.assert_clean(app)

    def test_no_synthetic_controls_in_sidebar(self):
        self.write_failures()
        app = self.app()
        self.assert_clean(app)
        self.assertFalse(any(item.key == "seed" for item in app.number_input))
        self.assertFalse(any(item.key == "scenario" for item in app.selectbox))

    def test_unknown_page_falls_back_to_command_center(self):
        with patch("src.ui.application.monitor_snapshot", side_effect=lambda: monitor_snapshot(self.path)):
            app = AppTest.from_file(str(APP), default_timeout=30)
            app.query_params["page"] = "nonexistent"
            app.run()
        self.assert_clean(app)
        self.assertEqual(app.radio(key="navigation").value, "Command Center")


if __name__ == "__main__":
    unittest.main()
