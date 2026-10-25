"""Behavioral integration tests over actual engines and Streamlit reruns."""
import json
import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest
from src.common.models import ContractError, SelectionStrategy
from src.readiness.assessment import assess_readiness_details, simulate_readiness_improvement
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

    def test_research_rejects_unknown_fields(self):
        raw = {"run_id": "saved-1", "strategy": "adaptive",
               "scenario_id": "potential_exfiltration",
               "selected_evidence_ids": [], "evidence_recall": None,
               "evidence_precision": None, "collection_cost": 0,
               "budget_utilization": 0, "invented_metric": 999}
        with self.assertRaises(ContractError):
            load_research_records(json.dumps(raw).encode())

    def test_research_rejects_non_object(self):
        with self.assertRaises(ContractError):
            load_research_records(b"[1,2,3]")

    def test_research_rejects_invalid_and_preserves_null(self):
        self.assertEqual(load_research_records(b""), [])
        with self.assertRaises(ContractError):
            load_research_records(b'{"fake_metrics":100}')
        raw = {"run_id": "saved-1", "strategy": "adaptive", "scenario_id": "potential_exfiltration",
               "selected_evidence_ids": [], "evidence_recall": None, "evidence_precision": None,
               "collection_cost": 0, "budget_utilization": 0}
        self.assertIsNone(load_research_records(json.dumps(raw).encode())[0]["evidence_recall"])


class DashboardInteractionTests(unittest.TestCase):
    def app(self):
        return AppTest.from_file(str(APP), default_timeout=30).run()

    def assert_clean(self, app):
        self.assertFalse(list(app.exception), str(list(app.exception)))
        self.assertFalse(list(app.error), str(list(app.error)))

    def test_every_page_renders(self):
        app = self.app()
        self.assert_clean(app)
        for page in ["Forensic Readiness", "Threat Detection", "Evidence Prioritization",
                     "Incident Investigation", "Evidence Vault", "Research Evaluation",
                     "Launch Status", "Privacy Policy", "Terms and Conditions"]:
            app.radio(key="navigation").set_value(page).run()
            self.assertFalse(list(app.exception), page)
            if page != "Launch Status":
                self.assert_clean(app)

    def test_scenario_switching_and_simulation(self):
        app = self.app()
        app.radio(key="navigation").set_value("Forensic Readiness").run()
        app.selectbox(key="scenario").set_value("potential_exfiltration").run()
        self.assert_clean(app)
        self.assertEqual(app.selectbox(key="inspect_potential_exfiltration").value, "network_flow")
        app.selectbox(key="sim_source_potential_exfiltration").set_value("dns_log").run()
        app.selectbox(key="sim_status_potential_exfiltration_dns_log").set_value("validated").run()
        self.assert_clean(app)
        ws = build_workspace("potential_exfiltration")
        simulation = simulate_readiness_improvement(ws["profile"], ws["statuses"], {"dns_log": "validated"})
        self.assertGreater(simulation["percentage_point_difference"], 0)
        self.assertNotIn("dns_log", ws["statuses"])

    def test_budget_and_exclusions_survive_navigation(self):
        app = self.app()
        app.radio(key="navigation").set_value("Evidence Prioritization").run()
        app.number_input(key="_budget").set_value(0).run()
        artifact = build_workspace("suspicious_authentication")["candidates"][0].evidence_id
        app.multiselect(key="_unavailable").set_value([artifact]).run()
        app.radio(key="navigation").set_value("Evidence Vault").run()
        self.assert_clean(app)
        self.assertTrue(app.button[0].disabled)
        app.radio(key="navigation").set_value("Evidence Prioritization").run()
        self.assertEqual(app.number_input(key="_budget").value, 0)
        self.assertEqual(app.multiselect(key="_unavailable").value, [artifact])

    def test_vault_and_investigation_controls(self):
        app = self.app()
        app.radio(key="navigation").set_value("Evidence Vault").run()
        app.button[0].click().run()
        self.assert_clean(app)
        app.button[1].click().run()
        self.assert_clean(app)
        self.assertGreater(app.session_state["verification"]["valid"], 0)
        app.radio(key="navigation").set_value("Incident Investigation").run()
        self.assert_clean(app)
        app.selectbox(key="scenario").set_value("potential_exfiltration").run()
        self.assertNotIn("preserved", app.session_state)

    def test_legal_deep_link(self):
        app = AppTest.from_file(str(APP), default_timeout=30)
        app.query_params["page"] = "Privacy Policy"
        app.run()
        self.assert_clean(app)
        self.assertEqual(app.radio(key="navigation").value, "Privacy Policy")

    def test_filters_and_each_strategy(self):
        app = self.app()
        app.radio(key="navigation").set_value("Threat Detection").run()
        app.multiselect[0].set_value([]).run()
        self.assert_clean(app)
        self.assertTrue(any("No records" in item.value for item in app.info))
        app.radio(key="navigation").set_value("Evidence Prioritization").run()
        for strategy in SelectionStrategy:
            app.selectbox(key="strategy").set_value(strategy.value).run()
            self.assert_clean(app)
        app.selectbox(key="scenario").set_value("suspicious_file_modification").run()
        self.assert_clean(app)
        app.number_input(key="seed").set_value(41).run()
        app.select_slider(key="count").set_value(6).run()
        self.assert_clean(app)

    def test_unknown_page_falls_back_to_overview(self):
        app = AppTest.from_file(str(APP), default_timeout=30)
        app.query_params["page"] = "nonexistent"
        app.run()
        self.assert_clean(app)
        self.assertEqual(app.radio(key="navigation").value, "Command Center")


if __name__ == "__main__":
    unittest.main()
