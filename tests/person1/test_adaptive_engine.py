import json
import random
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

from src.common.models import (
    AvailabilityStatus, ContractError, DetectionAlert, EvidenceAvailability,
    EvidenceCandidate, SelectionStrategy, Severity,
)
from src.readiness.assessment import assess_readiness, assess_readiness_details
from src.readiness.comparison import compare_selection_strategies
from src.readiness.demo import build_demo_summary
from src.readiness.metrics import selection_metrics
from src.readiness.selectors import rank_candidates, select_available_evidence, select_evidence
from src.threat_intel.catalog import get_technique, load_attack_catalog
from src.threat_intel.mapping import explain_attack_mappings, map_events_to_attack
from src.threat_intel.profiles import get_threat_profile, load_threat_profiles


STAMP = "2026-01-01T00:00:00Z"


class Person1Tests(unittest.TestCase):
    def setUp(self):
        self.profiles = load_threat_profiles()
        self.candidates = [
            EvidenceCandidate("E-AUTH", "authentication_log", 1),
            EvidenceCandidate("E-FILE", "file_access", 1),
            EvidenceCandidate("E-NET", "network_flow", 1),
            EvidenceCandidate("E-PROC", "process_creation", 1),
            EvidenceCandidate("E-PS", "powershell_log", 1),
        ]

    def alert(self, scenario, reason, alert_id="A1"):
        return DetectionAlert(alert_id, ("EV1",), STAMP, Severity.HIGH, scenario, reason)

    def test_01_verified_catalog_loading(self):
        catalog = load_attack_catalog()
        self.assertEqual(set(catalog), {"T1110", "T1110.001", "T1059.001", "T1003.001", "T1041"})
        self.assertEqual(catalog["T1041"].attack_dataset_version, "20.0")
        self.assertTrue(all(item.official_url.startswith("https://attack.mitre.org/") for item in catalog.values()))

    def test_02_correct_behavioral_mapping(self):
        alert = self.alert("suspicious_authentication", "Repeated login failures indicate password guessing")
        mappings = map_events_to_attack([alert], self.profiles["suspicious_authentication"])
        self.assertEqual({item.technique_id for item in mappings}, {"T1110", "T1110.001"})
        self.assertIn("supporting_event_ids=EV1", mappings[0].rationale)

    def test_03_unrelated_event_not_mapped(self):
        alert = self.alert("potential_exfiltration", "Generic outbound network traffic observed")
        self.assertEqual(map_events_to_attack([alert], self.profiles["potential_exfiltration"]), [])

    def test_04_unknown_technique_handling(self):
        with self.assertRaises(ContractError):
            get_technique("T9999")

    def test_05_valid_threat_profiles(self):
        self.assertEqual(set(self.profiles), {"suspicious_authentication", "suspicious_file_modification", "potential_exfiltration"})
        self.assertEqual(self.profiles["suspicious_authentication"].schema_version, "1.0")

    def test_06_scenario_specific_requirements(self):
        self.assertEqual(max(self.profiles["suspicious_authentication"].evidence_weights, key=self.profiles["suspicious_authentication"].evidence_weights.get), "authentication_log")
        self.assertEqual(max(self.profiles["suspicious_file_modification"].evidence_weights, key=self.profiles["suspicious_file_modification"].evidence_weights.get), "file_access")
        self.assertEqual(max(self.profiles["potential_exfiltration"].evidence_weights, key=self.profiles["potential_exfiltration"].evidence_weights.get), "network_flow")

    def test_07_weighted_readiness_calculation(self):
        profile = self.profiles["suspicious_authentication"]
        details = assess_readiness_details(profile, {"authentication_log": "validated", "process_creation": "collected", "network_flow": "missing", "powershell_log": "unknown"})
        self.assertAlmostEqual(details["score_fraction"], (0.9 + 0.4 * 0.85) / 1.9)

    def test_08_missing_and_unknown_evidence(self):
        details = assess_readiness_details(self.profiles["suspicious_authentication"], {"authentication_log": "missing"})
        self.assertIn("authentication_log", details["missing_evidence"])
        self.assertIn("network_flow", details["unknown_evidence"])

    def test_09_scenario_switching_changes_priority(self):
        expected = {
            "suspicious_authentication": "E-AUTH",
            "suspicious_file_modification": "E-FILE",
            "potential_exfiltration": "E-NET",
        }
        for scenario, first in expected.items():
            ranking = rank_candidates(SelectionStrategy.ADAPTIVE, self.candidates, self.profiles[scenario], set(), None)
            self.assertEqual(ranking[0], first)

    def test_10_budget_enforcement(self):
        result = select_evidence(SelectionStrategy.ADAPTIVE, self.candidates, self.profiles["potential_exfiltration"], set(), None, 3)
        self.assertLessEqual(result.selected_cost, 3)

    def test_11_unavailable_evidence_exclusion(self):
        result = select_available_evidence(SelectionStrategy.ADAPTIVE, self.candidates, self.profiles["potential_exfiltration"], set(), None, 3, {item.evidence_id: item.evidence_id != "E-NET" for item in self.candidates})
        self.assertNotIn("E-NET", result.selected_evidence_ids)

    def test_12_duplicate_prevention(self):
        result = select_evidence(SelectionStrategy.ADAPTIVE, self.candidates, self.profiles["potential_exfiltration"], {"E-NET"}, None, 3)
        self.assertNotIn("E-NET", result.selected_evidence_ids)
        with self.assertRaises(ContractError):
            select_evidence(SelectionStrategy.STATIC, self.candidates + [self.candidates[0]], None, set(), None, 2)

    def test_13_deterministic_ranking(self):
        args = (SelectionStrategy.ADAPTIVE, self.candidates, self.profiles["potential_exfiltration"], set(), None)
        self.assertEqual(rank_candidates(*args), rank_candidates(*args))

    def test_14_zero_budget(self):
        result = select_evidence(SelectionStrategy.STATIC, self.candidates, None, set(), None, 0)
        self.assertEqual(result.selected_evidence_ids, ())

    def test_15_zero_cost_rejected(self):
        with self.assertRaises(ContractError):
            EvidenceCandidate("ZERO", "network_flow", 0)

    def test_16_invalid_cost_rejected(self):
        with self.assertRaises(ContractError):
            EvidenceCandidate("BAD", "network_flow", -1)

    def test_17_static_baseline(self):
        ranking = rank_candidates(SelectionStrategy.STATIC, self.candidates, None, set(), None)
        self.assertEqual(ranking[:2], ["E-AUTH", "E-PROC"])

    def test_18_random_reproducibility(self):
        one = rank_candidates(SelectionStrategy.RANDOM, self.candidates, None, set(), random.Random(7))
        two = rank_candidates(SelectionStrategy.RANDOM, self.candidates, None, set(), random.Random(7))
        self.assertEqual(one, two)

    def test_19_threat_agnostic_ignores_context(self):
        one = rank_candidates(SelectionStrategy.THREAT_AGNOSTIC, self.candidates, self.profiles["suspicious_authentication"], set(), None)
        two = rank_candidates(SelectionStrategy.THREAT_AGNOSTIC, self.candidates, self.profiles["potential_exfiltration"], set(), None)
        self.assertEqual(one, two)

    def test_20_frozen_context_uses_supplied_initial_context(self):
        frozen = rank_candidates(SelectionStrategy.FROZEN_CONTEXT_ADAPTIVE, self.candidates, self.profiles["suspicious_authentication"], set(), None)
        adaptive_after_shift = rank_candidates(SelectionStrategy.ADAPTIVE, self.candidates, self.profiles["potential_exfiltration"], set(), None)
        self.assertEqual(frozen[0], "E-AUTH")
        self.assertEqual(adaptive_after_shift[0], "E-NET")

    def test_21_ground_truth_leakage_prevention(self):
        self.assertEqual({item.name for item in fields(EvidenceCandidate)}, {"evidence_id", "source_type", "collection_cost"})
        selector_source = (Path(__file__).resolve().parents[2] / "src/readiness/selectors.py").read_text(encoding="utf-8")
        self.assertNotIn("ground_truth", selector_source)
        self.assertNotIn("src.evaluation", selector_source)

    def test_22_evaluation_metrics(self):
        metrics = selection_metrics(["E1", "E2"], {"E2", "E3"}, {"E1": 1, "E2": 2}, 4)
        self.assertEqual(metrics["evidence_recall"], 0.5)
        self.assertEqual(metrics["evidence_precision"], 0.5)
        self.assertEqual(metrics["collection_cost"], 3)
        self.assertIsNone(selection_metrics([], set(), {}, 0)["evidence_recall"])

    def test_23_json_serialization_compatibility(self):
        mappings = map_events_to_attack([self.alert("suspicious_authentication", "Repeated login failures")], self.profiles["suspicious_authentication"])
        json.dumps(explain_attack_mappings(mappings))
        json.dumps(build_demo_summary())

    def test_24_invalid_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"source":"wrong","techniques":[]}', encoding="utf-8")
            with self.assertRaises(ContractError):
                load_attack_catalog(path)

    def test_25_shared_readiness_interface(self):
        profile = self.profiles["suspicious_authentication"]
        availability = [EvidenceAvailability("authentication_log", AvailabilityStatus.AVAILABLE, STAMP)]
        result = assess_readiness(profile, availability)
        self.assertEqual(result.scenario_id, "suspicious_authentication")
        self.assertGreater(result.score, 0)

    def test_26_all_five_strategies(self):
        results = compare_selection_strategies(self.candidates, self.profiles["potential_exfiltration"], 3, 11)
        self.assertEqual({item.strategy for item in results}, set(SelectionStrategy))


if __name__ == "__main__":
    unittest.main()

