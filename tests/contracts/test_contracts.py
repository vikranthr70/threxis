import json
import unittest
from dataclasses import fields
from pathlib import Path

from src.common.models import (
    AvailabilityStatus,
    SCENARIO_IDS,
    SCHEMA_VERSION,
    ContractError,
    DetectionAlert,
    EvaluationResult,
    EvidenceAvailability,
    EvidenceCandidate,
    EvidenceManifest,
    EvidenceSelectionResult,
    InvestigationCase,
    ReadinessAssessment,
    SecurityEvent,
    Severity,
    SelectionStrategy,
    ThreatMapping,
    ThreatProfile,
    TimelineEntry,
)
from src.common.selection import fill_to_budget


ROOT = Path(__file__).resolve().parents[2]


class ContractTests(unittest.TestCase):
    def load_events(self):
        records = json.loads((ROOT / "data/samples/security_events.json").read_text(encoding="utf-8"))
        return [SecurityEvent(**record) for record in records]

    def test_sample_events_validate_and_ids_are_unique(self):
        events = self.load_events()
        self.assertEqual(len(events), 3)
        self.assertEqual(len({item.event_id for item in events}), len(events))
        self.assertEqual({item.scenario_id for item in events}, SCENARIO_IDS)

    def test_timestamps_require_timezones(self):
        with self.assertRaises(ContractError):
            SecurityEvent("E1", "2026-01-01T00:00:00", "x", "authentication_log", "suspicious_authentication")

    def test_invalid_scenario_is_rejected(self):
        with self.assertRaises(ContractError):
            SecurityEvent("E1", "2026-01-01T00:00:00Z", "x", "authentication_log", "unknown")

    def test_records_serialize_to_json(self):
        for event in self.load_events():
            payload = json.dumps(event.to_dict(), sort_keys=True)
            self.assertIn(f'"schema_version": "{SCHEMA_VERSION}"', payload)

    def test_all_shared_models_validate_and_serialize(self):
        timestamp = "2026-01-01T00:00:00Z"
        records = [
            DetectionAlert("A1", ("E1",), timestamp, Severity.HIGH, "suspicious_authentication", "synthetic rule"),
            ThreatMapping("A1", "T1110", 0.5, "illustrative mapping only"),
            ThreatProfile("P1", "suspicious_authentication", ("T1110",), {"authentication_log": 0.9}),
            EvidenceCandidate("X1", "authentication_log", 1),
            EvidenceAvailability("X1", AvailabilityStatus.AVAILABLE, timestamp),
            ReadinessAssessment("R1", "suspicious_authentication", 0.8),
            EvidenceSelectionResult(SelectionStrategy.ADAPTIVE, ("X1",), 2, 1),
            EvidenceManifest("M1", "X1", timestamp, "0" * 64, "synthetic.json"),
            InvestigationCase("C1", "suspicious_authentication", ("A1",), timestamp),
            TimelineEntry("C1", timestamp, "alert", "Synthetic alert", ("A1",)),
            EvaluationResult("RUN1", SelectionStrategy.ADAPTIVE, "suspicious_authentication", ("X1",), 0.5, 1.0, 1, 0.5),
        ]
        for record in records:
            payload = record.to_dict()
            self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
            json.dumps(payload)

    def test_selector_candidate_is_a_strict_allowlist(self):
        names = {item.name for item in fields(EvidenceCandidate)}
        self.assertEqual(names, {"evidence_id", "source_type", "collection_cost"})
        forbidden = {"label", "relevant", "ground_truth", "scenario_id", "generator_seed", "instance_id", "mapping_quality_setting"}
        self.assertTrue(names.isdisjoint(forbidden))

    def test_runtime_event_rejects_truth_fields(self):
        with self.assertRaises(ContractError):
            SecurityEvent("E1", "2026-01-01T00:00:00Z", "x", "authentication_log", "suspicious_authentication", {"relevant": True})

    def test_budget_filler_skips_non_fitting_items(self):
        result = fill_to_budget(["expensive", "first", "second"], {"expensive": 4, "first": 2, "second": 1}, 3, set())
        self.assertEqual(result, ("first", "second"))

    def test_selection_rejects_over_budget_and_duplicates(self):
        with self.assertRaises(ContractError):
            EvidenceSelectionResult(SelectionStrategy.STATIC, ("E1",), 1, 2)
        with self.assertRaises(ContractError):
            EvidenceSelectionResult(SelectionStrategy.STATIC, ("E1", "E1"), 2, 2)

    def test_manifest_requires_sha256(self):
        with self.assertRaises(ContractError):
            EvidenceManifest("M1", "E1", "2026-01-01T00:00:00Z", "bad", "synthetic.json")

    def test_module_imports_and_schema_version_match(self):
        import src.detection
        import src.evaluation
        import src.forensics
        import src.investigation
        import src.readiness
        import src.synthetic
        import src.threat_intel
        from src import SCHEMA_VERSION as package_version
        self.assertEqual(package_version, SCHEMA_VERSION)

    def test_operational_packages_do_not_import_ground_truth(self):
        for package in ("readiness", "threat_intel"):
            text = (ROOT / "src" / package / "__init__.py").read_text(encoding="utf-8")
            self.assertNotIn("ground_truth", text)
            self.assertNotIn("src.evaluation", text)


if __name__ == "__main__":
    unittest.main()

