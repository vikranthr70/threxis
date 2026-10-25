from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from src.common.models import (AvailabilityStatus, ContractError, EvidenceAvailability,
                               EvidenceCandidate, SelectionStrategy, ThreatProfile)
from src.detection.correlation import correlate_events
from src.forensics.audit import read_audit_trail, record_verification
from src.forensics.vault import preserve_evidence, verify_evidence_vault
from src.integration.adapters import aggregate_source_availability, availability_flags
from src.integration.demo import run_demo
from src.readiness.assessment import assess_readiness_details, simulate_readiness_improvement
from src.readiness.comparison import compare_available_selection_strategies
from src.readiness.selectors import (ContextSelectionState, analyze_context_change,
                                     generic_prior_weights, severity_aware_rank_candidates)
from src.synthetic.multistage import generate_multistage_demonstration


NOW = "2026-01-01T00:00:00Z"


class AvailabilityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.candidates = [EvidenceCandidate("e1", "auth", 1), EvidenceCandidate("e2", "auth", 2),
                           EvidenceCandidate("e3", "net", 1)]
        self.observations = [EvidenceAvailability("e1", AvailabilityStatus.UNAVAILABLE, NOW),
                             EvidenceAvailability("e2", AvailabilityStatus.COLLECTED, NOW),
                             EvidenceAvailability("e3", AvailabilityStatus.AVAILABLE, NOW)]

    def test_source_presence_policy_and_trace(self):
        aggregate, trace = aggregate_source_availability(self.candidates, self.observations)
        self.assertEqual({item.evidence_id: item.availability_status for item in aggregate},
                         {"auth": AvailabilityStatus.COLLECTED, "net": AvailabilityStatus.AVAILABLE})
        self.assertEqual(trace["auth"], ("e1", "e2"))
        self.assertEqual(availability_flags(self.candidates, self.observations), {"e1": False, "e2": True, "e3": True})

    def test_inconsistent_records_rejected(self):
        with self.assertRaises(ContractError):
            availability_flags(self.candidates, self.observations[:-1])
        with self.assertRaises(ContractError):
            aggregate_source_availability(self.candidates, self.observations + [self.observations[0]])

    def test_all_baselines_use_same_available_pool_and_budget(self):
        profile = ThreatProfile("p", "suspicious_authentication", (), {"auth": .8, "net": .5})
        results = compare_available_selection_strategies(self.candidates, profile, 2, 4,
                                                         availability_flags(self.candidates, self.observations))
        self.assertEqual(len(results), 5)
        self.assertTrue(all("e1" not in result.selected_evidence_ids for result in results))
        self.assertTrue(all(result.selected_cost <= 2 for result in results))


class ReadinessAndRankingTests(unittest.TestCase):
    def setUp(self):
        self.before = ThreatProfile("p1", "suspicious_authentication", (), {"auth": .9, "net": .2})
        self.after = ThreatProfile("p2", "suspicious_authentication", (), {"auth": .1, "net": .9})
        self.candidates = [EvidenceCandidate("a", "auth", 1), EvidenceCandidate("n", "net", 1)]

    def test_configured_generic_prior_is_architecture_vocabulary(self):
        weights = generic_prior_weights()
        self.assertIn("authentication_log", weights)
        self.assertIn("scheduled_task", weights)
        self.assertNotIn("profile_id", weights)

    def test_frozen_and_adaptive_context_diverge(self):
        frozen = ContextSelectionState(self.before)
        adaptive = ContextSelectionState(self.before)
        frozen_result = frozen.select(SelectionStrategy.FROZEN_CONTEXT_ADAPTIVE, self.candidates, self.after, 1)
        adaptive_result = adaptive.select(SelectionStrategy.ADAPTIVE, self.candidates, self.after, 1)
        self.assertEqual(frozen_result.selected_evidence_ids, ("a",))
        self.assertEqual(adaptive_result.selected_evidence_ids, ("n",))

    def test_simulation_severity_and_context_analysis(self):
        original = assess_readiness_details(self.before, {"auth": "missing", "net": "available"})
        simulation = simulate_readiness_improvement(self.before, {"auth": "missing", "net": "available"}, {"auth": "available"})
        self.assertGreater(simulation["simulated_readiness"]["readiness_percentage"], original["readiness_percentage"])
        self.assertEqual(severity_aware_rank_candidates(self.candidates, self.before, {"net": 1.0})[0], "a")
        analysis = analyze_context_change(self.before, self.after)
        self.assertIn("net", analysis["newly_prioritized_sources"])


class ForensicUpgradeTests(unittest.TestCase):
    def test_multistage_truth_isolation_and_correlation(self):
        events, labels = generate_multistage_demonstration(9)
        self.assertEqual(len(events), 18)
        self.assertEqual({item.attributes["demonstration_stage"] for item in events}, {1, 2, 3})
        self.assertEqual({item.event_id for item in events}, {item.evidence_id for item in labels})
        self.assertTrue(all("relevant" not in item.attributes for item in events))
        self.assertTrue(correlate_events(events))

    def test_verification_summary_orphan_and_append_only_audit(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            source = root / "source.txt"; source.write_text("synthetic", encoding="utf-8")
            destination = root / "vault" / "artifact.txt"
            manifest = preserve_evidence(source, destination, "ev-1", NOW)
            audit = root / "vault" / "verification-audit.jsonl"
            record_verification(destination, manifest.sha256, "ev-1", audit)
            record_verification(destination, manifest.sha256, "ev-1", audit)
            self.assertEqual(len(read_audit_trail(audit)), 2)
            (root / "vault" / "orphan.bin").write_bytes(b"orphan")
            summary = verify_evidence_vault(root / "vault")
            self.assertEqual(summary["valid"], 1)
            self.assertEqual(summary["invalid_manifests"], 1)

    def test_complete_demo_is_deterministic_in_core_results(self):
        first, second = run_demo(), run_demo()
        keys = ("synthetic_event_count", "alert_count", "attack_mapping_count", "readiness",
                "selection_results", "preserved_evidence_count", "timeline_entry_count")
        self.assertEqual({key: first[key] for key in keys}, {key: second[key] for key in keys})
        self.assertFalse(first["ground_truth_passed_to_selection"])
        self.assertEqual(len(first["selection_results"]), 5)


if __name__ == "__main__":
    unittest.main()
