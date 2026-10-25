from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.common.models import ContractError, DetectionAlert, InvestigationCase, SecurityEvent, Severity
from src.detection.engine import detect_suspicious_activity
from src.evaluation.ground_truth import GroundTruthLabel
from src.forensics.vault import preserve_evidence, verify_evidence, verify_evidence_vault
from src.investigation.report import build_investigation_case_record, generate_markdown_report
from src.investigation.timeline import build_investigation_timeline
from src.synthetic.generator import generate_synthetic_events
from src.synthetic.integration import evidence_inputs_from_events


SCENARIOS = (
    "suspicious_authentication",
    "suspicious_file_modification",
    "potential_exfiltration",
)

ARCHITECTURE_SOURCE_TYPES = {
    "authentication_log",
    "process_creation",
    "network_flow",
    "dns_log",
    "file_access",
    "powershell_log",
    "registry_event",
    "scheduled_task",
}


def event(event_id: str, when: str, event_type: str, scenario: str, source: str, **attrs) -> SecurityEvent:
    return SecurityEvent(event_id, when, event_type, source, scenario, attrs)


class SyntheticGeneratorTests(unittest.TestCase):
    def test_deterministic_and_ids_unique(self):
        first = generate_synthetic_events(SCENARIOS[0], 24, 17)
        second = generate_synthetic_events(SCENARIOS[0], 24, 17)
        self.assertEqual([item.to_dict() for item in first[0]], [item.to_dict() for item in second[0]])
        self.assertEqual([item.evidence_id for item in first[1]], [item.evidence_id for item in second[1]])
        self.assertEqual(len({item.event_id for item in first[0]}), 24)
        ids = [item.event_id for item in first[0]]
        self.assertTrue(all(re.fullmatch(r"evt-[0-9a-f]{32}", event_id) for event_id in ids))
        self.assertNotEqual(ids, sorted(ids))

    def test_all_scenarios_and_timestamp_validity(self):
        for scenario in SCENARIOS:
            events, _ = generate_synthetic_events(scenario, 18, 3)
            self.assertEqual(len(events), 18)
            self.assertTrue(all(item.scenario_id == scenario for item in events))
            for item in events:
                parsed = datetime.fromisoformat(item.timestamp.replace("Z", "+00:00"))
                self.assertIsNotNone(parsed.tzinfo)
                ip = item.attributes.get("source_ip")
                if ip is not None:
                    self.assertIn(ip.split(".")[0], {"192", "198", "203"})

    def test_source_types_use_shared_architecture_vocabulary(self):
        generated_source_types = set()
        for scenario in SCENARIOS:
            events, _ = generate_synthetic_events(scenario, 18, 3)
            generated_source_types.update(item.source_type for item in events)
        self.assertLessEqual(generated_source_types, ARCHITECTURE_SOURCE_TYPES)
        self.assertIn("file_access", generated_source_types)
        self.assertIn("process_creation", generated_source_types)

    def test_truth_is_separate_and_ids_link_to_candidates(self):
        events, labels = generate_synthetic_events(SCENARIOS[1], 15, 5)
        self.assertTrue(all(isinstance(label, GroundTruthLabel) for label in labels))
        self.assertEqual({label.evidence_id for label in labels}, {item.event_id for item in events})
        for item in events:
            self.assertFalse({"relevant", "label", "ground_truth", "malicious"} & set(item.attributes))

    def test_readiness_integration_metadata(self):
        events, _ = generate_synthetic_events(SCENARIOS[0], 20, 8)
        candidates, availability = evidence_inputs_from_events(events)
        self.assertEqual({item.evidence_id for item in candidates}, {event.event_id for event in events})
        self.assertTrue(all(item.collection_cost > 0 for item in candidates))
        self.assertEqual(len(availability), len(events))
        self.assertEqual({item.availability_status.value for item in availability}, {"available"})
    def test_invalid_inputs(self):
        for args in (("unknown", 1, 1), (SCENARIOS[0], 0, 1), (SCENARIOS[0], -1, 1), (SCENARIOS[0], 1, True)):
            with self.assertRaises(ContractError):
                generate_synthetic_events(*args)


class DetectionTests(unittest.TestCase):
    def test_repeated_auth_failures_and_followed_success(self):
        events, _ = generate_synthetic_events(SCENARIOS[0], 20, 31)
        alerts = detect_suspicious_activity(events)
        rules = {alert.alert_id.split("-")[1] for alert in alerts}
        self.assertTrue(any("AUTH" in alert.alert_id and "REPEATED" in alert.alert_id for alert in alerts))
        self.assertTrue(any("FOLLOWED" in alert.alert_id or "THEN" in alert.alert_id for alert in alerts))
        self.assertTrue(all(alert.event_ids for alert in alerts))

    def test_file_modification_burst(self):
        events, _ = generate_synthetic_events(SCENARIOS[1], 16, 41)
        alerts = detect_suspicious_activity(events)
        self.assertTrue(any("FILE-MODIFICATION-BURST" in alert.alert_id for alert in alerts))

    def test_potential_exfiltration(self):
        events, _ = generate_synthetic_events(SCENARIOS[2], 16, 51)
        alerts = detect_suspicious_activity(events)
        self.assertTrue(any("EXFIL-OUTBOUND-VOLUME" in alert.alert_id for alert in alerts))

    def test_normal_events_do_not_alert(self):
        benign = [
            event("N1", "2026-01-01T00:00:00Z", "ssh_login", SCENARIOS[0], "authentication_log", source_ip="192.0.2.1", result="success"),
            event("N2", "2026-01-01T01:00:00Z", "ssh_login", SCENARIOS[0], "authentication_log", source_ip="192.0.2.1", result="success"),
            event("N3", "2026-01-01T02:00:00Z", "ssh_failed_password", SCENARIOS[0], "authentication_log", source_ip="198.51.100.2", result="failure"),
        ]
        self.assertEqual(detect_suspicious_activity(benign), [])
        normal_file = [
            event("F1", "2026-01-01T00:00:00Z", "file_modified", SCENARIOS[1], "file_access", host="h", user="u", file_path="/a", process_name="editor", authorized=True),
            event("F2", "2026-01-01T01:00:00Z", "file_modified", SCENARIOS[1], "file_access", host="h", user="u", file_path="/b", process_name="editor", authorized=True),
        ]
        self.assertEqual(detect_suspicious_activity(normal_file), [])
        normal_net = [event("X1", "2026-01-01T00:00:00Z", "network_connection", SCENARIOS[2], "network_flow", host="h", user="u", bytes_sent=1000, destination_ip="192.0.2.1")]
        self.assertEqual(detect_suspicious_activity(normal_net), [])

    def test_detection_rejects_invalid_or_mixed_input(self):
        with self.assertRaises(ContractError):
            detect_suspicious_activity([{}])
        with self.assertRaises(ContractError):
            detect_suspicious_activity([
                event("E1", "2026-01-01T00:00:00Z", "ssh_login", SCENARIOS[0], "auth"),
                event("E2", "2026-01-01T00:00:01Z", "file_modified", SCENARIOS[1], "file"),
            ])

    def test_detection_is_independent_of_ground_truth_output(self):
        events, labels = generate_synthetic_events(SCENARIOS[0], 18, 62)
        before = detect_suspicious_activity(events)
        labels.reverse()
        labels.clear()
        after = detect_suspicious_activity(events)
        self.assertEqual([a.to_dict() for a in before], [a.to_dict() for a in after])


class EvidenceVaultTests(unittest.TestCase):
    def test_preserve_hash_and_verify(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temp:
            root = Path(temp)
            source = root / "synthetic.json"
            source.write_bytes(b'{"synthetic":true}\n')
            destination = root / "vault" / "event-1.json"
            manifest = preserve_evidence(source, destination, "event-1", "2026-01-01T00:00:00Z")
            expected = hashlib.sha256(destination.read_bytes()).hexdigest()
            self.assertEqual(manifest.sha256, expected)
            self.assertTrue(verify_evidence(destination, expected))
            self.assertTrue((root / "vault" / "custody.jsonl").exists())
            self.assertTrue(Path(str(destination) + ".manifest.json").exists())

    def test_tampering_and_missing_artifacts(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temp:
            root = Path(temp)
            source = root / "source.json"
            source.write_text("synthetic", encoding="utf-8")
            destination = root / "vault" / "ev.json"
            manifest = preserve_evidence(source, destination, "ev1", "2026-01-01T00:00:00Z")
            destination.write_text("changed", encoding="utf-8")
            self.assertFalse(verify_evidence(destination, manifest.sha256))
            result = verify_evidence_vault(destination.parent)
            self.assertEqual(result["modified"], 1)
            destination.unlink()
            result = verify_evidence_vault(destination.parent)
            self.assertEqual(result["missing"], 1)
            with self.assertRaises(FileNotFoundError):
                verify_evidence(destination, manifest.sha256)

    def test_no_overwrite_bad_manifest_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as temp:
            root = Path(temp)
            source = root / "source.json"
            source.write_text("abc", encoding="utf-8")
            destination = root / "vault" / "ev.json"
            preserve_evidence(source, destination, "ev1", "2026-01-01T00:00:00Z")
            with self.assertRaises(ContractError):
                preserve_evidence(source, destination, "ev1", "2026-01-01T00:00:00Z")
            sidecar = Path(str(destination) + ".manifest.json")
            sidecar.write_text("{bad", encoding="utf-8")
            self.assertEqual(verify_evidence_vault(destination.parent)["invalid_manifests"], 1)
            with self.assertRaises(ContractError):
                preserve_evidence(source, root.parent / "escaped.json", "ev2", "2026-01-01T00:00:00Z")
            with self.assertRaises(ContractError):
                verify_evidence(source, "bad-hash")


class InvestigationTests(unittest.TestCase):
    def test_chronological_timeline_and_report_references(self):
        events, _ = generate_synthetic_events(SCENARIOS[0], 18, 72)
        alerts = detect_suspicious_activity(events)
        case = InvestigationCase("CASE-1", SCENARIOS[0], tuple(a.alert_id for a in alerts), events[0].timestamp)
        timeline = build_investigation_timeline(case, events, alerts)
        parsed = [datetime.fromisoformat(item.timestamp.replace("Z", "+00:00")) for item in timeline]
        self.assertEqual(parsed, sorted(parsed))
        report = generate_markdown_report(case, events, alerts, timeline)
        for event_id in events:
            self.assertIn(event_id.event_id, report)
        for alert in alerts:
            self.assertIn(alert.alert_id, report)
        self.assertIn("hypotheses", report.lower())
        self.assertIn("without a matching preserved evidence ID", report)
        structured = build_investigation_case_record(case, events, alerts, timeline)
        self.assertEqual(len(structured["observed_facts"]), len(events))
        json.dumps(structured)

    def test_timeline_rejects_unknown_and_cross_case_ids(self):
        case = InvestigationCase("CASE-2", SCENARIOS[0], ("UNKNOWN",), "2026-01-01T00:00:00Z")
        with self.assertRaises(ContractError):
            build_investigation_timeline(case, [], [])
        bad_alert = DetectionAlert("A1", ("E404",), "2026-01-01T00:00:00Z", Severity.HIGH, SCENARIOS[0], "synthetic")
        case2 = InvestigationCase("CASE-3", SCENARIOS[0], ("A1",), "2026-01-01T00:00:00Z")
        with self.assertRaises(ContractError):
            build_investigation_timeline(case2, [], [bad_alert])


if __name__ == "__main__":
    unittest.main()







