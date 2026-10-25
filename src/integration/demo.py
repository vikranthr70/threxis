"""Runnable Person 1 + Person 2 integration demonstration."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from src.common.models import InvestigationCase
from src.detection.correlation import correlate_events
from src.detection.engine import detect_suspicious_activity
from src.forensics.audit import record_verification
from src.forensics.vault import preserve_evidence, verify_evidence_vault
from src.integration.adapters import aggregate_source_availability, availability_flags
from src.investigation.report import build_investigation_case_record, generate_markdown_report
from src.investigation.timeline import build_investigation_timeline
from src.readiness.assessment import assess_readiness, assess_readiness_details
from src.readiness.comparison import compare_available_selection_strategies
from src.synthetic.generator import generate_synthetic_events
from src.synthetic.integration import evidence_inputs_from_events
from src.threat_intel.mapping import map_events_to_attack
from src.threat_intel.profiles import get_threat_profile


def run_demo() -> dict[str, object]:
    scenario = "suspicious_authentication"
    events, labels = generate_synthetic_events(scenario, 18, 20261025)
    alerts = detect_suspicious_activity(events)
    profile = get_threat_profile(scenario)
    mappings = map_events_to_attack(alerts, profile)
    candidates, event_availability = evidence_inputs_from_events(events)
    source_availability, trace = aggregate_source_availability(candidates, event_availability)
    readiness = assess_readiness(profile, source_availability)
    details = assess_readiness_details(profile, {
        item.evidence_id: "available" if item.availability_status.value == "available" else item.availability_status.value
        for item in source_availability
    })
    flags = availability_flags(candidates, event_availability)
    budget = max(1, sum(item.collection_cost for item in candidates) // 5)
    comparisons = compare_available_selection_strategies(candidates, profile, budget, 7, flags)
    adaptive = next(item for item in comparisons if item.strategy.value == "adaptive")
    case = InvestigationCase("CASE-INTEGRATION-DEMO", scenario, tuple(item.alert_id for item in alerts), events[0].timestamp)
    timeline = build_investigation_timeline(case, events, alerts)
    correlations = correlate_events(events)
    manifests = []
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
        workspace, vault = Path(temp), Path(temp) / "vault"
        for evidence_id in adaptive.selected_evidence_ids:
            source = workspace / f"{evidence_id}.json"
            event = next(item for item in events if item.event_id == evidence_id)
            source.write_text(json.dumps(event.to_dict(), sort_keys=True), encoding="utf-8")
            destination = vault / source.name
            manifest = preserve_evidence(source, destination, evidence_id, events[-1].timestamp)
            manifests.append(manifest)
            record_verification(destination, manifest.sha256, evidence_id, vault / "verification-audit.jsonl")
        verification = verify_evidence_vault(vault)
        case_record = build_investigation_case_record(case, events, alerts, timeline, manifests, correlations, verification)
        report = generate_markdown_report(case, events, alerts, timeline, manifests, correlations, verification)
    return {"synthetic_event_count": len(events), "ground_truth_label_count": len(labels),
            "ground_truth_passed_to_selection": False, "alert_count": len(alerts),
            "attack_mapping_count": len(mappings), "source_availability_trace": {k: list(v) for k, v in trace.items()},
            "readiness": readiness.to_dict(), "readiness_details": details,
            "selection_results": [item.to_dict() for item in comparisons],
            "preserved_evidence_count": len(manifests), "verification": verification,
            "timeline_entry_count": len(timeline), "correlation_count": len(correlations),
            "case_record": case_record, "markdown_report_length": len(report)}


def main() -> None:
    print(json.dumps(run_demo(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
