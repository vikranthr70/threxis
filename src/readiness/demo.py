"""Standalone Person 1 demonstration using synthetic fixtures only."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from src.common.models import DetectionAlert, EvidenceCandidate, Severity
from src.readiness.assessment import assess_readiness_details
from src.readiness.comparison import compare_selection_strategies
from src.readiness.metrics import selection_metrics
from src.readiness.selectors import explain_selection
from src.threat_intel.catalog import load_attack_catalog
from src.threat_intel.mapping import explain_attack_mappings, map_events_to_attack
from src.threat_intel.profiles import load_threat_profiles


def build_demo_summary() -> dict[str, object]:
    profiles, catalog = load_threat_profiles(), load_attack_catalog()
    alert = DetectionAlert(
        "ALERT-DEMO-1", ("EVENT-DEMO-1", "EVENT-DEMO-2"), "2026-01-01T00:00:00Z",
        Severity.HIGH, "suspicious_authentication",
        "Repeated login failures consistent with password guessing",
    )
    mappings = map_events_to_attack([alert], profiles["suspicious_authentication"])
    readiness = {}
    base_status = {"authentication_log": "validated", "process_creation": "collected", "network_flow": "available", "powershell_log": "unknown"}
    for scenario, profile in profiles.items():
        readiness[scenario] = assess_readiness_details(profile, {key: base_status.get(key, "missing") for key in profile.evidence_weights})
    candidates = [
        EvidenceCandidate("E-AUTH", "authentication_log", 2), EvidenceCandidate("E-PROC", "process_creation", 1),
        EvidenceCandidate("E-NET", "network_flow", 2), EvidenceCandidate("E-FILE", "file_access", 1),
        EvidenceCandidate("E-PS", "powershell_log", 1),
    ]
    context, truth = profiles["potential_exfiltration"], {"E-NET", "E-FILE"}
    costs = {item.evidence_id: item.collection_cost for item in candidates}
    selections = []
    for result in compare_selection_strategies(candidates, context, budget=4, seed=20261025):
        selections.append({"selection": explain_selection(result, candidates, context), "metrics": selection_metrics(result.selected_evidence_ids, truth, costs, 4)})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(), "synthetic_demo": True,
        "catalog": [item.to_dict() for item in catalog.values()],
        "attack_mappings": explain_attack_mappings(mappings), "readiness": readiness,
        "selections": selections,
        "warning": "Synthetic proof of concept; results do not establish real-world forensic effectiveness.",
    }


def main() -> None:
    print(json.dumps(build_demo_summary(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

