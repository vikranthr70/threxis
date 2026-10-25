"""Run the complete synthetic event-to-investigation demonstration.

Usage: python -m src.synthetic.demo
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from src.common.models import InvestigationCase
from src.detection.engine import detect_suspicious_activity
from src.forensics.vault import preserve_evidence, verify_evidence
from src.investigation.report import generate_markdown_report
from src.investigation.timeline import build_investigation_timeline
from src.synthetic.generator import generate_synthetic_events


def main() -> None:
    scenario = "suspicious_authentication"
    events, labels = generate_synthetic_events(scenario, count=18, seed=20261025)
    alerts = detect_suspicious_activity(events)
    case = InvestigationCase(
        case_id="CASE-DEMO-001", scenario_id=scenario,
        alert_ids=tuple(alert.alert_id for alert in alerts),
        opened_at=events[0].timestamp,
    )
    with tempfile.TemporaryDirectory(prefix="threxis-demo-", dir=Path(__file__).resolve().parents[2]) as temp:
        workspace = Path(temp)
        source = workspace / "synthetic-events.json"
        source.write_text(json.dumps([event.to_dict() for event in events], sort_keys=True, indent=2), encoding="utf-8")
        vault = workspace / "evidence"
        manifests = []
        selected = sorted({event_id for alert in alerts for event_id in alert.event_ids})[:3]
        for event_id in selected:
            manifest = preserve_evidence(source, vault / f"{event_id}.json", event_id, events[0].timestamp)
            manifests.append(manifest)
        verified = all(verify_evidence(Path(m.source_path), m.sha256) for m in manifests)
        timeline = build_investigation_timeline(case, events, alerts)
        report = generate_markdown_report(case, events, alerts, timeline, manifests)
        report_path = workspace / "investigation-report.md"
        report_path.write_text(report, encoding="utf-8")
        print("THREXIS synthetic demonstration")
        print(f"Scenario: {scenario}")
        print(f"Events generated: {len(events)}")
        print(f"Ground-truth labels kept separately: {len(labels)}")
        print(f"Heuristic alerts: {len(alerts)}")
        print(f"Evidence artifacts preserved: {len(manifests)}")
        print(f"SHA-256 verification: {'passed' if verified else 'failed'}")
        print(f"Timeline entries: {len(timeline)}")
        print(f"Markdown report generated: {report_path.name}")
        print("Alerts are synthetic investigative leads, not confirmed attacks.")


if __name__ == "__main__":
    main()

