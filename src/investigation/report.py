"""Deterministic Markdown report helpers for synthetic investigations."""

from __future__ import annotations

from collections.abc import Sequence

from src.common.models import DetectionAlert, EvidenceManifest, InvestigationCase, SecurityEvent, TimelineEntry




def build_investigation_case_record(
    case: InvestigationCase,
    events: Sequence[SecurityEvent],
    alerts: Sequence[DetectionAlert],
    timeline: Sequence[TimelineEntry],
    manifests: Sequence[EvidenceManifest] = (),
    correlations: Sequence[dict[str, object]] = (),
    verification_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return a JSON-compatible structured case with facts and hypotheses split."""
    event_ids = {event.event_id for event in events}
    preserved = {manifest.evidence_id for manifest in manifests}
    return {
        "case": case.to_dict(),
        "observed_facts": [event.to_dict() for event in sorted(events, key=lambda item: (item.timestamp, item.event_id))],
        "investigative_hypotheses": [alert.to_dict() for alert in sorted(alerts, key=lambda item: (item.timestamp, item.alert_id))],
        "timeline": [entry.to_dict() for entry in timeline],
        "evidence_manifests": [manifest.to_dict() for manifest in sorted(manifests, key=lambda item: item.evidence_id)],
        "missing_evidence_ids": sorted(event_ids - preserved),
        "correlated_event_groups": list(correlations),
        "evidence_verification_status": verification_summary,
        "limitations": ["Synthetic records only.", "Alerts and correlations are hypotheses, not proof.",
                        "Local custody logs are not tamper-proof."],
    }

def generate_markdown_report(
    case: InvestigationCase,
    events: Sequence[SecurityEvent],
    alerts: Sequence[DetectionAlert],
    timeline: Sequence[TimelineEntry],
    manifests: Sequence[EvidenceManifest] = (),
    correlations: Sequence[dict[str, object]] = (),
    verification_summary: dict[str, object] | None = None,
) -> str:
    """Render an evidence-linked report; alerts remain hypotheses, not findings."""
    event_ids = {event.event_id for event in events}
    preserved = {manifest.evidence_id for manifest in manifests}
    missing = sorted(event_ids - preserved)
    lines = [
        f"# THREXIS Synthetic Investigation: {case.case_id}", "",
        f"- Scenario: `{case.scenario_id}`", f"- Opened: `{case.opened_at}`",
        f"- Status: `{case.status}`", "",
        "## Scope and limitations", "",
        "This report describes artificial records and heuristic alerts. Alerts are investigative hypotheses and do not establish that an attack occurred.", "",
        "## Observed synthetic facts", "",
    ]
    if events:
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            lines.append(f"- `{event.timestamp}` `{event.event_type}` (`{event.event_id}`; source `{event.source_type}`).")
    else:
        lines.append("- No event records were supplied.")
    lines.extend(["", "## Investigative hypotheses", ""])
    if alerts:
        for alert in sorted(alerts, key=lambda item: (item.timestamp, item.alert_id)):
            refs = ", ".join(f"`{event_id}`" for event_id in alert.event_ids)
            lines.append(f"- `{alert.alert_id}` ({alert.severity.value}): {alert.reason} Supporting events: {refs}.")
    else:
        lines.append("- No heuristic alerts were generated.")
    lines.extend(["", "## Evidence preservation", ""])
    if manifests:
        for manifest in sorted(manifests, key=lambda item: item.evidence_id):
            lines.append(f"- `{manifest.evidence_id}` SHA-256 `{manifest.sha256}` at `{manifest.source_path}`.")
    else:
        lines.append("- No evidence manifests were supplied.")
    lines.append(f"- Event records without a matching preserved evidence ID: {', '.join(f'`{item}`' for item in missing) if missing else 'none'}.")
    lines.extend(["", "## Correlated event groups", ""])
    if correlations:
        for item in sorted(correlations, key=lambda row: str(row.get("correlation_id", ""))):
            lines.append(f"- `{item.get('correlation_id')}`: {item.get('explanation')} Support: `{item.get('rule_support_level')}`.")
    else:
        lines.append("- No event correlations were supplied.")
    lines.extend(["", "## Evidence verification status", ""])
    lines.append(f"- `{verification_summary}`" if verification_summary is not None else "- No batch verification summary was supplied.")
    lines.extend(["", "## Timeline", ""])
    if timeline:
        for entry in sorted(timeline, key=lambda item: (item.timestamp, item.entry_type, item.related_ids)):
            refs = ", ".join(f"`{item}`" for item in entry.related_ids)
            lines.append(f"- `{entry.timestamp}` **{entry.entry_type}** — {entry.summary} References: {refs or 'none'}.")
    else:
        lines.append("- No timeline entries were supplied.")
    lines.extend(["", "## Custody limitation", "", "The local JSONL custody record is append-only during ordinary operation but is not cryptographically tamper-proof. SHA-256 detects byte changes when compared with a trusted expected digest; it does not establish legal chain of custody.", ""])
    return "\n".join(lines)

