"""Build deterministic event and alert timelines for one investigation case."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from src.common.models import ContractError, DetectionAlert, InvestigationCase, SecurityEvent, TimelineEntry


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_investigation_timeline(
    case: InvestigationCase,
    events: Sequence[SecurityEvent],
    alerts: Sequence[DetectionAlert],
) -> list[TimelineEntry]:
    """Return chronologically sorted entries and reject unknown/cross-case IDs."""
    if not isinstance(case, InvestigationCase):
        raise ContractError("case must be an InvestigationCase")
    event_list, alert_list = list(events), list(alerts)
    if any(not isinstance(e, SecurityEvent) for e in event_list) or any(not isinstance(a, DetectionAlert) for a in alert_list):
        raise ContractError("events and alerts must contain shared contract records")
    if len({e.event_id for e in event_list}) != len(event_list) or len({a.alert_id for a in alert_list}) != len(alert_list):
        raise ContractError("event and alert IDs must be unique")
    event_map = {event.event_id: event for event in event_list}
    alert_map = {alert.alert_id: alert for alert in alert_list}
    if any(event.scenario_id != case.scenario_id for event in event_list):
        raise ContractError("case and event scenarios do not match")
    if any(alert.scenario_id != case.scenario_id for alert in alert_list):
        raise ContractError("case and alert scenarios do not match")
    if any(alert_id not in alert_map for alert_id in case.alert_ids):
        raise ContractError("case references an unknown alert ID")
    for alert in alert_list:
        if any(event_id not in event_map for event_id in alert.event_ids):
            raise ContractError(f"alert {alert.alert_id!r} references an unknown event ID")

    entries: list[TimelineEntry] = []
    for event in event_list:
        entries.append(TimelineEntry(case.case_id, event.timestamp, "event",
                                     f"Observed synthetic {event.event_type} from {event.source_type}.", (event.event_id,)))
    for alert_id in case.alert_ids:
        alert = alert_map[alert_id]
        entries.append(TimelineEntry(case.case_id, alert.timestamp, "alert",
                                     f"Heuristic alert ({alert.severity.value}): {alert.reason}",
                                     (alert.alert_id,) + tuple(alert.event_ids)))
    entries.append(TimelineEntry(case.case_id, case.opened_at, "case_opened",
                                 f"Investigation case opened with status {case.status}.", (case.case_id,)))
    return sorted(entries, key=lambda entry: (_time(entry.timestamp), entry.entry_type, entry.related_ids))
