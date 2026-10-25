"""Deterministic, ground-truth-independent heuristic detections."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta

from src.common.models import ContractError, DetectionAlert, SCENARIO_IDS, SecurityEvent, Severity

_AUTH_WINDOW = timedelta(minutes=5)
_SUCCESS_WINDOW = timedelta(minutes=15)
_FILE_WINDOW = timedelta(minutes=2)
_EXFIL_WINDOW = timedelta(minutes=10)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _alert(rule_id: str, scenario_id: str, events: Sequence[SecurityEvent], severity: Severity, reason: str) -> DetectionAlert:
    ordered = sorted(events, key=lambda event: (_parse_time(event.timestamp), event.event_id))
    ids = tuple(event.event_id for event in ordered)
    token = hashlib.sha256((rule_id + "|" + "|".join(ids)).encode("utf-8")).hexdigest()[:16]
    return DetectionAlert(
        alert_id=f"ALT-{rule_id}-{token}", event_ids=ids,
        timestamp=ordered[-1].timestamp, severity=severity,
        scenario_id=scenario_id, reason=reason,
    )


def _in_window(events: Sequence[SecurityEvent], window: timedelta) -> list[list[SecurityEvent]]:
    ordered = sorted(events, key=lambda e: (_parse_time(e.timestamp), e.event_id))
    groups: list[list[SecurityEvent]] = []
    left = 0
    for right, event in enumerate(ordered):
        while _parse_time(event.timestamp) - _parse_time(ordered[left].timestamp) > window:
            left += 1
        if right - left + 1 >= 3:
            groups.append(ordered[left:right + 1])
    # Keep only maximal windows to avoid emitting several alerts for one burst.
    maximal: list[list[SecurityEvent]] = []
    for group in groups:
        ids = {event.event_id for event in group}
        if not any(ids < {event.event_id for event in other} for other in groups):
            if not any(ids == {event.event_id for event in prev} for prev in maximal):
                maximal.append(group)
    return maximal


def detect_suspicious_activity(events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
    """Apply the four fixed demo rules to a single scenario's shared events."""
    if isinstance(events, (str, bytes)):
        raise ContractError("events must be a sequence of SecurityEvent records")
    try:
        items = list(events)
    except TypeError as exc:
        raise ContractError("events must be a sequence of SecurityEvent records") from exc
    if any(not isinstance(event, SecurityEvent) for event in items):
        raise ContractError("events must contain only SecurityEvent records")
    if not items:
        return []
    scenarios = {event.scenario_id for event in items}
    if len(scenarios) != 1 or not scenarios.issubset(SCENARIO_IDS):
        raise ContractError("events must belong to exactly one supported scenario")
    if len({event.event_id for event in items}) != len(items):
        raise ContractError("event IDs must be unique")
    scenario = next(iter(scenarios))
    alerts: list[DetectionAlert] = []

    if scenario == "suspicious_authentication":
        failures = [e for e in items if e.event_type == "ssh_failed_password" and e.attributes.get("result") == "failure"]
        by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in failures:
            ip = event.attributes.get("source_ip")
            if isinstance(ip, str):
                by_ip[ip].append(event)
        for ip, group in sorted(by_ip.items()):
            for window in _in_window(group, _AUTH_WINDOW):
                alerts.append(_alert("AUTH-REPEATED-FAILURES", scenario, window, Severity.HIGH,
                                     f"At least three failed SSH password attempts from {ip} occurred within five minutes; this pattern warrants review."))
        successes = [e for e in items if e.event_type in {"ssh_login", "ssh_login_success"} and e.attributes.get("result") == "success"]
        for success in successes:
            ip = success.attributes.get("source_ip")
            prior = [f for f in failures if f.attributes.get("source_ip") == ip and timedelta(0) <= _parse_time(success.timestamp) - _parse_time(f.timestamp) <= _SUCCESS_WINDOW]
            if prior:
                related = sorted(prior, key=lambda e: _parse_time(e.timestamp))[-3:] + [success]
                alerts.append(_alert("AUTH-FAILURE-THEN-SUCCESS", scenario, related, Severity.HIGH,
                                     "A successful SSH login followed failed attempts from the same source within fifteen minutes; the sequence is suspicious but not proof of compromise."))

    elif scenario == "suspicious_file_modification":
        modifications = [e for e in items if e.event_type in {"file_modified", "file_created", "file_deleted"}]
        by_actor: dict[tuple[object, object], list[SecurityEvent]] = defaultdict(list)
        for event in modifications:
            by_actor[(event.attributes.get("host"), event.attributes.get("user"))].append(event)
        for (host, user), group in sorted(by_actor.items(), key=lambda pair: str(pair[0])):
            for window in _in_window(group, _FILE_WINDOW):
                paths = {e.attributes.get("file_path") for e in window}
                proc_ids = {e.attributes.get("process_id") for e in window}
                suspicious_process = any(str(e.attributes.get("process_name", "")).lower() in {"powershell", "wscript", "cscript", "unknown"} for e in window)
                unauthorized = any(e.attributes.get("authorized") is False for e in window)
                if len(paths) >= 2 or len(proc_ids) >= 1 and suspicious_process or unauthorized:
                    alerts.append(_alert("FILE-MODIFICATION-BURST", scenario, window, Severity.HIGH,
                                         f"Multiple file changes by {user or 'an unknown user'} on {host or 'an unknown host'} occurred within two minutes, with correlated process or authorization indicators."))

    else:
        transfers = [e for e in items if e.event_type in {"network_connection", "outbound_transfer"}]
        accesses = [e for e in items if e.event_type in {"data_access", "file_read"}]
        by_host_user: dict[tuple[object, object], list[SecurityEvent]] = defaultdict(list)
        for event in transfers:
            by_host_user[(event.attributes.get("host"), event.attributes.get("user"))].append(event)
        for (host, user), group in sorted(by_host_user.items(), key=lambda pair: str(pair[0])):
            for window in _in_window(group, _EXFIL_WINDOW):
                total = sum(int(e.attributes.get("bytes_sent", 0)) for e in window if isinstance(e.attributes.get("bytes_sent", 0), int))
                peer_set = {e.attributes.get("destination_ip") for e in window}
                related_access = [a for a in accesses if a.attributes.get("host") == host and a.attributes.get("user") == user
                                  and min(abs((_parse_time(a.timestamp) - _parse_time(t.timestamp)).total_seconds()) for t in window) <= _EXFIL_WINDOW.total_seconds()]
                unusual_proc = any(str(e.attributes.get("process_name", "")).lower() in {"unknown-client", "curl", "rclone", "powershell"} for e in window)
                if total >= 10_000_000 and (related_access or unusual_proc or len(peer_set) == 1):
                    alerts.append(_alert("EXFIL-OUTBOUND-VOLUME", scenario, window + related_access, Severity.HIGH,
                                         f"Outbound transfers totaling {total} bytes from {user or 'an unknown user'} on {host or 'an unknown host'} coincide with repeated or unusual transfer behavior; validate business context."))

    # Stable ordering and duplicate suppression make results reproducible.
    unique = {alert.alert_id: alert for alert in alerts}
    return sorted(unique.values(), key=lambda a: (_parse_time(a.timestamp), a.alert_id))


