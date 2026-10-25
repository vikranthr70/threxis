"""Deterministic rule-supported correlation of synthetic events."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime

from src.common.models import ContractError, SecurityEvent


def _time(event: SecurityEvent) -> datetime:
    return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))


def correlate_events(events: Sequence[SecurityEvent], max_window_minutes: int = 60) -> list[dict[str, object]]:
    records = sorted(events, key=lambda item: (_time(item), item.event_id))
    if any(not isinstance(item, SecurityEvent) for item in records):
        raise ContractError("events must contain SecurityEvent records")
    if len({item.event_id for item in records}) != len(records):
        raise ContractError("event IDs must be unique")
    groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in records:
        host, user = event.attributes.get("host"), event.attributes.get("user")
        if isinstance(host, str): groups[("host", host)].append(event)
        if isinstance(user, str): groups[("account", user)].append(event)
    output = []
    for (kind, value), group in sorted(groups.items()):
        if len(group) < 2 or (_time(group[-1]) - _time(group[0])).total_seconds() > max_window_minutes * 60:
            continue
        types = {item.event_type for item in group}
        indicators = [f"same_{kind}:{value}"]
        failures = [index for index, item in enumerate(group) if item.event_type == "ssh_failed_password"]
        successes = [index for index, item in enumerate(group) if item.event_type in {"ssh_login", "ssh_login_success"}]
        files = [index for index, item in enumerate(group) if item.event_type.startswith("file_") or item.event_type == "data_access"]
        outbound = [index for index, item in enumerate(group) if item.event_type in {"network_connection", "outbound_transfer"}]
        if len(failures) >= 2 and successes and min(successes) > min(failures):
            indicators.append("authentication_failures_followed_by_success")
        if successes and files and max(files) > min(successes):
            indicators.append("file_activity_after_authentication")
        if files and outbound and max(outbound) > min(files):
            indicators.append("outbound_transfer_after_file_activity")
        ids = tuple(item.event_id for item in group)
        token = hashlib.sha256((kind + value + "|".join(ids)).encode()).hexdigest()[:16]
        output.append({"correlation_id": f"COR-{token}", "related_event_ids": list(ids),
                       "time_window": {"start": group[0].timestamp, "end": group[-1].timestamp},
                       "supporting_indicators": indicators,
                       "explanation": f"Synthetic events share {kind} {value}; correlation supports review but does not prove compromise.",
                       "rule_support_level": "strong" if len(indicators) >= 3 else "moderate"})
    return output
