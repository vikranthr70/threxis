"""Seeded demo events with ground truth on a separate evaluator-only path.

These three scenario fixtures are for the detection demonstration only; they
are not the Architecture Pack's phase-pair experiment candidate generator.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from src.common.models import ContractError, SCENARIO_IDS, SecurityEvent
from src.evaluation.ground_truth import GroundTruthLabel

_BASE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
_DOC_IPS = ("192.0.2.10", "198.51.100.23", "203.0.113.42")


def _subseed(seed: int, scenario_id: str, stream: str, index: int = 0) -> int:
    payload = f"{seed}|{scenario_id}|{stream}|{index}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest(), "big")


def _templates(scenario_id: str) -> list[tuple[str, str, dict[str, object], bool]]:
    """Return event type, source type, safe attributes, and private relevance."""
    if scenario_id == "suspicious_authentication":
        return [
            ("ssh_login", "authentication_log", {"user": "analyst", "source_ip": _DOC_IPS[0], "result": "success"}, False),
            ("ssh_failed_password", "authentication_log", {"user": "admin", "source_ip": _DOC_IPS[1], "result": "failure"}, True),
            ("ssh_failed_password", "authentication_log", {"user": "admin", "source_ip": _DOC_IPS[1], "result": "failure"}, True),
            ("ssh_failed_password", "authentication_log", {"user": "admin", "source_ip": _DOC_IPS[1], "result": "failure"}, True),
            ("ssh_login", "authentication_log", {"user": "admin", "source_ip": _DOC_IPS[1], "result": "success"}, True),
            ("session_open", "authentication_log", {"user": "admin", "source_ip": _DOC_IPS[1], "result": "opened"}, True),
        ]
    if scenario_id == "suspicious_file_modification":
        return [
            ("file_modified", "file_audit_log", {"user": "analyst", "host": "workstation-01", "file_path": "/home/analyst/notes.txt", "process_name": "text-editor", "process_id": 410, "authorized": True}, False),
            ("process_started", "process_audit_log", {"user": "svc-backup", "host": "server-02", "process_name": "powershell", "process_id": 880, "parent_process": "wscript"}, True),
            ("file_modified", "file_audit_log", {"user": "svc-backup", "host": "server-02", "file_path": "/srv/config/app.yml", "process_name": "powershell", "process_id": 880, "authorized": False}, True),
            ("file_modified", "file_audit_log", {"user": "svc-backup", "host": "server-02", "file_path": "/srv/config/agent.yml", "process_name": "powershell", "process_id": 880, "authorized": False}, True),
            ("file_modified", "file_audit_log", {"user": "svc-backup", "host": "server-02", "file_path": "/etc/cron.d/task", "process_name": "powershell", "process_id": 880, "authorized": False}, True),
        ]
    return [
        ("network_connection", "network_flow", {"user": "analyst", "host": "workstation-01", "destination_ip": _DOC_IPS[0], "destination_port": 443, "bytes_sent": 1200, "process_name": "browser"}, False),
        ("data_access", "file_audit_log", {"user": "svc-report", "host": "server-03", "data_path": "/srv/reports/customer-export.csv", "bytes_read": 8_000_000, "process_name": "python"}, True),
        ("network_connection", "network_flow", {"user": "svc-report", "host": "server-03", "destination_ip": _DOC_IPS[2], "destination_port": 8443, "bytes_sent": 12_000_000, "process_name": "unknown-client"}, True),
        ("network_connection", "network_flow", {"user": "svc-report", "host": "server-03", "destination_ip": _DOC_IPS[2], "destination_port": 8443, "bytes_sent": 11_000_000, "process_name": "unknown-client"}, True),
        ("network_connection", "network_flow", {"user": "svc-report", "host": "server-03", "destination_ip": _DOC_IPS[2], "destination_port": 8443, "bytes_sent": 10_000_000, "process_name": "unknown-client"}, True),
    ]


def generate_synthetic_events(
    scenario_id: str, count: int, seed: int
) -> tuple[list[SecurityEvent], list[GroundTruthLabel]]:
    """Generate deterministic records and separate evaluator-only labels.

    Event IDs are assigned after a deterministic shuffle and are random-looking
    tokens. Collection-cost draws use an independent SHA-256-derived random
    stream, separate from the scenario's private relevance sequence.
    """
    if scenario_id not in SCENARIO_IDS:
        raise ContractError(f"unsupported scenario_id: {scenario_id!r}")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ContractError("count must be a positive integer")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ContractError("seed must be an integer")

    templates = _templates(scenario_id)
    timing_rng = random.Random(_subseed(seed, scenario_id, "timing"))
    rows: list[dict[str, object]] = []
    offset = 0
    for index in range(count):
        event_type, source_type, base_attrs, relevant = templates[index % len(templates)]
        attrs = dict(base_attrs)
        if "source_ip" not in attrs:
            attrs["source_ip"] = random.Random(_subseed(seed, scenario_id, "address", index)).choice(_DOC_IPS)
        cost_rng = random.Random(_subseed(seed, scenario_id, "cost", index))
        attrs["collection_cost"] = cost_rng.randint(1, 5)
        attrs["evidence_available"] = True
        offset += timing_rng.randint(5, 22) if relevant else timing_rng.randint(600, 1800)
        timestamp = (_BASE_TIME + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
        rows.append({
            "ordinal": index, "timestamp": timestamp, "event_type": event_type,
            "source_type": source_type, "attributes": attrs, "relevant": relevant,
        })

    # IDs are assigned only after shuffling, so numeric order cannot expose
    # the generation sequence. Re-sort by time for convenient demo consumption.
    shuffled = list(rows)
    random.Random(_subseed(seed, scenario_id, "id-order")).shuffle(shuffled)
    id_rng = random.Random(_subseed(seed, scenario_id, "ids"))
    for row in shuffled:
        row["event_id"] = f"evt-{id_rng.getrandbits(128):032x}"

    ordered = sorted(rows, key=lambda row: (str(row["timestamp"]), str(row["event_id"])))
    events: list[SecurityEvent] = []
    labels: list[GroundTruthLabel] = []
    for row in ordered:
        event_id = str(row["event_id"])
        events.append(SecurityEvent(
            event_id=event_id,
            timestamp=str(row["timestamp"]),
            event_type=str(row["event_type"]),
            source_type=str(row["source_type"]),
            scenario_id=scenario_id,
            attributes=dict(row["attributes"]),
        ))
        labels.append(GroundTruthLabel(
            evidence_id=event_id, phase=scenario_id, relevant=bool(row["relevant"]),
        ))
    return events, labels
