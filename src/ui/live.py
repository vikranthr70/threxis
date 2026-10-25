"""Read a local append-only copy of Ubuntu sshd logs for an authorized lab demonstration.

No network listener, shell execution, credentials, or automatic SSH connection.
A separate operator-controlled transport must populate data/live/ubuntu-auth.log.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from src.common.models import SecurityEvent
from src.detection.engine import detect_suspicious_activity

LOG_PATH = Path(__file__).resolve().parents[2] / "data" / "live" / "ubuntu-auth.log"
# Ubuntu/OpenSSH journal messages and /var/log/auth.log lines.
FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>[^ ]+) from "
    r"(?P<ip>[0-9a-fA-F:.]+) port [0-9]+ ssh2", re.IGNORECASE
)
SYSLOG_DATE = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
                         r"(?P<time>\d\d:\d\d:\d\d)")
ISO_DATE = re.compile(r"^(?P<time>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?"
                      r"(?:Z|[+-]\d\d:\d\d))")


def _time(line: str, fallback: datetime) -> str:
    iso = ISO_DATE.match(line)
    if iso:
        try:
            return datetime.fromisoformat(iso.group("time").replace("Z", "+00:00")).isoformat()
        except ValueError:
            pass
    match = SYSLOG_DATE.match(line)
    if match:
        try:
            return datetime.strptime(
                f"{fallback.year} {match.group('month')} {match.group('day')} {match.group('time')}",
                "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=fallback.tzinfo).isoformat()
        except ValueError:
            pass
    return fallback.isoformat()


def read_auth_events(path: Path = LOG_PATH, limit: int = 2000) -> list[SecurityEvent]:
    """Parse SSH failures without inventing success events or other telemetry."""
    if limit < 1 or limit > 10000:
        raise ValueError("limit must be 1..10000")
    if not path.is_file():
        return []
    # Read only a bounded tail. Do not load unbounded log files into memory.
    from collections import deque
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = list(deque(handle, maxlen=limit))
    fallback = datetime.now(timezone.utc)
    output = []
    for position, line in enumerate(lines):
        match = FAILED.search(line)
        if not match:
            continue
        digest = hashlib.sha256(f"{position}|{line}".encode("utf-8")).hexdigest()[:24]
        output.append(SecurityEvent(
            event_id=f"ubuntu-{digest}",
            timestamp=_time(line, fallback),
            event_type="ssh_failed_password",
            source_type="authentication_log",
            scenario_id="suspicious_authentication",
            attributes={"user": match.group("user"), "source_ip": match.group("ip"),
                        "result": "failure", "host": "ubuntu-lab-vm",
                        "collection_cost": 1, "evidence_available": True},
        ))
    return output


def monitor_snapshot(path: Path = LOG_PATH) -> dict:
    events = read_auth_events(path)
    return {"events": events, "alerts": detect_suspicious_activity(events),
            "path_exists": path.is_file()}
