"""Ordinary append-only audit records for evidence actions (not tamper-proof)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from src.common.models import ContractError
from .vault import verify_evidence


def record_verification(path: Path, expected_sha256: str, evidence_id: str, audit_path: Path) -> dict[str, object]:
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        raise ContractError("evidence_id must be non-empty")
    result = verify_evidence(path, expected_sha256)
    record = {"evidence_id": evidence_id,
              "timestamp": datetime.now(timezone.utc).isoformat(),
              "source_reference": str(Path(path).resolve()),
              "preservation_destination": str(Path(path).resolve()),
              "sha256": expected_sha256.lower(), "collection_action": None,
              "verification_action": "sha256_recalculation", "verification_result": result}
    audit_path = Path(audit_path)
    if audit_path.is_symlink():
        raise ContractError("audit path may not be a symlink")
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8", newline="") as stream:
        stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return record


def read_audit_trail(path: Path) -> list[dict[str, object]]:
    path = Path(path)
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ContractError("audit trail contains invalid JSON") from exc
        if not isinstance(item, dict):
            raise ContractError("audit trail records must be objects")
        records.append(item)
    return records
