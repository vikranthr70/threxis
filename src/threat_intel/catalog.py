"""Small verified offline MITRE ATT&CK catalog."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.common.models import ContractError

CATALOG_PATH = Path(__file__).resolve().parents[2] / "config" / "threat_profiles" / "attack_catalog.json"


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    summary: str
    official_url: str
    attack_dataset_version: str
    technique_version: str
    retrieved_at: str
    revoked: bool
    deprecated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id, "name": self.name,
            "tactics": list(self.tactics), "summary": self.summary,
            "official_url": self.official_url,
            "attack_dataset_version": self.attack_dataset_version,
            "technique_version": self.technique_version,
            "retrieved_at": self.retrieved_at, "revoked": self.revoked,
            "deprecated": self.deprecated,
        }


def load_attack_catalog(path: Path = CATALOG_PATH) -> dict[str, AttackTechnique]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid ATT&CK catalog: {path}") from exc
    if payload.get("source") != "MITRE ATT&CK Enterprise":
        raise ContractError("catalog source must be MITRE ATT&CK Enterprise")
    dataset_version, retrieved_at = payload.get("attack_dataset_version"), payload.get("retrieved_at")
    if not isinstance(dataset_version, str) or not isinstance(retrieved_at, str):
        raise ContractError("catalog must record dataset version and retrieval date")
    catalog: dict[str, AttackTechnique] = {}
    for raw in payload.get("techniques", []):
        try:
            item = AttackTechnique(
                raw["technique_id"], raw["name"], tuple(raw["tactics"]), raw["summary"],
                raw["official_url"], dataset_version, raw["technique_version"], retrieved_at,
                bool(raw.get("revoked", False)), bool(raw.get("deprecated", False)),
            )
        except (KeyError, TypeError) as exc:
            raise ContractError("malformed ATT&CK technique record") from exc
        if item.technique_id in catalog or not item.technique_id.startswith("T"):
            raise ContractError(f"duplicate or invalid technique ID: {item.technique_id}")
        if not item.official_url.startswith("https://attack.mitre.org/techniques/"):
            raise ContractError(f"non-official ATT&CK URL for {item.technique_id}")
        catalog[item.technique_id] = item
    if not catalog:
        raise ContractError("ATT&CK catalog is empty")
    return catalog


def get_technique(technique_id: str) -> AttackTechnique:
    try:
        return load_attack_catalog()[technique_id]
    except KeyError as exc:
        raise ContractError(f"unsupported ATT&CK technique: {technique_id}") from exc

