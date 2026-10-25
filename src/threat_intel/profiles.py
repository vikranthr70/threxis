"""Config-backed threat profiles using shared integration models."""

from __future__ import annotations

import json
from pathlib import Path

from src.common.models import ContractError, SCENARIO_IDS, ThreatProfile
from .catalog import load_attack_catalog

PROFILES_PATH = Path(__file__).resolve().parents[2] / "config" / "threat_profiles" / "profiles.json"


def load_threat_profiles(path: Path = PROFILES_PATH) -> dict[str, ThreatProfile]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid threat profile configuration: {path}") from exc
    catalog, profiles = load_attack_catalog(), {}
    if not isinstance(payload.get("profiles"), list):
        raise ContractError("profiles must be a list")
    for raw in payload["profiles"]:
        try:
            scenario_id, technique_ids = raw["scenario_id"], tuple(raw["technique_ids"])
            profile = ThreatProfile(raw["profile_id"], scenario_id, technique_ids, dict(raw["evidence_weights"]))
        except (KeyError, TypeError, ContractError) as exc:
            raise ContractError("malformed threat profile") from exc
        if scenario_id in profiles:
            raise ContractError(f"duplicate scenario profile: {scenario_id}")
        unknown = set(technique_ids) - set(catalog)
        if unknown:
            raise ContractError(f"profile references unknown techniques: {sorted(unknown)}")
        profiles[scenario_id] = profile
    if set(profiles) != set(SCENARIO_IDS):
        raise ContractError("configuration must define exactly the shared scenarios")
    return profiles


def get_threat_profile(scenario_id: str) -> ThreatProfile:
    try:
        return load_threat_profiles()[scenario_id]
    except KeyError as exc:
        raise ContractError(f"unsupported scenario_id: {scenario_id}") from exc


def load_profile_metadata(path: Path = PROFILES_PATH) -> dict[str, dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return {item["scenario_id"]: item for item in payload["profiles"]}
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ContractError(f"invalid threat profile metadata: {path}") from exc

