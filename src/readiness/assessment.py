"""Weighted evidence-availability readiness assessment."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from src.common.models import AvailabilityStatus, ContractError, EvidenceAvailability, ReadinessAssessment, ThreatProfile
from src.threat_intel.profiles import load_profile_metadata

STATUS_FACTORS = {"available": 0.60, "collected": 0.85, "validated": 1.00, "missing": 0.00, "unknown": 0.00, "not_applicable": None}


def _shared_status(status: AvailabilityStatus) -> str:
    if status is AvailabilityStatus.AVAILABLE:
        return "available"
    if status is AvailabilityStatus.COLLECTED:
        return "collected"
    return "missing"


def assess_readiness(profile: ThreatProfile, availability: Sequence[EvidenceAvailability]) -> ReadinessAssessment:
    """Return compact shared result; evidence_id identifies a source requirement."""
    statuses: dict[str, str] = {}
    for item in availability:
        if not isinstance(item, EvidenceAvailability):
            raise ContractError("availability must contain EvidenceAvailability records")
        if item.evidence_id in statuses:
            raise ContractError(f"duplicate availability entry: {item.evidence_id}")
        statuses[item.evidence_id] = _shared_status(item.availability_status)
    details = assess_readiness_details(profile, statuses)
    return ReadinessAssessment(
        f"readiness-{profile.scenario_id}", profile.scenario_id,
        details["score_fraction"], tuple(details["missing_evidence"]),
    )


def assess_readiness_details(profile: ThreatProfile, statuses: Mapping[str, str]) -> dict[str, object]:
    if not isinstance(profile, ThreatProfile):
        raise ContractError("profile must be a ThreatProfile")
    extra = set(statuses) - set(profile.evidence_weights)
    if extra:
        raise ContractError(f"availability contains unknown source types: {sorted(extra)}")
    invalid = {value for value in statuses.values() if value not in STATUS_FACTORS}
    if invalid:
        raise ContractError(f"unsupported readiness statuses: {sorted(invalid)}")
    numerator = denominator = 0.0
    assessed, missing, unknown = [], [], []
    for source_type, weight in profile.evidence_weights.items():
        status = statuses.get(source_type, "unknown")
        factor, contribution = STATUS_FACTORS[status], 0.0
        if factor is not None:
            denominator += weight
            contribution = weight * factor
            numerator += contribution
        if status == "missing":
            missing.append(source_type)
        elif status == "unknown":
            unknown.append(source_type)
        assessed.append({"source_type": source_type, "weight": weight, "status": status, "status_factor": factor, "weighted_contribution": contribution})
    if denominator <= 0:
        raise ContractError("readiness score is undefined: no applicable evidence requirements")
    score = numerator / denominator
    metadata = load_profile_metadata().get(profile.scenario_id, {})
    actions = [f"Enable and validate collection for {item}." for item in missing]
    actions.extend(f"Confirm whether {item} is available." for item in unknown)
    return {
        "assessment_id": f"readiness-{profile.scenario_id}", "scenario_id": profile.scenario_id,
        "score_fraction": score, "readiness_percentage": 100.0 * score,
        "requirements": assessed, "missing_evidence": missing, "unknown_evidence": unknown,
        "recommended_actions": actions,
        "scoring_explanation": "Weighted status factors: available=0.60, collected=0.85, validated=1.00, missing/unknown=0; not_applicable is excluded. Collected is not assumed validated.",
        "model_limit": "Model-based readiness indicator, not an investigation-success guarantee.",
        "profile_display_name": metadata.get("display_name", profile.scenario_id),
    }

