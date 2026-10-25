"""Compatibility adapters between event artifacts and source readiness."""
from __future__ import annotations

from collections.abc import Sequence

from src.common.models import (
    AvailabilityStatus, ContractError, EvidenceAvailability, EvidenceCandidate,
)


def _validated_pairs(
    candidates: Sequence[EvidenceCandidate], observations: Sequence[EvidenceAvailability]
) -> tuple[dict[str, EvidenceCandidate], dict[str, EvidenceAvailability]]:
    by_id: dict[str, EvidenceCandidate] = {}
    for candidate in candidates:
        if not isinstance(candidate, EvidenceCandidate):
            raise ContractError("candidates must contain EvidenceCandidate records")
        if candidate.evidence_id in by_id:
            raise ContractError(f"duplicate candidate evidence ID: {candidate.evidence_id}")
        by_id[candidate.evidence_id] = candidate
    availability: dict[str, EvidenceAvailability] = {}
    for item in observations:
        if not isinstance(item, EvidenceAvailability):
            raise ContractError("availability must contain EvidenceAvailability records")
        if item.evidence_id in availability:
            raise ContractError(f"duplicate availability evidence ID: {item.evidence_id}")
        if item.evidence_id not in by_id:
            raise ContractError(f"availability references unknown evidence: {item.evidence_id}")
        availability[item.evidence_id] = item
    missing = set(by_id) - set(availability)
    if missing:
        raise ContractError(f"availability is missing candidate evidence IDs: {sorted(missing)}")
    return by_id, availability


def availability_flags(
    candidates: Sequence[EvidenceCandidate], observations: Sequence[EvidenceAvailability]
) -> dict[str, bool]:
    """Return an exact eligibility map; unknown records are rejected, never assumed available."""
    by_id, availability = _validated_pairs(candidates, observations)
    eligible = {AvailabilityStatus.AVAILABLE, AvailabilityStatus.COLLECTED}
    return {evidence_id: availability[evidence_id].availability_status in eligible for evidence_id in by_id}


def aggregate_source_availability(
    candidates: Sequence[EvidenceCandidate], observations: Sequence[EvidenceAvailability]
) -> tuple[list[EvidenceAvailability], dict[str, tuple[str, ...]]]:
    """Aggregate artifacts by source using the documented source-presence policy.

    A source is AVAILABLE when at least one artifact is available, otherwise COLLECTED
    when at least one is collected, otherwise UNAVAILABLE. This establishes presence,
    not completeness. The returned trace maps each source to its sorted artifact IDs.
    """
    by_id, availability = _validated_pairs(candidates, observations)
    grouped: dict[str, list[str]] = {}
    for evidence_id, candidate in by_id.items():
        grouped.setdefault(candidate.source_type, []).append(evidence_id)
    aggregate: list[EvidenceAvailability] = []
    trace: dict[str, tuple[str, ...]] = {}
    for source in sorted(grouped):
        ids = tuple(sorted(grouped[source]))
        trace[source] = ids
        records = [availability[item] for item in ids]
        states = {item.availability_status for item in records}
        if AvailabilityStatus.AVAILABLE in states:
            status = AvailabilityStatus.AVAILABLE
        elif AvailabilityStatus.COLLECTED in states:
            status = AvailabilityStatus.COLLECTED
        else:
            status = AvailabilityStatus.UNAVAILABLE
        observed_at = max(item.observed_at for item in records)
        aggregate.append(EvidenceAvailability(source, status, observed_at))
    return aggregate, trace
