"""Adapters from normalized events to Person 1's shared readiness inputs."""
from __future__ import annotations

from collections.abc import Sequence

from src.common.models import AvailabilityStatus, ContractError, EvidenceAvailability, EvidenceCandidate, SecurityEvent


def evidence_inputs_from_events(
    events: Sequence[SecurityEvent],
) -> tuple[list[EvidenceCandidate], list[EvidenceAvailability]]:
    """Return selector-safe candidates and separate availability observations."""
    candidates: list[EvidenceCandidate] = []
    availability: list[EvidenceAvailability] = []
    seen: set[str] = set()
    for event in events:
        if not isinstance(event, SecurityEvent):
            raise ContractError("events must contain only SecurityEvent records")
        if event.event_id in seen:
            raise ContractError("event IDs must be unique")
        seen.add(event.event_id)
        cost = event.attributes.get("collection_cost")
        available = event.attributes.get("evidence_available")
        if isinstance(cost, bool) or not isinstance(cost, int) or cost <= 0:
            raise ContractError(f"event {event.event_id!r} has invalid collection_cost metadata")
        if not isinstance(available, bool):
            raise ContractError(f"event {event.event_id!r} has invalid evidence_available metadata")
        candidates.append(EvidenceCandidate(event.event_id, event.source_type, cost))
        availability.append(EvidenceAvailability(
            event.event_id,
            AvailabilityStatus.AVAILABLE if available else AvailabilityStatus.UNAVAILABLE,
            event.timestamp,
        ))
    return candidates, availability
