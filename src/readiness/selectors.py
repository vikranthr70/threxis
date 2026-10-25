"""Five fair, label-blind evidence ranking strategies."""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence

from src.common.models import ContractError, EvidenceCandidate, EvidenceSelectionResult, SelectionStrategy, ThreatProfile
from src.common.selection import fill_to_budget
from src.threat_intel.profiles import load_threat_profiles

STATIC_PRIORITY = ("authentication_log", "process_creation", "network_flow", "file_access", "dns_log", "powershell_log", "registry_event", "scheduled_task")


def _validate_candidates(candidates: Sequence[EvidenceCandidate]) -> list[EvidenceCandidate]:
    records = list(candidates)
    if any(not isinstance(item, EvidenceCandidate) for item in records):
        raise ContractError("candidates must contain EvidenceCandidate records")
    ids = [item.evidence_id for item in records]
    if len(ids) != len(set(ids)):
        raise ContractError("candidate evidence IDs must be unique")
    return records


def generic_prior_weights() -> dict[str, float]:
    profiles = list(load_threat_profiles().values())
    sources = {key for profile in profiles for key in profile.evidence_weights}
    return {source: sum(profile.evidence_weights.get(source, 0.0) for profile in profiles) / len(profiles) for source in sources}


def rank_candidates(
    strategy: SelectionStrategy, candidates: Sequence[EvidenceCandidate], context: ThreatProfile | None,
    already_selected_ids: set[str], rng: random.Random | None,
) -> list[str]:
    """Return a complete ranking; never inspect labels or fill a budget."""
    if not isinstance(strategy, SelectionStrategy):
        raise ContractError("strategy must be a SelectionStrategy")
    records = [item for item in _validate_candidates(candidates) if item.evidence_id not in already_selected_ids]
    if strategy is SelectionStrategy.RANDOM:
        if rng is None:
            raise ContractError("random strategy requires a seeded random.Random")
        ids = sorted(item.evidence_id for item in records)
        rng.shuffle(ids)
        return ids
    if strategy is SelectionStrategy.STATIC:
        order = {source: index for index, source in enumerate(STATIC_PRIORITY)}
        return [item.evidence_id for item in sorted(records, key=lambda item: (order.get(item.source_type, len(order)), item.evidence_id))]
    if strategy is SelectionStrategy.THREAT_AGNOSTIC:
        weights = generic_prior_weights()
    else:
        if context is None:
            raise ContractError(f"{strategy.value} strategy requires a threat context")
        weights = context.evidence_weights
    return [item.evidence_id for item in sorted(records, key=lambda item: (-(weights.get(item.source_type, 0.0) / item.collection_cost), item.evidence_id))]


def select_evidence(
    strategy: SelectionStrategy, candidates: Sequence[EvidenceCandidate], context: ThreatProfile | None,
    already_selected_ids: set[str], rng: random.Random | None, budget: int,
) -> EvidenceSelectionResult:
    records = _validate_candidates(candidates)
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < 0:
        raise ContractError("budget must be a non-negative integer")
    ranking = rank_candidates(strategy, records, context, already_selected_ids, rng)
    costs = {item.evidence_id: item.collection_cost for item in records}
    selected = fill_to_budget(ranking, costs, budget, already_selected_ids)
    return EvidenceSelectionResult(strategy, selected, budget, sum(costs[item] for item in selected))


def select_available_evidence(
    strategy: SelectionStrategy, candidates: Sequence[EvidenceCandidate], context: ThreatProfile | None,
    already_selected_ids: set[str], rng: random.Random | None, budget: int,
    availability_by_id: Mapping[str, bool],
) -> EvidenceSelectionResult:
    records = _validate_candidates(candidates)
    unknown = set(availability_by_id) - {item.evidence_id for item in records}
    if unknown:
        raise ContractError(f"availability references unknown candidates: {sorted(unknown)}")
    available = [item for item in records if availability_by_id.get(item.evidence_id, False)]
    return select_evidence(strategy, available, context, already_selected_ids, rng, budget)


def explain_selection(result: EvidenceSelectionResult, candidates: Sequence[EvidenceCandidate], context: ThreatProfile | None) -> dict[str, object]:
    by_id = {item.evidence_id: item for item in _validate_candidates(candidates)}
    rows = []
    for evidence_id in result.selected_evidence_ids:
        item = by_id[evidence_id]
        weight = None if context is None else context.evidence_weights.get(item.source_type, 0.0)
        rows.append({
            "evidence_id": evidence_id, "source_type": item.source_type,
            "collection_cost": item.collection_cost, "context_weight": weight,
            "estimated_value_density": None if weight is None else weight / item.collection_cost,
            "explanation": f"Selected by {result.strategy.value} ranking under the shared budget rule.",
        })
    return {
        **result.to_dict(), "remaining_budget": result.budget - result.selected_cost,
        "selected": rows, "context_scenario_id": None if context is None else context.scenario_id,
        "heuristic_limit": "Greedy ranking heuristic; no global-optimality claim.",
    }

