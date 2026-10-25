"""Five fair, label-blind evidence ranking strategies."""

from __future__ import annotations

import random
import json
from dataclasses import dataclass, field
from pathlib import Path
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


_DEFAULT_PRIORS = Path(__file__).resolve().parents[2] / "data" / "config" / "context_priors.example.json"


def generic_prior_weights(config_path: Path | None = None) -> dict[str, float]:
    """Load and average un-noised context priors, never ground-truth probabilities."""
    path = _DEFAULT_PRIORS if config_path is None else Path(config_path)
    if "truth" in path.name.lower():
        raise ContractError("ground-truth probability configuration cannot supply selection priors")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"unable to load context priors: {path}") from exc
    priors = payload.get("weights", payload.get("phase_context_priors", payload))
    if not isinstance(priors, dict) or not priors:
        raise ContractError("context-prior configuration must contain non-empty mappings")
    rows = list(priors.values())
    if any(not isinstance(row, dict) or not row for row in rows):
        raise ContractError("each context prior must be a non-empty mapping")
    sources = {source for row in rows for source in row}
    for row in rows:
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1 for value in row.values()):
            raise ContractError("context-prior weights must be numeric values in [0, 1]")
    return {source: sum(float(row.get(source, 0.0)) for row in rows) / len(rows) for source in sorted(sources)}


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
    candidate_ids = {item.evidence_id for item in records}
    unknown = set(availability_by_id) - candidate_ids
    if unknown:
        raise ContractError(f"availability references unknown candidates: {sorted(unknown)}")
    missing = candidate_ids - set(availability_by_id)
    if missing:
        raise ContractError(f"availability is missing candidates: {sorted(missing)}")
    if any(type(value) is not bool for value in availability_by_id.values()):
        raise ContractError("availability values must be booleans")
    available = [item for item in records if availability_by_id[item.evidence_id]]
    result = select_evidence(strategy, available, context, already_selected_ids, rng, budget)
    costs = {item.evidence_id: item.collection_cost for item in available}
    recalculated = sum(costs[item] for item in result.selected_evidence_ids)
    if recalculated != result.selected_cost or recalculated > budget:
        raise ContractError("selector returned an inconsistent or over-budget result")
    return result


def explain_selection(result: EvidenceSelectionResult, candidates: Sequence[EvidenceCandidate], context: ThreatProfile | None) -> dict[str, object]:
    by_id = {item.evidence_id: item for item in _validate_candidates(candidates)}
    ranking = rank_candidates(result.strategy, candidates, context, set(), random.Random(0) if result.strategy is SelectionStrategy.RANDOM else None)
    rows = []
    running_cost = 0
    selected_ids = set(result.selected_evidence_ids)
    for position, evidence_id in enumerate(ranking, 1):
        item = by_id[evidence_id]
        weight = None if context is None else context.evidence_weights.get(item.source_type, 0.0)
        selected = evidence_id in selected_ids
        if selected:
            running_cost += item.collection_cost
        rows.append({
            "evidence_id": evidence_id, "source_type": item.source_type,
            "collection_cost": item.collection_cost, "context_weight": weight,
            "estimated_relevance_per_cost_score": None if weight is None else weight / item.collection_cost,
            "ranking_position": position, "selected": selected,
            "selection_or_exclusion_reason": (
                f"Selected by {result.strategy.value} under the shared budget rule."
                if selected else "Excluded because it was not selected within the budget."
            ),
            "budget_impact": item.collection_cost if selected else 0,
        })
    return {
        **result.to_dict(), "remaining_budget": result.budget - result.selected_cost,
        "ranked_candidates": rows, "context_scenario_id": None if context is None else context.scenario_id,
        "heuristic_limit": "Greedy ranking weights are ordinal judgments, not calibrated probabilities.",
    }


def severity_aware_rank_candidates(
    candidates: Sequence[EvidenceCandidate], context: ThreatProfile, severity_by_source: Mapping[str, float]
) -> list[str]:
    """Opt-in experimental ranker; does not alter any frozen baseline."""
    records = _validate_candidates(candidates)
    unknown = set(severity_by_source) - {item.source_type for item in records}
    if unknown:
        raise ContractError(f"severity references unknown source types: {sorted(unknown)}")
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1 for value in severity_by_source.values()):
        raise ContractError("severity inputs must be numeric values in [0, 1]")
    return [item.evidence_id for item in sorted(records, key=lambda item: (
        -(context.evidence_weights.get(item.source_type, 0.0) * (1.0 + float(severity_by_source.get(item.source_type, 0.0))) / item.collection_cost),
        item.evidence_id,
    ))]


def analyze_context_change(before: ThreatProfile, after: ThreatProfile) -> dict[str, object]:
    sources = sorted(set(before.evidence_weights) | set(after.evidence_weights))
    old_rank = sorted(sources, key=lambda source: (-before.evidence_weights.get(source, 0.0), source))
    new_rank = sorted(sources, key=lambda source: (-after.evidence_weights.get(source, 0.0), source))
    old_positions, new_positions = ({v: i + 1 for i, v in enumerate(old_rank)}, {v: i + 1 for i, v in enumerate(new_rank)})
    changes = [{"source_type": source, "before_weight": before.evidence_weights.get(source, 0.0),
                "after_weight": after.evidence_weights.get(source, 0.0), "before_rank": old_positions[source],
                "after_rank": new_positions[source]} for source in sources]
    return {"changed_evidence_weights": [item for item in changes if item["before_weight"] != item["after_weight"]],
            "changed_evidence_rankings": [item for item in changes if item["before_rank"] != item["after_rank"]],
            "newly_prioritized_sources": sorted(item["source_type"] for item in changes if item["after_rank"] < item["before_rank"]),
            "deprioritized_sources": sorted(item["source_type"] for item in changes if item["after_rank"] > item["before_rank"]),
            "explanation": "Rank changes reflect context weights only; they are not probabilities."}


@dataclass
class ContextSelectionState:
    """Stateful helper distinguishing adaptive and frozen-context behavior."""
    initial_context: ThreatProfile
    already_selected_ids: set[str] = field(default_factory=set)

    def select(self, strategy: SelectionStrategy, candidates: Sequence[EvidenceCandidate], current_context: ThreatProfile,
               budget: int, rng: random.Random | None = None) -> EvidenceSelectionResult:
        if strategy not in {SelectionStrategy.ADAPTIVE, SelectionStrategy.FROZEN_CONTEXT_ADAPTIVE}:
            raise ContractError("ContextSelectionState supports adaptive strategies only")
        context = self.initial_context if strategy is SelectionStrategy.FROZEN_CONTEXT_ADAPTIVE else current_context
        result = select_evidence(strategy, candidates, context, self.already_selected_ids, rng, budget)
        self.already_selected_ids.update(result.selected_evidence_ids)
        return result

