"""Pure post-selection metrics; ground truth enters only this module."""

from collections.abc import Iterable, Mapping
from typing import Optional

from src.common.models import ContractError


def selection_metrics(selected_ids: Iterable[str], relevant_ids: set[str], costs: Mapping[str, int], budget: int, relevance_weights: Optional[Mapping[str, float]] = None) -> dict[str, object]:
    selected = tuple(selected_ids)
    if len(selected) != len(set(selected)):
        raise ContractError("selected IDs must be unique")
    if budget < 0:
        raise ContractError("budget must be non-negative")
    unknown = set(selected) - set(costs)
    if unknown:
        raise ContractError(f"missing costs for selected IDs: {sorted(unknown)}")
    selected_cost = sum(costs[item] for item in selected)
    if selected_cost > budget:
        raise ContractError("selection exceeds budget")
    captured = set(selected).intersection(relevant_ids)
    weighted = None if relevance_weights is None else sum(relevance_weights.get(item, 0.0) for item in captured)
    return {
        "evidence_recall": None if not relevant_ids else len(captured) / len(relevant_ids),
        "evidence_precision": None if not selected else len(captured) / len(selected),
        "collection_cost": selected_cost,
        "budget_utilization": 0.0 if budget == 0 else selected_cost / budget,
        "selected_artifact_count": len(selected), "relevant_evidence_count": len(captured),
        "cost_per_relevant_item": None if not captured else selected_cost / len(captured),
        "relevant_evidence_weight_captured": weighted,
    }

