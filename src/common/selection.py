"""Shared, strategy-neutral budget filling utility."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .models import ContractError


def fill_to_budget(
    ranked_ids: Iterable[str],
    costs: Mapping[str, int],
    round_budget: int,
    already_selected_ids: set[str],
) -> tuple[str, ...]:
    """Apply the frozen skip-non-fitting-and-continue rule."""
    if round_budget < 0:
        raise ContractError("round_budget must be non-negative")
    selected: list[str] = []
    remaining = round_budget
    for evidence_id in ranked_ids:
        if evidence_id in already_selected_ids or evidence_id in selected or evidence_id not in costs:
            continue
        cost = costs[evidence_id]
        if isinstance(cost, bool) or not isinstance(cost, int) or cost <= 0:
            raise ContractError("all costs must be positive integers")
        if cost <= remaining:
            selected.append(evidence_id)
            remaining -= cost
    return tuple(selected)

