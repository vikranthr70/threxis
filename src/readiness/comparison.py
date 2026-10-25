"""Fair same-pool execution of all operational strategies."""

import random
from collections.abc import Sequence

from src.common.models import EvidenceCandidate, EvidenceSelectionResult, SelectionStrategy, ThreatProfile
from .selectors import select_available_evidence, select_evidence


def compare_selection_strategies(candidates: Sequence[EvidenceCandidate], context: ThreatProfile, budget: int, seed: int) -> list[EvidenceSelectionResult]:
    """Run five strategies on identical inputs; caller retains phase-A context for frozen multi-round runs."""
    results = []
    for strategy in SelectionStrategy:
        rng = random.Random(seed) if strategy is SelectionStrategy.RANDOM else None
        results.append(select_evidence(strategy, candidates, context, set(), rng, budget))
    return results


def compare_available_selection_strategies(candidates, context, budget, seed, availability_by_id):
    """Run all frozen baselines on the identical validated eligible pool."""
    results = []
    for strategy in SelectionStrategy:
        rng = random.Random(seed) if strategy is SelectionStrategy.RANDOM else None
        results.append(select_available_evidence(strategy, candidates, context, set(), rng, budget, availability_by_id))
    return results

