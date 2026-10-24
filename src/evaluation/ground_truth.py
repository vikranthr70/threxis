"""Evaluator-only relevance contract, deliberately outside runtime models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GroundTruthLabel:
    evidence_id: str
    phase: str
    relevant: bool

