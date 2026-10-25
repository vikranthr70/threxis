"""Reproducible, entirely artificial security event fixtures."""

from .generator import generate_synthetic_events
from .integration import evidence_inputs_from_events

__all__ = ["generate_synthetic_events", "evidence_inputs_from_events"]
