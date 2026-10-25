"""Reproducible, entirely artificial security event fixtures."""

from .generator import generate_synthetic_events
from .integration import evidence_inputs_from_events
from .multistage import generate_multistage_demonstration

__all__ = ["generate_synthetic_events", "generate_multistage_demonstration", "evidence_inputs_from_events"]
