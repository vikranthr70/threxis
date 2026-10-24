"""Dependency-free shared data contracts for all three implementation lanes."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar, Mapping, Optional, Sequence


SCHEMA_VERSION = "1.0"


class ContractError(ValueError):
    """Raised when a record violates a shared contract."""


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AvailabilityStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    COLLECTED = "collected"


class SelectionStrategy(str, Enum):
    STATIC = "static"
    RANDOM = "random"
    THREAT_AGNOSTIC = "threat_agnostic"
    ADAPTIVE = "adaptive"
    FROZEN_CONTEXT_ADAPTIVE = "frozen_context_adaptive"


SCENARIO_IDS = frozenset(
    {
        "suspicious_authentication",
        "suspicious_file_modification",
        "potential_exfiltration",
    }
)


def _required_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be a non-empty string")


def _timestamp(value: str) -> None:
    _required_text("timestamp", value)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContractError("timestamp must include an explicit timezone")


def _schema(value: str) -> None:
    if value != SCHEMA_VERSION:
        raise ContractError(f"schema_version must be {SCHEMA_VERSION!r}")


def _scenario(value: str) -> None:
    if value not in SCENARIO_IDS:
        raise ContractError(f"unsupported scenario_id: {value!r}")


class JsonRecord:
    """Mixin for deterministic JSON-compatible dictionaries."""

    def to_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, tuple):
                return [convert(item) for item in value]
            if isinstance(value, dict):
                return {key: convert(item) for key, item in value.items()}
            return value

        payload = {key: convert(value) for key, value in asdict(self).items()}
        payload.setdefault("schema_version", getattr(self, "schema_version", SCHEMA_VERSION))
        return payload


@dataclass(frozen=True)
class SecurityEvent(JsonRecord):
    event_id: str
    timestamp: str
    event_type: str
    source_type: str
    scenario_id: str
    attributes: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in ("event_id", "event_type", "source_type"):
            _required_text(name, getattr(self, name))
        _timestamp(self.timestamp)
        _scenario(self.scenario_id)
        forbidden = {"relevant", "label", "ground_truth", "malicious"}
        if forbidden.intersection(self.attributes):
            raise ContractError("runtime event attributes must not contain truth labels")


@dataclass(frozen=True)
class DetectionAlert(JsonRecord):
    alert_id: str
    event_ids: tuple[str, ...]
    timestamp: str
    severity: Severity
    scenario_id: str
    reason: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("alert_id", self.alert_id)
        _required_text("reason", self.reason)
        if not self.event_ids or any(not item for item in self.event_ids):
            raise ContractError("event_ids must contain stable IDs")
        _timestamp(self.timestamp)
        _scenario(self.scenario_id)


@dataclass(frozen=True)
class ThreatMapping(JsonRecord):
    alert_id: str
    technique_id: str
    confidence: float
    rationale: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("alert_id", self.alert_id)
        if not self.technique_id.startswith("T"):
            raise ContractError("technique_id must be an ATT&CK-style T identifier")
        if not 0.0 <= self.confidence <= 1.0:
            raise ContractError("confidence must be in [0, 1]")
        _required_text("rationale", self.rationale)


@dataclass(frozen=True)
class ThreatProfile(JsonRecord):
    profile_id: str
    scenario_id: str
    technique_ids: tuple[str, ...]
    evidence_weights: Mapping[str, float]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("profile_id", self.profile_id)
        _scenario(self.scenario_id)
        if any(not item.startswith("T") for item in self.technique_ids):
            raise ContractError("all technique_ids must be ATT&CK-style T identifiers")
        if not self.evidence_weights or any(not 0.0 <= value <= 1.0 for value in self.evidence_weights.values()):
            raise ContractError("evidence_weights must be non-empty values in [0, 1]")


@dataclass(frozen=True)
class EvidenceCandidate(JsonRecord):
    """Strict selector allowlist. Never add labels or scenario/generator IDs."""

    evidence_id: str
    source_type: str
    collection_cost: int
    schema_version: ClassVar[str] = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _required_text("evidence_id", self.evidence_id)
        _required_text("source_type", self.source_type)
        if isinstance(self.collection_cost, bool) or self.collection_cost <= 0:
            raise ContractError("collection_cost must be a positive integer")


@dataclass(frozen=True)
class EvidenceAvailability(JsonRecord):
    evidence_id: str
    availability_status: AvailabilityStatus
    observed_at: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("evidence_id", self.evidence_id)
        _timestamp(self.observed_at)


@dataclass(frozen=True)
class ReadinessAssessment(JsonRecord):
    assessment_id: str
    scenario_id: str
    score: float
    missing_source_types: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("assessment_id", self.assessment_id)
        _scenario(self.scenario_id)
        if not 0.0 <= self.score <= 1.0:
            raise ContractError("score must be in [0, 1]")


@dataclass(frozen=True)
class EvidenceSelectionResult(JsonRecord):
    strategy: SelectionStrategy
    selected_evidence_ids: tuple[str, ...]
    budget: int
    selected_cost: int
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        if self.budget < 0 or self.selected_cost < 0 or self.selected_cost > self.budget:
            raise ContractError("selected_cost must be between zero and budget")
        if len(set(self.selected_evidence_ids)) != len(self.selected_evidence_ids):
            raise ContractError("selected_evidence_ids must be unique")


@dataclass(frozen=True)
class EvidenceManifest(JsonRecord):
    manifest_id: str
    evidence_id: str
    collected_at: str
    sha256: str
    source_path: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("manifest_id", self.manifest_id)
        _required_text("evidence_id", self.evidence_id)
        _timestamp(self.collected_at)
        if len(self.sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in self.sha256):
            raise ContractError("sha256 must be 64 hexadecimal characters")
        _required_text("source_path", self.source_path)


@dataclass(frozen=True)
class InvestigationCase(JsonRecord):
    case_id: str
    scenario_id: str
    alert_ids: tuple[str, ...]
    opened_at: str
    status: str = "open"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("case_id", self.case_id)
        _scenario(self.scenario_id)
        _timestamp(self.opened_at)
        if self.status not in {"open", "closed"}:
            raise ContractError("status must be 'open' or 'closed'")


@dataclass(frozen=True)
class TimelineEntry(JsonRecord):
    case_id: str
    timestamp: str
    entry_type: str
    summary: str
    related_ids: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("case_id", self.case_id)
        _timestamp(self.timestamp)
        _required_text("entry_type", self.entry_type)
        _required_text("summary", self.summary)


@dataclass(frozen=True)
class EvaluationResult(JsonRecord):
    run_id: str
    strategy: SelectionStrategy
    scenario_id: str
    selected_evidence_ids: tuple[str, ...]
    evidence_recall: Optional[float]
    evidence_precision: Optional[float]
    collection_cost: int
    budget_utilization: float
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _required_text("run_id", self.run_id)
        _scenario(self.scenario_id)
        for name in ("evidence_recall", "evidence_precision"):
            value = getattr(self, name)
            if value is not None and not 0.0 <= value <= 1.0:
                raise ContractError(f"{name} must be None or in [0, 1]")
        if self.collection_cost < 0 or not 0.0 <= self.budget_utilization <= 1.0:
            raise ContractError("invalid cost or budget utilization")


__all__ = [
    "SCHEMA_VERSION", "SCENARIO_IDS", "ContractError", "Severity",
    "AvailabilityStatus", "SelectionStrategy", "SecurityEvent",
    "DetectionAlert", "ThreatMapping", "ThreatProfile", "EvidenceCandidate",
    "EvidenceAvailability", "ReadinessAssessment", "EvidenceSelectionResult",
    "EvidenceManifest", "InvestigationCase", "TimelineEntry", "EvaluationResult",
]

