"""Presentation orchestration using shared backend interfaces."""
from __future__ import annotations

import io
from dataclasses import fields
import json
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from src.common.models import (AvailabilityStatus, ContractError, EvidenceAvailability,
                               EvaluationResult, InvestigationCase, SelectionStrategy)
from src.detection.engine import detect_suspicious_activity
from src.detection.correlation import correlate_events
from src.integration.adapters import aggregate_source_availability, availability_flags
from src.readiness.assessment import assess_readiness, assess_readiness_details
from src.readiness.comparison import compare_available_selection_strategies
from src.synthetic.generator import generate_synthetic_events
from src.synthetic.integration import evidence_inputs_from_events
from src.threat_intel.profiles import get_threat_profile
from src.threat_intel.mapping import map_events_to_attack, explain_attack_mappings
from src.forensics.vault import preserve_evidence, verify_evidence_vault
from src.forensics.audit import record_verification, read_audit_trail
from src.investigation.timeline import build_investigation_timeline
from src.investigation.report import build_investigation_case_record, generate_markdown_report

SCENARIOS = {
    "suspicious_authentication": "Suspicious Authentication",
    "suspicious_file_modification": "Suspicious File Modification",
    "potential_exfiltration": "Potential Exfiltration",
}


def build_workspace(scenario: str, count: int = 18, seed: int = 25,
                    unavailable_ids: tuple[str, ...] = (), budget: int = 10) -> dict:
    """Generate one explicit demonstration; truth is discarded before any operational step."""
    events, _labels = generate_synthetic_events(scenario, count, seed)
    del _labels
    candidates, observations = evidence_inputs_from_events(events)
    unknown = set(unavailable_ids) - {item.event_id for item in events}
    if unknown:
        raise ContractError("unavailable IDs must belong to the current scenario instance")
    observations = [EvidenceAvailability(item.evidence_id,
                    AvailabilityStatus.UNAVAILABLE if item.evidence_id in unavailable_ids else item.availability_status,
                    item.observed_at) for item in observations]
    sources, trace = aggregate_source_availability(candidates, observations)
    profile = get_threat_profile(scenario)
    relevant_sources = [item for item in sources if item.evidence_id in profile.evidence_weights]
    statuses = {item.evidence_id: "missing" if item.availability_status is AvailabilityStatus.UNAVAILABLE
                else item.availability_status.value for item in relevant_sources}
    flags = availability_flags(candidates, observations)
    alerts = detect_suspicious_activity(events)
    mappings = map_events_to_attack(alerts, profile)
    comparisons = compare_available_selection_strategies(candidates, profile, budget, seed, flags)
    case = InvestigationCase(f"CASE-{scenario.upper()}-{seed}", scenario,
                             tuple(item.alert_id for item in alerts), events[0].timestamp)
    return {"scenario": scenario, "seed": seed, "events": events, "candidates": candidates,
            "observations": observations, "flags": flags, "source_trace": trace,
            "profile": profile, "statuses": statuses, "alerts": alerts,
            "mappings": explain_attack_mappings(mappings),
            "readiness": assess_readiness(profile, relevant_sources),
            "details": assess_readiness_details(profile, statuses),
            "comparisons": comparisons, "case": case,
            "timeline": build_investigation_timeline(case, events, alerts),
            "correlations": correlate_events(events)}


@dataclass
class PreservedSession:
    """Session-scoped temporary vault; never accept caller-supplied filesystem paths."""
    temporary: tempfile.TemporaryDirectory
    manifests: list

    @property
    def vault(self) -> Path:
        return Path(self.temporary.name) / "vault"

    def verify(self) -> dict:
        for manifest in self.manifests:
            if Path(manifest.source_path).exists():
                record_verification(Path(manifest.source_path), manifest.sha256, manifest.evidence_id,
                                    self.vault / "verification-audit.jsonl")
        return verify_evidence_vault(self.vault)

    def archive(self) -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(self.vault.iterdir()):
                if path.is_file() and not path.is_symlink():
                    archive.write(path, path.name)
        return stream.getvalue()

    def close(self):
        self.temporary.cleanup()


def preserve_selected(workspace: dict, strategy: SelectionStrategy) -> PreservedSession:
    result = next(item for item in workspace["comparisons"] if item.strategy is strategy)
    if not result.selected_evidence_ids:
        raise ContractError("No evidence was selected. Increase the collection budget.")
    temporary = tempfile.TemporaryDirectory(prefix="threxis-ui-")
    root = Path(temporary.name)
    (root / "vault").mkdir()
    events = {item.event_id: item for item in workspace["events"]}
    manifests = []
    try:
        for evidence_id in result.selected_evidence_ids:
            source = root / f"{evidence_id}.json"
            source.write_text(json.dumps(events[evidence_id].to_dict(), sort_keys=True), encoding="utf-8")
            manifests.append(preserve_evidence(source, root / "vault" / source.name,
                                              evidence_id, workspace["events"][-1].timestamp))
    except Exception:
        temporary.cleanup()
        raise
    return PreservedSession(temporary, manifests)


def case_outputs(workspace: dict, preserved: PreservedSession | None = None, verification=None):
    args = (workspace["case"], workspace["events"], workspace["alerts"], workspace["timeline"],
            [] if preserved is None else preserved.manifests, workspace["correlations"], verification)
    return build_investigation_case_record(*args), generate_markdown_report(*args)


def load_research_records(payload: bytes) -> list[dict]:
    """Validate supplied per-run records; no experiment or metric calculation here."""
    if len(payload) > 5 * 1024 * 1024:
        raise ContractError("Research upload exceeds 5 MiB")
    output = []
    try:
        for line in payload.decode("utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ContractError("Each EvaluationResult JSONL line must be an object")
            allowed = {field.name for field in fields(EvaluationResult)}
            unknown = set(raw) - allowed
            if unknown:
                raise ContractError(f"Unknown EvaluationResult fields: {sorted(unknown)}")
            raw["strategy"] = SelectionStrategy(raw["strategy"])
            raw["selected_evidence_ids"] = tuple(raw["selected_evidence_ids"])
            output.append(EvaluationResult(**raw).to_dict())
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError) as exc:
        raise ContractError(f"Invalid EvaluationResult JSONL: {exc}") from exc
    return output
