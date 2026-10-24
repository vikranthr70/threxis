"""Conservative, explainable alert-to-ATT&CK behavioral mappings."""

from __future__ import annotations

from collections.abc import Sequence

from src.common.models import ContractError, DetectionAlert, ThreatMapping, ThreatProfile
from .catalog import get_technique

_RULES = {
    "T1110": (("brute force", "repeated login", "multiple failed", "many authentication failure"), (), 0.70, "possible"),
    "T1110.001": (("password guess", "common password", "iterative login"), (), 0.90, "strongly_supported"),
    "T1059.001": (("powershell",), ("script", "command", "encoded", "execute", "download"), 0.90, "strongly_supported"),
    "T1003.001": (("lsass",), ("memory", "dump", "credential"), 0.90, "strongly_supported"),
    "T1041": (("c2", "command and control"), ("exfil", "upload", "transfer", "stolen data"), 0.90, "strongly_supported"),
}


def _matches(text: str, required_any: tuple[str, ...], supporting_any: tuple[str, ...]) -> bool:
    return any(term in text for term in required_any) and (not supporting_any or any(term in text for term in supporting_any))


def map_events_to_attack(alerts: Sequence[DetectionAlert], profile: ThreatProfile) -> list[ThreatMapping]:
    """Map alert behavior to candidates; confidence is ordinal, not probability."""
    if not isinstance(profile, ThreatProfile):
        raise ContractError("profile must be a ThreatProfile")
    seen, output = set(), []
    for alert in alerts:
        if not isinstance(alert, DetectionAlert):
            raise ContractError("alerts must contain DetectionAlert records")
        if alert.alert_id in seen:
            raise ContractError(f"duplicate alert_id: {alert.alert_id}")
        seen.add(alert.alert_id)
        if alert.scenario_id != profile.scenario_id:
            raise ContractError("alert scenario does not match threat profile")
        text = alert.reason.casefold()
        for technique_id in profile.technique_ids:
            rule = _RULES.get(technique_id)
            if rule is None or not _matches(text, rule[0], rule[1]):
                continue
            technique = get_technique(technique_id)
            rationale = (
                f"{rule[3]}: alert {alert.alert_id} reports behavior consistent with {technique.name}; "
                f"supporting_event_ids={','.join(alert.event_ids)}. This is a candidate mapping, not proof."
            )
            output.append(ThreatMapping(alert.alert_id, technique_id, rule[2], rationale))
    return sorted(output, key=lambda item: (item.alert_id, item.technique_id))


def explain_attack_mappings(mappings: Sequence[ThreatMapping]) -> list[dict[str, object]]:
    rows = []
    for mapping in mappings:
        technique = get_technique(mapping.technique_id)
        rows.append({
            **mapping.to_dict(), "technique_name": technique.name,
            "tactics": list(technique.tactics),
            "classification": "strongly_supported" if mapping.confidence >= 0.85 else "possible",
            "official_url": technique.official_url,
            "support_score_semantics": "ordinal_rule_support_not_probability",
        })
    return rows

