"""Clearly labelled multi-stage synthetic demonstration data."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from src.common.models import SecurityEvent
from src.evaluation.ground_truth import GroundTruthLabel
from .generator import generate_synthetic_events


def generate_multistage_demonstration(seed: int = 1) -> tuple[list[SecurityEvent], list[GroundTruthLabel]]:
    """Combine three artificial stages without changing existing scenario contracts."""
    stages = ("suspicious_authentication", "suspicious_file_modification", "potential_exfiltration")
    events, labels = [], []
    anchor = datetime.fromisoformat("2026-01-02T00:00:00+00:00")
    for stage_number, scenario in enumerate(stages):
        stage_events, stage_labels = generate_synthetic_events(scenario, 6, seed + stage_number)
        label_by_id = {label.evidence_id: label for label in stage_labels}
        for index, event in enumerate(stage_events):
            new_id = f"stage-{stage_number + 1}-{event.event_id}"
            timestamp = (anchor + timedelta(minutes=stage_number * 20, seconds=index * 30)).isoformat().replace("+00:00", "Z")
            attributes = dict(event.attributes)
            attributes.update({"host": "demo-host-01", "user": "demo-account", "demonstration_stage": stage_number + 1})
            events.append(replace(event, event_id=new_id, timestamp=timestamp, attributes=attributes))
            label = label_by_id[event.event_id]
            labels.append(GroundTruthLabel(new_id, f"stage_{stage_number + 1}", label.relevant))
    return events, labels
