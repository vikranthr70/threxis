# Person 1 and Person 2 integration

## Architecture and data flow

Person 2 generates normalized synthetic events and separate evaluator-only labels. Detection consumes events only. `src.synthetic.integration` derives selector-safe candidates and event-level availability; `src.integration.adapters` validates the IDs and aggregates them to source requirements for Person 1 readiness.

The source-presence policy is deterministic: a source is `available` if any artifact is available, otherwise `collected` if any artifact is collected, otherwise `unavailable`. The adapter returns contributing artifact IDs for traceability. Presence does not establish completeness.

Operational flow:

1. Generate artificial events and separately retain labels.
2. Detect patterns and conservatively map supported alerts to ATT&CK candidates.
3. Build candidates and exact availability observations.
4. Aggregate source presence for readiness and filter event artifacts for selection.
5. Run all five frozen baselines on the same eligible pool and budget.
6. Preserve selected artifacts, recalculate SHA-256, reconstruct the timeline, and report facts separately from hypotheses.

Ground-truth labels never enter readiness, ranking, correlation, preservation, or reporting.

## Fixed issues and features

- Bridged event-ID availability to source-ID readiness with strict validation and traceability.
- Added identical unavailable-evidence filtering and independent cost checks for all strategies.
- Changed the threat-agnostic prior to the architecture context-prior configuration, never the truth model.
- Added explicit current-context adaptive and initial-context frozen state.
- Kept shared enums unchanged while exposing rich readiness details separately.
- Added readiness simulation, opt-in severity ranking, context-change analysis, ranking explanations, a multi-stage demonstration, correlations, vault verification summaries, verification audit records, and advanced reports.

## Readiness and selection semantics

Status factors are available `0.60`, collected `0.85`, validated `1.00`, and missing/unknown `0.00`; not-applicable is excluded. Collected is not assumed validated, and availability is not integrity verification. Scenario scores are normalized weighted sums. Optional overall readiness is an explicitly labelled unweighted mean across supplied scenarios.

The five research baselines remain static, seeded random, configured threat-agnostic, current-context adaptive, and initial-context frozen adaptive. Ranking is label-blind and selection is without replacement. Explainability scores are ordinal judgments, not calibrated probabilities. Severity-aware ranking is opt-in and never replaces a baseline.

## Reproduction

```text
python -m pytest -q
python -m unittest discover -s tests -p "test_*.py" -q
python -m src.readiness.demo
python -m src.synthetic.demo
python -m src.integration.demo
```

## Limitations

All activity is synthetic. Detection thresholds and weights are demonstration judgments. ATT&CK mappings and correlations are investigative leads, not proof. Source presence does not prove completeness. SHA-256 detects byte differences only when its expected digest is trusted. Local manifests and JSONL logs are not tamper-proof and do not establish legal chain of custody. This work adds no dashboard, scientific experiment runner, or paper logic.
