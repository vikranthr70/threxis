# THREXIS three-person integration contract

Status: foundation v1.0, adapted from Architecture Pack v1.2 for a three-person, three-day prototype.

## 1. Frozen research contract

Research question: **Does threat-informed adaptive evidence selection improve relevant forensic evidence retrieval under a fixed collection budget compared with static and random selection strategies in a synthetic incident environment?**

The implementation must also retain the threat-agnostic and frozen-context-adaptive baselines. A result against static alone cannot isolate the value of threat context. The evaluator-only oracle is an upper bound, never an operational baseline.

All strategies receive the same candidate instance, availability state, costs, and budget. Operational selectors receive only `EvidenceCandidate(evidence_id, source_type, collection_cost)` and legitimate current context. They must never receive labels, scenario/template IDs, generator seeds, instance IDs, true phase, context-quality/noise metadata, or oracle output. Ground truth is generated independently, stored separately, and loaded only from `src.evaluation`.

All rankers return a complete ordering of eligible IDs. Only `src.common.selection.fill_to_budget()` applies the frozen skip-non-fitting-and-continue rule. Selection is without replacement; the runner independently recomputes cost and rejects over-budget runs.

Keep the pack's five strategies exactly:

1. `static`: frozen source-type ordering; ascending randomized evidence ID within type.
2. `random`: deterministic seeded permutation.
3. `threat_agnostic`: mean un-noised context weight by source type divided by cost; never changes with phase.
4. `adaptive`: current phase/context weight divided by cost; re-ranks on context change.
5. `frozen_context_adaptive`: same scoring as adaptive but retains the initial context after the shift.

Truth probabilities and independently authored context weights must not be derived from each other. Context weights are ranking judgments, not real-world probabilities. Synthetic outcomes may be gains, ties, or losses and must all be reported.

## 2. Shared schemas

`src.common.models` is the single source of truth. All records use schema version `1.0`, stable string IDs, and timezone-aware ISO 8601 timestamps. Contract violations raise `ContractError` (a `ValueError`). `to_dict()` returns JSON-compatible dictionaries; callers serialize with `json.dumps` and UTF-8.

| Model | Required fields | Allowed/validation notes |
|---|---|---|
| `SecurityEvent` | `event_id, timestamp, event_type, source_type, scenario_id` | `attributes` optional; truth-like keys forbidden |
| `DetectionAlert` | `alert_id, event_ids, timestamp, severity, scenario_id, reason` | severity: low/medium/high/critical |
| `ThreatMapping` | `alert_id, technique_id, confidence, rationale` | ATT&CK-style `T...`; confidence `[0,1]`; mapping is not proof |
| `ThreatProfile` | `profile_id, scenario_id, technique_ids, evidence_weights` | weights `[0,1]`; context author owns review/citations |
| `EvidenceCandidate` | `evidence_id, source_type, collection_cost` | exact selector allowlist; positive integer cost |
| `EvidenceAvailability` | `evidence_id, availability_status, observed_at` | available/unavailable/collected |
| `ReadinessAssessment` | `assessment_id, scenario_id, score` | score `[0,1]`; optional missing types |
| `EvidenceSelectionResult` | `strategy, selected_evidence_ids, budget, selected_cost` | unique IDs; selected cost cannot exceed budget |
| `EvidenceManifest` | `manifest_id, evidence_id, collected_at, sha256, source_path` | SHA-256 is integrity, not legal chain-of-custody proof |
| `InvestigationCase` | `case_id, scenario_id, alert_ids, opened_at, status` | status open/closed |
| `TimelineEntry` | `case_id, timestamp, entry_type, summary` | optional related IDs |
| `EvaluationResult` | `run_id, strategy, scenario_id, selected_evidence_ids, evidence_recall, evidence_precision, collection_cost, budget_utilization` | metrics `None` when undefined or otherwise `[0,1]` |

Ground truth uses `src.evaluation.ground_truth.GroundTruthLabel` and is intentionally absent from runtime models. Do not add `relevant`, `malicious`, `label`, or `ground_truth` to shared runtime records.

Initial demo scenarios are `suspicious_authentication`, `suspicious_file_modification`, and `potential_exfiltration`. They are user-facing synthetic examples, not the hidden experiment phase/template identifiers and not assertions that a real ATT&CK technique occurred.

## 3. Public interfaces

Implement exactly these APIs; do not add fake stubs to make imports pass. Functions accept/return shared dataclasses or JSON-compatible dictionaries derived from them.

### Person 2 — synthetic detection and forensics

| Module and signature | Return | Errors |
|---|---|---|
| `src.synthetic.generator.generate_synthetic_events(scenario_id: str, count: int, seed: int) -> tuple[list[SecurityEvent], list[GroundTruthLabel]]` | candidates/events and labels written through separate paths | `ContractError` for unsupported scenario/count; never read context priors |
| `src.detection.engine.detect_suspicious_activity(events: Sequence[SecurityEvent]) -> list[DetectionAlert]` | deterministic alerts | `ContractError` for invalid/mixed records |
| `src.forensics.vault.preserve_evidence(source: Path, destination: Path, evidence_id: str, collected_at: str) -> EvidenceManifest` | copied synthetic artifact plus manifest | `FileNotFoundError`, `ContractError`, `OSError`; no overwrite by default |
| `src.forensics.vault.verify_evidence(path: Path, expected_sha256: str) -> bool` | byte-integrity result | `FileNotFoundError`, `ContractError` |
| `src.investigation.timeline.build_investigation_timeline(case: InvestigationCase, events: Sequence[SecurityEvent], alerts: Sequence[DetectionAlert]) -> list[TimelineEntry]` | timestamp-sorted deterministic entries | `ContractError` for cross-case/unknown IDs |

### Person 1 — threat intelligence and readiness

| Module and signature | Return | Errors |
|---|---|---|
| `src.threat_intel.mapping.map_events_to_attack(alerts: Sequence[DetectionAlert], profile: ThreatProfile) -> list[ThreatMapping]` | cited, deterministic mappings | `ContractError`; never claim technique occurrence as fact |
| `src.readiness.assessment.assess_readiness(profile: ThreatProfile, availability: Sequence[EvidenceAvailability]) -> ReadinessAssessment` | weighted normalized assessment | `ContractError` for duplicate/missing evidence definitions |
| `src.readiness.selectors.select_evidence(strategy: SelectionStrategy, candidates: Sequence[EvidenceCandidate], context: ThreatProfile | None, already_selected_ids: set[str], rng: random.Random | None, budget: int) -> EvidenceSelectionResult` | ranking passed through shared budget filler | `ContractError`; no imports from generator/evaluation/ground truth |
| `src.readiness.comparison.compare_selection_strategies(candidates: Sequence[EvidenceCandidate], context: ThreatProfile, budget: int, seed: int) -> list[EvidenceSelectionResult]` | one fair result per five operational strategies | `ContractError`; identical candidate/cost/budget inputs required |

### Person 3 — runner, evaluation, export, and optional UI

| Module and signature | Return | Errors |
|---|---|---|
| `src.evaluation.runner.run_experiment(config_path: Path) -> list[EvaluationResult]` | raw per-run records; evaluates labels only after selection | `FileNotFoundError`, `ContractError`; refuse unfrozen/invalid configs for main mode |
| `src.evaluation.dashboard.build_dashboard_data(results: Sequence[EvaluationResult]) -> dict[str, object]` | presentation-only aggregate | `ContractError`; never invent missing results |
| `src.evaluation.export.export_experiment_results(results: Sequence[EvaluationResult], output_dir: Path) -> tuple[Path, ...]` | UTF-8 JSON/JSONL and `newline=""` CSV | `OSError`, `ContractError`; no silent overwrite |

JSON field names exactly match `to_dict()`. Enums serialize to lowercase string values; tuples serialize as arrays; undefined metrics serialize as `null`. Unknown fields are rejected at construction boundaries rather than silently retained.

## 4. Experiment protocol that must survive scope cuts

- Candidate records and phase-specific labels are separate artifacts. IDs are assigned after shuffling; cost and display metadata are generated independently of relevance conditional on source type.
- Single-round absolute budgets are `floor(total_candidate_cost * p)` for `p = 0.05, 0.10, 0.20, 0.40`.
- The shift test has six rounds: phase A in rounds 1–2, phase B in rounds 3–6; total budgets are 20% and 40%; split with `divmod(total_budget, 6)`; early rounds receive remainder units; unused per-round budget expires.
- All candidates are available from round 1. No arrival, overlap, or duplicate-artifact model is allowed in the MVP.
- Required metrics: evidence recall, evidence precision, selected cost, budget utilization, cost per relevant item, post-shift phase-B recall after rounds 1/2/3, and normalized trapezoidal phase-B recall AUC. Undefined recall/precision is `null`, never silently zero.
- Preserve deterministic SHA-256 seed derivation, canonical JSON config hashes, UTF-8 I/O, instance-level replication, and same-candidate paired comparisons.
- The selector input allowlist, forbidden-import scan, budget/no-double-selection invariants, deterministic/noise checks, and evaluator-only oracle bounds are release gates.
- Export raw per-run JSONL, aggregate CSV/JSON, config hashes, seed inputs, Python/Git metadata, and a manifest. Paper figures are generated only from saved results.

## 5. Three-day scope decision

### Must ship

Walking-skeleton CLI; independent generator/context paths; all five operational baselines; shared budget utility; separate evaluator/oracle; small multi-phase synthetic fixtures; leakage and budget tests; raw exports/manifest; one reproducible smoke grid; honest README/demo/paper limitations.

### Reduce but do not redefine

The pack's proposed full grid (3 templates × 30 instances × 200 items × 30 random seeds × 10 noise seeds × budgets/qualities) is too risky for three people alongside implementation and writing. Start with 3 templates, **10 instances each**, 100–200 items, **10 random seeds**, and **5 noise seeds** for engineering validation. If time permits, run the full preregistered grid. Any reduction must be committed before inspecting comparative results and described as exploratory; never treat records or seeds as independent replicates.

Use the three user-facing detection scenarios only for the demo layer; retain the pack's phase-pair experiment templates for the scientific run. A complete forensic vault/custody product, live Sysmon ingestion, API, database, cloud services, polished dashboard, ML/online learning, and legal chain-of-custody claims are deferred. Build only a thin dashboard after the CLI and invariant tests pass.

MITRE mapping verification and related-work claims require checked primary sources and cannot be fabricated under deadline. Until reviewed, context priors remain `example`/`proposed`, never frozen.

## 6. Ownership and integration order

- Person 1 owns context review, readiness, five selectors, and selection comparison. They must not author truth probabilities or import evaluation paths.
- Person 2 owns generator truth production, demo detection, evidence hashing, and timelines. They must not author context weights. Candidate output and truth output are separate.
- Person 3 owns experiment runner/evaluator/oracle, exports/statistics/paper, integration, and optional Streamlit. The runner is the trusted bridge; UI contains no experiment logic.

Integration order: (1) shared contracts/config freeze, (2) generator + separated labels, (3) selectors + shared budget behavior, (4) evaluator/oracle + invariant tests, (5) one CLI smoke run, (6) scaled runs/statistics, (7) thin UI and paper figures. Contract changes require all three members' review.

Do not modify another owner's files. Do not modify `src/common/`, `tests/contracts/`, frozen configs, or shared fixtures without an integration PR and explicit notice to all members.

