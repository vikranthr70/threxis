# Person 1 methodology: threat-informed adaptive forensic readiness

## Scope and research problem

THREXIS evaluates whether a simple threat-context-driven evidence-ranking heuristic retrieves more synthetically relevant evidence under a fixed collection budget than fixed comparators. It is a controlled proof of concept, not a production acquisition platform, detection product, legal chain-of-custody system, or claim of real-world effectiveness.

Research question: **Does threat-informed adaptive evidence selection improve relevant forensic evidence retrieval under a fixed collection budget compared with static, random, threat-agnostic, and frozen-context strategies in a synthetic incident environment?** Results may favor, tie, or disfavor the adaptive strategy.

## ATT&CK catalog and mapping

The offline catalog contains only T1110, T1110.001, T1059.001, T1003.001, and T1041. It was checked on 2026-10-25 against MITRE ATT&CK Enterprise and the official `mitre-attack/attack-stix-data` version 20.0 release. Catalog records include technique-page versions, tactics, official URLs, and revoked/deprecated flags.

Mappings are explicit behavioral rules over `DetectionAlert.reason`; an input technique label is never independent proof. Repeated authentication failures may support T1110, but T1110.001 requires password-guessing behavior. PowerShell requires PowerShell plus script/command/execution behavior. LSASS Memory requires LSASS plus memory/dump/credential behavior. T1041 requires evidence of both an existing C2 channel and data transfer/exfiltration. Generic file modification and generic outbound traffic map to nothing. The shared `confidence` field stores an ordinal rule-support score, not a calibrated probability. Every rationale states that the result is a candidate mapping, not proof.

Verified primary references:

- MITRE ATT&CK T1110: https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1110.001: https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1003.001: https://attack.mitre.org/techniques/T1003/001/
- MITRE ATT&CK T1041: https://attack.mitre.org/techniques/T1041/
- Official STIX data release: https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.0

## Threat profiles and evidence requirements

`config/threat_profiles/profiles.json` defines three shared demo scenarios. Authentication prioritizes `authentication_log`; file modification prioritizes `file_access` and `process_creation`; potential exfiltration prioritizes `network_flow`, `file_access`, and `dns_log`. Source names intentionally match the architecture experiment vocabulary. Weights encode independently authored ranking importance, not truth probabilities or real-world prevalence.

The experiment phase profiles in `data/config/context_priors.example.json` remain separate from `data/config/truth_probability_model.json`. The former is selector context; the latter is evaluator-only synthetic truth-generation input. The Person 1 code never imports generator, evaluator, or ground-truth modules.

## Weighted readiness

For applicable requirement `i`, importance weight `w_i` and status factor `f_i`:

```text
readiness = 100 * sum(w_i * f_i) / sum(w_i)
```

Status factors are available=0.60, collected=0.85, validated=1.00, missing=0, and unknown=0. Not-applicable requirements are excluded from the denominator. Collected is deliberately not treated as validated. An all-not-applicable input is undefined and rejected. The compact shared interface supports available, collected, and unavailable; `assess_readiness_details()` supplies the richer validated/missing/unknown/not-applicable view without modifying shared schemas.

## Adaptive selection objective and pseudocode

For candidate `e` and current context `t`:

```text
estimated_value(e,t) = context_weight(t, e.source_type)
value_density(e,t) = estimated_value(e,t) / e.collection_cost
rank descending by value_density, then ascending evidence_id
selected = shared fill_to_budget(ranking, costs, budget, already_selected)
```

All candidate costs are positive integers; zero or malformed costs are rejected by the shared model. The shared filler skips a non-fitting item and continues. The heuristic is greedy and no global optimality is claimed. Callers filter unavailable artifacts with `select_available_evidence()` before ranking.

## Baselines

- **Static:** frozen architecture source order; ID tie-break.
- **Random:** seeded permutation of the same eligible IDs.
- **Threat-agnostic:** mean profile weight by source type, divided by cost; it ignores the active scenario.
- **Adaptive:** current context weight divided by cost.
- **Frozen-context adaptive:** the same formula but the runner must retain phase-A context after the phase shift.

Each selector returns a ranking; only the shared budget utility selects. In a one-round comparison, adaptive and frozen necessarily receive the same context. Person 3 must retain the initial `ThreatProfile` for frozen-context calls in rounds 3–6 while passing the updated profile to adaptive calls.

## Experiment and metrics

Strategies must use the same candidate instance, costs, availability, and budget. Single-round budgets are 5%, 10%, 20%, and 40% of total candidate cost. The shift experiment has phase A in rounds 1–2, phase B in rounds 3–6, 20% and 40% total budgets, `divmod` round allocation, and no budget rollover. Person 1 exposes post-selection recall, precision, selected cost, utilization, selected/relevant counts, cost per relevant item, and optional captured relevance weight. Undefined recall or precision is `null`, never silently zero.

Deterministic controls include stable ID tie-breaking, seeded `random.Random`, UTF-8 JSON, shared candidate pools, and separate ground truth. Tests scan the selector source for forbidden evaluation/ground-truth imports and assert the exact `EvidenceCandidate` allowlist.

## Integration examples

Person 2 passes contract `DetectionAlert`, `EvidenceCandidate`, and `EvidenceAvailability` objects; Person 1 does not import Person 2 implementations. Person 3 can call:

```python
profile = get_threat_profile("potential_exfiltration")
mappings = map_events_to_attack(alerts, profile)
readiness = assess_readiness(profile, availability)
results = compare_selection_strategies(candidates, profile, budget=20, seed=7)
dashboard_rows = [result.to_dict() for result in results]
```

For richer JSON, use `explain_attack_mappings()`, `assess_readiness_details()`, and `explain_selection()`.

## Limitations and threats to validity

- Synthetic relevance assumptions cannot establish enterprise effectiveness.
- Type-level weights cannot distinguish two same-type records except by cost and ID.
- Context weights are expert judgments and may be incomplete or wrong.
- Alert reasons are simplified behavioral summaries, not raw telemetry.
- The shared schema cannot represent validated/unknown/not-applicable directly; the detailed owned view carries them.
- The smoke grid has reduced instances and seeds; inferential claims require the frozen full protocol or must be labeled exploratory.
- ATT&CK changes over time; versions and retrieval dates must be rechecked before publication.
- A hash confirms byte identity, not forensic provenance or legal admissibility.

## Integration upgrade

The threat-agnostic baseline now reads the un-noised `weights` section of `data/config/context_priors.example.json`; it never reads the independently authored truth probability model. `ContextSelectionState` makes shift semantics explicit: adaptive selection receives current context while frozen-context selection retains initial context. The compatibility comparison filters one validated availability map before all five strategies and independently checks selected cost.

Detailed readiness output distinguishes available, collected, validated, missing, unknown, and not-applicable without expanding the shared three-value availability enum. Cross-scenario readiness, when requested, is an explicitly labelled unweighted arithmetic mean. Improvement simulation, severity-aware ranking, and context-change analysis are deterministic advisory extensions. Severity-aware ranking is opt-in and is not one of the five research baselines.

