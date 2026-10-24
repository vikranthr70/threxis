# Contributing to THREXIS

## Branches and ownership

- Person 1: `feature/adaptive-engine`; owns `src/threat_intel/`, `src/readiness/`, `config/threat_profiles/`, `tests/person1/`, and `docs/person1_methodology.md`.
- Person 2: `feature/forensics`; owns `src/synthetic/`, `src/detection/`, `src/forensics/`, `src/investigation/`, and `tests/person2/`.
- Person 3: `feature/dashboard-paper`; owns `app.py`, `src/evaluation/` except `ground_truth.py` contract changes, `paper/`, and `tests/person3/`.
- Integration lead approval is required for `src/common/`, `tests/contracts/`, `TEAM_CONTRACT.md`, frozen config, and shared fixtures.

Never merge directly to the integration branch. Rebase or merge the latest integration branch, run all tests, then open a small pull request. At least one non-author reviews schema, config, and experiment changes. Resolve cross-owner conflicts together; do not duplicate shared logic inside an owned module.

## Required checks

```text
python -m pytest
```

Fallback when pytest is not installed:

```text
python -m unittest discover -s tests -p "test_*.py" -v
```

A pull request must describe changed contracts, commands run, actual results, and any protocol deviation. Main comparative results may be generated only after configs, static ordering, metrics, seed rules, and the independently reviewed context map are committed and hashed.

Use UTF-8 for text, `newline=""` for CSV, `pathlib.Path` for paths, canonical JSON for hashes, and SHA-256-derived deterministic seeds. Never push credentials, real security telemetry, generated bulk results, or evidence-vault contents.

