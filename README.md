# THREXIS mini project

THREXIS is a three-person, 72-hour research prototype for comparing evidence-selection strategies under a common synthetic collection budget. It is not a production forensic-acquisition or detection system.

The foundation in this directory defines shared models, module boundaries, small artificial fixtures, and contract tests. Implementation teams must follow [`TEAM_CONTRACT.md`](TEAM_CONTRACT.md). The architecture pack in `../threxis_v1_2/` is a reference; this project deliberately keeps the research-validity controls while reducing delivery scope.

## Quick start

Target runtime: Python 3.12.x.

```text
python -m pip install -r requirements.txt
python -m pytest
```

Without pytest, the current contract suite is also executable with:

```text
python -m unittest discover -s tests -p "test_*.py" -v
```

Only synthetic data is permitted. Do not use real credentials, malware, attacks, endpoint monitoring, paid APIs, or cloud services.

## Forensic research workstation

The Streamlit dashboard is available on `feature/forensic-dashboard`, based on the Person 1/Person 2 integration branch.

```text
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open http://127.0.0.1:8501. See [dashboard documentation](docs/dashboard.md) for features, actual tests, data handling, and launch requirements. Public launch status: **NOT READY FOR PUBLIC LAUNCH**. Domain verification, human legal review, and desktop/mobile browser inspection remain incomplete.

