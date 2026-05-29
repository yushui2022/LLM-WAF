# Contributing

LLM-WAF changes should keep the firewall behavior measurable and explainable.

## Local Setup

```bash
python -m venv .venv
. .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Quality Gates

Run these before opening a PR:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -B -m coverage run -m unittest discover -s tests
python -B -m coverage report
python -B scripts/redos_probe.py
python -B scripts/evaluate.py --direction input --min-precision 0.95 --min-recall 0.95 --min-category-recall 0.95
python -B scripts/evaluate.py --direction output --min-precision 0.95 --min-recall 0.95 --min-category-recall 0.95
```

Coverage is currently report-only. Do not lower coverage intentionally; add focused tests when touching WAF behavior.

## Scanner Rule Changes

Rule or normalization changes must include eval samples. Add malicious examples and nearby benign hard negatives where possible.

Use these docs:

- `docs/rule-quality.md` for rule maturity, ReDoS expectations, false-positive reports, and bypass reports.
- `docs/protocol-support.md` for supported protocols and unsupported native-route behavior.

## Pull Request Shape

Keep PRs focused:

- One behavior change per PR.
- README and docs updated with user-visible changes.
- No heavy default dependencies.
- No raw secrets in logs, metrics, audit output, screenshots, or examples.
