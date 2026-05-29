# Contributing

Thanks for improving LLM-WAF.

## Local Setup

Use the same commands the CI gate runs:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -B -m unittest discover -s tests
```

If you change request-path behavior, scanner logic, or audit output, also run
the evaluation scripts in `scripts/` and update the matching eval set in the
same change.

## Change Shape

- Keep changes small and focused.
- Update README or docs when user-facing behavior changes.
- Keep secrets, prompts, and raw evidence out of logs, metrics, and audit
  output.
- Add tests for any new rule, sink, or protocol behavior.

## Reporting False Positives

Use the `false_positive` issue template for deterministic rule misses or
overblocking.

Include:

- route or endpoint
- redacted payload
- expected behavior
- actual finding or block reason

## Reporting Bypasses

Use the `bypass_report` issue template for prompt-injection bypasses or other
security gaps.

If the report may disclose sensitive data, open a private security advisory
instead.

## Review Checklist

- [ ] tests pass
- [ ] evals updated when behavior changed
- [ ] docs updated when users would notice
- [ ] audit and metrics remain redaction-safe
