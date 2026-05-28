# Rule Quality Process

LLM-WAF's default rules are intentionally conservative. They are useful for catching high-confidence prompt injection, jailbreaks, obvious system-prompt extraction, PII, and common secrets, but they should not be described as commercial-grade coverage yet.

Treat the checked-in rules as a tested baseline, not a finished threat model.

## Maturity Levels

Use these labels when discussing rules, eval samples, and release notes:

| Level | Meaning |
|---|---|
| `experimental` | New rule or heuristic. Needs more real-world samples before being relied on broadly. |
| `default` | Enabled by default because precision is acceptable in the current eval set. |
| `stable` | Has survived real-world usage, bypass reports, and benign hard negatives. |
| `deprecated` | Kept temporarily for compatibility or audit history, but should not be expanded. |

Most Chinese prompt-injection rules should be treated as `experimental` or `default` until the eval set contains enough real attack samples and benign hard negatives from production-like traffic.

## Rule Change Checklist

Before changing `config/rules.yaml`:

1. Add at least one malicious eval sample that the rule is supposed to catch.
2. Add at least one nearby benign hard negative when possible.
3. Run the full test suite and both eval directions.
4. Check category-level recall, not only aggregate recall.
5. Keep `app/security/rules.py` aligned with `config/rules.yaml` until fallback generation is implemented.
6. Update documentation if user-facing behavior changes.

Required local checks:

```bash
python -B -m unittest discover -s tests
python -B scripts/evaluate.py --direction input --min-precision 0.95 --min-recall 0.95 --min-category-recall 0.95
python -B scripts/evaluate.py --direction output --min-precision 0.95 --min-recall 0.95 --min-category-recall 0.95
```

## False Positive Reports

False positives are high priority because broad blocking rules make a WAF unusable.

Use this format in issues or PRs:

```text
Type: false_positive
Direction: input | output
Rule ID:
Category:
Policy name:
Expected decision: allowed | redacted | blocked
Actual decision:
Minimal sanitized sample:
Why this is legitimate:
Suggested tuning, if any:
```

Do not paste secrets, customer data, or full private prompts. Use a minimal sanitized reproduction that still triggers the finding.

## Bypass Reports

Use this format for missed attacks:

```text
Type: bypass
Direction: input | output
Expected category:
Expected action: block | redact | log_only
Minimal sanitized attack sample:
Obfuscation used, if any:
Provider/model, if relevant:
Why this should be blocked or redacted:
```

Bypass reports should become eval samples before a new rule is merged.

## Audit-To-Eval Workflow

The audit log can produce review candidates:

```bash
python scripts/audit_to_eval_candidates.py --audit var/audit/events.jsonl --output var/audit/eval_candidates.jsonl
```

This script intentionally writes `label: review`. It does not update rules automatically. A maintainer must review the candidate, sanitize the sample, add it to the correct eval set, and pass the quality gates.
