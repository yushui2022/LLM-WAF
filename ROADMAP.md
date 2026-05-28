# LLM-WAF Roadmap

This roadmap keeps the project focused on its core purpose: **a zero-intrusion LLM application firewall**. Telemetry such as token usage and cost estimates is useful, but it is secondary. The main product value is runtime protection, explainable decisions, low false positives, and easy deployment.

## Product Positioning

LLM-WAF is an OpenAI-compatible security gateway for LLM applications.

Primary promise:

> Change one `base_url` and get safer LLM traffic without breaking streaming.

Core constraints:

- Zero-intrusion by default: users should not rewrite agent or RAG code.
- Streaming-safe: SSE streaming must continue to work.
- Low latency: high-confidence checks should run before any expensive model call.
- Visible value: dashboard and JSONL audit must show what was blocked, redacted, or allowed.
- Defense quality first: rules must be evaluated against malicious samples and benign hard negatives.

## Non-Goals For Now

These are intentionally not the main direction:

- Billing platform or BI dashboard.
- Training a large model from scratch.
- Full multi-provider router competing with LiteLLM / OneAPI.
- Heavy React dashboard or complex frontend build.
- Native Anthropic/Gemini protocol support before the WAF core is solid.

## Current Baseline

Implemented:

- OpenAI-compatible `/v1/chat/completions` proxy.
- Streaming and non-streaming request handling.
- Input scanner for high-confidence prompt injection and jailbreak patterns.
- Sensitive data redaction for PII and common secrets.
- Output scanner for sensitive data and basic system-prompt leak hints.
- JSONL audit log.
- Built-in dashboard.
- Gateway API key auth.
- In-memory per-principal rate limiting.
- Route policy YAML.
- Token usage extraction.
- Optional model pricing estimates.
- Input and output WAF scanner evaluation harnesses.

Validation commands:

```bash
python -m unittest discover -s tests
python scripts/evaluate.py --direction input --show-misses --min-precision 0.95 --min-recall 0.95
python scripts/evaluate.py --direction output --show-misses --min-precision 0.95 --min-recall 0.95
```

## Guiding Engineering Rules

- Every scanner rule change should add or update eval samples.
- Every new malicious sample should have nearby benign hard negatives when possible.
- Prefer high-confidence blocking over broad rules that create false positives.
- Redact secrets by default; block prompt-injection attempts by default.
- Audit evidence must be useful but should not leak the original sensitive value.
- Keep dependencies light and local-deploy friendly.
- README must be updated in the same change as user-facing behavior.

## Phase 0: Stabilize The WAF Core

Goal: make the existing MVP reliable enough for outside users to try without obvious breakage.

Tasks:

- Expand `tests/eval_set.jsonl` with more Chinese and multilingual attack samples. (done twice; continue expanding with real bypass reports)
- Add benign hard negatives for security education content.
- Add benign hard negatives for normal roleplay, writing, and instruction-following prompts.
- Add encoded and obfuscated injection samples:
  - Base64
  - URL encoding
  - HTML entities
  - zero-width characters
  - mixed Chinese/English text
- Add output-side eval set for leakage detection. (done)
- Add CI workflow for unit tests and scanner eval. (done)
- Document false-positive reporting format.
- Add audit-to-eval candidate extraction for reviewed rule updates. (done)

Exit criteria:

- Unit tests pass.
- Scanner eval passes configured precision/recall thresholds.
- README quick start stays accurate.
- Dashboard remains useful without extra setup.

## Phase 1: Rule Quality And Explainability

Goal: make findings understandable, defensible, and easy to tune.

Tasks:

- Split built-in rules into YAML or data files while keeping Python fallback defaults. (done; keep fallback aligned until generated fallback exists)
- Add rule metadata to findings and future rule files: (partially done)
  - `rule_id`
  - `category`
  - `severity`
  - `action`
  - `description`
  - `references`
  - `recommended_remediation`
- Add per-rule enable/disable support in `config/policy.yaml`. (done)
- Add `action: block | redact | log_only`.
- Add rule tags such as `cn`, `en`, `encoded`, `jailbreak`, `system_prompt`.
- Add audit summary that groups findings by category and severity. (done)
- Add dashboard finding summary views for category and severity. (done)
- Add dashboard filters for decision/category/severity. (done)

Exit criteria:

- A user can turn off a noisy rule without editing code.
- Audit events clearly explain why a request was blocked or redacted.
- Evaluation can report metrics by category.

## Phase 2: Output Protection

Goal: prevent model responses from leaking secrets, PII, system prompts, and tool results.

Tasks:

- Create `tests/output_eval_set.jsonl`. (done)
- Add output eval script support or extend `scripts/evaluate.py` with `--direction input|output`. (done)
- Improve system prompt leak heuristics.
- Add private key, token, credential, and stack trace output detectors.
- Add configurable output action:
  - redact and pass
  - block entire response
  - replace with safe error message
- Add audit fields for output redaction counts.
- Add rolling-window stream scanning for cross-SSE-frame leakage. (done)
- Add optional SSE frame hold-back for stricter cross-frame redaction. (done)
- Improve streaming output redaction limitations documentation. (done)

Exit criteria:

- Output scanner has a measurable eval set.
- Non-streaming output redaction is reliable.
- Streaming output behavior remains low-latency and documented.

## Phase 3: Tool Call And Agent Boundary

Goal: protect dangerous actions even when the model is manipulated.

Tasks:

- Scan OpenAI `tool_calls[].function.arguments`. (partially done; request and response text/redaction paths covered)
- Add tool-risk policy model:
  - read-only
  - network
  - file-write
  - shell
  - destructive
- Add per-tool allow/deny configuration.
- Add argument validators:
  - path allowlist
  - domain allowlist
  - method allowlist
  - max payload size
- Add policy action `require_approval`.
- Add audit events for tool-call decisions.
- Add eval samples for tool-abuse prompts and safe tool use.

Exit criteria:

- Tool-call arguments are scanned and audited.
- Dangerous tool calls can be blocked independent of model text.
- Policy can distinguish safe and unsafe tool usage.

## Phase 4: Trust-Aware Mode

Goal: support deeper protection for RAG and agent teams willing to add lightweight annotations.

Default mode remains zero-intrusion. Trust-aware mode is optional.

Tasks:

- Add request headers or metadata for content origin:
  - user
  - system
  - rag
  - tool_result
  - web
  - email
- Add SDK/helper examples for marking untrusted content.
- Add spotlighting wrappers for untrusted content.
- Add policies for untrusted content touching high-risk tools.
- Add indirect prompt injection eval samples from RAG/web/tool-result contexts.

Exit criteria:

- Existing zero-intrusion users are not affected.
- Integrated users can mark untrusted context and get stronger policies.
- Indirect injection behavior is measurable.

## Phase 5: Deployment Hardening

Goal: make the gateway easier to run safely outside localhost.

Tasks:

- Add Docker healthcheck.
- Add structured startup config summary without printing secrets.
- Implement `FAIL_CLOSED` scanner failure behavior. (done)
- Add config validation endpoint.
- Add log rotation guidance for JSONL audit logs.
- Add optional SQLite audit backend.
- Add Redis-backed rate limiter option. (done)
- Add Kubernetes/Helm example after Docker Compose is stable.

Exit criteria:

- A user can run the gateway on a shared dev server safely.
- Basic production deployment guidance exists.
- Secrets are not printed in startup logs or audit output.

## Backlog

Potential future work:

- Semantic scanner plugin interface.
- External semantic scanner HTTP hook. (done)
- Optional local small-model classifier.
- promptfoo or garak integration.
- OWASP LLM Top 10 mapping in findings.
- Export audit events to OpenTelemetry.
- Admin UI for policy edits.
- Native provider adapters after OpenAI-compatible path is mature.

## Near-Term Execution Order

Start here:

1. Add tool-call argument scanning and policy.
2. Add generated Python fallback checks for `config/rules.yaml`.
3. Improve system prompt leak heuristics.

The next implementation task should be **tool-call argument scanning and policy**, unless a blocking bug appears first.
