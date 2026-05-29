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
- Document false-positive and bypass reporting format. (done)
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
- Block known unscanned generation passthrough routes by default. (done)
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
- Protocol support matrix and native-adapter requirements. (done)
- Native provider adapters after OpenAI-compatible path is mature.

## Near-Term Execution Order

Start here:

1. Add tool-call argument scanning and policy.
2. Add generated Python fallback checks for `config/rules.yaml`.
3. Improve system prompt leak heuristics.

The next implementation task should be **tool-call argument scanning and policy**, unless a blocking bug appears first.

---

## Review Findings & Next Steps (2026-05-28)

This section captures gaps identified in a code review of the current `main` snapshot, the work items to address them in order, and the prerequisites each item depends on. Numbering is the recommended execution order. Each item is sized to be a single focused PR.

### Identified Gaps (summary)

- **G1. ReDoS risk surface.** Many rules combine `re.DOTALL | re.IGNORECASE` with patterns like `.{0,60}` / `.{0,80}` and large alternations (e.g. `inj.role_hijack.en`). Adversarial input can drive catastrophic backtracking. No per-scan timeout exists.
- **G2. Regex re-compilation on every access.** `Rule.regex` is a `@property` that calls `re.compile` on every hit. CPython's internal cache hides cost but is fragile; high QPS or large rule sets will thrash it.
- **G3. Encoding bypass coverage is single-layer.** `text_variants` decodes base64/hex once, does not recurse, and does not re-decode after normalization. `base64(base64(...))` and zero-width-inside-base64 evade the scanner.
- **G4. Streaming defaults favor latency over safety.** `STREAM_HOLD_BACK_FRAMES=0` is the default, so output redaction only catches single-frame hits. For a tool branded "WAF", the safe default should be `>=1`.
- **G5. Pure-regex recall ceiling.** Rules cannot catch paraphrased / translated / indirect-injection attacks. The `semantic.py` hook is optional and off by default; new users may believe deployment alone is sufficient.
- **G6. `app/main.py` is ~930 lines.** Routing, lifecycle, audit-event construction, streaming, and redaction dispatch are co-located. Adding native protocols or new routes will worsen this.
- **G7. Rate-limit memory backend silently incorrect under multi-worker.** README warns, but the process does not log a startup warning when `RATE_LIMIT_BACKEND=memory` and `--workers > 1` (or replica count > 1).
- **G8. Streaming integration test coverage is unclear.** Cross-frame finding + hold-back redaction is the most regression-prone path and needs explicit end-to-end tests.
- **G9. Rule ID naming inconsistency.** Mix of `inj.ignore_previous.en`, `inj.template_tags` (no lang), `inj.hidden_rules_extract.zh`. Hurts docs, dashboards, and `disabled_rules` config ergonomics.
- **G10. Startup logs and audit output are not audited for secret leakage.** No structured "safe startup summary" exists yet (already tracked in Phase 5).

### Execution Plan

The order below is chosen so that safety-critical, low-risk-of-regression items come first, and items that unlock later work (timeouts, rule ID schema) precede items that depend on them.

#### 1. Harden regex execution against ReDoS  *(addresses G1, G2)*

**Why first:** this is the only gap with a clear *availability* impact — a single adversarial prompt can pin a worker. Everything else is recall/precision tuning.

**Prerequisites:**
- Inventory all patterns in `app/security/rules.py` and `config/rules.yaml` containing unbounded `.*`, `.+`, or `.{0,N}` with `N >= 20` inside alternations.
- Decide on engine strategy: stay on stdlib `re` with a wall-clock timeout, or migrate hot rules to `google/re2` (no backtracking, but no lookaround). Document the decision in `docs/rule-quality.md`.
- Add a ReDoS micro-benchmark harness (`scripts/redos_probe.py`) that feeds known pathological inputs to each rule and asserts per-match wall time.

**Work:**
- Replace `Rule.regex` `@property` with a precomputed `re.Pattern` set once in `__post_init__` (use `object.__setattr__` because the dataclass is frozen). Single compilation per process.
- Add `SCANNER_RULE_TIMEOUT_MS` (default e.g. `50`) and enforce per-rule timeout in `_scan_direct` / `_scan_sensitive`. If stdlib `re` is kept, run scans in a worker thread with a deadline; on timeout, emit a `scanner.timeout` finding and continue.
- Tighten the worst offenders: bound character classes (`[^\n]{0,60}` instead of `.{0,60}`) and remove `re.DOTALL` from rules that don't actually want newline matching.

**Exit criteria:**
- `scripts/redos_probe.py` finishes under 1s per rule on the supplied adversarial corpus.
- Rule load happens once at import time (verifiable via a unit test that asserts `rule.regex is rule.regex`).
- New env var documented in README.

#### 2. Streaming safety: change default + add integration tests  *(addresses G4, G8)*

**Prerequisites:**
- Item 1 merged (so that scanner timeouts don't reintroduce streaming stalls).
- Decide and document the new default for `STREAM_HOLD_BACK_FRAMES` in README ("Known limitations" section). Recommended: `1`.

**Work:**
- Change default in `app/config.py` and `docs/protocol-support.md`.
- Add `tests/test_streaming_holdback.py` covering:
  - cross-frame secret split across 2 SSE frames is redacted with hold-back=1;
  - hold-back=0 reproduces the documented leak;
  - `FAIL_CLOSED=true` mid-stream produces an SSE error event and terminates cleanly;
  - `usage` frame still arrives and is recorded.
- Add a TTFB regression test that asserts first-frame latency stays within an agreed envelope at hold-back=1.

**Exit criteria:**
- New default ships with green tests.
- README delta clearly explains the latency/safety tradeoff change.

#### 3. Multi-layer encoding bypass coverage  *(addresses G3)*

**Prerequisites:**
- Items 1 and 2 merged (do not stack new scanning work on top of unhardened regex).
- Add bypass samples to `tests/eval_set.jsonl`:
  - `base64(base64(payload))`
  - base64 with zero-width chars interleaved
  - URL-encoded base64
  - hex-of-utf8 attacks
  - normalize-then-decode and decode-then-normalize variants

**Work:**
- In `app/security/normalizer.py`, recurse `text_variants` up to a bounded depth (suggest 2) with cycle protection via the existing `seen` set.
- Run normalization *after* each decode pass, not only on the original input.
- Cap total derived variant size to bound CPU.

**Exit criteria:**
- New eval samples pass at configured precision/recall thresholds.
- Worst-case variant generation time per request is bounded and benchmarked.

#### 4. Rule ID schema unification + per-rule metadata cleanup  *(addresses G9)* — DONE 2026-05-29

**Prerequisites:**
- Lock the schema: `<category>.<subtype>.<lang|universal>`. Document in `docs/rule-quality.md`.
- Plan a migration: keep old IDs as `aliases` for one release so existing `disabled_rules` configs don't break.

**Work:**
- Rename rule IDs across `app/security/rules.py` and `config/rules.yaml`.
- Add `aliases: tuple[str, ...]` to `Rule` and honor aliases in `_rule_enabled` and in eval reports.
- Update CHANGELOG / README with the migration window.

**Exit criteria:**
- All rule IDs match the schema.
- Old IDs in `policy.yaml.disabled_rules` still work and emit a deprecation warning in startup logs.

#### 5. Optional default semantic classifier  *(addresses G5)*

**Prerequisites:**
- Items 1–4 merged. The deterministic layer must be solid before adding a probabilistic one — otherwise eval signals get muddled.
- Choose a small model that runs on CPU within the gateway's latency budget (e.g. a distilled prompt-injection classifier, ONNX or GGUF). Document the licensing.
- Define a stable plugin interface in `app/security/semantic.py` so HTTP and in-process scanners share a contract.

**Work:**
- Add `app/security/semantic_local.py` implementing the plugin interface with a lazy-loaded local model. Default off; enabled via `SEMANTIC_LOCAL=true`.
- Wire the result through `merge_scan_results` exactly like the HTTP hook.
- Add eval samples that the regex layer is known to miss (paraphrased "ignore previous", translated jailbreaks, indirect-injection prose) and measure recall lift.

**Exit criteria:**
- With `SEMANTIC_LOCAL=true`, recall on the new "regex-miss" eval slice rises measurably; precision on benign hard negatives does not drop below threshold.
- Default-off behavior is unchanged on existing eval.

#### 6. `app/main.py` decomposition  *(addresses G6)*

**Prerequisites:**
- Items 1–3 merged so refactor diffs don't collide with behavior changes.
- Snapshot existing test coverage; the refactor must be behavior-preserving.

**Work:**
- Split `app/main.py` into:
  - `app/gateway/app_factory.py` — FastAPI app + middleware + DI wiring.
  - `app/gateway/chat_completions.py` — the `/v1/chat/completions` handler.
  - `app/gateway/streaming.py` — SSE proxying, rolling window, hold-back.
  - `app/gateway/audit_event.py` — event construction and finalization.
  - `app/gateway/passthrough.py` — `/v1/*` safe routes and rejected unscanned routes.
- `main.py` becomes a thin entrypoint (target: <100 lines).

**Exit criteria:**
- All existing tests pass without modification.
- No module exceeds 300 lines.

#### 7. Safe startup summary + multi-worker rate-limit warning  *(addresses G7, G10)*

**Prerequisites:**
- Item 6 merged (cleaner `app_factory.py` is the natural home for startup hooks).
- Inventory which settings are sensitive and must be redacted in any log output (`UPSTREAM_API_KEY`, `GATEWAY_API_KEYS`, `REDIS_URL` password, `SEMANTIC_SCANNER_URL` token if embedded).

**Work:**
- On startup, log a single structured JSON line with effective config, with secrets replaced by `"<set>"` / `"<unset>"`.
- Detect `RATE_LIMIT_BACKEND=memory` combined with multi-worker (`WEB_CONCURRENCY` / `--workers > 1` / replica > 1 if detectable) and log a WARNING that limits are per-worker.
- Add `/health/config` (auth-gated) that returns the same redacted summary for ops verification.

**Exit criteria:**
- No secret material appears in any default log path or `/health/config` output.
- A unit test confirms the warning fires under the misconfigured combination.

### Cross-Cutting Prerequisites (apply to every item above)

- Each PR updates or adds eval samples in `tests/eval_set.jsonl` and/or `tests/output_eval_set.jsonl` when it touches rules or scanning behavior.
- Each PR keeps `python -m unittest discover -s tests` green and meets the configured precision/recall gates.
- README and `docs/` are updated in the same PR as user-visible behavior changes.
- No regression in TTFB or end-to-end latency beyond a documented envelope.

### Suggested Sequencing Note

Items 1, 2, 3 are safety-critical and should land before the project is recommended for any production use. Items 4 and 6 are pure hygiene and can be parallelized with item 5 if reviewer bandwidth allows. Item 7 is the final pre-deployment polish before declaring the gateway ready for shared-dev or staging environments.
