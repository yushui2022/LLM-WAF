# LLM-WAF Roadmap

This roadmap keeps the project focused on its core purpose: **a zero-intrusion LLM application firewall**. Telemetry such as token usage and cost estimates is useful, but it is secondary. The main product value is runtime protection, explainable decisions, low false positives, and easy deployment.

## Product Positioning

LLM-WAF is an OpenAI-compatible security gateway for LLM applications, with native adapters only where protocol-specific WAF coverage exists.

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
- Untested native provider passthrough. Native adapters must have protocol-specific extraction, redaction, streaming fixtures, and audit coverage before being enabled.

## Current Baseline

Implemented:

- OpenAI-compatible `/v1/chat/completions` proxy.
- Streaming and non-streaming request handling.
- Anthropic native `/v1/messages` streaming and non-streaming scanning.
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
- Anthropic native `/v1/messages` buffered and streaming adapter. (done)
- Native Gemini adapter after Anthropic proves the adapter pattern.

## Near-Term Direction

The old near-term list has been superseded by the Phase 2 plan below. `P2-C1` is done; current priority is:

1. Start the optional local semantic layer (`P2-A1`) and the credible eval-set expansion (`P2-A2`).
2. Run production-readiness work in parallel where possible: observability, benchmark, and audit durability (`Track B`).
3. Continue indirect/tool-call injection protection after the semantic/eval foundation is in place (`P2-A3`).

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

#### 1. Harden regex execution against ReDoS  *(addresses G1, G2)* — DONE 2026-05-29

**Why first:** this is the only gap with a clear *availability* impact — a single adversarial prompt can pin a worker. Everything else is recall/precision tuning.

**Prerequisites:**
- Inventory all patterns in `app/security/rules.py` and `config/rules.yaml` containing unbounded `.*`, `.+`, or `.{0,N}` with `N >= 20` inside alternations.
- Decide on engine strategy: stay on stdlib `re` with a wall-clock timeout, or migrate hot rules to `google/re2` (no backtracking, but no lookaround). Document the decision in `docs/rule-quality.md`.
- Add a ReDoS micro-benchmark harness (`scripts/redos_probe.py`) that feeds known pathological inputs to each rule and asserts per-match wall time.

**Work:**
- Replace `Rule.regex` `@property` with a precomputed `re.Pattern` set once in `__post_init__` (use `object.__setattr__` because the dataclass is frozen). Single compilation per process.
- Add `SCANNER_RULE_TIMEOUT_MS` (default e.g. `50`) and enforce per-rule timeout in `_scan_direct` / `_scan_sensitive`. If stdlib `re` is kept, run scans in a worker thread with a deadline; on timeout, emit a `scanner.timeout` finding and continue.
- Tighten the worst offenders: bound character classes (`[^\n]{0,60}` instead of `.{0,60}`) and remove `re.DOTALL` from rules that don't actually want newline matching.

**Progress (2026-05-29):**
- Done: `SECURITY.md` and `docs/threat-model.md` published.
- Done: basic issue templates and a PR template are in place.
- Pending: CONTRIBUTING guidance.

**Progress (2026-05-29):**
- Done: `SECURITY.md`, `docs/threat-model.md`, `CONTRIBUTING.md`, and issue / PR
  templates are in place.

**Exit criteria:**
- `scripts/redos_probe.py` finishes under 1s per rule on the supplied adversarial corpus.
- Rule load happens once at import time (verifiable via a unit test that asserts `rule.regex is rule.regex`).
- New env var documented in README.

#### 2. Streaming safety: change default + add integration tests  *(addresses G4, G8)* — DONE 2026-05-29

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

#### 3. Multi-layer encoding bypass coverage  *(addresses G3)* — DONE 2026-05-29

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

Items 1–4 are done. Remaining legacy work maps into Phase 2: item 5 becomes `P2-A1`, item 6 should happen before large native-adapter work, and item 7 belongs with production-readiness work in Track B.

---

## Phase 2: Path to a Production-Grade, Adoptable Open-Source WAF (2026-05-29)

Items 1–4 are merged: the deterministic core (ReDoS hardening, streaming safety,
multi-layer decoding, unified rule IDs) is solid. The gaps below are what
separates "a working regex gateway" from "a WAF people trust in production and
star on GitHub." They are grouped into three tracks. **The tracks are largely
independent and can run in parallel**; within a track, items are ordered.

This section is written to be executed by an implementation agent (Codex). Each
item states *why it matters*, its *prerequisites*, a *file-level task list*, and
*exit criteria*. Difficulty/risk tags help with scheduling:

- **Difficulty**: S (a few hours) / M (1–2 days) / L (multi-day, needs design).
- **Risk**: how likely the change breaks existing behavior.
- **Blocking**: must another item land first?

> **Recommended global order for "going big":** P2-C1 (CI gates) first, then
> P2-A1 (semantic layer) → P2-A2 (eval set credibility) → Track B
> (observability/ops) and the rest of Track C in parallel. The semantic layer is
> the only item that *qualitatively* changes what the product can detect; the
> other tracks make it trustworthy and adoptable.

---

### Track A — Detection capability (the product ceiling)

This track decides whether the project is "yet another regex WAF" or a genuinely
differentiated tool. Highest strategic value.

#### P2-A1. Optional local semantic classifier  *(supersedes the detailed plan of legacy Item 5; addresses G5)*

**Difficulty:** L · **Risk:** Medium (default-off keeps blast radius small) · **Blocking:** none (core is ready)

**Why it matters:** Regex cannot catch paraphrased ("pretend the earlier rules
don't apply"), translated, or indirect-injection (attack hidden in
RAG/tool-returned text) attacks. A small CPU classifier closes most of this gap
and is the single biggest differentiator. Must be *optional and default-off* so
the gateway stays dependency-light and deterministic unless the operator opts in.

**Prerequisites / decisions to lock before coding:**
- **Model choice.** Pick a small, permissively-licensed prompt-injection
  classifier that runs on CPU within budget. Candidates to evaluate:
  `protectai/deberta-v3-base-prompt-injection-v2` (ONNX-exportable),
  `deepset/deberta-v3-base-injection`, or a distilled/quantized variant. Record
  the chosen model, its license, size, and measured CPU latency (p50/p95 for a
  256-token input) in `docs/semantic-local.md`. **Do not** add a heavyweight
  framework (no full `torch` if an ONNX runtime suffices); prefer
  `onnxruntime` + `tokenizers`.
- **Dependency isolation.** New deps go in an optional extra
  (`pip install llm-waf[semantic]`), declared in `pyproject.toml` under
  `[project.optional-dependencies]`. The base install must not pull them in.
- **Interface contract.** Reuse the existing async contract from
  `app/security/semantic.py`: a scanner exposes `async def scan_input(text) -> ScanResult`
  and `async def scan_output(text) -> ScanResult`, and results are combined via
  `merge_scan_results`. Define a `SemanticScanner` `Protocol` in `semantic.py`
  that both `HttpSemanticScanner` and the new local scanner satisfy.

**File-level tasks:**
- `app/security/semantic.py`: extract a `SemanticScanner` `typing.Protocol`
  (methods `scan_input`, `scan_output`). Make `HttpSemanticScanner` explicitly
  conform. Keep `merge_scan_results` as the single combination point.
- `app/security/semantic_local.py` (NEW): implement `LocalSemanticScanner`
  conforming to the protocol.
  - Lazy-load the ONNX model + tokenizer on first scan (not at import), so a
    default-off deployment never pays the load cost. Guard the import of
    `onnxruntime`/`tokenizers` and raise a clear, actionable error if the
    `[semantic]` extra is missing.
  - Map the classifier score to a `Finding`: `rule_id="semantic.prompt_injection.local"`,
    `category="prompt_injection"`, `severity` derived from score band,
    `action` driven by config (see below), `source="semantic_local"`,
    `evidence` = truncated/redacted snippet (never log the full input).
  - Threshold + action are configurable: scores below `SEMANTIC_LOCAL_THRESHOLD`
    produce no finding; above it, `action` is `SEMANTIC_LOCAL_ACTION`
    (`log_only` | `block` for input, `redact` | `log_only` for output).
    Default action `log_only` so enabling the model can't suddenly start
    blocking traffic.
  - Hard-cap input length fed to the model (`SEMANTIC_LOCAL_MAX_CHARS`, e.g.
    4000) to bound latency; document that very long inputs are truncated.
  - Wrap inference in a timeout/error guard: on model error, honor the global
    `FAIL_CLOSED` setting exactly like other scanner failures (do not invent a
    new failure mode).
- `app/config.py`: add `semantic_local_enabled` (`SEMANTIC_LOCAL`, default
  `False`), `semantic_local_model_path` (`SEMANTIC_LOCAL_MODEL_PATH`),
  `semantic_local_threshold` (`SEMANTIC_LOCAL_THRESHOLD`, default e.g. `0.85`),
  `semantic_local_action` (`SEMANTIC_LOCAL_ACTION`, default `log_only`),
  `semantic_local_max_chars` (`SEMANTIC_LOCAL_MAX_CHARS`, default `4000`).
- `app/main.py` (or the post-Item-6 factory): instantiate `LocalSemanticScanner`
  when `SEMANTIC_LOCAL=true`; wire its result through `merge_scan_results` in
  both input and output paths, exactly mirroring how `HttpSemanticScanner` is
  used today. If both HTTP and local are configured, run both and merge all.
- `pyproject.toml`: add `[project.optional-dependencies] semantic = [...]`.
- `tests/test_semantic_local.py` (NEW): unit tests with the model **mocked**
  (no network/model download in CI) verifying score→finding mapping, threshold
  gating, action selection, length cap, fail-closed behavior, and that
  default-off yields no scanner instance.
- `tests/eval_set.jsonl` + a NEW `tests/eval_set_regex_miss.jsonl`: add a
  labeled slice of attacks the regex layer is known to miss (paraphrased ignore,
  translated jailbreaks, prose-embedded indirect injection) plus nearby benign
  hard negatives.
- `scripts/evaluate.py`: support an optional `--with-semantic-local` flag (or a
  separate eval invocation) so CI can measure recall lift on the regex-miss
  slice without making the model a hard CI dependency. Gate this eval behind a
  marker so the default CI job (no model) still passes.
- `docs/semantic-local.md` (NEW) + README "Semantic scanner hook" section:
  document model choice, license, opt-in install, env vars, latency numbers,
  and the explicit recommendation to start with `action=log_only` and review
  audit logs before switching to `block`.

**Progress (2026-05-29):**
- Done: shared semantic scanner protocol, multiple semantic scanners, local ONNX adapter, optional `[semantic]` dependencies, mocked local scanner tests, and `docs/semantic-local.md`.
- Done: `tests/eval_set_regex_miss.jsonl` now records paraphrased, multilingual, and indirect-injection samples plus benign hard negatives.
- Done: `scripts/evaluate.py` accepts `--dataset` as the documented dataset selector while keeping `--file` as a compatibility alias.
- Pending: choose a real model, document its license and CPU latency, and add a model-backed semantic eval invocation that stays out of default CI when model files are absent.

**Exit criteria:**
- Base `pip install` works with **zero** new heavy dependencies; semantic deps
  only arrive via the `[semantic]` extra.
- With `SEMANTIC_LOCAL=true`, recall on `eval_set_regex_miss.jsonl` rises
  measurably vs. regex-only, while precision on the benign hard negatives in
  that slice stays above the configured threshold.
- Default-off behavior is byte-identical on the existing eval and test suite.
- Mocked unit tests cover every config branch; **no model download happens in CI**.

#### P2-A2. Eval-set credibility: scale up + import public datasets  *(addresses the "52 self-authored samples prove little" gap)*

**Difficulty:** M · **Risk:** Low (test-data only) · **Blocking:** none; strongly complements P2-A1

**Why it matters:** `P=R=100%` on 52 hand-written samples only proves the rules
match their own authors' imagination. Credible recall/precision claims need
volume and *independently sourced* attacks. This is what lets the README make
honest, defensible quality statements — table stakes for adoption.

**Prerequisites / decisions:**
- Survey permissively-licensed public datasets and record license + attribution
  for each before importing. Candidates: `deepset/prompt-injections`,
  `jackhhao/jailbreak-classification`, Lakera "Gandalf"-style public dumps,
  `JasperLS/prompt-injections`. **Only import datasets whose license permits
  redistribution**; otherwise add a downloader script instead of vendoring.
- Decide the target eval size and the benign:malicious ratio (recommend a
  realistic skew, e.g. heavily benign, so FPR is measured meaningfully).
- Decide how to keep CI fast: a small curated in-repo `eval_set.jsonl` for the
  per-PR gate, plus an opt-in larger `eval_set_extended.jsonl` (or downloaded
  corpus) for a nightly/weekly job.

**File-level tasks:**
- `scripts/import_eval_datasets.py` (NEW): fetch/convert permitted public
  datasets into the project's JSONL schema (`id`, `text`, `label`, `category`),
  deduplicate against existing samples, and emit `tests/eval_set_extended.jsonl`.
  For non-redistributable sets, fetch at runtime and document the manual step.
- `tests/eval_set.jsonl`: grow the curated per-PR set with the most
  discriminating imported samples and new benign hard negatives (multilingual,
  security-education prose, legitimate roleplay, code containing keyword-like
  tokens).
- `tests/eval_set_extended.jsonl` (NEW, possibly git-LFS or generated): the
  larger corpus for the extended job.
- `scripts/evaluate.py`: add a `--dataset` path arg so the same harness runs on
  either set; print a per-category breakdown and a confusion matrix.
- `.github/workflows/`: add a separate scheduled (nightly) workflow that runs
  the extended eval with looser-but-tracked thresholds and uploads the report as
  an artifact. Keep the per-PR job on the fast curated set.
- `docs/rule-quality.md` + README: replace any "100%" claim with honest,
  dataset-attributed numbers and a link to the methodology. Add a results table
  with sample counts and sources.

**Exit criteria:**
- Per-PR CI still runs in well under a minute on the curated set.
- Extended eval runs on >= an order of magnitude more samples than today, with
  documented sources and licenses.
- README quality claims are reproducible via a single documented command.

#### P2-A3. Indirect / tool-call injection scanning  *(extends the legacy Phase-5 "tool-call argument scanning" item)*

**Difficulty:** M · **Risk:** Medium · **Blocking:** P2-A1 recommended first (so semantic + regex both cover the new surface)

**Why it matters:** The highest-severity real-world LLM attacks are *indirect*:
malicious instructions arrive inside tool results, RAG documents, or function
arguments — content the current gateway treats as trusted. Scanning these
surfaces is a meaningful coverage expansion and a strong differentiator.

**Prerequisites / decisions:**
- Enumerate where untrusted content enters an OpenAI-compatible request:
  `messages[].content` with `role: tool`, `tool_calls[].function.arguments`,
  and (for vision/multimodal) text parts. Document the threat model: tool/role
  content is *data*, not *instructions*.
- Decide policy semantics: should a finding inside a `tool` message `block`,
  `redact`, or `log_only` by default? (Recommend `redact`/`log_only` default,
  `block` opt-in, since false positives here break legitimate RAG.)

**File-level tasks:**
- `app/security/payload.py`: add extraction of tool-role message content and
  `tool_calls` argument JSON as separately-labeled scannable segments. (done
  2026-05-29; gateway policy wiring still pending)
- Scanner/gateway path: scan these segments through the same rule + semantic
  pipeline, tagging findings with `source="tool_call"` / `source="tool_result"`
  so audit and policy can treat them distinctly. (partially done 2026-05-29:
  audit records safe segment counts and route policy can include/exclude tool
  arguments and tool results; deterministic input findings now carry segment
  source labels; dashboard/audit summaries can group and filter by source;
  semantic segment-level attribution pending)
- `app/policy.py`: add per-route toggles
  (`scan_tool_arguments`, `scan_tool_results`, with safe defaults). (done
  2026-05-29)
- `tests/`: add malicious-indirect-injection samples (instruction smuggled in a
  fake "search result") and benign tool-result hard negatives.
- README + `docs/protocol-support.md`: document the new scan surfaces and
  policy knobs.

**Exit criteria:**
- Indirect-injection eval samples are caught; benign tool results are not
  false-flagged at the default policy.
- Existing non-tool requests are unaffected.

---

### Track B — Production readiness (so operators trust it)

Independent of Track A. These make the difference between "runs on my laptop"
and "I'll put it in front of real traffic."

#### P2-B1. Observability: metrics, structured logs, health detail

**Difficulty:** M · **Risk:** Low · **Blocking:** cleaner after Item 6 (decomposition), but not required

**Why it matters:** The first question any operator asks about a gateway is "how
do I monitor it and what latency does it add?" Today there are no metrics, no
structured logs, no latency visibility. This is a hard blocker for production
adoption.

**Prerequisites / decisions:**
- Choose the metrics approach: `prometheus_client` exposing `/metrics` is the
  conventional, low-friction choice. Confirm it's an acceptable (optional?)
  dependency.
- Define the metric set and label cardinality budget (avoid high-cardinality
  labels like raw rule text or user IDs).

**File-level tasks:**
- `app/observability.py` (NEW): define counters/histograms — requests by
  route/decision (`allowed`/`blocked`/`redacted`), findings by
  `category`/`severity`, scanner latency histogram, upstream latency histogram,
  scanner-timeout counter, fail-closed-trip counter.
- Gateway path: increment metrics at the decision points (reuse the existing
  audit-event construction site so the two stay consistent).
- `GET /metrics` endpoint (optionally auth-gated / bindable to a separate port
  via config) returning Prometheus exposition format.
- Replace ad-hoc logging with structured JSON logs (one event per request) using
  stdlib `logging` + a JSON formatter; **route all secret-bearing fields through
  the same redaction used by P2-B3**.
- `tests/test_observability.py` (NEW): assert counters move on block/redact/allow
  and that `/metrics` renders.
- README "Architecture"/ops section + a new `docs/observability.md`: list every
  metric, its labels, and a sample Grafana panel query.

**Exit criteria:**
- `/metrics` exposes the documented series; scraping it is documented.
- Structured logs contain no secret material (shared test with P2-B3).
- Negligible latency overhead (verify with the P2-B2 benchmark).

**Progress (2026-05-29):**
- Done: dependency-free Prometheus-compatible `/metrics` endpoint.
- Done: request counter, request latency histogram, scanner latency histogram, upstream latency histogram, finding counter by category/severity/action/source, scanner error counter, and fail-closed counter.
- Done: `docs/observability.md` documents metrics, scrape config, and starter PromQL queries.
- Done: structured JSON request log through `llm_waf.requests`, with raw finding evidence and exception text omitted.
- Done: auth-gated `/health/config` redacted runtime configuration summary.
- Pending: startup-time structured config summary.

#### P2-B2. Performance benchmark + published latency budget

**Difficulty:** S–M · **Risk:** Low · **Blocking:** none

**Why it matters:** A WAF's adoption hinges on its added latency. There is
currently no number to cite. A repeatable benchmark also guards against future
latency regressions.

**File-level tasks:**
- `scripts/benchmark.py` (NEW): drive the gateway with a fixed corpus
  (benign + malicious, streaming + non-streaming) against a *fake/stub upstream*
  (reuse the `_FakeAsyncClient` pattern from `tests/test_streaming_holdback.py`),
  and report added-latency p50/p95/p99, TTFB for streaming, and throughput.
- `docs/performance.md` (NEW): publish methodology, hardware, and the measured
  overhead with vs. without scanning, and with vs. without the semantic layer.
- Optional CI guardrail: a job that runs a short benchmark and fails if added
  p95 latency regresses beyond a documented envelope (mark non-blocking first to
  avoid flaky-perf CI failures).

**Exit criteria:**
- A single command produces a reproducible latency/throughput report.
- README cites a concrete "adds ~X ms p95" number with a link to methodology.

#### P2-B3. Audit log durability: rotation + external sinks

**Difficulty:** M · **Risk:** Medium (touches the audit write path) · **Blocking:** none

**Why it matters:** Audit currently appends to a single local JSONL file with no
rotation — it will fill the disk in production, and there's no path to a SIEM.
Compliance-minded users need durable, exportable audit.

**Prerequisites / decisions:**
- Decide sink abstraction: a pluggable `AuditSink` interface with
  implementations for rotating-file, stdout-JSON (for container log shippers),
  and an HTTP/webhook sink (for SIEM ingest). Keep file the default.

**File-level tasks:**
- `app/audit.py`: introduce an `AuditSink` protocol; refactor the existing
  writer into a `FileAuditSink` with size/time-based rotation
  (`AUDIT_ROTATE_MAX_BYTES`, `AUDIT_ROTATE_BACKUPS`). Add `StdoutAuditSink` and
  an optional `HttpAuditSink` (best-effort, non-blocking, bounded queue so a slow
  SIEM can't stall request handling).
- `app/config.py`: `AUDIT_SINK` (`file`|`stdout`|`http`), rotation + HTTP sink
  settings.
- Ensure findings written to audit are already redaction-safe (evidence is
  truncated; no raw secrets). Add a test that a secret in input never appears
  verbatim in any audit sink output.
- `tests/test_audit.py`: extend for rotation and the new sinks (HTTP sink with a
  fake server).
- README + `docs/`: document sinks and rotation.

**Exit criteria:**
- File sink rotates and never grows unbounded.
- A misbehaving HTTP sink degrades gracefully (drops/queues, never blocks the
  request path) and this is tested.
- No secret material in any sink output (shared test with P2-B1).

**Progress (2026-05-29):**
- Done: default JSONL audit sink rotates by size with configurable backup count.
- Done: `AUDIT_SINK=stdout` emits one JSON audit event per line for container
  log collectors while keeping a bounded dashboard buffer.
- Done: `AUDIT_SINK=http` ships audit events asynchronously to a webhook/SIEM
  endpoint with a bounded queue and drop-on-full behavior.
- Done: `/metrics` reports audit queue depth, dropped events, and delivery
  failures with only the low-cardinality `sink` label.
- Pending: shutdown-time flush.

---

### Track C — Release engineering & project hygiene (so contributors and users arrive)

Cheap, high-leverage, mostly parallelizable. These make the repo look and behave
like a serious open-source project.

#### P2-C1. CI quality gates: lint + type-check + coverage — DONE 2026-05-29

**Difficulty:** S · **Risk:** Low · **Blocking:** none (do early — it improves every later PR)

**File-level tasks:**
- Add `ruff` (lint + format) and `mypy` configs to `pyproject.toml`. Fix or
  explicitly ignore existing findings in a dedicated PR so the gate starts green.
- `.github/workflows/ci.yml`: add `ruff check`, `ruff format --check`, `mypy app`,
  and a coverage run (`coverage`/`pytest-cov`) that uploads a report. Start
  coverage as report-only, then ratchet a minimum once a baseline is known.
- `docs/`/CONTRIBUTING: document the local pre-commit commands.

**Exit criteria:**
- CI fails on lint/type errors; the gate is green at merge time.
- Coverage is reported on every PR.

#### P2-C2. Packaging & distribution: PyPI + versioning + CHANGELOG + image publish

**Difficulty:** M · **Risk:** Low · **Blocking:** P2-C1 recommended first

**Why it matters:** Users currently can only `git clone`. `pip install llm-waf`
and `docker pull` dramatically lower the adoption barrier.

**File-level tasks:**
- `pyproject.toml`: finalize package metadata, entry-point/console script for
  launching the gateway, classifiers, and the `[semantic]` extra (from P2-A1).
- Adopt semantic versioning; add `CHANGELOG.md` (Keep-a-Changelog format) and
  start tagging releases.
- `.github/workflows/release.yml` (NEW): on tag, build the sdist/wheel and
  publish to PyPI (trusted publishing/OIDC), and build+push a multi-arch Docker
  image to GHCR. Pin and document the published image name.
- README: add `pip install` and `docker pull` quick-starts; add a version badge.

**Exit criteria:**
- A tagged release publishes a wheel to PyPI and an image to GHCR
  automatically.
- README install instructions work from a clean environment.

**Progress (2026-05-29):**
- Done: `pyproject.toml` has a console script, `Dockerfile` now uses the
  packaged CLI, `CHANGELOG.md` exists, and `.github/workflows/release.yml`
  scaffolds tag-based publishing.
- Done: README includes `pip install` and local `llm-waf` quick-starts plus a
  version badge.
- Done: local sdist and wheel builds are verified with `python -m build
  --no-isolation`.
- Pending: first tagged release verification.

#### P2-C3. Community & security hygiene

**Difficulty:** S · **Risk:** None · **Blocking:** none

**Why it matters:** A *security* tool with no responsible-disclosure policy is a
bad look and deters serious users. These files also signal maturity.

**File-level tasks:**
- `SECURITY.md` (NEW): responsible disclosure contact + process + supported
  versions.
- Strengthen `CONTRIBUTING` (if thin): dev setup, the eval-gate workflow, how to
  file false-positive/bypass reports (link the existing formats in
  `docs/rule-quality.md`).
- Issue/PR templates under `.github/`: bug, false-positive, bypass-report,
  feature.
- A short "Threat model & non-goals" section in README or `docs/threat-model.md`
  so users understand what the WAF does and does **not** defend against (sets
  honest expectations — important for a security tool).

**Exit criteria:**
- Repo has SECURITY.md, templates, and a clear threat-model statement.

---

### Phase 2 Cross-Cutting Rules (apply to every item)

- **Default-off for anything heavy.** New dependencies (semantic model, metrics
  client) must be optional extras; the base install stays light and the default
  behavior stays deterministic.
- **No secrets in any output.** Logs, metrics labels, audit sinks, `/metrics`,
  and `/health/config` must all pass the shared redaction test.
- **Eval/tests move with behavior.** Any rule/scanning change ships eval samples
  in the same PR and keeps the per-PR gate green.
- **Latency is a feature.** Anything in the request path must be benchmarked
  (P2-B2) and stay within the documented envelope.
- **One focused PR per item.** Each item above is sized for a single reviewable
  PR; do not bundle a Track A detection change with a Track C packaging change.

### Phase 2 Suggested Schedule for an Implementation Agent

1. **P2-C1** (CI gates) — done.
2. **P2-A1** (semantic layer) — the headline capability; longest lead time, start early.
3. **P2-A2** (eval credibility) in parallel with A1 — A1 needs the regex-miss slice A2 produces.
4. **Track B** (observability, benchmark, audit sinks) — parallelizable across agents.
5. **P2-A3** (indirect injection) after A1 lands.
6. **P2-C2 / P2-C3** (packaging, community) — interleave anytime; do C3 before the first public "release" announcement.
