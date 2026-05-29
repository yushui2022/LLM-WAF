# Observability

LLM-WAF exposes dependency-free Prometheus-compatible metrics at `/metrics`.

The endpoint intentionally uses low-cardinality labels. Do not add raw user IDs,
API keys, prompts, rule evidence, or full request paths as labels.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `llm_waf_requests_total` | counter | `route`, `path`, `decision`, `status_code`, `stream` | Final request decisions recorded from the same event used for audit. |
| `llm_waf_request_latency_ms` | histogram | `route`, `path`, `decision`, `status_code`, `stream`, `le` | End-to-end gateway latency in milliseconds. |
| `llm_waf_scanner_latency_ms` | histogram | `route`, `path`, `decision`, `status_code`, `stream`, `stage`, `le` | Input or output scanner latency in milliseconds. |
| `llm_waf_upstream_latency_ms` | histogram | `route`, `path`, `decision`, `status_code`, `stream`, `phase`, `le` | Upstream provider latency. Streaming requests use `phase="headers"` for upstream response-header latency. |
| `llm_waf_findings_total` | counter | `category`, `severity`, `action`, `source` | WAF findings emitted by deterministic and semantic scanners. |
| `llm_waf_scanner_errors_total` | counter | `kind`, `fail_closed` | Scanner failures, split by deterministic vs. semantic scanner. |
| `llm_waf_fail_closed_total` | counter | `decision` | Requests or streams where `FAIL_CLOSED=true` converted a scanner failure into a blocked/error decision. |

## Example Scrape Config

```yaml
scrape_configs:
  - job_name: llm-waf
    static_configs:
      - targets: ["llm-waf:8080"]
```

## Useful Queries

Blocked request rate:

```promql
sum(rate(llm_waf_requests_total{decision="blocked"}[5m]))
```

Findings by source:

```promql
sum by (source) (rate(llm_waf_findings_total[5m]))
```

p95 gateway latency:

```promql
histogram_quantile(0.95, sum by (le) (rate(llm_waf_request_latency_ms_bucket[5m])))
```

p95 scanner latency by stage:

```promql
histogram_quantile(0.95, sum by (stage, le) (rate(llm_waf_scanner_latency_ms_bucket[5m])))
```

p95 upstream latency:

```promql
histogram_quantile(0.95, sum by (phase, le) (rate(llm_waf_upstream_latency_ms_bucket[5m])))
```

Fail-closed trips:

```promql
sum(rate(llm_waf_fail_closed_total[5m]))
```

## Structured Request Logs

LLM-WAF emits one JSON log line per finalized request through the
`llm_waf.requests` logger.

The structured log includes safe operational fields such as:

- `trace_id`
- `method`
- `path`
- `policy`
- `decision`
- `status_code`
- latency fields
- `finding_count`
- `finding_summary`
- `input_segments`

It intentionally excludes:

- raw prompts and request bodies
- `findings[].evidence`
- raw exception text
- provider or gateway API keys
- authorization headers

Use JSONL audit for detailed finding records. Use structured logs for container
log shipping and operational alerting.

## Audit Rotation

The default file audit sink rotates by size so a long-running gateway does not
grow one file forever:

```env
AUDIT_SINK=file
AUDIT_LOG_PATH=var/audit/events.jsonl
AUDIT_ROTATE_MAX_BYTES=10000000
AUDIT_ROTATE_BACKUPS=5
```

Rotated files are named `events.jsonl.1`, `events.jsonl.2`, and so on. Set
`AUDIT_ROTATE_MAX_BYTES=0` to disable rotation.

For containerized deployments, set `AUDIT_SINK=stdout` to emit each audit event
as one JSON line on stdout. The dashboard keeps a bounded in-memory recent-event
buffer in this mode, but stdout remains the durable handoff point for log
collectors.

## Health And Config

`GET /health` returns a basic liveness response.

`GET /health/config` returns a redacted runtime configuration summary. It uses
the same gateway API-key authentication as the chat endpoint when
`GATEWAY_API_KEYS` is configured.

The config endpoint reports whether secrets are set, but never returns the
secret values themselves. URLs with userinfo are redacted, for example:

```text
redis://<redacted>@localhost:6379/0
```
