# Observability

LLM-WAF exposes dependency-free Prometheus-compatible metrics at `/metrics`.

The endpoint intentionally uses low-cardinality labels. Do not add raw user IDs,
API keys, prompts, rule evidence, or full request paths as labels.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `llm_waf_requests_total` | counter | `route`, `path`, `decision`, `status_code`, `stream` | Final request decisions recorded from the same event used for audit. |
| `llm_waf_request_latency_ms` | histogram | `route`, `path`, `decision`, `status_code`, `stream`, `le` | End-to-end gateway latency in milliseconds. |
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

Fail-closed trips:

```promql
sum(rate(llm_waf_fail_closed_total[5m]))
```
