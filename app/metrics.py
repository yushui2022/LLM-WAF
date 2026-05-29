"""Small Prometheus-compatible metrics registry."""

from __future__ import annotations

import math
from collections import defaultdict
from threading import Lock
from typing import Any

DEFAULT_LATENCY_BUCKETS_MS = (5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, math.inf)


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], dict[str, Any]] = {}

    def inc(self, name: str, labels: dict[str, str] | None = None, amount: float = 1.0) -> None:
        key = (name, _label_key(labels or {}))
        with self._lock:
            self._counters[key] += amount

    def observe(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
        buckets: tuple[float, ...] = DEFAULT_LATENCY_BUCKETS_MS,
    ) -> None:
        key = (name, _label_key(labels or {}))
        with self._lock:
            histogram = self._histograms.setdefault(
                key,
                {
                    "buckets": tuple(buckets),
                    "counts": {bucket: 0 for bucket in buckets},
                    "count": 0,
                    "sum": 0.0,
                },
            )
            histogram["count"] += 1
            histogram["sum"] += value
            for bucket in histogram["buckets"]:
                if value <= bucket:
                    histogram["counts"][bucket] += 1

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            histograms = {
                key: {
                    "buckets": tuple(value["buckets"]),
                    "counts": dict(value["counts"]),
                    "count": value["count"],
                    "sum": value["sum"],
                }
                for key, value in self._histograms.items()
            }

        lines = [
            "# HELP llm_waf_requests_total Total requests handled by LLM-WAF.",
            "# TYPE llm_waf_requests_total counter",
        ]
        lines.extend(_render_counter(counters, "llm_waf_requests_total"))
        lines.extend(
            [
                "# HELP llm_waf_findings_total Total WAF findings by category, severity, action, and source.",
                "# TYPE llm_waf_findings_total counter",
            ]
        )
        lines.extend(_render_counter(counters, "llm_waf_findings_total"))
        lines.extend(
            [
                "# HELP llm_waf_scanner_errors_total Total scanner errors.",
                "# TYPE llm_waf_scanner_errors_total counter",
            ]
        )
        lines.extend(_render_counter(counters, "llm_waf_scanner_errors_total"))
        lines.extend(
            [
                "# HELP llm_waf_fail_closed_total Total fail-closed trips.",
                "# TYPE llm_waf_fail_closed_total counter",
            ]
        )
        lines.extend(_render_counter(counters, "llm_waf_fail_closed_total"))
        lines.extend(
            [
                "# HELP llm_waf_request_latency_ms End-to-end gateway request latency in milliseconds.",
                "# TYPE llm_waf_request_latency_ms histogram",
            ]
        )
        lines.extend(_render_histogram(histograms, "llm_waf_request_latency_ms"))
        lines.extend(
            [
                "# HELP llm_waf_scanner_latency_ms Scanner latency in milliseconds.",
                "# TYPE llm_waf_scanner_latency_ms histogram",
            ]
        )
        lines.extend(_render_histogram(histograms, "llm_waf_scanner_latency_ms"))
        lines.extend(
            [
                "# HELP llm_waf_upstream_latency_ms Upstream provider latency in milliseconds.",
                "# TYPE llm_waf_upstream_latency_ms histogram",
            ]
        )
        lines.extend(_render_histogram(histograms, "llm_waf_upstream_latency_ms"))
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._histograms.clear()


metrics_registry = MetricsRegistry()


def record_event_metrics(event: dict[str, Any], registry: MetricsRegistry | None = None) -> None:
    registry = metrics_registry if registry is None else registry
    decision = _label_value(event.get("decision", "unknown"))
    route = _label_value(event.get("policy", "unknown"))
    path = _route_path(event)
    stream = "true" if event.get("stream") else "false"
    status_code = _label_value(event.get("status_code", "unknown"))
    labels = {"route": route, "path": path, "decision": decision, "status_code": status_code, "stream": stream}
    registry.inc("llm_waf_requests_total", labels)

    latency = event.get("latency_ms")
    if isinstance(latency, (int, float)):
        registry.observe("llm_waf_request_latency_ms", float(latency), labels)

    for field, stage in (("input_scanner_latency_ms", "input"), ("output_scanner_latency_ms", "output")):
        scanner_latency = event.get(field)
        if isinstance(scanner_latency, (int, float)):
            registry.observe("llm_waf_scanner_latency_ms", float(scanner_latency), {**labels, "stage": stage})

    upstream_latency = event.get("upstream_latency_ms")
    if isinstance(upstream_latency, (int, float)):
        registry.observe("llm_waf_upstream_latency_ms", float(upstream_latency), {**labels, "phase": "full_response"})

    upstream_header_latency = event.get("upstream_header_latency_ms")
    if isinstance(upstream_header_latency, (int, float)):
        registry.observe("llm_waf_upstream_latency_ms", float(upstream_header_latency), {**labels, "phase": "headers"})

    for finding in event.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        registry.inc(
            "llm_waf_findings_total",
            {
                "category": _label_value(finding.get("category", "unknown")),
                "severity": _label_value(finding.get("severity", "unknown")),
                "action": _label_value(finding.get("action", "unknown")),
                "source": _label_value(finding.get("source", "unknown")),
            },
        )

    if event.get("scanner_error"):
        registry.inc(
            "llm_waf_scanner_errors_total",
            {"kind": "deterministic", "fail_closed": _bool_label(event.get("fail_closed"))},
        )
    for _ in event.get("semantic_scanner_errors", []) or []:
        registry.inc(
            "llm_waf_scanner_errors_total",
            {"kind": "semantic", "fail_closed": _bool_label(event.get("fail_closed"))},
        )

    if event.get("fail_closed") and event.get("reason") == "scanner_failure":
        registry.inc("llm_waf_fail_closed_total", {"decision": decision})


def render_audit_sink_metrics(sink: str, snapshot: dict[str, int]) -> str:
    labels = (("sink", _label_value(sink)),)
    queued = max(0, int(snapshot.get("queued", 0)))
    dropped = max(0, int(snapshot.get("dropped", 0)))
    failed = max(0, int(snapshot.get("failed", 0)))
    lines = [
        "# HELP llm_waf_audit_queue_depth Current queued audit events.",
        "# TYPE llm_waf_audit_queue_depth gauge",
        f"llm_waf_audit_queue_depth{_format_labels(labels)} {queued}",
        "# HELP llm_waf_audit_events_dropped_total Total audit events dropped by audit sinks.",
        "# TYPE llm_waf_audit_events_dropped_total counter",
        f"llm_waf_audit_events_dropped_total{_format_labels(labels)} {dropped}",
        "# HELP llm_waf_audit_delivery_failures_total Total audit delivery failures.",
        "# TYPE llm_waf_audit_delivery_failures_total counter",
        f"llm_waf_audit_delivery_failures_total{_format_labels(labels)} {failed}",
    ]
    return "\n".join(lines) + "\n"


def _render_counter(counters: dict[tuple[str, tuple[tuple[str, str], ...]], float], name: str) -> list[str]:
    lines: list[str] = []
    for (metric_name, labels), value in sorted(counters.items()):
        if metric_name != name:
            continue
        lines.append(f"{name}{_format_labels(labels)} {_format_number(value)}")
    return lines


def _render_histogram(histograms: dict[tuple[str, tuple[tuple[str, str], ...]], dict[str, Any]], name: str) -> list[str]:
    lines: list[str] = []
    for (metric_name, labels), histogram in sorted(histograms.items()):
        if metric_name != name:
            continue
        for bucket in histogram["buckets"]:
            bucket_labels = (*labels, ("le", _bucket_label(bucket)))
            lines.append(f"{name}_bucket{_format_labels(bucket_labels)} {histogram['counts'][bucket]}")
        lines.append(f"{name}_sum{_format_labels(labels)} {_format_number(histogram['sum'])}")
        lines.append(f"{name}_count{_format_labels(labels)} {histogram['count']}")
    return lines


def _label_key(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(key), _label_value(value)) for key, value in labels.items()))


def _label_value(value: Any) -> str:
    text = str(value or "unknown").strip()
    return text if text else "unknown"


def _route_path(event: dict[str, Any]) -> str:
    path = str(event.get("path", "") or "").strip()
    if path == "/v1/chat/completions":
        return "/v1/chat/completions"
    if path.startswith("/v1/"):
        return "/v1/*"
    if path == "/metrics":
        return "/metrics"
    if path == "/health":
        return "/health"
    return "other"


def _bool_label(value: Any) -> str:
    return "true" if bool(value) else "false"


def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{key}="{_escape_label(value)}"' for key, value in labels) + "}"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _bucket_label(bucket: float) -> str:
    if math.isinf(bucket):
        return "+Inf"
    if bucket.is_integer():
        return str(int(bucket))
    return str(bucket)


def _format_number(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")
