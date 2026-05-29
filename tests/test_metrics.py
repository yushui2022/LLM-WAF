import unittest

from app.metrics import MetricsRegistry, record_event_metrics, render_audit_sink_metrics


class MetricsTests(unittest.TestCase):
    def test_records_request_finding_and_latency_metrics(self):
        registry = MetricsRegistry()
        record_event_metrics(
            {
                "decision": "blocked",
                "policy": "chat",
                "path": "/v1/chat/completions",
                "status_code": 403,
                "stream": False,
                "latency_ms": 12.5,
                "input_scanner_latency_ms": 2.0,
                "output_scanner_latency_ms": 3.0,
                "upstream_latency_ms": 7.0,
                "findings": [
                    {
                        "category": "prompt_injection",
                        "severity": "critical",
                        "action": "block",
                        "source": "tool_result",
                    }
                ],
            },
            registry=registry,
        )

        rendered = registry.render()

        self.assertIn('llm_waf_requests_total{decision="blocked"', rendered)
        self.assertIn('llm_waf_findings_total{action="block",category="prompt_injection"', rendered)
        self.assertIn('source="tool_result"', rendered)
        self.assertIn("llm_waf_request_latency_ms_bucket", rendered)
        self.assertIn("llm_waf_scanner_latency_ms_bucket", rendered)
        self.assertIn("llm_waf_upstream_latency_ms_bucket", rendered)

    def test_records_scanner_errors_and_fail_closed(self):
        registry = MetricsRegistry()
        record_event_metrics(
            {
                "decision": "blocked",
                "policy": "chat",
                "path": "/v1/chat/completions",
                "status_code": 503,
                "scanner_error": "RuntimeError",
                "semantic_scanner_errors": ["TimeoutError"],
                "fail_closed": True,
                "reason": "scanner_failure",
            },
            registry=registry,
        )

        rendered = registry.render()

        self.assertIn('llm_waf_scanner_errors_total{fail_closed="true",kind="deterministic"} 1', rendered)
        self.assertIn('llm_waf_scanner_errors_total{fail_closed="true",kind="semantic"} 1', rendered)
        self.assertIn('llm_waf_fail_closed_total{decision="blocked"} 1', rendered)

    def test_escapes_label_values(self):
        registry = MetricsRegistry()
        registry.inc("llm_waf_requests_total", {"route": 'bad"route', "decision": "allowed"})

        rendered = registry.render()

        self.assertIn('route="bad\\"route"', rendered)

    def test_renders_audit_sink_metrics(self):
        rendered = render_audit_sink_metrics("http", {"queued": 3, "dropped": 2, "failed": 1})

        self.assertIn('llm_waf_audit_queue_depth{sink="http"} 3', rendered)
        self.assertIn('llm_waf_audit_events_dropped_total{sink="http"} 2', rendered)
        self.assertIn('llm_waf_audit_delivery_failures_total{sink="http"} 1', rendered)


if __name__ == "__main__":
    unittest.main()
