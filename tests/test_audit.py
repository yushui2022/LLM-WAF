import io
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from app.audit import AuditLog, FileAuditSink, HttpAuditSink, StdoutAuditSink, create_audit_sink
from app.dashboard import render_dashboard


class AuditLogTests(unittest.TestCase):
    def test_append_and_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            audit = AuditLog(path)
            audit.append({"trace_id": "one", "decision": "allowed"})
            audit.append({"trace_id": "two", "decision": "blocked"})

            events = audit.tail(1)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["trace_id"], "two")

    def test_rotates_file_by_size_and_tails_across_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            audit = AuditLog(path, rotate_max_bytes=70, rotate_backups=2)

            for index in range(6):
                audit.append({"trace_id": f"event-{index}", "decision": "allowed", "padding": "x" * 20})

            self.assertTrue(Path(f"{path}.1").exists())
            events = audit.tail(3)
            self.assertEqual([event["trace_id"] for event in events], ["event-3", "event-4", "event-5"])

    def test_stdout_sink_writes_json_and_keeps_recent_events(self):
        stream = io.StringIO()
        audit = StdoutAuditSink(stream=stream, max_recent=2)

        audit.append({"trace_id": "one", "decision": "allowed"})
        audit.append({"trace_id": "two", "decision": "blocked"})
        audit.append({"trace_id": "three", "decision": "allowed"})

        lines = stream.getvalue().splitlines()
        self.assertEqual(json.loads(lines[-1])["trace_id"], "three")
        self.assertEqual([event["trace_id"] for event in audit.tail(10)], ["two", "three"])
        self.assertEqual(audit.tail(0), [])

    def test_http_sink_posts_json_event(self):
        received: list[dict[str, Any]] = []
        auth_headers: list[str | None] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                received.append(json.loads(body))
                auth_headers.append(self.headers.get("Authorization"))
                self.send_response(204)
                self.end_headers()

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            audit = HttpAuditSink(
                f"http://127.0.0.1:{server.server_port}/audit",
                timeout_seconds=1.0,
                queue_size=10,
                bearer_token="audit-token",
            )
            audit.append({"trace_id": "http", "decision": "allowed"})

            deadline = time.monotonic() + 2.0
            while not received and time.monotonic() < deadline:
                time.sleep(0.01)

            self.assertEqual(received[0]["trace_id"], "http")
            self.assertEqual(auth_headers[0], "Bearer audit-token")
            self.assertEqual(audit.tail(1)[0]["trace_id"], "http")
        finally:
            server.shutdown()
            server.server_close()

    def test_http_sink_drops_when_queue_is_full(self):
        audit = HttpAuditSink("http://127.0.0.1:1/audit", queue_size=1, start_worker=False)

        audit.append({"trace_id": "one", "decision": "allowed"})
        audit.append({"trace_id": "two", "decision": "allowed"})

        self.assertEqual(audit.dropped_count, 1)
        self.assertEqual([event["trace_id"] for event in audit.tail(2)], ["one", "two"])

    def test_http_sink_counts_failed_delivery_without_stopping_request_path(self):
        def failing_sender(_line: str) -> None:
            raise RuntimeError("delivery failed")

        audit = HttpAuditSink("http://example.test/audit", queue_size=10, sender=failing_sender)
        audit.append({"trace_id": "failed", "decision": "allowed"})

        deadline = time.monotonic() + 2.0
        while audit.failed_count == 0 and time.monotonic() < deadline:
            time.sleep(0.01)

        self.assertEqual(audit.failed_count, 1)
        self.assertEqual(audit.tail(1)[0]["trace_id"], "failed")

    def test_create_audit_sink_selects_supported_sinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"

            self.assertIsInstance(create_audit_sink("file", path), FileAuditSink)
            self.assertIsInstance(create_audit_sink("stdout", path), StdoutAuditSink)
            self.assertIsInstance(
                create_audit_sink("http", path, http_url="http://127.0.0.1:1/audit"),
                HttpAuditSink,
            )

            with self.assertRaises(ValueError):
                create_audit_sink("unknown", path)
            with self.assertRaises(ValueError):
                create_audit_sink("http", path)

    def test_dashboard_renders_token_usage(self):
        html = render_dashboard(
            [
                {
                    "trace_id": "one",
                    "decision": "allowed",
                    "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
                    "cost": {"total_cost": 0.000012},
                }
            ]
        )
        self.assertIn("Tokens", html)
        self.assertIn(">5<", html)
        self.assertIn("$0.000012", html)

    def test_dashboard_renders_finding_summary(self):
        html = render_dashboard(
            [
                {
                    "trace_id": "one",
                    "decision": "blocked",
                    "finding_count": 1,
                    "finding_summary": {
                        "by_category": {"prompt_injection": 1},
                        "by_severity": {"critical": 1},
                        "by_action": {"block": 1},
                        "by_source": {"tool_result": 1},
                        "max_severity": "critical",
                    },
                    "findings": [
                        {
                            "rule_id": "inj.ignore_previous.en",
                            "category": "prompt_injection",
                            "severity": "critical",
                            "action": "block",
                            "source": "tool_result",
                            "evidence": "Ignore all previous instructions",
                        }
                    ],
                }
            ]
        )
        self.assertIn("inj.ignore_previous.en", html)
        self.assertIn("prompt_injection:1", html)
        self.assertIn("tool_result:1", html)
        self.assertIn("critical", html)

    def test_dashboard_filters_by_finding_category(self):
        html = render_dashboard(
            [
                {
                    "trace_id": "allowed-row",
                    "decision": "allowed",
                    "finding_count": 0,
                    "findings": [],
                },
                {
                    "trace_id": "blocked-row",
                    "decision": "blocked",
                    "finding_count": 1,
                    "finding_summary": {
                        "by_category": {"prompt_injection": 1},
                        "by_severity": {"critical": 1},
                        "by_action": {"block": 1},
                        "by_source": {"tool_result": 1},
                        "max_severity": "critical",
                    },
                    "findings": [
                        {
                            "rule_id": "inj.ignore_previous.en",
                            "category": "prompt_injection",
                            "severity": "critical",
                            "action": "block",
                            "source": "tool_result",
                            "evidence": "Ignore all previous instructions",
                        }
                    ],
                },
            ],
            filters={"category": "prompt_injection"},
        )
        self.assertIn("blocked-row", html)
        self.assertNotIn("allowed-row", html)

    def test_dashboard_filters_by_finding_source(self):
        html = render_dashboard(
            [
                {
                    "trace_id": "message-row",
                    "decision": "blocked",
                    "finding_count": 1,
                    "finding_summary": {
                        "by_category": {"prompt_injection": 1},
                        "by_severity": {"critical": 1},
                        "by_action": {"block": 1},
                        "by_source": {"message_content": 1},
                        "max_severity": "critical",
                    },
                    "findings": [{"source": "message_content", "category": "prompt_injection", "severity": "critical"}],
                },
                {
                    "trace_id": "tool-row",
                    "decision": "blocked",
                    "finding_count": 1,
                    "finding_summary": {
                        "by_category": {"prompt_injection": 1},
                        "by_severity": {"critical": 1},
                        "by_action": {"block": 1},
                        "by_source": {"tool_result": 1},
                        "max_severity": "critical",
                    },
                    "findings": [{"source": "tool_result", "category": "prompt_injection", "severity": "critical"}],
                },
            ],
            filters={"source": "tool_result"},
        )
        self.assertIn("tool-row", html)
        self.assertNotIn("message-row", html)


if __name__ == "__main__":
    unittest.main()
