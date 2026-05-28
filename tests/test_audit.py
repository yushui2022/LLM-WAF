import tempfile
import unittest
from pathlib import Path

from app.audit import AuditLog
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
                        "max_severity": "critical",
                    },
                    "findings": [
                        {
                            "rule_id": "inj.ignore_previous.en",
                            "category": "prompt_injection",
                            "severity": "critical",
                            "action": "block",
                            "evidence": "Ignore all previous instructions",
                        }
                    ],
                }
            ]
        )
        self.assertIn("inj.ignore_previous.en", html)
        self.assertIn("prompt_injection:1", html)
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
                        "max_severity": "critical",
                    },
                    "findings": [
                        {
                            "rule_id": "inj.ignore_previous.en",
                            "category": "prompt_injection",
                            "severity": "critical",
                            "action": "block",
                            "evidence": "Ignore all previous instructions",
                        }
                    ],
                },
            ],
            filters={"category": "prompt_injection"},
        )
        self.assertIn("blocked-row", html)
        self.assertNotIn("allowed-row", html)


if __name__ == "__main__":
    unittest.main()
