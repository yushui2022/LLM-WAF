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
                }
            ]
        )
        self.assertIn("Tokens", html)
        self.assertIn(">5<", html)


if __name__ == "__main__":
    unittest.main()
