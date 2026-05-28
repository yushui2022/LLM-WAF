import tempfile
import unittest
from pathlib import Path

from scripts.audit_to_eval_candidates import build_candidates, load_events, write_jsonl


class AuditToEvalCandidateTests(unittest.TestCase):
    def test_builds_candidates_without_prompt_text(self):
        candidates = build_candidates(
            [
                {
                    "trace_id": "waf_one",
                    "decision": "blocked",
                    "prompt_sha256": "abc123",
                    "findings": [{"rule_id": "inj.ignore_previous.en", "category": "prompt_injection"}],
                }
            ],
            limit=10,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["label"], "review")
        self.assertEqual(candidates[0]["category"], "prompt_injection")
        self.assertEqual(candidates[0]["prompt_sha256"], "abc123")
        self.assertNotIn("text", candidates[0])

    def test_round_trips_jsonl_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            write_jsonl(path, [{"trace_id": "one", "decision": "blocked"}])
            events = load_events(path)
            self.assertEqual(events[0]["trace_id"], "one")


if __name__ == "__main__":
    unittest.main()
