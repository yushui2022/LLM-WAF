import tempfile
import unittest
from pathlib import Path

from app.policy import PolicyStore, RoutePolicy


class PolicyStoreTests(unittest.TestCase):
    def test_missing_file_uses_fallback_policy(self):
        fallback = RoutePolicy(name="fallback", blocked_status_code=499)
        store = PolicyStore.load(Path("missing-policy-file.yaml"), fallback)
        policy = store.for_path("/v1/chat/completions")
        self.assertEqual(policy.name, "fallback")
        self.assertEqual(policy.blocked_status_code, 499)

    def test_loads_default_and_exact_route_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.yaml"
            path.write_text(
                """
default:
  blocked_status_code: 403
  redact_outputs: true
routes:
  - name: strict_chat
    path: /v1/chat/completions
    blocked_status_code: 451
    output_scanning: false
""",
                encoding="utf-8",
            )
            store = PolicyStore.load(path, RoutePolicy())
            policy = store.for_path("/v1/chat/completions")
            self.assertEqual(policy.name, "strict_chat")
            self.assertEqual(policy.blocked_status_code, 451)
            self.assertFalse(policy.output_scanning)
            self.assertTrue(policy.redact_outputs)

    def test_prefix_route_matching(self):
        store = PolicyStore(
            default=RoutePolicy(name="default"),
            routes=[RoutePolicy(name="admin", path="/v1/admin/*", audit=False)],
        )
        self.assertEqual(store.for_path("/v1/admin/jobs").name, "admin")
        self.assertEqual(store.for_path("/v1/models").name, "default")


if __name__ == "__main__":
    unittest.main()

