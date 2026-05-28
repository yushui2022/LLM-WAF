import tempfile
import unittest
from pathlib import Path

from app.pricing import PricingStore


class PricingStoreTests(unittest.TestCase):
    def test_missing_file_returns_no_estimate(self):
        store = PricingStore.load(Path("missing-pricing-file.yaml"))
        self.assertEqual(store.estimate("gpt-test", {"total_tokens": 10}), {})

    def test_exact_model_estimate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pricing.yaml"
            path.write_text(
                """
currency: USD
models:
  test-model:
    input_per_1m: 2
    output_per_1m: 4
""",
                encoding="utf-8",
            )
            store = PricingStore.load(path)
            cost = store.estimate("test-model", {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500})
            self.assertEqual(cost["currency"], "USD")
            self.assertEqual(cost["total_tokens"], 1500)
            self.assertEqual(cost["input_cost"], 0.002)
            self.assertEqual(cost["output_cost"], 0.002)
            self.assertEqual(cost["total_cost"], 0.004)

    def test_prefix_wildcard_estimate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pricing.yaml"
            path.write_text(
                """
models:
  test-*:
    input_per_1m: 1
    output_per_1m: 3
""",
                encoding="utf-8",
            )
            store = PricingStore.load(path)
            cost = store.estimate("test-v2", {"prompt_tokens": 1000, "completion_tokens": 1000})
            self.assertEqual(cost["total_cost"], 0.004)


if __name__ == "__main__":
    unittest.main()

