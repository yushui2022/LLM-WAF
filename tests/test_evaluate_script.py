import unittest
from pathlib import Path

from scripts.evaluate import evaluate, load_samples


class EvaluateScriptTests(unittest.TestCase):
    def test_eval_set_has_expected_shape(self):
        samples = load_samples(Path("tests/eval_set.jsonl"))
        self.assertGreaterEqual(len(samples), 20)
        self.assertTrue(any(sample.label == 1 for sample in samples))
        self.assertTrue(any(sample.label == 0 for sample in samples))

    def test_builtin_eval_set_has_no_current_misses(self):
        samples = load_samples(Path("tests/eval_set.jsonl"))
        _, metrics = evaluate(samples, direction="input")
        self.assertEqual(metrics["fp"], 0)
        self.assertEqual(metrics["fn"], 0)
        self.assertIn("prompt_injection", metrics["by_category"])
        self.assertEqual(metrics["by_category"]["prompt_injection"]["fn"], 0)

    def test_output_eval_set_has_expected_shape(self):
        samples = load_samples(Path("tests/output_eval_set.jsonl"))
        self.assertGreaterEqual(len(samples), 20)
        self.assertTrue(any(sample.label == 1 for sample in samples))
        self.assertTrue(any(sample.label == 0 for sample in samples))

    def test_builtin_output_eval_set_has_no_current_misses(self):
        samples = load_samples(Path("tests/output_eval_set.jsonl"))
        _, metrics = evaluate(samples, direction="output")
        self.assertEqual(metrics["fp"], 0)
        self.assertEqual(metrics["fn"], 0)
        self.assertIn("system_prompt_leak", metrics["by_category"])


if __name__ == "__main__":
    unittest.main()
