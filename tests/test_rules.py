import tempfile
import unittest
from pathlib import Path

from app.security.rules import FALLBACK_RULE_SET, load_rule_set
from app.security.scanner import SecurityScanner


class RuleLoadingTests(unittest.TestCase):
    def test_loads_yaml_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.yaml"
            path.write_text(
                """
input:
  - rule_id: custom.block
    category: prompt_injection
    severity: high
    action: block
    pattern: "block-me"
    description: Custom block rule.
    tags: [custom, test]
sensitive: []
output: []
""",
                encoding="utf-8",
            )
            rules = load_rule_set(path)
            scanner = SecurityScanner(
                input_rules=rules.input_rules,
                sensitive_rules=rules.sensitive_rules,
                output_rules=rules.output_rules,
            )

            result = scanner.scan_input("please block-me")
            self.assertTrue(result.blocked)
            self.assertEqual(result.findings[0].rule_id, "custom.block")
            self.assertEqual(result.findings[0].tags, ("custom", "test"))

    def test_invalid_yaml_rule_file_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.yaml"
            path.write_text("input:\n  - rule_id: missing-required-fields\n", encoding="utf-8")
            rules = load_rule_set(path)
            self.assertEqual(rules.input_rules, FALLBACK_RULE_SET.input_rules)


if __name__ == "__main__":
    unittest.main()
