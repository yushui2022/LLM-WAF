import unittest

from app.security.semantic import merge_scan_results
from app.security.models import Finding, ScanResult


class SemanticScannerTests(unittest.TestCase):
    def test_merges_static_and_semantic_findings(self):
        static = ScanResult(
            findings=[
                Finding(
                    rule_id="pii.email",
                    category="pii",
                    severity="medium",
                    action="redact",
                    source="plain",
                    evidence="tes***com",
                    description="Email address.",
                )
            ],
            redacted_text="email [REDACTED:email]",
        )
        semantic = ScanResult(
            findings=[
                Finding(
                    rule_id="semantic.prompt_injection",
                    category="prompt_injection",
                    severity="high",
                    action="block",
                    source="semantic",
                    evidence="[semantic]",
                    description="Semantic finding.",
                )
            ]
        )

        merged = merge_scan_results(static, semantic)
        self.assertTrue(merged.blocked)
        self.assertEqual(len(merged.findings), 2)
        self.assertEqual(merged.redacted_text, "email [REDACTED:email]")


if __name__ == "__main__":
    unittest.main()
