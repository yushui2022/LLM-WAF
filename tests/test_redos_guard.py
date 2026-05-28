"""Regression tests for ReDoS hardening (G1, G2).

Covers:
- Rule.regex is precompiled once (identity-stable).
- Rules don't use re.DOTALL unless explicitly whitelisted.
- A pathological pattern + adversarial input is bounded by
  SCANNER_RULE_TIMEOUT_MS instead of pinning a worker indefinitely.
"""

from __future__ import annotations

import os
import time
import unittest

from app.security.rules import INPUT_RULES, Rule
from app.security.scanner import SecurityScanner
from app.security.timing import TIMEOUT_SENTINEL, run_with_timeout


class PrecompileTests(unittest.TestCase):
    def test_regex_is_cached(self):
        rule = INPUT_RULES[0]
        self.assertIs(rule.regex, rule.regex)

    def test_input_rules_do_not_use_dotall_unless_whitelisted(self):
        import re as _re

        for rule in INPUT_RULES:
            self.assertFalse(
                rule.regex.flags & _re.DOTALL,
                f"{rule.rule_id} should not compile with re.DOTALL",
            )

    def test_invalid_pattern_raises_in_post_init(self):
        import re as _re

        with self.assertRaises(_re.error):
            Rule(
                rule_id="invalid.test",
                category="prompt_injection",
                severity="low",
                action="log_only",
                pattern="(",
                description="invalid",
            )


class TimeoutHelperTests(unittest.TestCase):
    def test_returns_result_when_fast(self):
        self.assertEqual(run_with_timeout(lambda: 42, timeout_ms=200), 42)

    def test_returns_sentinel_when_slow(self):
        def slow() -> int:
            time.sleep(0.5)
            return 1

        self.assertIs(run_with_timeout(slow, timeout_ms=50), TIMEOUT_SENTINEL)

    def test_zero_timeout_disables_deadline(self):
        self.assertEqual(run_with_timeout(lambda: "ok", timeout_ms=0), "ok")


class ScannerTimeoutIntegrationTests(unittest.TestCase):
    """Scanner-level integration of the timeout helper.

    We cannot reliably test interruption of a runaway `re` call from pure
    Python on CPython — the GIL is held inside the regex engine. Instead we
    verify the timeout-path machinery: when the helper signals timeout, the
    scanner records a `scanner.timeout` finding and keeps scanning the rest
    of the rules.
    """

    def test_scanner_emits_timeout_finding_when_helper_signals(self):
        from app.security import scanner as scanner_module

        pathological = Rule(
            rule_id="test.redos",
            category="prompt_injection",
            severity="low",
            action="log_only",
            pattern=r"a",
            description="pathological",
        )
        good = Rule(
            rule_id="test.ok",
            category="prompt_injection",
            severity="low",
            action="log_only",
            pattern=r"b",
            description="ok",
        )
        scanner = SecurityScanner(
            input_rules=(pathological, good),
            sensitive_rules=(),
            output_rules=(),
        )

        calls = {"n": 0}

        def fake_run_with_timeout(fn, timeout_ms=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return TIMEOUT_SENTINEL
            return fn()

        original = scanner_module.run_with_timeout
        scanner_module.run_with_timeout = fake_run_with_timeout
        try:
            result = scanner.scan_input("ab")
        finally:
            scanner_module.run_with_timeout = original

        ids = [f.rule_id for f in result.findings]
        self.assertIn("scanner.timeout", ids)
        self.assertIn("test.ok", ids)
        timeout_finding = next(f for f in result.findings if f.rule_id == "scanner.timeout")
        self.assertEqual(timeout_finding.category, "scanner_error")
        self.assertEqual(timeout_finding.action, "log_only")


if __name__ == "__main__":
    unittest.main()
