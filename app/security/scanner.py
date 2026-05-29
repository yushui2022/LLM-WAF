"""Security scanner pipeline for input and output text."""

from __future__ import annotations

from collections.abc import Collection

from app.security.models import Finding, ScanResult
from app.security.normalizer import text_variants
from app.security.rules import INPUT_RULES, OUTPUT_RULES, SENSITIVE_RULES, Rule
from app.security.timing import TIMEOUT_SENTINEL, run_with_timeout


MAX_EVIDENCE_CHARS = 120
MAX_FINDINGS = 50


def _timeout_finding(rule: Rule, source: str) -> Finding:
    return Finding(
        rule_id="scanner.timeout",
        category="scanner_error",
        severity="low",
        action="log_only",
        source=source,
        evidence=f"rule={rule.rule_id}",
        description="Regex evaluation exceeded SCANNER_RULE_TIMEOUT_MS and was skipped.",
        tags=("scanner_error", "timeout", rule.rule_id),
    )


def _preview(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    compact = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _masked_evidence(text: str) -> str:
    compact = _preview(text, limit=80)
    if len(compact) <= 8:
        return "***"
    return compact[:3] + "***" + compact[-3:]


class SecurityScanner:
    """Built-in MVP scanner.

    It combines:
    - high-confidence prompt-injection rules that block;
    - sensitive-data rules that redact;
    - output leak heuristics that redact.
    """

    def __init__(
        self,
        input_rules: tuple[Rule, ...] | None = None,
        sensitive_rules: tuple[Rule, ...] | None = None,
        output_rules: tuple[Rule, ...] | None = None,
    ):
        self.input_rules = INPUT_RULES if input_rules is None else input_rules
        self.sensitive_rules = SENSITIVE_RULES if sensitive_rules is None else sensitive_rules
        self.output_rules = OUTPUT_RULES if output_rules is None else output_rules

    def scan_input(
        self,
        text: str,
        disabled_rule_ids: Collection[str] | None = None,
        disabled_categories: Collection[str] | None = None,
    ) -> ScanResult:
        disabled_rule_ids = frozenset(disabled_rule_ids or ())
        disabled_categories = frozenset(disabled_categories or ())
        findings: list[Finding] = []
        findings.extend(self._scan_static_rules(text, self.input_rules, disabled_rule_ids, disabled_categories))
        findings.extend(self._scan_sensitive(text, disabled_rule_ids, disabled_categories))

        redacted = self.redact_sensitive(text, disabled_rule_ids, disabled_categories)
        return ScanResult(
            findings=self._dedupe(findings),
            redacted_text=redacted if redacted != text else None,
        )

    def scan_output(
        self,
        text: str,
        disabled_rule_ids: Collection[str] | None = None,
        disabled_categories: Collection[str] | None = None,
    ) -> ScanResult:
        disabled_rule_ids = frozenset(disabled_rule_ids or ())
        disabled_categories = frozenset(disabled_categories or ())
        findings: list[Finding] = []
        findings.extend(self._scan_sensitive(text, disabled_rule_ids, disabled_categories))
        findings.extend(
            self._scan_direct(
                text,
                self.output_rules,
                source="output",
                disabled_rule_ids=disabled_rule_ids,
                disabled_categories=disabled_categories,
            )
        )

        redacted = self.redact_output(text, disabled_rule_ids, disabled_categories)
        return ScanResult(
            findings=self._dedupe(findings),
            redacted_text=redacted if redacted != text else None,
        )

    def redact_sensitive(
        self,
        text: str,
        disabled_rule_ids: Collection[str] | None = None,
        disabled_categories: Collection[str] | None = None,
    ) -> str:
        disabled_rule_ids = frozenset(disabled_rule_ids or ())
        disabled_categories = frozenset(disabled_categories or ())
        redacted = text
        for rule in self.sensitive_rules:
            if not _rule_enabled(rule, disabled_rule_ids, disabled_categories):
                continue
            current = redacted
            outcome = run_with_timeout(
                lambda r=rule, t=current: r.regex.sub(r.replacement or "[REDACTED]", t)
            )
            if outcome is TIMEOUT_SENTINEL:
                continue
            redacted = outcome  # type: ignore[assignment]
        return redacted

    def redact_output(
        self,
        text: str,
        disabled_rule_ids: Collection[str] | None = None,
        disabled_categories: Collection[str] | None = None,
    ) -> str:
        disabled_rule_ids = frozenset(disabled_rule_ids or ())
        disabled_categories = frozenset(disabled_categories or ())
        redacted = self.redact_sensitive(text, disabled_rule_ids, disabled_categories)
        for rule in self.output_rules:
            if not _rule_enabled(rule, disabled_rule_ids, disabled_categories):
                continue
            current = redacted
            outcome = run_with_timeout(
                lambda r=rule, t=current: r.regex.sub(r.replacement or "[REDACTED]", t)
            )
            if outcome is TIMEOUT_SENTINEL:
                continue
            redacted = outcome  # type: ignore[assignment]
        return redacted

    def _scan_static_rules(
        self,
        text: str,
        rules: tuple[Rule, ...],
        disabled_rule_ids: Collection[str],
        disabled_categories: Collection[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for variant in text_variants(text):
            findings.extend(
                self._scan_direct(
                    variant.text,
                    rules,
                    source=variant.source,
                    disabled_rule_ids=disabled_rule_ids,
                    disabled_categories=disabled_categories,
                )
            )
            if len(findings) >= MAX_FINDINGS:
                break
        return findings

    def _scan_sensitive(
        self,
        text: str,
        disabled_rule_ids: Collection[str],
        disabled_categories: Collection[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.sensitive_rules:
            if not _rule_enabled(rule, disabled_rule_ids, disabled_categories):
                continue
            outcome = run_with_timeout(lambda r=rule, t=text: list(r.regex.finditer(t)))
            if outcome is TIMEOUT_SENTINEL:
                findings.append(_timeout_finding(rule, "plain"))
                if len(findings) >= MAX_FINDINGS:
                    return findings
                continue
            for match in outcome:  # type: ignore[union-attr]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        action=rule.action,
                        source="plain",
                        evidence=_masked_evidence(match.group(0)),
                        description=rule.description,
                        tags=rule.effective_tags,
                        references=rule.references,
                        recommended_remediation=rule.recommended_remediation,
                    )
                )
                if len(findings) >= MAX_FINDINGS:
                    return findings
        return findings

    def _scan_direct(
        self,
        text: str,
        rules: tuple[Rule, ...],
        source: str,
        disabled_rule_ids: Collection[str],
        disabled_categories: Collection[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            if not _rule_enabled(rule, disabled_rule_ids, disabled_categories):
                continue
            outcome = run_with_timeout(lambda r=rule, t=text: r.regex.search(t))
            if outcome is TIMEOUT_SENTINEL:
                findings.append(_timeout_finding(rule, source))
                if len(findings) >= MAX_FINDINGS:
                    return findings
                continue
            match = outcome
            if not match:
                continue
            evidence = _masked_evidence(match.group(0)) if rule.category in {"secret", "pii"} else _preview(match.group(0))
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    action=rule.action,
                    source=source,
                    evidence=evidence,
                    description=rule.description,
                    tags=rule.effective_tags,
                    references=rule.references,
                    recommended_remediation=rule.recommended_remediation,
                )
            )
            if len(findings) >= MAX_FINDINGS:
                return findings
        return findings

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, str]] = set()
        unique: list[Finding] = []
        for finding in findings:
            key = (finding.rule_id, finding.source, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
            if len(unique) >= MAX_FINDINGS:
                break
        return unique


def _rule_enabled(rule: Rule, disabled_rule_ids: Collection[str], disabled_categories: Collection[str]) -> bool:
    if rule.category in disabled_categories:
        return False
    # A rule is disabled if its current ID *or any deprecated alias* appears in
    # the disabled set, so policy.yaml configs keep working across the rename.
    return all(rid not in disabled_rule_ids for rid in rule.all_ids)
