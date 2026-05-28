"""Security scanner pipeline for input and output text."""

from __future__ import annotations

from dataclasses import replace

from app.security.models import Finding, ScanResult
from app.security.normalizer import text_variants
from app.security.rules import INPUT_RULES, OUTPUT_RULES, SENSITIVE_RULES, Rule


MAX_EVIDENCE_CHARS = 120
MAX_FINDINGS = 50


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

    def scan_input(self, text: str) -> ScanResult:
        findings: list[Finding] = []
        findings.extend(self._scan_static_rules(text, INPUT_RULES))
        findings.extend(self._scan_sensitive(text))

        redacted = self.redact_sensitive(text)
        return ScanResult(
            findings=self._dedupe(findings),
            redacted_text=redacted if redacted != text else None,
        )

    def scan_output(self, text: str) -> ScanResult:
        findings: list[Finding] = []
        findings.extend(self._scan_sensitive(text))
        findings.extend(self._scan_direct(text, OUTPUT_RULES, source="output"))

        redacted = self.redact_output(text)
        return ScanResult(
            findings=self._dedupe(findings),
            redacted_text=redacted if redacted != text else None,
        )

    def redact_sensitive(self, text: str) -> str:
        redacted = text
        for rule in SENSITIVE_RULES:
            redacted = rule.regex.sub(rule.replacement or "[REDACTED]", redacted)
        return redacted

    def redact_output(self, text: str) -> str:
        redacted = self.redact_sensitive(text)
        for rule in OUTPUT_RULES:
            redacted = rule.regex.sub(rule.replacement or "[REDACTED]", redacted)
        return redacted

    def _scan_static_rules(self, text: str, rules: tuple[Rule, ...]) -> list[Finding]:
        findings: list[Finding] = []
        for variant in text_variants(text):
            findings.extend(self._scan_direct(variant.text, rules, source=variant.source))
            if len(findings) >= MAX_FINDINGS:
                break
        return findings

    def _scan_sensitive(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in SENSITIVE_RULES:
            for match in rule.regex.finditer(text):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        action=rule.action,
                        source="plain",
                        evidence=_masked_evidence(match.group(0)),
                        description=rule.description,
                    )
                )
                if len(findings) >= MAX_FINDINGS:
                    return findings
        return findings

    def _scan_direct(self, text: str, rules: tuple[Rule, ...], source: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            match = rule.regex.search(text)
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

