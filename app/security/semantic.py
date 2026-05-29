"""Optional semantic scanner hook.

The built-in regex rules stay local and deterministic. This module lets users
attach an external classifier or LLM-based scanner without coupling the gateway
to any vendor or model.
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from app.security.models import Finding, ScanResult


class SemanticScanner(Protocol):
    async def scan_input(self, text: str) -> ScanResult:
        """Scan request text and return semantic findings."""

    async def scan_output(self, text: str) -> ScanResult:
        """Scan response text and return semantic findings."""


class HttpSemanticScanner:
    def __init__(self, url: str, timeout_seconds: float = 2.0):
        self.url = url
        self.timeout_seconds = timeout_seconds

    async def scan_input(self, text: str) -> ScanResult:
        return await self._scan("input", text)

    async def scan_output(self, text: str) -> ScanResult:
        return await self._scan("output", text)

    async def _scan(self, direction: str, text: str) -> ScanResult:
        if not text:
            return ScanResult()

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(self.url, json={"direction": direction, "text": text})
            response.raise_for_status()
            payload = response.json()

        if not isinstance(payload, dict):
            return ScanResult()
        return ScanResult(
            findings=_parse_findings(payload.get("findings")),
            redacted_text=str(payload["redacted_text"]) if isinstance(payload.get("redacted_text"), str) else None,
        )


def merge_scan_results(primary: ScanResult, *secondary_results: ScanResult | None) -> ScanResult:
    findings = list(primary.findings)
    redacted_text = primary.redacted_text
    for secondary in secondary_results:
        if secondary is None:
            continue
        findings.extend(secondary.findings)
        redacted_text = secondary.redacted_text or redacted_text
    return ScanResult(
        findings=findings,
        redacted_text=redacted_text,
    )


def _parse_findings(raw_findings: Any) -> list[Finding]:
    if not isinstance(raw_findings, list):
        return []

    findings: list[Finding] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule_id", "semantic.external")).strip() or "semantic.external"
        category = str(item.get("category", "semantic")).strip() or "semantic"
        severity = str(item.get("severity", "medium")).strip() or "medium"
        action = str(item.get("action", "log_only")).strip() or "log_only"
        description = str(item.get("description", "External semantic scanner finding.")).strip()
        evidence = str(item.get("evidence", "[semantic]")).strip() or "[semantic]"
        findings.append(
            Finding(
                rule_id=rule_id,
                category=category,
                severity=severity,
                action=action,
                source="semantic",
                evidence=evidence[:120],
                description=description,
                tags=("semantic",),
            )
        )
    return findings
