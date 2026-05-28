"""Shared scanner models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    action: str
    source: str
    evidence: str
    description: str

    def to_audit_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "action": self.action,
            "source": self.source,
            "evidence": self.evidence,
            "description": self.description,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str | None = None

    @property
    def blocked(self) -> bool:
        return any(f.action == "block" for f in self.findings)

    @property
    def redacted(self) -> bool:
        return self.redacted_text is not None

    @property
    def max_severity(self) -> str:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda f: order.get(f.severity, 0)).severity

    def to_audit_findings(self, limit: int = 20) -> list[dict]:
        return [f.to_audit_dict() for f in self.findings[:limit]]

