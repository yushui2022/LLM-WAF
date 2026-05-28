"""Create human-review eval candidates from JSONL audit events.

This does not auto-update rules. It extracts safe metadata and hashes from
audit logs so maintainers can label real misses or false positives and then add
reviewed samples to tests/eval_set.jsonl or tests/output_eval_set.jsonl.

Usage:
    python scripts/audit_to_eval_candidates.py --audit var/audit/events.jsonl --output var/audit/eval_candidates.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
    return events


def build_candidates(events: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for event in reversed(events):
        findings = event.get("findings", []) or []
        if not findings and event.get("decision") not in {"blocked", "redacted"}:
            continue
        candidates.append(
            {
                "id": f"audit_{event.get('trace_id', len(candidates))}",
                "trace_id": event.get("trace_id", ""),
                "direction": _direction(event),
                "decision": event.get("decision", ""),
                "label": "review",
                "category": _primary_category(findings),
                "rule_ids": [finding.get("rule_id", "") for finding in findings if isinstance(finding, dict)],
                "prompt_sha256": event.get("prompt_sha256", ""),
                "notes": "Set label to 1 for true attack/leak, 0 for benign false positive, then copy a reviewed text sample into the eval set.",
            }
        )
        if len(candidates) >= limit:
            break
    return list(reversed(candidates))


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _direction(event: dict[str, Any]) -> str:
    if event.get("output_redacted"):
        return "output"
    return "input"


def _primary_category(findings: list[Any]) -> str:
    for finding in findings:
        if isinstance(finding, dict) and finding.get("category"):
            return str(finding["category"])
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create eval candidates from LLM-WAF audit logs.")
    parser.add_argument("--audit", type=Path, default=Path("var/audit/events.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("var/audit/eval_candidates.jsonl"))
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()

    events = load_events(args.audit)
    candidates = build_candidates(events, max(1, args.limit))
    write_jsonl(args.output, candidates)
    print(f"wrote {len(candidates)} candidates to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
