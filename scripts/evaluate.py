"""Evaluate the built-in WAF scanner on a JSONL dataset.

Usage:
    python scripts/evaluate.py
    python scripts/evaluate.py --file tests/eval_set.jsonl --show-misses
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security.scanner import SecurityScanner


@dataclass(frozen=True)
class EvalSample:
    sample_id: str
    text: str
    label: int
    category: str


@dataclass(frozen=True)
class EvalResult:
    sample: EvalSample
    blocked: bool
    finding_ids: list[str]

    @property
    def correct(self) -> bool:
        return self.blocked == bool(self.sample.label)


def load_samples(path: Path) -> list[EvalSample]:
    samples: list[EvalSample] = []
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            samples.append(
                EvalSample(
                    sample_id=str(raw.get("id", f"line_{line_num}")),
                    text=str(raw["text"]),
                    label=int(raw["label"]),
                    category=str(raw.get("category", "unknown")),
                )
            )
    return samples


def evaluate(samples: list[EvalSample]) -> tuple[list[EvalResult], dict[str, Any]]:
    scanner = SecurityScanner()
    results: list[EvalResult] = []

    tp = fp = tn = fn = 0
    for sample in samples:
        scan = scanner.scan_input(sample.text)
        blocked = scan.blocked
        finding_ids = [finding.rule_id for finding in scan.findings]
        results.append(EvalResult(sample=sample, blocked=blocked, finding_ids=finding_ids))

        if sample.label == 1 and blocked:
            tp += 1
        elif sample.label == 1 and not blocked:
            fn += 1
        elif sample.label == 0 and blocked:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    metrics = {
        "samples": len(samples),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
    }
    return results, metrics


def print_summary(metrics: dict[str, Any]) -> None:
    print("LLM-WAF scanner evaluation")
    print("=" * 30)
    print(f"samples : {metrics['samples']}")
    print(f"TP / FP : {metrics['tp']} / {metrics['fp']}")
    print(f"TN / FN : {metrics['tn']} / {metrics['fn']}")
    print(f"precision: {metrics['precision']:.2%}")
    print(f"recall   : {metrics['recall']:.2%}")
    print(f"f1       : {metrics['f1']:.2%}")
    print(f"fpr      : {metrics['false_positive_rate']:.2%}")


def print_misses(results: list[EvalResult]) -> None:
    misses = [result for result in results if not result.correct]
    if not misses:
        print("\nNo misses.")
        return

    print("\nMisses")
    print("-" * 30)
    for result in misses:
        expected = "block" if result.sample.label else "allow"
        actual = "block" if result.blocked else "allow"
        print(f"{result.sample.sample_id}: expected={expected} actual={actual} category={result.sample.category}")
        print(f"  text: {result.sample.text}")
        print(f"  findings: {', '.join(result.finding_ids) or '-'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate LLM-WAF scanner rules.")
    parser.add_argument("--file", type=Path, default=ROOT / "tests" / "eval_set.jsonl")
    parser.add_argument("--show-misses", action="store_true")
    parser.add_argument("--min-precision", type=float, default=0.0)
    parser.add_argument("--min-recall", type=float, default=0.0)
    args = parser.parse_args()

    samples = load_samples(args.file)
    results, metrics = evaluate(samples)
    print_summary(metrics)
    if args.show_misses:
        print_misses(results)

    if metrics["precision"] < args.min_precision or metrics["recall"] < args.min_recall:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

