"""Evaluate the built-in WAF scanner on a JSONL dataset.

Usage:
    python scripts/evaluate.py
    python scripts/evaluate.py --direction input --file tests/eval_set.jsonl --show-misses
    python scripts/evaluate.py --direction output --file tests/output_eval_set.jsonl --show-misses
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security.scanner import SecurityScanner  # noqa: E402

Direction = Literal["input", "output"]


@dataclass(frozen=True)
class EvalSample:
    sample_id: str
    text: str
    label: int
    category: str


@dataclass(frozen=True)
class EvalResult:
    sample: EvalSample
    detected: bool
    finding_ids: list[str]

    @property
    def correct(self) -> bool:
        return self.detected == bool(self.sample.label)


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


def _scan_sample(scanner: SecurityScanner, text: str, direction: Direction) -> tuple[bool, list[str]]:
    if direction == "input":
        scan = scanner.scan_input(text)
        return scan.blocked, [finding.rule_id for finding in scan.findings]
    if direction == "output":
        scan = scanner.scan_output(text)
        return bool(scan.findings), [finding.rule_id for finding in scan.findings]
    raise ValueError(f"Unsupported evaluation direction: {direction}")


def evaluate(samples: list[EvalSample], direction: Direction = "input") -> tuple[list[EvalResult], dict[str, Any]]:
    scanner = SecurityScanner()
    results: list[EvalResult] = []

    tp = fp = tn = fn = 0
    by_category: dict[str, dict[str, Any]] = {}
    for sample in samples:
        detected, finding_ids = _scan_sample(scanner, sample.text, direction)
        results.append(EvalResult(sample=sample, detected=detected, finding_ids=finding_ids))
        category_metrics = by_category.setdefault(sample.category, {"samples": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0})
        category_metrics["samples"] += 1

        if sample.label == 1 and detected:
            tp += 1
            category_metrics["tp"] += 1
        elif sample.label == 1 and not detected:
            fn += 1
            category_metrics["fn"] += 1
        elif sample.label == 0 and detected:
            fp += 1
            category_metrics["fp"] += 1
        else:
            tn += 1
            category_metrics["tn"] += 1

    for category_metrics in by_category.values():
        _add_rates(category_metrics)

    metrics = {
        "direction": direction,
        "samples": len(samples),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "by_category": dict(sorted(by_category.items())),
    }
    _add_rates(metrics)
    return results, metrics


def _add_rates(metrics: dict[str, Any]) -> None:
    tp = int(metrics.get("tp", 0))
    fp = int(metrics.get("fp", 0))
    tn = int(metrics.get("tn", 0))
    fn = int(metrics.get("fn", 0))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    metrics["precision"] = precision
    metrics["recall"] = recall
    metrics["f1"] = f1
    metrics["false_positive_rate"] = fpr


def print_summary(metrics: dict[str, Any]) -> None:
    print("LLM-WAF scanner evaluation")
    print("=" * 30)
    print(f"direction: {metrics['direction']}")
    print(f"samples : {metrics['samples']}")
    print(f"TP / FP : {metrics['tp']} / {metrics['fp']}")
    print(f"TN / FN : {metrics['tn']} / {metrics['fn']}")
    print(f"precision: {metrics['precision']:.2%}")
    print(f"recall   : {metrics['recall']:.2%}")
    print(f"f1       : {metrics['f1']:.2%}")
    print(f"fpr      : {metrics['false_positive_rate']:.2%}")
    print_category_summary(metrics)


def print_category_summary(metrics: dict[str, Any]) -> None:
    categories = metrics.get("by_category", {})
    if not categories:
        return

    print("\nBy category")
    print("-" * 30)
    for category, values in categories.items():
        positive_count = values["tp"] + values["fn"]
        if positive_count:
            rates = f"precision={values['precision']:.2%} recall={values['recall']:.2%}"
        else:
            rates = f"fpr={values['false_positive_rate']:.2%}"
        print(f"{category}: samples={values['samples']} TP/FP/TN/FN={values['tp']}/{values['fp']}/{values['tn']}/{values['fn']} {rates}")


def _format_decision(direction: Direction, positive: bool) -> str:
    if direction == "input":
        return "block" if positive else "allow"
    return "detect" if positive else "clean"


def print_misses(results: list[EvalResult], direction: Direction) -> None:
    misses = [result for result in results if not result.correct]
    if not misses:
        print("\nNo misses.")
        return

    print("\nMisses")
    print("-" * 30)
    for result in misses:
        expected = _format_decision(direction, bool(result.sample.label))
        actual = _format_decision(direction, result.detected)
        print(f"{result.sample.sample_id}: expected={expected} actual={actual} category={result.sample.category}")
        print(f"  text: {result.sample.text}")
        print(f"  findings: {', '.join(result.finding_ids) or '-'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate LLM-WAF scanner rules.")
    parser.add_argument("--direction", choices=("input", "output"), default="input")
    parser.add_argument("--file", type=Path)
    parser.add_argument("--show-misses", action="store_true")
    parser.add_argument("--min-precision", type=float, default=0.0)
    parser.add_argument("--min-recall", type=float, default=0.0)
    parser.add_argument("--min-category-recall", type=float, default=0.0)
    args = parser.parse_args()

    default_file = "output_eval_set.jsonl" if args.direction == "output" else "eval_set.jsonl"
    sample_path = args.file or ROOT / "tests" / default_file

    samples = load_samples(sample_path)
    results, metrics = evaluate(samples, direction=args.direction)
    print_summary(metrics)
    if args.show_misses:
        print_misses(results, direction=args.direction)

    if metrics["precision"] < args.min_precision or metrics["recall"] < args.min_recall:
        return 1
    for values in metrics["by_category"].values():
        has_positive_samples = values["tp"] + values["fn"] > 0
        if has_positive_samples and values["recall"] < args.min_category_recall:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
