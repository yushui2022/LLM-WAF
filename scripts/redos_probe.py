"""ReDoS probe for LLM-WAF scanner rules.

Feeds each loaded rule a set of adversarial inputs designed to provoke
catastrophic backtracking on common pattern shapes (long runs of `a`, mixed
ASCII/Unicode filler, repeated delimiters, etc.) and asserts that every
individual regex call returns within a wall-clock threshold.

Run:
    python -B scripts/redos_probe.py
    python -B scripts/redos_probe.py --max-ms 100 --filler 5000

Exit code 0 = all rules within budget; 1 = at least one rule exceeded the
threshold. Use this as a pre-merge check whenever you add or relax a rule
pattern.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.security.rules import (  # noqa: E402
    INPUT_RULES,
    OUTPUT_RULES,
    SENSITIVE_RULES,
    Rule,
)


def adversarial_inputs(filler_len: int) -> list[tuple[str, str]]:
    """Inputs designed to push bounded-quantifier patterns toward worst case."""

    a_run = "a" * filler_len
    zh_run = "测" * (filler_len // 3)
    mixed = ("a" * 64 + "测" * 32) * max(1, filler_len // 96)
    role_bait = "you are now " + ("x" * 60)
    pretend_bait = "pretend you are " + ("x" * 80)
    ignore_zh = "忽略" + ("之" * 12) + "上面" + ("之" * 12) + "指令"
    hidden_zh = "原样" + ("x" * 12) + "复述" + ("x" * 20) + "后台" + ("x" * 12) + "规则"
    return [
        ("a_run", a_run + "b"),
        ("zh_run", zh_run + "X"),
        ("mixed", mixed + "Z"),
        ("role_bait", role_bait),
        ("pretend_bait", pretend_bait),
        ("ignore_zh", ignore_zh),
        ("hidden_zh", hidden_zh),
        ("empty", ""),
    ]


def probe_rule(rule: Rule, inputs: list[tuple[str, str]], max_ms: float) -> list[str]:
    """Return list of failure messages (empty = rule passed)."""

    failures: list[str] = []
    for label, text in inputs:
        start = time.perf_counter()
        try:
            rule.regex.search(text)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{rule.rule_id} [{label}] raised {type(exc).__name__}: {exc}")
            continue
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if elapsed_ms > max_ms:
            failures.append(f"{rule.rule_id} [{label}] took {elapsed_ms:.1f}ms (limit {max_ms:.0f}ms)")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-ms",
        type=float,
        default=100.0,
        help="Per-call wall-clock budget in milliseconds (default: 100).",
    )
    parser.add_argument(
        "--filler",
        type=int,
        default=2000,
        help="Length of adversarial filler strings (default: 2000).",
    )
    args = parser.parse_args()

    inputs = adversarial_inputs(args.filler)
    all_rules: tuple[tuple[str, tuple[Rule, ...]], ...] = (
        ("input", INPUT_RULES),
        ("sensitive", SENSITIVE_RULES),
        ("output", OUTPUT_RULES),
    )

    total = 0
    failures: list[str] = []
    for group_name, rules in all_rules:
        for rule in rules:
            total += 1
            failures.extend(probe_rule(rule, inputs, args.max_ms))
        print(f"  {group_name}: {len(rules)} rules probed")

    print(f"\nProbed {total} rules with {len(inputs)} inputs each.")
    if failures:
        print(f"FAIL: {len(failures)} rule/input pairs exceeded budget:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print("PASS: all rules within budget.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
