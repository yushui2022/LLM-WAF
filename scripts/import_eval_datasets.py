"""Convert permissively-licensed public prompt-injection datasets into the
project eval JSONL schema and merge them into an extended evaluation set.

The default run is **offline**: it reads already-downloaded source files from a
local cache directory and writes the merged, deduplicated corpus to
``tests/eval_set_extended.jsonl``. Network fetching is opt-in via ``--fetch``
and only covers datasets whose license permits redistribution. Datasets that
may not be redistributed are documented for manual download instead of being
vendored into the repository.

Output schema (one JSON object per line)::

    {"id": str, "text": str, "label": int, "category": str}

Usage::

    # Offline: convert cached sources -> tests/eval_set_extended.jsonl
    python scripts/import_eval_datasets.py

    # Online: fetch redistributable sources into the cache first
    python scripts/import_eval_datasets.py --fetch

Sources (see docs for license details):
    - deepset/prompt-injections (Apache-2.0, redistributable)
    - JasperLS/prompt-injections (MIT, redistributable)
    - jackhhao/jailbreak-classification (manual fetch; check license)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE = ROOT / "tests" / "_eval_cache"
DEFAULT_OUTPUT = ROOT / "tests" / "eval_set_extended.jsonl"
# Existing curated sets we dedupe against so the extended set stays additive.
BASE_SETS = (
    ROOT / "tests" / "eval_set.jsonl",
    ROOT / "tests" / "output_eval_set.jsonl",
    ROOT / "tests" / "eval_set_regex_miss.jsonl",
)


@dataclass(frozen=True)
class Sample:
    text: str
    label: int
    category: str

    @property
    def fingerprint(self) -> str:
        normalized = " ".join(self.text.lower().split())
        return hashlib.sha1(normalized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SourceDataset:
    name: str
    cache_file: str
    category: str
    redistributable: bool
    url: str | None
    parser: Callable[[Any], Iterable[Sample]]


def _parse_deepset(raw: Any) -> Iterable[Sample]:
    """deepset/prompt-injections: rows of {"text": str, "label": 0|1}."""
    for row in _iter_rows(raw):
        text = str(row.get("text", "")).strip()
        if not text:
            continue
        label = 1 if int(row.get("label", 0)) == 1 else 0
        yield Sample(text=text, label=label, category="prompt_injection")


def _parse_jasperls(raw: Any) -> Iterable[Sample]:
    """JasperLS/prompt-injections: {"text": str, "label": 0|1}."""
    for row in _iter_rows(raw):
        text = str(row.get("text", "")).strip()
        if not text:
            continue
        label = 1 if int(row.get("label", 0)) == 1 else 0
        yield Sample(text=text, label=label, category="prompt_injection")


def _parse_jailbreak_classification(raw: Any) -> Iterable[Sample]:
    """jackhhao/jailbreak-classification: {"prompt": str, "type": "jailbreak"|"benign"}."""
    for row in _iter_rows(raw):
        text = str(row.get("prompt", row.get("text", ""))).strip()
        if not text:
            continue
        kind = str(row.get("type", row.get("label", ""))).lower()
        label = 1 if kind in {"jailbreak", "1", "malicious"} else 0
        yield Sample(text=text, label=label, category="jailbreak")


SOURCES: tuple[SourceDataset, ...] = (
    SourceDataset(
        name="deepset/prompt-injections",
        cache_file="deepset_prompt_injections.jsonl",
        category="prompt_injection",
        redistributable=True,
        url="https://huggingface.co/datasets/deepset/prompt-injections/resolve/main/train.csv",
        parser=_parse_deepset,
    ),
    SourceDataset(
        name="JasperLS/prompt-injections",
        cache_file="jasperls_prompt_injections.jsonl",
        category="prompt_injection",
        redistributable=True,
        url="https://huggingface.co/datasets/JasperLS/prompt-injections/resolve/main/train.jsonl",
        parser=_parse_jasperls,
    ),
    SourceDataset(
        name="jackhhao/jailbreak-classification",
        cache_file="jailbreak_classification.jsonl",
        category="jailbreak",
        redistributable=False,
        url=None,
        parser=_parse_jailbreak_classification,
    ),
)


def _iter_rows(raw: Any) -> Iterable[dict[str, Any]]:
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                yield item
    elif isinstance(raw, dict):
        rows = raw.get("rows") or raw.get("data")
        if isinstance(rows, list):
            for item in rows:
                if isinstance(item, dict):
                    yield item


def _read_cache_file(path: Path) -> Any:
    if path.suffix == ".jsonl":
        rows: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_base_fingerprints() -> set[str]:
    seen: set[str] = set()
    for path in BASE_SETS:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                text = str(raw.get("text", "")).strip()
                if text:
                    label = 1 if int(raw.get("label", 0)) == 1 else 0
                    seen.add(Sample(text=text, label=label, category="").fingerprint)
    return seen


def build_extended_set(cache_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    base_fingerprints = load_base_fingerprints()
    seen = set(base_fingerprints)
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    counters: dict[str, int] = {}

    for source in SOURCES:
        cache_file = cache_dir / source.cache_file
        if not cache_file.exists():
            warnings.append(
                f"skipping {source.name}: cache file {cache_file} not found"
                + (
                    f" (fetch with --fetch from {source.url})"
                    if source.redistributable and source.url
                    else " (manual download required; not redistributable)"
                )
            )
            continue

        raw = _read_cache_file(cache_file)
        for sample in source.parser(raw):
            fp = sample.fingerprint
            if fp in seen:
                continue
            seen.add(fp)
            slug = source.name.split("/")[-1].replace("-", "_")
            idx = counters.get(slug, 0)
            counters[slug] = idx + 1
            records.append(
                {
                    "id": f"{slug}_{idx:05d}",
                    "text": sample.text,
                    "label": sample.label,
                    "category": sample.category,
                }
            )

    return records, warnings


def _fetch_sources(cache_dir: Path) -> list[str]:
    try:
        import urllib.request
    except ImportError:  # pragma: no cover - stdlib always present
        return ["urllib unavailable; cannot fetch"]

    cache_dir.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []
    for source in SOURCES:
        if not source.redistributable or not source.url:
            notes.append(f"manual: download {source.name} -> {cache_dir / source.cache_file}")
            continue
        dest = cache_dir / source.cache_file
        try:
            with urllib.request.urlopen(source.url, timeout=30) as resp:  # noqa: S310
                payload = resp.read().decode("utf-8")
        except Exception as exc:  # pragma: no cover - network dependent
            notes.append(f"fetch failed for {source.name}: {exc}")
            continue
        dest.write_text(_normalize_fetched(payload), encoding="utf-8")
        notes.append(f"fetched {source.name} -> {dest}")
    return notes


def _normalize_fetched(payload: str) -> str:
    """Best-effort: pass JSONL through, convert simple CSV (text,label) to JSONL."""
    stripped = payload.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return payload
    lines = [ln for ln in payload.splitlines() if ln.strip()]
    if not lines:
        return ""
    header = [c.strip().lower() for c in lines[0].split(",")]
    out: list[str] = []
    for line in lines[1:]:
        cells = line.split(",")
        if len(cells) < len(header):
            continue
        row = dict(zip(header, (c.strip().strip('"') for c in cells)))
        out.append(json.dumps(row, ensure_ascii=False))
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fetch", action="store_true", help="download redistributable sources first")
    args = parser.parse_args(argv)

    if args.fetch:
        for note in _fetch_sources(args.cache_dir):
            print(f"[fetch] {note}")

    records, warnings = build_extended_set(args.cache_dir)
    for warning in warnings:
        print(f"[warn] {warning}", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    pos = sum(1 for r in records if r["label"] == 1)
    print(f"[done] wrote {len(records)} samples ({pos} positive) -> {args.output}")
    if not records:
        print("[done] no cached sources found; see warnings for manual fetch steps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
