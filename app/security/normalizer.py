"""Text normalization and lightweight decoding helpers."""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote


ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{20,})(?![0-9a-fA-F])")

# Bound how many decode layers we peel through. Two layers catches the
# common `base64(base64(payload))` shape without letting a small input
# explode into many derived variants.
MAX_DECODE_DEPTH = 2

# Bound total length across all derived variants to cap per-request CPU.
# A long benign string that happens to look like base64 / hex would
# otherwise generate variant fan-out proportional to its length.
MAX_TOTAL_VARIANT_CHARS = 200_000


@dataclass(frozen=True)
class TextVariant:
    source: str
    text: str


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return ZERO_WIDTH_RE.sub("", normalized)


def _try_decode_base64(candidate: str) -> str | None:
    try:
        padded = candidate + "=" * (-len(candidate) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return decoded if len(decoded.strip()) >= 6 else None


def _try_decode_hex(candidate: str) -> str | None:
    if len(candidate) % 2:
        return None
    try:
        decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
    except ValueError:
        return None
    return decoded if len(decoded.strip()) >= 6 else None


def text_variants(text: str) -> list[TextVariant]:
    """Generate decoded / normalized variants of `text` for rule scanning.

    Recurses through up to `MAX_DECODE_DEPTH` layers of base64/hex decoding so
    that nested encodings such as `base64(base64(payload))` and zero-width
    chars interleaved inside base64 (caught after a normalize pass) are
    surfaced to the scanner.

    Both `base64(base64(...))` and `normalize(decode(normalize(text)))` paths
    are explored. Each derived string is added under a `source` label that
    records the decoding chain, e.g. `base64_decoded.base64_decoded`.

    Total combined variant size is capped at `MAX_TOTAL_VARIANT_CHARS` to
    bound per-request CPU on adversarial inputs that look like long base64.
    """

    variants: list[TextVariant] = []
    seen: set[str] = set()
    total_chars = 0

    def add(source: str, value: str) -> bool:
        nonlocal total_chars
        if not value or value in seen:
            return False
        if total_chars + len(value) > MAX_TOTAL_VARIANT_CHARS:
            return False
        seen.add(value)
        total_chars += len(value)
        variants.append(TextVariant(source=source, text=value))
        return True

    # (source_label, text, decode_depth)
    queue: list[tuple[str, str, int]] = []

    if add("plain", text):
        queue.append(("plain", text, 0))

    normalized = normalize_text(text)
    if add("normalized", normalized):
        queue.append(("normalized", normalized, 0))

    add("html_unescaped", html.unescape(text))
    add("url_decoded", unquote(text))

    while queue:
        parent_source, parent_text, depth = queue.pop(0)
        if depth >= MAX_DECODE_DEPTH:
            continue

        # Decode base64 candidates found in this layer.
        for candidate in BASE64_RE.findall(parent_text):
            decoded = _try_decode_base64(candidate)
            if decoded is None:
                continue
            child_source = f"{parent_source}.base64_decoded" if parent_source != "plain" else "base64_decoded"
            if add(child_source, decoded):
                queue.append((child_source, decoded, depth + 1))
            normalized_decoded = normalize_text(decoded)
            if normalized_decoded != decoded:
                norm_source = f"{child_source}_normalized"
                if add(norm_source, normalized_decoded):
                    queue.append((norm_source, normalized_decoded, depth + 1))

        # Decode hex candidates found in this layer.
        for candidate in HEX_RE.findall(parent_text):
            decoded = _try_decode_hex(candidate)
            if decoded is None:
                continue
            child_source = f"{parent_source}.hex_decoded" if parent_source != "plain" else "hex_decoded"
            if add(child_source, decoded):
                queue.append((child_source, decoded, depth + 1))
            normalized_decoded = normalize_text(decoded)
            if normalized_decoded != decoded:
                norm_source = f"{child_source}_normalized"
                if add(norm_source, normalized_decoded):
                    queue.append((norm_source, normalized_decoded, depth + 1))

    return variants

