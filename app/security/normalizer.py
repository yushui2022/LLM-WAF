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


@dataclass(frozen=True)
class TextVariant:
    source: str
    text: str


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return ZERO_WIDTH_RE.sub("", normalized)


def text_variants(text: str) -> list[TextVariant]:
    variants: list[TextVariant] = []
    seen: set[str] = set()

    def add(source: str, value: str) -> None:
        if not value:
            return
        if value in seen:
            return
        seen.add(value)
        variants.append(TextVariant(source=source, text=value))

    add("plain", text)
    add("normalized", normalize_text(text))
    add("html_unescaped", html.unescape(text))
    add("url_decoded", unquote(text))

    for candidate in BASE64_RE.findall(text):
        try:
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if len(decoded.strip()) >= 6:
            add("base64_decoded", decoded)
            add("base64_decoded_normalized", normalize_text(decoded))

    for candidate in HEX_RE.findall(text):
        if len(candidate) % 2:
            continue
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
        except ValueError:
            continue
        if len(decoded.strip()) >= 6:
            add("hex_decoded", decoded)
            add("hex_decoded_normalized", normalize_text(decoded))

    return variants

