"""Helpers for extracting and redacting OpenAI-compatible payload text."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any


def extract_request_text(body: dict[str, Any]) -> str:
    parts: list[str] = []
    for message in body.get("messages", []) or []:
        if not isinstance(message, dict):
            continue
        _collect_content_text(message.get("content"), parts)
        for tool_call in message.get("tool_calls", []) or []:
            function = tool_call.get("function", {}) if isinstance(tool_call, dict) else {}
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                parts.append(arguments)
    return "\n".join(p for p in parts if p)


def redact_request_body(body: dict[str, Any], redact: Callable[[str], str]) -> dict[str, Any]:
    redacted = copy.deepcopy(body)
    for message in redacted.get("messages", []) or []:
        if not isinstance(message, dict):
            continue
        message["content"] = _redact_content(message.get("content"), redact)
        for tool_call in message.get("tool_calls", []) or []:
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if not isinstance(function, dict):
                continue
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                function["arguments"] = redact(arguments)
    return redacted


def extract_response_text(body: dict[str, Any]) -> str:
    parts: list[str] = []
    for choice in body.get("choices", []) or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message") or {}
        if isinstance(message, dict):
            _collect_content_text(message.get("content"), parts)
        delta = choice.get("delta") or {}
        if isinstance(delta, dict):
            _collect_content_text(delta.get("content"), parts)
    return "\n".join(p for p in parts if p)


def redact_response_body(body: dict[str, Any], redact: Callable[[str], str]) -> dict[str, Any]:
    redacted = copy.deepcopy(body)
    for choice in redacted.get("choices", []) or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict):
            message["content"] = _redact_content(message.get("content"), redact)
        delta = choice.get("delta")
        if isinstance(delta, dict):
            delta["content"] = _redact_content(delta.get("content"), redact)
    return redacted


def redact_sse_json_payload(payload: dict[str, Any], redact: Callable[[str], str]) -> tuple[dict[str, Any], bool]:
    changed = False
    for choice in payload.get("choices", []) or []:
        if not isinstance(choice, dict):
            continue
        delta = choice.get("delta")
        if isinstance(delta, dict):
            new_content, content_changed = _redact_content_with_flag(delta.get("content"), redact)
            if content_changed:
                delta["content"] = new_content
                changed = True
        message = choice.get("message")
        if isinstance(message, dict):
            new_content, content_changed = _redact_content_with_flag(message.get("content"), redact)
            if content_changed:
                message["content"] = new_content
                changed = True
    return payload, changed


def _collect_content_text(content: Any, parts: list[str]) -> None:
    if isinstance(content, str):
        parts.append(content)
        return
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") in {"text", "input_text", "output_text"} and isinstance(item.get("text"), str):
                parts.append(item["text"])


def _redact_content(content: Any, redact: Callable[[str], str]) -> Any:
    new_content, _ = _redact_content_with_flag(content, redact)
    return new_content


def _redact_content_with_flag(content: Any, redact: Callable[[str], str]) -> tuple[Any, bool]:
    if isinstance(content, str):
        new_value = redact(content)
        return new_value, new_value != content
    if isinstance(content, list):
        changed = False
        new_items = []
        for item in content:
            if isinstance(item, dict) and item.get("type") in {"text", "input_text", "output_text"} and isinstance(item.get("text"), str):
                new_item = copy.deepcopy(item)
                new_text = redact(new_item["text"])
                if new_text != new_item["text"]:
                    changed = True
                    new_item["text"] = new_text
                new_items.append(new_item)
            else:
                new_items.append(item)
        return new_items, changed
    return content, False


def json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

