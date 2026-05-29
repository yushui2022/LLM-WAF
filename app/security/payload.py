"""Helpers for extracting and redacting OpenAI-compatible payload text."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PayloadTextSegment:
    text: str
    kind: str
    role: str = ""
    path: str = ""


def extract_request_text(body: dict[str, Any]) -> str:
    return "\n".join(segment.text for segment in extract_request_segments(body) if segment.text)


def extract_request_segments(body: dict[str, Any]) -> list[PayloadTextSegment]:
    segments: list[PayloadTextSegment] = []
    for message_index, message in enumerate(body.get("messages", []) or []):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role", "")).strip()
        content_kind = "tool_result" if role == "tool" else "message_content"
        _collect_content_segments(message.get("content"), segments, content_kind, role, f"messages[{message_index}].content")
        _collect_tool_call_argument_segments(
            message.get("tool_calls"), segments, "tool_call_arguments", role, f"messages[{message_index}].tool_calls"
        )
    return segments


def redact_request_body(body: dict[str, Any], redact: Callable[[str], str]) -> dict[str, Any]:
    redacted = copy.deepcopy(body)
    for message in redacted.get("messages", []) or []:
        if not isinstance(message, dict):
            continue
        message["content"] = _redact_content(message.get("content"), redact)
        _redact_tool_call_arguments(message.get("tool_calls"), redact)
    return redacted


def extract_anthropic_request_text(body: dict[str, Any]) -> str:
    return "\n".join(segment.text for segment in extract_anthropic_request_segments(body) if segment.text)


def extract_anthropic_request_segments(body: dict[str, Any]) -> list[PayloadTextSegment]:
    segments: list[PayloadTextSegment] = []
    _collect_anthropic_content_segments(body.get("system"), segments, "system_content", "system", "system")
    for message_index, message in enumerate(body.get("messages", []) or []):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role", "")).strip()
        _collect_anthropic_content_segments(
            message.get("content"),
            segments,
            "message_content",
            role,
            f"messages[{message_index}].content",
        )
    return segments


def redact_anthropic_request_body(body: dict[str, Any], redact: Callable[[str], str]) -> dict[str, Any]:
    redacted = copy.deepcopy(body)
    if "system" in redacted:
        redacted["system"] = _redact_anthropic_content(redacted.get("system"), redact)
    for message in redacted.get("messages", []) or []:
        if not isinstance(message, dict):
            continue
        if "content" in message:
            message["content"] = _redact_anthropic_content(message.get("content"), redact)
    return redacted


def extract_response_text(body: dict[str, Any]) -> str:
    return "\n".join(segment.text for segment in extract_response_segments(body) if segment.text)


def extract_response_segments(body: dict[str, Any]) -> list[PayloadTextSegment]:
    segments: list[PayloadTextSegment] = []
    for choice_index, choice in enumerate(body.get("choices", []) or []):
        if not isinstance(choice, dict):
            continue
        message = choice.get("message") or {}
        if isinstance(message, dict):
            role = str(message.get("role", "")).strip()
            _collect_content_segments(
                message.get("content"), segments, "response_content", role, f"choices[{choice_index}].message.content"
            )
            _collect_tool_call_argument_segments(
                message.get("tool_calls"),
                segments,
                "response_tool_call_arguments",
                role,
                f"choices[{choice_index}].message.tool_calls",
            )
        delta = choice.get("delta") or {}
        if isinstance(delta, dict):
            role = str(delta.get("role", "")).strip()
            _collect_content_segments(delta.get("content"), segments, "response_delta", role, f"choices[{choice_index}].delta.content")
            _collect_tool_call_argument_segments(
                delta.get("tool_calls"),
                segments,
                "response_delta_tool_call_arguments",
                role,
                f"choices[{choice_index}].delta.tool_calls",
            )
    return segments


def extract_usage(body: dict[str, Any]) -> dict[str, int]:
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return {}

    result: dict[str, int] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = usage.get(key)
        if isinstance(value, int):
            result[key] = value
        elif isinstance(value, float):
            result[key] = int(value)
        elif isinstance(value, str) and value.isdigit():
            result[key] = int(value)
    return result


def extract_anthropic_response_text(body: dict[str, Any]) -> str:
    return "\n".join(segment.text for segment in extract_anthropic_response_segments(body) if segment.text)


def extract_anthropic_response_segments(body: dict[str, Any]) -> list[PayloadTextSegment]:
    segments: list[PayloadTextSegment] = []
    _collect_anthropic_content_segments(body.get("content"), segments, "response_content", "assistant", "content")
    return segments


def extract_anthropic_usage(body: dict[str, Any]) -> dict[str, int]:
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return {}

    result: dict[str, int] = {}
    input_tokens = _coerce_token_count(usage.get("input_tokens"))
    output_tokens = _coerce_token_count(usage.get("output_tokens"))
    if input_tokens is not None:
        result["prompt_tokens"] = input_tokens
    if output_tokens is not None:
        result["completion_tokens"] = output_tokens
    if input_tokens is not None or output_tokens is not None:
        result["total_tokens"] = (input_tokens or 0) + (output_tokens or 0)
    return result


def redact_response_body(body: dict[str, Any], redact: Callable[[str], str]) -> dict[str, Any]:
    redacted = copy.deepcopy(body)
    for choice in redacted.get("choices", []) or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict):
            message["content"] = _redact_content(message.get("content"), redact)
            _redact_tool_call_arguments(message.get("tool_calls"), redact)
        delta = choice.get("delta")
        if isinstance(delta, dict):
            delta["content"] = _redact_content(delta.get("content"), redact)
            _redact_tool_call_arguments(delta.get("tool_calls"), redact)
    return redacted


def redact_anthropic_response_body(body: dict[str, Any], redact: Callable[[str], str]) -> dict[str, Any]:
    redacted = copy.deepcopy(body)
    if "content" in redacted:
        redacted["content"] = _redact_anthropic_content(redacted.get("content"), redact)
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
            changed = _redact_tool_call_arguments(delta.get("tool_calls"), redact) or changed
        message = choice.get("message")
        if isinstance(message, dict):
            new_content, content_changed = _redact_content_with_flag(message.get("content"), redact)
            if content_changed:
                message["content"] = new_content
                changed = True
            changed = _redact_tool_call_arguments(message.get("tool_calls"), redact) or changed
    return payload, changed


def _collect_content_segments(content: Any, segments: list[PayloadTextSegment], kind: str, role: str, path: str) -> None:
    if isinstance(content, str):
        segments.append(PayloadTextSegment(text=content, kind=kind, role=role, path=path))
        return
    if isinstance(content, list):
        for item_index, item in enumerate(content):
            if not isinstance(item, dict):
                continue
            if item.get("type") in {"text", "input_text", "output_text"} and isinstance(item.get("text"), str):
                segments.append(
                    PayloadTextSegment(
                        text=item["text"],
                        kind=kind,
                        role=role,
                        path=f"{path}[{item_index}].text",
                    )
                )


def _collect_tool_call_argument_segments(tool_calls: Any, segments: list[PayloadTextSegment], kind: str, role: str, path: str) -> None:
    if not isinstance(tool_calls, list):
        return
    for tool_call_index, tool_call in enumerate(tool_calls):
        if not isinstance(tool_call, dict):
            continue
        function = tool_call.get("function")
        if not isinstance(function, dict):
            continue
        arguments = function.get("arguments")
        if isinstance(arguments, str):
            segments.append(
                PayloadTextSegment(
                    text=arguments,
                    kind=kind,
                    role=role,
                    path=f"{path}[{tool_call_index}].function.arguments",
                )
            )


def _collect_anthropic_content_segments(
    content: Any,
    segments: list[PayloadTextSegment],
    kind: str,
    role: str,
    path: str,
) -> None:
    if isinstance(content, str):
        segments.append(PayloadTextSegment(text=content, kind=kind, role=role, path=path))
        return
    if not isinstance(content, list):
        return
    for item_index, item in enumerate(content):
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        item_path = f"{path}[{item_index}]"
        if item_type == "text" and isinstance(item.get("text"), str):
            segments.append(PayloadTextSegment(text=item["text"], kind=kind, role=role, path=f"{item_path}.text"))
            continue
        if item_type == "tool_result":
            _collect_anthropic_content_segments(item.get("content"), segments, "tool_result", role, f"{item_path}.content")
            continue
        if item_type == "tool_use" and "input" in item:
            segments.append(
                PayloadTextSegment(
                    text=json_dumps(item["input"]),
                    kind="tool_call_arguments" if not kind.startswith("response_") else "response_tool_call_arguments",
                    role=role,
                    path=f"{item_path}.input",
                )
            )


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


def _redact_anthropic_content(content: Any, redact: Callable[[str], str]) -> Any:
    if isinstance(content, str):
        return redact(content)
    if not isinstance(content, list):
        return content

    new_items = []
    for item in content:
        if not isinstance(item, dict):
            new_items.append(item)
            continue
        new_item = copy.deepcopy(item)
        item_type = new_item.get("type")
        if item_type == "text" and isinstance(new_item.get("text"), str):
            new_item["text"] = redact(new_item["text"])
        elif item_type == "tool_result":
            new_item["content"] = _redact_anthropic_content(new_item.get("content"), redact)
        elif item_type == "tool_use" and "input" in new_item:
            new_item["input"] = _redact_nested_strings(new_item["input"], redact)
        new_items.append(new_item)
    return new_items


def _redact_nested_strings(value: Any, redact: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redact_nested_strings(item, redact) for item in value]
    if isinstance(value, dict):
        return {key: _redact_nested_strings(item, redact) for key, item in value.items()}
    return value


def _redact_tool_call_arguments(tool_calls: Any, redact: Callable[[str], str]) -> bool:
    if not isinstance(tool_calls, list):
        return False

    changed = False
    for tool_call in tool_calls:
        if not isinstance(tool_call, dict):
            continue
        function = tool_call.get("function")
        if not isinstance(function, dict):
            continue
        arguments = function.get("arguments")
        if not isinstance(arguments, str):
            continue
        redacted = redact(arguments)
        if redacted != arguments:
            function["arguments"] = redacted
            changed = True
    return changed


def _coerce_token_count(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
