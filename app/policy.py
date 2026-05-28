"""Route policy loading and matching."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class RoutePolicy:
    name: str = "default"
    path: str = "*"
    input_scanning: bool = True
    output_scanning: bool = True
    redact_inputs: bool = True
    redact_outputs: bool = True
    block_prompt_injection: bool = True
    audit: bool = True
    blocked_status_code: int = 403

    def matches(self, request_path: str) -> bool:
        if self.path == "*":
            return True
        if self.path.endswith("*"):
            return request_path.startswith(self.path[:-1])
        return request_path == self.path


class PolicyStore:
    def __init__(self, default: RoutePolicy, routes: list[RoutePolicy]):
        self.default = default
        self.routes = routes

    @classmethod
    def load(cls, path: Path, fallback: RoutePolicy) -> "PolicyStore":
        if not path.exists():
            return cls(default=fallback, routes=[])

        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        if not isinstance(raw, dict):
            return cls(default=fallback, routes=[])

        default = _merge_policy(fallback, raw.get("default", {}), fallback.path, fallback.name)
        routes: list[RoutePolicy] = []
        for index, item in enumerate(raw.get("routes", []) or []):
            if not isinstance(item, dict):
                continue
            route_path = str(item.get("path", "*"))
            route_name = str(item.get("name", f"route_{index + 1}"))
            routes.append(_merge_policy(default, item, route_path, route_name))
        return cls(default=default, routes=routes)

    def for_path(self, request_path: str) -> RoutePolicy:
        for route in self.routes:
            if route.matches(request_path):
                return route
        return self.default


def _merge_policy(base: RoutePolicy, raw: Any, path: str, name: str) -> RoutePolicy:
    if not isinstance(raw, dict):
        return replace(base, path=path, name=name)

    values: dict[str, Any] = {"path": path, "name": name}
    for field in (
        "input_scanning",
        "output_scanning",
        "redact_inputs",
        "redact_outputs",
        "block_prompt_injection",
        "audit",
    ):
        if field in raw:
            values[field] = _coerce_bool(raw[field], getattr(base, field))

    if "blocked_status_code" in raw:
        values["blocked_status_code"] = _coerce_int(raw["blocked_status_code"], base.blocked_status_code)

    return replace(base, **values)


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(value, int):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

