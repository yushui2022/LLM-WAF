"""Gateway authentication and in-memory rate limiting."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthResult:
    allowed: bool
    principal: str
    method: str
    used_authorization_header: bool = False
    reason: str | None = None


class GatewayAuth:
    def __init__(self, api_keys: tuple[str, ...], header_name: str = "X-LLM-WAF-Key"):
        self.api_keys = api_keys
        self.header_name = header_name.lower()

    @property
    def enabled(self) -> bool:
        return bool(self.api_keys)

    def authenticate_headers(self, headers: Mapping[str, str]) -> AuthResult:
        if not self.api_keys:
            return AuthResult(True, "anonymous", "disabled")

        normalized = {key.lower(): value for key, value in headers.items()}
        header_value = normalized.get(self.header_name, "").strip()
        if header_value and self._matches(header_value):
            return AuthResult(True, self._principal(header_value), self.header_name)

        auth_value = normalized.get("authorization", "").strip()
        if auth_value.lower().startswith("bearer "):
            token = auth_value[7:].strip()
            if self._matches(token):
                return AuthResult(True, self._principal(token), "authorization", used_authorization_header=True)

        return AuthResult(False, "unauthenticated", "none", reason="missing_or_invalid_gateway_api_key")

    def _matches(self, token: str) -> bool:
        return any(hmac.compare_digest(token, key) for key in self.api_keys)

    def _principal(self, token: str) -> str:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
        return f"key:{digest}"


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int = 0
    limit: int = 0
    window_seconds: int = 60


class InMemoryRateLimiter:
    """Simple per-principal sliding-window limiter.

    It is deliberately local-memory only for the MVP. Multi-process or
    multi-replica deployments should replace this with Redis or another
    shared counter backend.
    """

    def __init__(self, limit_per_minute: int, window_seconds: int = 60):
        self.limit = max(0, limit_per_minute)
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._requests: dict[str, deque[float]] = {}

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def check(self, principal: str) -> RateLimitResult:
        if not self.enabled:
            return RateLimitResult(True, remaining=0, limit=0, window_seconds=self.window_seconds)

        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._requests.setdefault(principal, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.limit:
                retry_after = max(1, int(bucket[0] + self.window_seconds - now))
                return RateLimitResult(
                    False,
                    remaining=0,
                    retry_after_seconds=retry_after,
                    limit=self.limit,
                    window_seconds=self.window_seconds,
                )

            bucket.append(now)
            return RateLimitResult(
                True,
                remaining=max(0, self.limit - len(bucket)),
                limit=self.limit,
                window_seconds=self.window_seconds,
            )

