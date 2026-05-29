"""Runtime configuration for the LLM-WAF gateway."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_csv(name: str) -> tuple[str, ...]:
    value = os.getenv(name, "")
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    service_name: str = os.getenv("LLM_WAF_SERVICE_NAME", "LLM-WAF")
    bind_host: str = os.getenv("LLM_WAF_HOST", "0.0.0.0")
    bind_port: int = _env_int("LLM_WAF_PORT", 8080)

    # This should be the provider base_url a user would normally configure in
    # their SDK, for example https://api.openai.com/v1 or https://api.deepseek.com.
    upstream_base_url: str = os.getenv("UPSTREAM_BASE_URL", "https://api.openai.com/v1")
    upstream_api_key: str = os.getenv("UPSTREAM_API_KEY", "")
    upstream_timeout_seconds: float = _env_float("UPSTREAM_TIMEOUT_SECONDS", 90.0)

    max_body_bytes: int = _env_int("MAX_BODY_BYTES", 2_000_000)
    gateway_api_keys: tuple[str, ...] = _env_csv("GATEWAY_API_KEYS")
    gateway_api_key_header: str = os.getenv("GATEWAY_API_KEY_HEADER", "X-LLM-WAF-Key")
    rate_limit_per_minute: int = _env_int("RATE_LIMIT_PER_MINUTE", 0)
    rate_limit_backend: str = os.getenv("RATE_LIMIT_BACKEND", "memory")
    redis_url: str = os.getenv("REDIS_URL", "")
    allow_unscanned_generation_passthrough: bool = _env_bool("ALLOW_UNSCANNED_GENERATION_PASSTHROUGH", False)
    policy_path: Path = Path(os.getenv("POLICY_PATH", "config/policy.yaml"))
    rules_path: Path = Path(os.getenv("RULES_PATH", "config/rules.yaml"))
    pricing_path: Path = Path(os.getenv("PRICING_PATH", "config/pricing.yaml"))
    fail_closed: bool = _env_bool("FAIL_CLOSED", False)
    redact_inputs: bool = _env_bool("REDACT_INPUTS", True)
    redact_outputs: bool = _env_bool("REDACT_OUTPUTS", True)
    scan_outputs: bool = _env_bool("SCAN_OUTPUTS", True)
    scanner_rule_timeout_ms: int = _env_int("SCANNER_RULE_TIMEOUT_MS", 50)
    stream_scan_window_chars: int = _env_int("STREAM_SCAN_WINDOW_CHARS", 4096)
    stream_hold_back_frames: int = _env_int("STREAM_HOLD_BACK_FRAMES", 1)
    semantic_scanner_url: str = os.getenv("SEMANTIC_SCANNER_URL", "")
    semantic_scanner_timeout_seconds: float = _env_float("SEMANTIC_SCANNER_TIMEOUT_SECONDS", 2.0)
    semantic_local_enabled: bool = _env_bool("SEMANTIC_LOCAL", False)
    semantic_local_model_path: Path = Path(os.getenv("SEMANTIC_LOCAL_MODEL_PATH", ""))
    semantic_local_tokenizer_path: Path = Path(os.getenv("SEMANTIC_LOCAL_TOKENIZER_PATH", ""))
    semantic_local_threshold: float = _env_float("SEMANTIC_LOCAL_THRESHOLD", 0.85)
    semantic_local_action: str = os.getenv("SEMANTIC_LOCAL_ACTION", "log_only")
    semantic_local_max_chars: int = _env_int("SEMANTIC_LOCAL_MAX_CHARS", 4000)
    semantic_local_timeout_seconds: float = _env_float("SEMANTIC_LOCAL_TIMEOUT_SECONDS", 2.0)
    blocked_status_code: int = _env_int("BLOCKED_STATUS_CODE", 403)

    audit_log_path: Path = Path(os.getenv("AUDIT_LOG_PATH", "var/audit/events.jsonl"))
    audit_rotate_max_bytes: int = _env_int("AUDIT_ROTATE_MAX_BYTES", 10_000_000)
    audit_rotate_backups: int = _env_int("AUDIT_ROTATE_BACKUPS", 5)
    dashboard_limit: int = _env_int("DASHBOARD_LIMIT", 50)

    enable_cors: bool = _env_bool("ENABLE_CORS", True)
    cors_allow_origins: str = os.getenv("CORS_ALLOW_ORIGINS", "*")


settings = Settings()
