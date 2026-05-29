"""LLM-WAF MVP gateway.

Run locally:
    uvicorn app.main:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import codecs
import hashlib
import json
import logging
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.access import AuthResult, GatewayAuth, RateLimitResult, create_rate_limiter
from app.audit import AuditLog
from app.config import settings
from app.dashboard import render_dashboard
from app.policy import PolicyStore, RoutePolicy
from app.pricing import PricingStore
from app.security.models import ScanResult
from app.security.payload import (
    PayloadTextSegment,
    extract_request_segments,
    extract_response_text,
    extract_usage,
    json_dumps,
    redact_request_body,
    redact_response_body,
    redact_sse_json_payload,
)
from app.security.rules import RULE_SET, deprecated_alias_map
from app.security.scanner import SecurityScanner
from app.security.semantic import HttpSemanticScanner, SemanticScanner, merge_scan_results
from app.security.semantic_local import LocalSemanticConfig, LocalSemanticScanner

app = FastAPI(
    title="LLM-WAF",
    description="Zero-intrusion LLM security gateway with streaming proxy, redaction, audit logs, and dashboard.",
    version="0.1.0",
)

if settings.enable_cors:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in settings.cors_allow_origins.split(",")],
        allow_methods=["*"],
        allow_headers=["*"],
    )

scanner = SecurityScanner()
semantic_scanners: tuple[SemanticScanner, ...] = tuple(
    scanner
    for scanner in (
        HttpSemanticScanner(settings.semantic_scanner_url, settings.semantic_scanner_timeout_seconds)
        if settings.semantic_scanner_url
        else None,
        LocalSemanticScanner(
            LocalSemanticConfig(
                model_path=settings.semantic_local_model_path,
                tokenizer_path=settings.semantic_local_tokenizer_path,
                threshold=settings.semantic_local_threshold,
                action=settings.semantic_local_action,
                max_chars=settings.semantic_local_max_chars,
                timeout_seconds=settings.semantic_local_timeout_seconds,
            )
        )
        if settings.semantic_local_enabled
        else None,
    )
    if scanner is not None
)
audit_log = AuditLog(settings.audit_log_path)
gateway_auth = GatewayAuth(settings.gateway_api_keys, settings.gateway_api_key_header)
rate_limiter = create_rate_limiter(settings.rate_limit_per_minute, settings.rate_limit_backend, settings.redis_url)
policy_store = PolicyStore.load(
    settings.policy_path,
    RoutePolicy(
        redact_inputs=settings.redact_inputs,
        redact_outputs=settings.redact_outputs,
        output_scanning=settings.scan_outputs,
        blocked_status_code=settings.blocked_status_code,
    ),
)
pricing_store = PricingStore.load(settings.pricing_path)

logger = logging.getLogger("llm_waf")


def _warn_deprecated_disabled_rules() -> None:
    """Warn once at startup if any policy disables a rule by a deprecated alias.

    Aliases keep old `disabled_rules` configs working for one release; this
    nudges operators to migrate before the aliases are removed.
    """

    alias_map = deprecated_alias_map(RULE_SET)
    if not alias_map:
        return
    seen: set[str] = set()
    for policy in (policy_store.default, *policy_store.routes):
        for rule_id in policy.disabled_rules:
            if rule_id in alias_map and rule_id not in seen:
                seen.add(rule_id)
                logger.warning(
                    "policy %r disables rule by deprecated ID %r; rename to %r (aliases are removed next release)",
                    policy.name,
                    rule_id,
                    alias_map[rule_id],
                )


_warn_deprecated_disabled_rules()

UNSCANNED_GENERATION_ROUTES = {
    "completions": "legacy OpenAI completions",
    "messages": "Anthropic native messages",
    "responses": "OpenAI responses",
}


@app.get("/")
async def index() -> dict[str, str]:
    return {
        "service": settings.service_name,
        "version": "0.1.0",
        "chat_completions": "/v1/chat/completions",
        "dashboard": "/dashboard",
        "health": "/health",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.service_name, "version": "0.1.0"}


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    events = audit_log.tail(settings.dashboard_limit)
    filters = {
        "decision": request.query_params.get("decision", ""),
        "category": request.query_params.get("category", ""),
        "severity": request.query_params.get("severity", ""),
    }
    return HTMLResponse(render_dashboard(events, filters=filters))


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    trace_id = _trace_id()
    started = time.perf_counter()
    policy = policy_store.for_path(request.url.path)
    auth = gateway_auth.authenticate_headers(request.headers)
    if not auth.allowed:
        event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy)
        event.update({"decision": "blocked", "status_code": 401, "reason": auth.reason})
        _audit(event, policy)
        return _error_response(
            trace_id,
            401,
            "unauthorized",
            "Missing or invalid gateway API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    rate_limit = rate_limiter.check(auth.principal)
    if not rate_limit.allowed:
        event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy, rate_limit=rate_limit)
        event.update({"decision": "blocked", "status_code": 429, "reason": "rate_limited"})
        _audit(event, policy)
        return _error_response(
            trace_id,
            429,
            "rate_limited",
            "Gateway rate limit exceeded.",
            headers={"Retry-After": str(rate_limit.retry_after_seconds)},
        )

    raw_body = await request.body()

    if len(raw_body) > settings.max_body_bytes:
        event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy, rate_limit=rate_limit)
        event.update({"decision": "blocked", "status_code": 413, "reason": "request_too_large"})
        _audit(event, policy)
        return _error_response(trace_id, 413, "request_too_large", "Request body exceeds MAX_BODY_BYTES.")

    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy, rate_limit=rate_limit)
        event.update({"decision": "blocked", "status_code": 400, "reason": "invalid_json"})
        _audit(event, policy)
        return _error_response(trace_id, 400, "invalid_json", "Invalid JSON request body.")

    stream = bool(body.get("stream"))
    model = str(body.get("model", ""))
    request_segments = extract_request_segments(body)
    request_text = _join_payload_text(request_segments)
    event = _base_event(trace_id, request, started, model=model, stream=stream, auth=auth, policy=policy, rate_limit=rate_limit)
    event["prompt_sha256"] = _sha256(request_text)
    event["input_segments"] = _payload_segment_summary(request_segments)

    input_scan = await _scan_input_safely(request_text, policy, event) if policy.input_scanning else None
    if input_scan is None and event.get("reason") == "scanner_failure" and settings.fail_closed:
        event.update({"decision": "blocked", "status_code": 503, **_finding_fields([])})
        _audit(event, policy)
        return _error_response(trace_id, 503, "scanner_failure", "Input scanner failed and FAIL_CLOSED is enabled.")

    findings = input_scan.to_audit_findings() if input_scan else []

    if input_scan and input_scan.blocked and policy.block_prompt_injection:
        event.update(
            {
                "decision": "blocked",
                "status_code": policy.blocked_status_code,
                **_finding_fields(findings),
            }
        )
        _audit(event, policy)
        return _blocked_response(trace_id, findings, policy)

    forwarded_body = body
    input_redacted = bool(input_scan and input_scan.redacted and policy.redact_inputs)
    if input_redacted:
        forwarded_body = redact_request_body(
            body,
            lambda text: scanner.redact_sensitive(text, policy.disabled_rules, policy.disabled_categories),
        )

    if stream:
        return await _proxy_streaming(request, trace_id, started, forwarded_body, event, findings, input_redacted, auth, policy)
    return await _proxy_buffered(request, trace_id, started, forwarded_body, event, findings, input_redacted, auth, policy)


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def passthrough(request: Request, path: str) -> Response:
    """Pass through non-chat OpenAI-compatible routes such as /v1/models."""

    trace_id = _trace_id()
    started = time.perf_counter()
    policy = policy_store.for_path(request.url.path)
    auth = gateway_auth.authenticate_headers(request.headers)
    if not auth.allowed:
        event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy)
        event.update({"decision": "blocked", "status_code": 401, "reason": auth.reason})
        _audit(event, policy)
        return _error_response(
            trace_id,
            401,
            "unauthorized",
            "Missing or invalid gateway API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    rate_limit = rate_limiter.check(auth.principal)
    if not rate_limit.allowed:
        event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy, rate_limit=rate_limit)
        event.update({"decision": "blocked", "status_code": 429, "reason": "rate_limited"})
        _audit(event, policy)
        return _error_response(
            trace_id,
            429,
            "rate_limited",
            "Gateway rate limit exceeded.",
            headers={"Retry-After": str(rate_limit.retry_after_seconds)},
        )

    if _is_unscanned_generation_route(request.method, path):
        route_name = UNSCANNED_GENERATION_ROUTES.get(path.strip("/").lower(), "unsupported generation route")
        event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy, rate_limit=rate_limit)
        event.update(
            {
                "decision": "blocked",
                "status_code": 501,
                "reason": "unsupported_unscanned_generation_route",
                "route": request.url.path,
                "route_name": route_name,
                "latency_ms": _elapsed_ms(started),
                **_finding_fields([]),
            }
        )
        _audit(event, policy)
        return _error_response(
            trace_id,
            501,
            "unsupported_protocol",
            (
                f"{request.url.path} can generate model output but is not scanned by LLM-WAF. "
                "Use OpenAI-compatible /v1/chat/completions, or set "
                "ALLOW_UNSCANNED_GENERATION_PASSTHROUGH=true to bypass WAF scanning explicitly."
            ),
        )

    raw_body = await request.body()
    upstream_url = _upstream_url(request.url.path)
    headers = _forward_headers(request, trace_id, auth)

    try:
        async with httpx.AsyncClient(timeout=settings.upstream_timeout_seconds) as client:
            upstream = await client.request(
                request.method,
                upstream_url,
                params=request.query_params,
                headers=headers,
                content=raw_body or None,
            )
    except httpx.HTTPError as exc:
        event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy, rate_limit=rate_limit)
        event.update({"decision": "error", "status_code": 502, "reason": str(exc)})
        _audit(event, policy)
        return _error_response(trace_id, 502, "upstream_error", str(exc))

    event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy, rate_limit=rate_limit)
    event.update(
        {
            "decision": "allowed",
            "status_code": upstream.status_code,
            "upstream_status": upstream.status_code,
            "latency_ms": _elapsed_ms(started),
            **_finding_fields([]),
        }
    )
    _audit(event, policy)
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_response_headers(upstream),
        media_type=upstream.headers.get("content-type"),
    )


async def _proxy_buffered(
    request: Request,
    trace_id: str,
    started: float,
    body: dict[str, Any],
    event: dict[str, Any],
    input_findings: list[dict[str, Any]],
    input_redacted: bool,
    auth: AuthResult,
    policy: RoutePolicy,
) -> Response:
    upstream_url = _upstream_url(request.url.path)
    headers = _forward_headers(request, trace_id, auth)

    try:
        async with httpx.AsyncClient(timeout=settings.upstream_timeout_seconds) as client:
            upstream = await client.post(upstream_url, params=request.query_params, headers=headers, json=body)
    except httpx.HTTPError as exc:
        event.update(
            {
                "decision": "error",
                "status_code": 502,
                "reason": str(exc),
                **_finding_fields(input_findings),
                "latency_ms": _elapsed_ms(started),
            }
        )
        _audit(event, policy)
        return _error_response(trace_id, 502, "upstream_error", str(exc))

    content = upstream.content
    response_headers = _response_headers(upstream)
    output_findings: list[dict[str, Any]] = []
    output_redacted = False
    usage: dict[str, int] = {}

    if _looks_like_json(upstream):
        try:
            response_body = upstream.json()
            usage = extract_usage(response_body)
            if policy.output_scanning:
                output_text = extract_response_text(response_body)
                output_scan = await _scan_output_safely(output_text, policy, event)
                if output_scan is None and settings.fail_closed:
                    event.update(
                        {
                            "decision": "blocked",
                            "status_code": 503,
                            "upstream_status": upstream.status_code,
                            "latency_ms": _elapsed_ms(started),
                            **_finding_fields(input_findings),
                        }
                    )
                    _audit(event, policy)
                    return _error_response(trace_id, 503, "scanner_failure", "Output scanner failed and FAIL_CLOSED is enabled.")
                if output_scan is None:
                    output_scan = ScanResult()
                output_findings = output_scan.to_audit_findings()
                output_redacted = bool(output_scan.redacted and policy.redact_outputs)
                if output_redacted:
                    response_body = redact_response_body(
                        response_body,
                        lambda text: scanner.redact_output(text, policy.disabled_rules, policy.disabled_categories),
                    )
                    content = json_dumps(response_body).encode("utf-8")
                    response_headers.pop("content-length", None)
        except (ValueError, TypeError):
            pass

    findings = input_findings + output_findings
    decision = _decision(blocked=False, redacted=input_redacted or output_redacted)
    event.update(
        {
            "decision": decision,
            "status_code": upstream.status_code,
            "upstream_status": upstream.status_code,
            "latency_ms": _elapsed_ms(started),
            **_finding_fields(findings),
            "input_redacted": input_redacted,
            "output_redacted": output_redacted,
        }
    )
    if usage:
        event["usage"] = usage
        cost = pricing_store.estimate(str(event.get("model", "")), usage)
        if cost:
            event["cost"] = cost
    _audit(event, policy)

    return Response(
        content=content,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=upstream.headers.get("content-type"),
    )


async def _proxy_streaming(
    request: Request,
    trace_id: str,
    started: float,
    body: dict[str, Any],
    event: dict[str, Any],
    input_findings: list[dict[str, Any]],
    input_redacted: bool,
    auth: AuthResult,
    policy: RoutePolicy,
) -> Response:
    upstream_url = _upstream_url(request.url.path)
    headers = _forward_headers(request, trace_id, auth)
    client = httpx.AsyncClient(timeout=None)

    try:
        upstream_request = client.build_request(
            "POST",
            upstream_url,
            params=request.query_params,
            headers=headers,
            json=body,
        )
        upstream = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        event.update(
            {
                "decision": "error",
                "status_code": 502,
                "reason": str(exc),
                **_finding_fields(input_findings),
                "latency_ms": _elapsed_ms(started),
            }
        )
        _audit(event, policy)
        return _error_response(trace_id, 502, "upstream_error", str(exc))

    output_findings: list[dict[str, Any]] = []
    output_redacted = False
    output_usage: dict[str, int] = {}
    content_type = upstream.headers.get("content-type", "text/event-stream")
    stream_scan_state = StreamScanState(window_chars=settings.stream_scan_window_chars)
    stream_hold_back = StreamHoldBackBuffer(frame_count=settings.stream_hold_back_frames)
    stream_scanner_error = ""

    async def generate():
        nonlocal output_redacted, stream_scanner_error
        decoder = codecs.getincrementaldecoder("utf-8")()
        buffer = ""
        try:
            async for chunk in upstream.aiter_bytes():
                if not policy.output_scanning or "text/event-stream" not in content_type:
                    yield chunk
                    continue
                buffer += decoder.decode(chunk)
                while "\n\n" in buffer:
                    frame, buffer = buffer.split("\n\n", 1)
                    try:
                        transformed, changed, frame_findings, frame_usage = _transform_sse_frame(
                            frame,
                            redact_outputs=policy.redact_outputs,
                            disabled_rule_ids=policy.disabled_rules,
                            disabled_categories=policy.disabled_categories,
                            stream_scan_state=stream_scan_state,
                        )
                    except Exception as exc:
                        stream_scanner_error = _record_scanner_error(event, exc)
                        if settings.fail_closed:
                            yield _sse_error_frame(trace_id, "scanner_failure", "Output scanner failed and FAIL_CLOSED is enabled.")
                            return
                        yield frame + "\n\n"
                        continue
                    output_redacted = output_redacted or changed
                    output_findings.extend(frame_findings)
                    if frame_usage:
                        output_usage.update(frame_usage)
                    frame_record = transformed + "\n\n"
                    if stream_hold_back.enabled:
                        for ready_frame in stream_hold_back.add(
                            frame_record,
                            redact_pending=_has_stream_window_finding(frame_findings),
                        ):
                            yield ready_frame
                    else:
                        yield frame_record
            tail = buffer + decoder.decode(b"", final=True)
            if tail:
                try:
                    transformed, changed, frame_findings, frame_usage = _transform_sse_frame(
                        tail,
                        redact_outputs=policy.redact_outputs,
                        disabled_rule_ids=policy.disabled_rules,
                        disabled_categories=policy.disabled_categories,
                        stream_scan_state=stream_scan_state,
                    )
                except Exception as exc:
                    stream_scanner_error = _record_scanner_error(event, exc)
                    if settings.fail_closed:
                        yield _sse_error_frame(trace_id, "scanner_failure", "Output scanner failed and FAIL_CLOSED is enabled.")
                        return
                    yield tail
                    return
                output_redacted = output_redacted or changed
                output_findings.extend(frame_findings)
                if frame_usage:
                    output_usage.update(frame_usage)
                if stream_hold_back.enabled:
                    for ready_frame in stream_hold_back.add(
                        transformed,
                        redact_pending=_has_stream_window_finding(frame_findings),
                    ):
                        yield ready_frame
                else:
                    yield transformed
            if stream_hold_back.enabled:
                for ready_frame in stream_hold_back.flush():
                    yield ready_frame
        finally:
            await upstream.aclose()
            await client.aclose()
            findings = input_findings + output_findings[:20]
            stream_failed_closed = bool(stream_scanner_error and settings.fail_closed)
            stream_event = {
                "decision": "error" if stream_failed_closed else _decision(blocked=False, redacted=input_redacted or output_redacted),
                "status_code": 503 if stream_failed_closed else upstream.status_code,
                "upstream_status": upstream.status_code,
                "latency_ms": _elapsed_ms(started),
                **_finding_fields(findings),
                "input_redacted": input_redacted,
                "output_redacted": output_redacted,
            }
            if stream_failed_closed:
                stream_event["reason"] = "scanner_failure"
            event.update(stream_event)
            if output_usage:
                event["usage"] = output_usage
                cost = pricing_store.estimate(str(event.get("model", "")), output_usage)
                if cost:
                    event["cost"] = cost
            _audit(event, policy)

    return StreamingResponse(
        generate(),
        status_code=upstream.status_code,
        headers=_response_headers(upstream),
        media_type=content_type,
    )


def _transform_sse_frame(
    frame: str,
    redact_outputs: bool = True,
    disabled_rule_ids: tuple[str, ...] = (),
    disabled_categories: tuple[str, ...] = (),
    stream_scan_state: "StreamScanState | None" = None,
) -> tuple[str, bool, list[dict[str, Any]], dict[str, int]]:
    changed = False
    findings: list[dict[str, Any]] = []
    usage: dict[str, int] = {}
    out_lines: list[str] = []

    for line in frame.splitlines():
        if not line.startswith("data:"):
            out_lines.append(line)
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            out_lines.append(line)
            continue
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            out_lines.append(line)
            continue

        frame_usage = extract_usage(payload)
        if frame_usage:
            usage.update(frame_usage)

        output_text = extract_response_text(payload)
        frame_findings: list[dict[str, Any]] = []
        if output_text:
            if stream_scan_state is not None and stream_scan_state.enabled:
                frame_findings = stream_scan_state.scan(output_text, disabled_rule_ids, disabled_categories)
            else:
                scan = scanner.scan_output(output_text, disabled_rule_ids, disabled_categories)
                frame_findings = scan.to_audit_findings(limit=5)
            findings.extend(frame_findings)

        payload_changed = False
        if redact_outputs:
            payload, payload_changed = redact_sse_json_payload(
                payload,
                lambda text: scanner.redact_output(text, disabled_rule_ids, disabled_categories),
            )
            if frame_findings and not payload_changed and stream_scan_state is not None and stream_scan_state.enabled:
                payload, payload_changed = redact_sse_json_payload(
                    payload,
                    lambda text: "[REDACTED:stream_window]" if text else text,
                )
            changed = changed or payload_changed
        out_lines.append("data: " + json_dumps(payload))

    return "\n".join(out_lines), changed, findings, usage


@dataclass
class StreamScanState:
    window_chars: int = 4096
    window: str = ""
    seen_findings: set[tuple[str, str]] = field(default_factory=set)

    @property
    def enabled(self) -> bool:
        return self.window_chars > 0

    def scan(
        self,
        text: str,
        disabled_rule_ids: tuple[str, ...] = (),
        disabled_categories: tuple[str, ...] = (),
    ) -> list[dict[str, Any]]:
        if not text or not self.enabled:
            return []

        combined = self.window + text
        scan = scanner.scan_output(combined, disabled_rule_ids, disabled_categories)
        self.window = combined[-self.window_chars :]

        findings: list[dict[str, Any]] = []
        for finding in scan.to_audit_findings(limit=10):
            key = (str(finding.get("rule_id", "")), str(finding.get("evidence", "")))
            if key in self.seen_findings:
                continue
            self.seen_findings.add(key)
            finding["source"] = "stream_window"
            findings.append(finding)
        return findings[:5]


@dataclass
class StreamHoldBackBuffer:
    frame_count: int = 0
    pending: list[str] = field(default_factory=list)

    @property
    def enabled(self) -> bool:
        return self.frame_count > 0

    def add(self, frame: str, redact_pending: bool = False) -> list[str]:
        if not self.enabled:
            return [frame]
        if redact_pending and self.pending:
            self.pending = [_redact_sse_frame_text(item, "[REDACTED:stream_hold_back]") for item in self.pending]
        self.pending.append(frame)

        ready: list[str] = []
        while len(self.pending) > self.frame_count:
            ready.append(self.pending.pop(0))
        return ready

    def flush(self) -> list[str]:
        ready = self.pending
        self.pending = []
        return ready


def _has_stream_window_finding(findings: list[dict[str, Any]]) -> bool:
    return any(finding.get("source") == "stream_window" for finding in findings)


def _redact_sse_frame_text(frame: str, replacement: str) -> str:
    suffix = "\n\n" if frame.endswith("\n\n") else ""
    body = frame[:-2] if suffix else frame
    transformed, _, _, _ = _transform_sse_frame(
        body,
        redact_outputs=True,
        stream_scan_state=None,
    )

    # Force redaction of held text even when the held fragment was not risky on its own.
    out_lines: list[str] = []
    for line in transformed.splitlines():
        if not line.startswith("data:"):
            out_lines.append(line)
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            out_lines.append(line)
            continue
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            out_lines.append(line)
            continue
        payload, _ = redact_sse_json_payload(payload, lambda text: replacement if text else text)
        out_lines.append("data: " + json_dumps(payload))
    return "\n".join(out_lines) + suffix


def _upstream_url(request_path: str) -> str:
    path = request_path
    if path == "/v1":
        path = ""
    elif path.startswith("/v1/"):
        path = path[3:]
    return settings.upstream_base_url.rstrip("/") + path


def _is_unscanned_generation_route(method: str, path: str) -> bool:
    if settings.allow_unscanned_generation_passthrough:
        return False
    if method.upper() == "GET":
        return False
    return path.strip("/").lower() in UNSCANNED_GENERATION_ROUTES


def _forward_headers(request: Request, trace_id: str, auth: AuthResult) -> dict[str, str]:
    blocked = {"host", "content-length", "connection", settings.gateway_api_key_header.lower()}
    if gateway_auth.enabled and auth.used_authorization_header and not settings.upstream_api_key:
        blocked.add("authorization")
    headers = {k: v for k, v in request.headers.items() if k.lower() not in blocked}
    if settings.upstream_api_key:
        headers["authorization"] = f"Bearer {settings.upstream_api_key}"
    headers["x-llm-waf-trace-id"] = trace_id
    return headers


def _response_headers(upstream: httpx.Response) -> dict[str, str]:
    blocked = {"content-length", "content-encoding", "transfer-encoding", "connection"}
    return {k: v for k, v in upstream.headers.items() if k.lower() not in blocked}


def _looks_like_json(response: httpx.Response) -> bool:
    return "application/json" in response.headers.get("content-type", "")


def _blocked_response(trace_id: str, findings: list[dict[str, Any]], policy: RoutePolicy) -> JSONResponse:
    top = findings[0] if findings else {}
    message = top.get("description", "Request blocked by LLM-WAF policy.")
    return _error_response(
        trace_id,
        policy.blocked_status_code,
        "waf_blocked",
        str(message),
        extra={"findings": findings},
    )


def _error_response(
    trace_id: str,
    status_code: int,
    code: str,
    message: str,
    extra: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "error": {
            "message": f"[LLM-WAF] {message}",
            "type": code,
            "code": code,
            "trace_id": trace_id,
        }
    }
    if extra:
        body["error"].update(extra)
    return JSONResponse(body, status_code=status_code, headers=headers)


def _sse_error_frame(trace_id: str, code: str, message: str) -> str:
    payload = {
        "error": {
            "message": f"[LLM-WAF] {message}",
            "type": code,
            "code": code,
            "trace_id": trace_id,
        }
    }
    return "event: error\ndata: " + json_dumps(payload) + "\n\n"


def _base_event(
    trace_id: str,
    request: Request,
    started: float,
    model: str,
    stream: bool,
    auth: AuthResult,
    policy: RoutePolicy,
    rate_limit: RateLimitResult | None = None,
) -> dict[str, Any]:
    event = {
        "trace_id": trace_id,
        "ts": datetime.now(UTC).isoformat(),
        "method": request.method,
        "path": request.url.path,
        "model": model,
        "stream": stream,
        "client": request.client.host if request.client else "",
        "principal": auth.principal,
        "auth_method": auth.method,
        "policy": policy.name,
        "latency_ms": _elapsed_ms(started),
    }
    if rate_limit is not None and rate_limit.limit:
        event["rate_limit"] = {
            "backend": rate_limit.backend,
            "limit": rate_limit.limit,
            "remaining": rate_limit.remaining,
            "retry_after_seconds": rate_limit.retry_after_seconds,
        }
    return event


def _audit(event: dict[str, Any], policy: RoutePolicy) -> None:
    if policy.audit:
        audit_log.append(event)


def _join_payload_text(segments: list[PayloadTextSegment]) -> str:
    return "\n".join(segment.text for segment in segments if segment.text)


def _payload_segment_summary(segments: list[PayloadTextSegment]) -> dict[str, Any]:
    by_kind = Counter(segment.kind for segment in segments if segment.kind)
    by_role = Counter(segment.role or "unknown" for segment in segments)
    return {
        "total": len(segments),
        "by_kind": dict(sorted(by_kind.items())),
        "by_role": dict(sorted(by_role.items())),
    }


async def _scan_input_safely(text: str, policy: RoutePolicy, event: dict[str, Any]) -> ScanResult | None:
    try:
        result = scanner.scan_input(text, policy.disabled_rules, policy.disabled_categories)
    except Exception as exc:
        _record_scanner_error(event, exc)
        return None

    return await _merge_semantic_scans(result, "input", text, event)


async def _scan_output_safely(text: str, policy: RoutePolicy, event: dict[str, Any]) -> ScanResult | None:
    try:
        result = scanner.scan_output(text, policy.disabled_rules, policy.disabled_categories)
    except Exception as exc:
        _record_scanner_error(event, exc)
        return None

    return await _merge_semantic_scans(result, "output", text, event)


async def _merge_semantic_scans(base: ScanResult, direction: str, text: str, event: dict[str, Any]) -> ScanResult | None:
    if not semantic_scanners:
        return base

    result = base
    for semantic_scanner in semantic_scanners:
        try:
            semantic_result = await semantic_scanner.scan_input(text) if direction == "input" else await semantic_scanner.scan_output(text)
        except Exception as exc:
            _record_semantic_scanner_error(event, exc)
            if settings.fail_closed:
                return None
            continue
        result = merge_scan_results(result, semantic_result)
    return result


def _record_scanner_error(event: dict[str, Any], exc: Exception) -> str:
    error = exc.__class__.__name__
    event["reason"] = "scanner_failure"
    event["scanner_error"] = error
    event["fail_closed"] = settings.fail_closed
    return error


def _record_semantic_scanner_error(event: dict[str, Any], exc: Exception) -> str:
    error = exc.__class__.__name__
    event["semantic_scanner_error"] = error
    event.setdefault("semantic_scanner_errors", []).append(error)
    event["fail_closed"] = settings.fail_closed
    if settings.fail_closed:
        event["reason"] = "scanner_failure"
    return error


def _finding_fields(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "finding_count": len(findings),
        "findings": findings,
        "finding_summary": _finding_summary(findings),
    }


def _finding_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_category: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_action: Counter[str] = Counter()

    for finding in findings:
        category = str(finding.get("category", "unknown") or "unknown")
        severity = str(finding.get("severity", "unknown") or "unknown")
        action = str(finding.get("action", "unknown") or "unknown")
        by_category[category] += 1
        by_severity[severity] += 1
        by_action[action] += 1

    return {
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "by_action": dict(by_action),
        "max_severity": _max_severity(by_severity),
    }


def _max_severity(counts: Counter[str]) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if not counts:
        return "none"
    return max(counts, key=lambda severity: order.get(severity, 0))


def _decision(blocked: bool, redacted: bool) -> str:
    if blocked:
        return "blocked"
    if redacted:
        return "redacted"
    return "allowed"


def _trace_id() -> str:
    return "waf_" + uuid.uuid4().hex


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)


def _sha256(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.bind_host, port=settings.bind_port, reload=False)
