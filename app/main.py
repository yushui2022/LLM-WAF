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
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.access import AuthResult, GatewayAuth, RateLimitResult, create_rate_limiter
from app.audit import create_audit_sink
from app.config import settings
from app.dashboard import render_dashboard
from app.metrics import metrics_registry, record_event_metrics
from app.policy import PolicyStore, RoutePolicy
from app.pricing import PricingStore
from app.security.models import Finding, ScanResult
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
request_logger = logging.getLogger("llm_waf.requests")
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
audit_log = create_audit_sink(
    settings.audit_sink,
    settings.audit_log_path,
    settings.audit_rotate_max_bytes,
    settings.audit_rotate_backups,
    settings.audit_http_url,
    settings.audit_http_timeout_seconds,
    settings.audit_http_queue_size,
    settings.audit_http_bearer_token,
)
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
        "metrics": "/metrics",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.service_name, "version": "0.1.0"}


@app.get("/health/config")
async def health_config(request: Request) -> Response:
    auth = gateway_auth.authenticate_headers(request.headers)
    if not auth.allowed:
        return _error_response(
            _trace_id(),
            401,
            "unauthorized",
            "Missing or invalid gateway API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return JSONResponse(_redacted_config_summary())


@app.get("/metrics")
async def metrics() -> Response:
    return Response(metrics_registry.render(), media_type="text/plain; version=0.0.4; charset=utf-8")


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
    input_scan_text = _request_scan_text(request_segments, policy)
    event = _base_event(trace_id, request, started, model=model, stream=stream, auth=auth, policy=policy, rate_limit=rate_limit)
    event["prompt_sha256"] = _sha256(request_text)
    event["input_segments"] = _payload_segment_summary(request_segments, policy)
    if input_scan_text != request_text:
        event["scanned_prompt_sha256"] = _sha256(input_scan_text)

    input_scan = None
    if policy.input_scanning:
        scanner_started = time.perf_counter()
        input_scan = await _scan_input_segments_safely(request_segments, policy, event)
        event["input_scanner_latency_ms"] = _elapsed_ms(scanner_started)
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

    upstream_started = time.perf_counter()
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
        event.update({"decision": "error", "status_code": 502, "reason": str(exc), "upstream_latency_ms": _elapsed_ms(upstream_started)})
        _audit(event, policy)
        return _error_response(trace_id, 502, "upstream_error", str(exc))
    upstream_latency_ms = _elapsed_ms(upstream_started)

    event = _base_event(trace_id, request, started, model="", stream=False, auth=auth, policy=policy, rate_limit=rate_limit)
    event.update(
        {
            "decision": "allowed",
            "status_code": upstream.status_code,
            "upstream_status": upstream.status_code,
            "upstream_latency_ms": upstream_latency_ms,
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

    upstream_started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=settings.upstream_timeout_seconds) as client:
            upstream = await client.post(upstream_url, params=request.query_params, headers=headers, json=body)
    except httpx.HTTPError as exc:
        event.update(
            {
                "decision": "error",
                "status_code": 502,
                "reason": str(exc),
                "upstream_latency_ms": _elapsed_ms(upstream_started),
                **_finding_fields(input_findings),
                "latency_ms": _elapsed_ms(started),
            }
        )
        _audit(event, policy)
        return _error_response(trace_id, 502, "upstream_error", str(exc))
    upstream_latency_ms = _elapsed_ms(upstream_started)

    content = upstream.content
    response_headers = _response_headers(upstream)
    output_findings: list[dict[str, Any]] = []
    output_redacted = False
    output_scanner_latency_ms = 0.0
    usage: dict[str, int] = {}

    if _looks_like_json(upstream):
        try:
            response_body = upstream.json()
            usage = extract_usage(response_body)
            if policy.output_scanning:
                output_text = extract_response_text(response_body)
                scanner_started = time.perf_counter()
                output_scan = await _scan_output_safely(output_text, policy, event)
                output_scanner_latency_ms += _elapsed_ms(scanner_started)
                if output_scan is None and settings.fail_closed:
                    event.update(
                        {
                            "decision": "blocked",
                            "status_code": 503,
                            "upstream_status": upstream.status_code,
                            "upstream_latency_ms": upstream_latency_ms,
                            "output_scanner_latency_ms": round(output_scanner_latency_ms, 2),
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
            "upstream_latency_ms": upstream_latency_ms,
            "latency_ms": _elapsed_ms(started),
            **_finding_fields(findings),
            "input_redacted": input_redacted,
            "output_redacted": output_redacted,
        }
    )
    if output_scanner_latency_ms:
        event["output_scanner_latency_ms"] = round(output_scanner_latency_ms, 2)
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

    upstream_started = time.perf_counter()
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
                "upstream_header_latency_ms": _elapsed_ms(upstream_started),
                **_finding_fields(input_findings),
                "latency_ms": _elapsed_ms(started),
            }
        )
        _audit(event, policy)
        return _error_response(trace_id, 502, "upstream_error", str(exc))
    upstream_header_latency_ms = _elapsed_ms(upstream_started)

    output_findings: list[dict[str, Any]] = []
    output_redacted = False
    output_usage: dict[str, int] = {}
    content_type = upstream.headers.get("content-type", "text/event-stream")
    stream_scan_state = StreamScanState(window_chars=settings.stream_scan_window_chars)
    stream_hold_back = StreamHoldBackBuffer(frame_count=settings.stream_hold_back_frames)
    stream_scanner_error = ""
    output_scanner_latency_ms = 0.0

    async def generate():
        nonlocal output_redacted, output_scanner_latency_ms, stream_scanner_error
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
                    scanner_started = time.perf_counter()
                    try:
                        transformed, changed, frame_findings, frame_usage = _transform_sse_frame(
                            frame,
                            redact_outputs=policy.redact_outputs,
                            disabled_rule_ids=policy.disabled_rules,
                            disabled_categories=policy.disabled_categories,
                            stream_scan_state=stream_scan_state,
                        )
                    except Exception as exc:
                        output_scanner_latency_ms += _elapsed_ms(scanner_started)
                        stream_scanner_error = _record_scanner_error(event, exc)
                        if settings.fail_closed:
                            yield _sse_error_frame(trace_id, "scanner_failure", "Output scanner failed and FAIL_CLOSED is enabled.")
                            return
                        yield frame + "\n\n"
                        continue
                    output_scanner_latency_ms += _elapsed_ms(scanner_started)
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
                scanner_started = time.perf_counter()
                try:
                    transformed, changed, frame_findings, frame_usage = _transform_sse_frame(
                        tail,
                        redact_outputs=policy.redact_outputs,
                        disabled_rule_ids=policy.disabled_rules,
                        disabled_categories=policy.disabled_categories,
                        stream_scan_state=stream_scan_state,
                    )
                except Exception as exc:
                    output_scanner_latency_ms += _elapsed_ms(scanner_started)
                    stream_scanner_error = _record_scanner_error(event, exc)
                    if settings.fail_closed:
                        yield _sse_error_frame(trace_id, "scanner_failure", "Output scanner failed and FAIL_CLOSED is enabled.")
                        return
                    yield tail
                    return
                output_scanner_latency_ms += _elapsed_ms(scanner_started)
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
                "upstream_header_latency_ms": upstream_header_latency_ms,
                "latency_ms": _elapsed_ms(started),
                **_finding_fields(findings),
                "input_redacted": input_redacted,
                "output_redacted": output_redacted,
            }
            if output_scanner_latency_ms:
                stream_event["output_scanner_latency_ms"] = round(output_scanner_latency_ms, 2)
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
    record_event_metrics(event)
    request_logger.info(json_dumps(_structured_log_event(event)))
    if policy.audit:
        audit_log.append(event)


def _structured_log_event(event: dict[str, Any]) -> dict[str, Any]:
    allowed_fields = (
        "trace_id",
        "ts",
        "method",
        "path",
        "model",
        "stream",
        "principal",
        "auth_method",
        "policy",
        "decision",
        "status_code",
        "upstream_status",
        "latency_ms",
        "input_scanner_latency_ms",
        "output_scanner_latency_ms",
        "upstream_latency_ms",
        "upstream_header_latency_ms",
        "finding_count",
        "finding_summary",
        "input_segments",
        "input_redacted",
        "output_redacted",
        "fail_closed",
    )
    return {field: event[field] for field in allowed_fields if field in event}


def _redacted_config_summary() -> dict[str, Any]:
    return {
        "service_name": settings.service_name,
        "bind_host": settings.bind_host,
        "bind_port": settings.bind_port,
        "upstream_base_url": _redact_url(settings.upstream_base_url),
        "upstream_api_key": _secret_state(settings.upstream_api_key),
        "upstream_timeout_seconds": settings.upstream_timeout_seconds,
        "max_body_bytes": settings.max_body_bytes,
        "gateway_api_keys": {"enabled": bool(settings.gateway_api_keys), "count": len(settings.gateway_api_keys)},
        "rate_limit": {
            "per_minute": settings.rate_limit_per_minute,
            "backend": settings.rate_limit_backend,
            "redis_url": _redact_url(settings.redis_url),
        },
        "policy_path": str(settings.policy_path),
        "rules_path": str(settings.rules_path),
        "pricing_path": str(settings.pricing_path),
        "fail_closed": settings.fail_closed,
        "redact_inputs": settings.redact_inputs,
        "redact_outputs": settings.redact_outputs,
        "scan_outputs": settings.scan_outputs,
        "scanner_rule_timeout_ms": settings.scanner_rule_timeout_ms,
        "stream_scan_window_chars": settings.stream_scan_window_chars,
        "stream_hold_back_frames": settings.stream_hold_back_frames,
        "semantic_scanner": {
            "enabled": bool(settings.semantic_scanner_url),
            "url": _redact_url(settings.semantic_scanner_url),
            "timeout_seconds": settings.semantic_scanner_timeout_seconds,
        },
        "semantic_local": {
            "enabled": settings.semantic_local_enabled,
            "model_path": _secret_state(str(settings.semantic_local_model_path)),
            "tokenizer_path": _secret_state(str(settings.semantic_local_tokenizer_path)),
            "threshold": settings.semantic_local_threshold,
            "action": settings.semantic_local_action,
            "max_chars": settings.semantic_local_max_chars,
            "timeout_seconds": settings.semantic_local_timeout_seconds,
        },
        "allow_unscanned_generation_passthrough": settings.allow_unscanned_generation_passthrough,
        "audit": {
            "sink": settings.audit_sink,
            "log_path": str(settings.audit_log_path),
            "rotate_max_bytes": settings.audit_rotate_max_bytes,
            "rotate_backups": settings.audit_rotate_backups,
            "http": {
                "url": _redact_url(settings.audit_http_url),
                "timeout_seconds": settings.audit_http_timeout_seconds,
                "queue_size": settings.audit_http_queue_size,
                "bearer_token": _secret_state(settings.audit_http_bearer_token),
            },
        },
    }


def _secret_state(value: str) -> str:
    return "<set>" if str(value).strip() else "<unset>"


def _redact_url(value: str) -> str:
    if not value:
        return "<unset>"
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<set>"
    if not parsed.netloc:
        return value
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    netloc = f"<redacted>@{host}{port}" if parsed.username or parsed.password else f"{host}{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))


def _join_payload_text(segments: list[PayloadTextSegment]) -> str:
    return "\n".join(segment.text for segment in segments if segment.text)


def _request_scan_text(segments: list[PayloadTextSegment], policy: RoutePolicy) -> str:
    return "\n".join(segment.text for segment in segments if segment.text and _segment_scanned(segment, policy))


def _segment_scanned(segment: PayloadTextSegment, policy: RoutePolicy) -> bool:
    if segment.kind == "tool_call_arguments":
        return policy.scan_tool_arguments
    if segment.kind == "tool_result":
        return policy.scan_tool_results
    return True


def _payload_segment_summary(segments: list[PayloadTextSegment], policy: RoutePolicy) -> dict[str, Any]:
    by_kind = Counter(segment.kind for segment in segments if segment.kind)
    by_role = Counter(segment.role or "unknown" for segment in segments)
    scanned_by_kind = Counter(segment.kind for segment in segments if segment.kind and _segment_scanned(segment, policy))
    return {
        "total": len(segments),
        "scanned": sum(scanned_by_kind.values()),
        "by_kind": dict(sorted(by_kind.items())),
        "by_role": dict(sorted(by_role.items())),
        "scanned_by_kind": dict(sorted(scanned_by_kind.items())),
    }


async def _scan_input_segments_safely(
    segments: list[PayloadTextSegment],
    policy: RoutePolicy,
    event: dict[str, Any],
) -> ScanResult | None:
    scannable_segments = [segment for segment in segments if segment.text and _segment_scanned(segment, policy)]
    joined_text = _join_payload_text(scannable_segments)
    seen: set[tuple[str, str, str, str]] = set()
    results: list[ScanResult] = []

    try:
        for segment in scannable_segments:
            segment_result = scanner.scan_input(segment.text, policy.disabled_rules, policy.disabled_categories)
            results.append(_dedupe_against_seen(_tag_segment_result(segment_result, segment), seen))

        if len(scannable_segments) > 1:
            joined_result = scanner.scan_input(joined_text, policy.disabled_rules, policy.disabled_categories)
            results.append(_dedupe_against_seen(_tag_joined_result(joined_result), seen))
    except Exception as exc:
        _record_scanner_error(event, exc)
        return None

    combined = merge_scan_results(ScanResult(), *results)
    return await _merge_semantic_scans(combined, "input", joined_text, event)


def _tag_segment_result(result: ScanResult, segment: PayloadTextSegment) -> ScanResult:
    tags = _segment_tags(segment)
    return ScanResult(
        findings=[
            replace(
                finding,
                source=_segment_source(segment, finding.source),
                tags=tuple(dict.fromkeys((*finding.tags, *tags))),
            )
            for finding in result.findings
        ],
        redacted_text=result.redacted_text,
    )


def _tag_joined_result(result: ScanResult) -> ScanResult:
    return ScanResult(
        findings=[
            replace(
                finding,
                source="request_joined" if finding.source == "plain" else f"request_joined:{finding.source}",
                tags=tuple(dict.fromkeys((*finding.tags, "segment:request_joined"))),
            )
            for finding in result.findings
        ],
        redacted_text=result.redacted_text,
    )


def _segment_source(segment: PayloadTextSegment, original_source: str) -> str:
    source = "tool_call" if segment.kind == "tool_call_arguments" else segment.kind
    if original_source == "plain":
        return source
    return f"{source}:{original_source}"


def _segment_tags(segment: PayloadTextSegment) -> tuple[str, ...]:
    tags = [f"segment:{segment.kind}"]
    if segment.role:
        tags.append(f"role:{segment.role}")
    return tuple(tags)


def _dedupe_against_seen(result: ScanResult, seen: set[tuple[str, str, str, str]]) -> ScanResult:
    findings: list[Finding] = []
    for finding in result.findings:
        key = (finding.rule_id, finding.category, finding.action, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
    return ScanResult(findings=findings, redacted_text=result.redacted_text)


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
    by_source: Counter[str] = Counter()

    for finding in findings:
        category = str(finding.get("category", "unknown") or "unknown")
        severity = str(finding.get("severity", "unknown") or "unknown")
        action = str(finding.get("action", "unknown") or "unknown")
        source = str(finding.get("source", "unknown") or "unknown")
        by_category[category] += 1
        by_severity[severity] += 1
        by_action[action] += 1
        by_source[source] += 1

    return {
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "by_action": dict(by_action),
        "by_source": dict(by_source),
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
