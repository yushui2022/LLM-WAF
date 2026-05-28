# Protocol Support

LLM-WAF is currently an OpenAI-compatible LLM firewall. Its strongest WAF behavior is implemented around the OpenAI chat completions request and response shape.

This document is intentionally explicit so users do not assume native protocol coverage that does not exist yet.

## Support Matrix

| Protocol / Route | Status | WAF Coverage |
|---|---|---|
| OpenAI-compatible `POST /v1/chat/completions` | Supported | Input scan, input redaction, tool-call argument scan, output scan, output redaction, streaming scan, audit. |
| OpenAI-compatible `POST /v1/chat/completions` with SSE streaming | Supported | Rolling-window scan by default; optional `STREAM_HOLD_BACK_FRAMES` for stricter cross-frame redaction. |
| OpenAI-compatible `/v1/*` non-chat routes | Passthrough | Auth, rate limit, and audit only. Request/response WAF scanning is not applied to generic passthrough routes. |
| Anthropic native `/v1/messages` | Not supported natively | Use an OpenAI-compatible endpoint or adapter in front of LLM-WAF for now. |
| Gemini native `generateContent` / `streamGenerateContent` | Not supported natively | Use an OpenAI-compatible endpoint or adapter in front of LLM-WAF for now. |

## What "OpenAI-Compatible" Means Here

The gateway expects chat request bodies with fields such as:

- `messages[].content`
- `messages[].tool_calls[].function.arguments`
- `stream`

It scans response bodies or SSE payloads with fields such as:

- `choices[].message.content`
- `choices[].message.tool_calls[].function.arguments`
- `choices[].delta.content`
- `choices[].delta.tool_calls[].function.arguments`
- `usage`

Providers are compatible when they use this shape closely enough that these extractors work.

## Native Adapter Requirements

Native protocol support should not be added as a thin blind proxy. Each native adapter needs protocol-specific WAF extraction and tests:

1. Request text extraction for user, system, tool, and multimodal text fields.
2. Request redaction that preserves provider schema.
3. Output text extraction for normal and streaming responses.
4. Output redaction that preserves provider schema.
5. Tool-call or tool-use argument extraction.
6. Streaming fixtures that prove cross-frame findings are still handled.
7. Audit fields that identify the protocol and provider.

Until those requirements are met, native support should stay marked as not supported.

## Recommended Upgrade Path

1. Keep the current OpenAI-compatible WAF path strict and well-tested.
2. Split payload extraction into protocol-specific modules, for example `openai_compat`, `anthropic`, and `gemini`.
3. Add fixture-based conformance tests before enabling any native route.
4. Add native Anthropic `/v1/messages` after the extractor layer is stable.
5. Add native Gemini after Anthropic proves the adapter pattern.

This keeps the project focused on firewall correctness instead of becoming a generic provider router.
