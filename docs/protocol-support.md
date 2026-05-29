# Protocol Support

LLM-WAF is primarily an OpenAI-compatible LLM firewall. Its strongest WAF behavior is implemented around the OpenAI chat completions request and response shape, with native Anthropic Messages support for streaming and non-streaming requests.

This document is intentionally explicit so users do not assume native protocol coverage that does not exist yet.

## Support Matrix

| Protocol / Route | Status | WAF Coverage |
|---|---|---|
| OpenAI-compatible `POST /v1/chat/completions` | Supported | Input scan, input redaction, tool-result scan, tool-call argument scan, output scan, output redaction, streaming scan, audit. This covers OpenAI-compatible providers such as OpenAI, DeepSeek, Moonshot, Groq, Ollama, and vLLM. |
| OpenAI-compatible `POST /v1/chat/completions` with SSE streaming | Supported | Rolling-window scan + one-frame hold-back by default (`STREAM_HOLD_BACK_FRAMES=1`); raise for stricter cross-frame redaction, set `0` for lowest first-token latency. |
| OpenAI-compatible `/v1/*` non-chat routes | Passthrough | Safe non-generation routes get auth, rate limit, and audit only. Request/response WAF scanning is not applied to generic passthrough routes. |
| Anthropic native `POST /v1/messages` with `stream=false` | Supported | Input scan, input redaction, `system` text scan, `tool_result` scan, `tool_use.input` scan, output scan, output redaction, usage extraction, Anthropic header forwarding, and audit with `protocol=anthropic_native`. |
| Anthropic native `POST /v1/messages` with `stream=true` | Supported | Protocol-specific SSE/event transformation for `content_block_delta` text, thinking, and `input_json_delta.partial_json`; rolling-window scan + one-frame hold-back by default; `message_start` / `message_delta` usage extraction; Anthropic header forwarding; audit with `protocol=anthropic_native`. |
| OpenAI `/v1/responses` and legacy `/v1/completions` | Blocked by default | Not scanned by the current chat-completions WAF path. |
| Gemini native `generateContent` / `streamGenerateContent` | Not supported natively | Use an OpenAI-compatible endpoint or adapter in front of LLM-WAF for now. |

## What "OpenAI-Compatible" Means Here

The gateway expects chat request bodies with fields such as:

- `messages[].content`
- `messages[].tool_calls[].function.arguments`
- `messages[]` with `role: tool` (labeled as tool-result text)
- `stream`

It scans response bodies or SSE payloads with fields such as:

- `choices[].message.content`
- `choices[].message.tool_calls[].function.arguments`
- `choices[].delta.content`
- `choices[].delta.tool_calls[].function.arguments`
- `usage`

Providers are compatible when they use this shape closely enough that these extractors work.

DeepSeek is handled through this OpenAI-compatible path. There is no separate DeepSeek-native adapter because the practical integration surface is the OpenAI-compatible `/v1/chat/completions` schema.

`UPSTREAM_BASE_URL` may be either SDK-style with `/v1` (`https://api.openai.com/v1`) or origin-style without `/v1` (`https://api.deepseek.com`). LLM-WAF avoids duplicating `/v1` when the upstream base URL already ends with that version segment.

## Native Adapter Requirements

Native protocol support should not be added as a thin blind proxy. Each native adapter needs protocol-specific WAF extraction and tests:

1. Request text extraction for user, system, tool, and multimodal text fields.
2. Request redaction that preserves provider schema.
3. Output text extraction for normal and streaming responses.
4. Output redaction that preserves provider schema.
5. Tool-call or tool-use argument extraction.
6. Streaming fixtures that prove cross-frame findings are still handled.
7. Audit fields that identify the protocol and provider.

Until those requirements are met for a route and mode, native support should stay marked as not supported. Anthropic `/v1/messages` now meets this baseline for both buffered and streaming responses.

## Unsupported Generation Route Guard

Known generation routes that are not scanned by the current WAF path return `501 unsupported_protocol` by default:

- `/v1/responses`
- `/v1/completions`

Anthropic native `/v1/messages` is no longer a generic passthrough route: streaming and non-streaming requests are scanned by the Anthropic adapter.

This prevents a dangerous silent failure mode where a native client appears to work through the gateway but bypasses prompt and output scanning.

To intentionally allow raw passthrough, set:

```env
ALLOW_UNSCANNED_GENERATION_PASSTHROUGH=true
```

Use that only for controlled compatibility tests. It is not WAF protection.

## Recommended Upgrade Path

1. Keep the current OpenAI-compatible WAF path strict and well-tested.
2. Split payload extraction into protocol-specific modules, for example `openai_compat`, `anthropic`, and `gemini`.
3. Add fixture-based conformance tests before enabling any native route.
4. Add native Gemini after Anthropic proves the adapter pattern across both buffered and streaming modes.
5. Add OpenAI `/v1/responses` support only after it has route-specific request, response, and streaming fixtures.

This keeps the project focused on firewall correctness instead of becoming a generic provider router.
