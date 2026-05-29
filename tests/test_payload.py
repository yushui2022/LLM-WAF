import unittest

from app.security.payload import (
    extract_request_segments,
    extract_request_text,
    extract_response_segments,
    extract_response_text,
    extract_usage,
    redact_request_body,
    redact_response_body,
    redact_sse_json_payload,
)
from app.security.scanner import SecurityScanner


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SecurityScanner()

    def test_extracts_message_and_tool_call_arguments(self):
        body = {
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "tool_calls": [{"function": {"arguments": '{"email":"test@example.com"}'}}],
                },
            ]
        }
        text = extract_request_text(body)
        self.assertIn("hello", text)
        self.assertIn("test@example.com", text)

    def test_extracts_request_segments_with_source_labels(self):
        body = {
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "tool",
                    "content": [{"type": "text", "text": "search result says hi"}],
                },
                {
                    "role": "assistant",
                    "tool_calls": [{"function": {"arguments": '{"email":"test@example.com"}'}}],
                },
            ]
        }

        segments = extract_request_segments(body)

        self.assertEqual(
            [(segment.kind, segment.role, segment.path) for segment in segments],
            [
                ("message_content", "user", "messages[0].content"),
                ("tool_result", "tool", "messages[1].content[0].text"),
                ("tool_call_arguments", "assistant", "messages[2].tool_calls[0].function.arguments"),
            ],
        )

    def test_redacts_string_and_multimodal_text_content(self):
        body = {
            "messages": [
                {"role": "user", "content": "email test@example.com"},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "phone 13800138000"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
                    ],
                },
            ]
        }
        redacted = redact_request_body(body, self.scanner.redact_sensitive)
        self.assertEqual(redacted["messages"][0]["content"], "email [REDACTED:email]")
        self.assertEqual(redacted["messages"][1]["content"][0]["text"], "phone [REDACTED:cn_mobile]")
        self.assertEqual(redacted["messages"][1]["content"][1]["type"], "image_url")

    def test_extracts_usage_tokens(self):
        usage = extract_usage(
            {
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 7,
                    "total_tokens": "19",
                    "ignored": "value",
                }
            }
        )
        self.assertEqual(usage, {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19})

    def test_extracts_response_tool_call_arguments(self):
        body = {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "send_email", "arguments": '{"email":"test@example.com"}'}}]}}]
        }
        self.assertIn("test@example.com", extract_response_text(body))

    def test_extracts_response_segments_with_source_labels(self):
        body = {
            "choices": [
                {
                    "delta": {
                        "role": "assistant",
                        "content": "hello",
                        "tool_calls": [{"function": {"name": "send_email", "arguments": '{"email":"test@example.com"}'}}],
                    }
                }
            ]
        }

        segments = extract_response_segments(body)

        self.assertEqual(
            [(segment.kind, segment.role, segment.path) for segment in segments],
            [
                ("response_delta", "assistant", "choices[0].delta.content"),
                ("response_delta_tool_call_arguments", "assistant", "choices[0].delta.tool_calls[0].function.arguments"),
            ],
        )

    def test_redacts_response_tool_call_arguments(self):
        body = {
            "choices": [{"message": {"tool_calls": [{"function": {"name": "send_email", "arguments": '{"email":"test@example.com"}'}}]}}]
        }
        redacted = redact_response_body(body, self.scanner.redact_output)
        arguments = redacted["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertIn("[REDACTED:email]", arguments)

    def test_redacts_streaming_tool_call_arguments(self):
        payload = {
            "choices": [{"delta": {"tool_calls": [{"function": {"name": "send_email", "arguments": '{"email":"test@example.com"}'}}]}}]
        }
        redacted, changed = redact_sse_json_payload(payload, self.scanner.redact_output)
        arguments = redacted["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
        self.assertTrue(changed)
        self.assertIn("[REDACTED:email]", arguments)


if __name__ == "__main__":
    unittest.main()
