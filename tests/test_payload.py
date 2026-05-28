import unittest

from app.security.payload import extract_request_text, redact_request_body
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
                    "tool_calls": [
                        {"function": {"arguments": "{\"email\":\"test@example.com\"}"}}
                    ],
                },
            ]
        }
        text = extract_request_text(body)
        self.assertIn("hello", text)
        self.assertIn("test@example.com", text)

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


if __name__ == "__main__":
    unittest.main()

