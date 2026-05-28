import unittest

from app.access import GatewayAuth, InMemoryRateLimiter


class GatewayAuthTests(unittest.TestCase):
    def test_disabled_auth_allows_anonymous(self):
        auth = GatewayAuth(())
        result = auth.authenticate_headers({})
        self.assertTrue(result.allowed)
        self.assertEqual(result.principal, "anonymous")

    def test_header_key_authenticates(self):
        auth = GatewayAuth(("secret-key",), "X-LLM-WAF-Key")
        result = auth.authenticate_headers({"X-LLM-WAF-Key": "secret-key"})
        self.assertTrue(result.allowed)
        self.assertTrue(result.principal.startswith("key:"))
        self.assertEqual(result.method, "x-llm-waf-key")

    def test_authorization_bearer_authenticates(self):
        auth = GatewayAuth(("secret-key",), "X-LLM-WAF-Key")
        result = auth.authenticate_headers({"Authorization": "Bearer secret-key"})
        self.assertTrue(result.allowed)
        self.assertTrue(result.used_authorization_header)

    def test_invalid_key_is_rejected(self):
        auth = GatewayAuth(("secret-key",), "X-LLM-WAF-Key")
        result = auth.authenticate_headers({"X-LLM-WAF-Key": "wrong"})
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "missing_or_invalid_gateway_api_key")


class RateLimiterTests(unittest.TestCase):
    def test_disabled_limiter_allows(self):
        limiter = InMemoryRateLimiter(0)
        self.assertTrue(limiter.check("anonymous").allowed)

    def test_limiter_rejects_after_limit(self):
        limiter = InMemoryRateLimiter(2, window_seconds=60)
        self.assertTrue(limiter.check("key:a").allowed)
        self.assertTrue(limiter.check("key:a").allowed)
        third = limiter.check("key:a")
        self.assertFalse(third.allowed)
        self.assertGreaterEqual(third.retry_after_seconds, 1)


if __name__ == "__main__":
    unittest.main()

