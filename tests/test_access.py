import unittest
from collections import defaultdict

from app.access import GatewayAuth, InMemoryRateLimiter, RedisRateLimiter, create_rate_limiter


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

    def test_redis_limiter_shares_state_across_instances(self):
        client = FakeRedis()
        first = RedisRateLimiter(2, "redis://localhost:6379/0", client=client)
        second = RedisRateLimiter(2, "redis://localhost:6379/0", client=client)
        self.assertTrue(first.check("key:a").allowed)
        self.assertTrue(second.check("key:a").allowed)
        third = second.check("key:a")
        self.assertFalse(third.allowed)
        self.assertEqual(third.backend, "redis")

    def test_create_rate_limiter_requires_redis_url(self):
        with self.assertRaises(ValueError):
            create_rate_limiter(10, backend="redis", redis_url="")


class FakeRedis:
    def __init__(self):
        self.values = defaultdict(int)
        self.expirations = {}

    def incr(self, key: str) -> int:
        self.values[key] += 1
        return self.values[key]

    def expire(self, key: str, seconds: int) -> None:
        self.expirations[key] = seconds


if __name__ == "__main__":
    unittest.main()
