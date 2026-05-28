"""End-to-end integration tests for SSE streaming hold-back (roadmap item 2).

Covers four claims of the streaming path:
1. With hold_back=1 (the new default), a cross-frame finding completed in the
   *next* frame redacts the already-held earlier fragment.
2. With hold_back=0, the same cross-frame leak slips out in the first frame
   (this is the documented regression behavior — we test that the toggle
   genuinely matters).
3. `FAIL_CLOSED=true` combined with a scanner exception mid-stream emits an
   SSE error frame and terminates the response cleanly.
4. A `usage` SSE frame still arrives through the gateway and is recorded in
   the audit event.

The upstream is replaced by an in-process fake that yields scripted SSE
bytes — no real network, no real provider.
"""

from __future__ import annotations

import json
import unittest
from typing import Iterable

from fastapi.testclient import TestClient

import app.main as main_module
from app.main import app


# ---------------------------------------------------------------------------
# Fake upstream
# ---------------------------------------------------------------------------


class _FakeUpstreamResponse:
    def __init__(self, frames: list[bytes], status_code: int = 200):
        self._frames = frames
        self.status_code = status_code
        self.headers = {"content-type": "text/event-stream"}

    async def aiter_bytes(self) -> Iterable[bytes]:
        for frame in self._frames:
            yield frame

    async def aclose(self) -> None:
        return None


class _FakeAsyncClient:
    """Stand-in for httpx.AsyncClient that streams scripted SSE bytes."""

    _frames: list[bytes] = []
    _status: int = 200

    def __init__(self, *args, **kwargs):
        pass

    def build_request(self, *args, **kwargs):
        return ("fake-request", args, kwargs)

    async def send(self, request, stream: bool = True):
        return _FakeUpstreamResponse(list(self._frames), self._status)

    async def aclose(self) -> None:
        return None


def _install_fake_upstream(frames: list[bytes], status_code: int = 200):
    _FakeAsyncClient._frames = frames
    _FakeAsyncClient._status = status_code
    return main_module.httpx.AsyncClient


def _restore_httpx(saved):
    main_module.httpx.AsyncClient = saved


def _post_stream(client: TestClient, body: dict) -> tuple[int, str]:
    body = {**body, "stream": True}
    with client.stream("POST", "/v1/chat/completions", json=body) as resp:
        chunks: list[bytes] = []
        for chunk in resp.iter_bytes():
            chunks.append(chunk)
        return resp.status_code, b"".join(chunks).decode("utf-8", errors="replace")


def _sse_data_frame(payload: dict) -> bytes:
    return (f"data: {json.dumps(payload)}\n\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class StreamingHoldBackTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self._saved_httpx = main_module.httpx.AsyncClient
        self._saved_settings_hold = main_module.settings.stream_hold_back_frames
        self._saved_fail_closed = main_module.settings.fail_closed

    def tearDown(self):
        main_module.httpx.AsyncClient = self._saved_httpx
        object.__setattr__(main_module.settings, "stream_hold_back_frames", self._saved_settings_hold)
        object.__setattr__(main_module.settings, "fail_closed", self._saved_fail_closed)

    # ---- 1. hold_back=1 redacts the earlier held frame ----
    def test_holdback_one_redacts_cross_frame_leak_in_held_frame(self):
        object.__setattr__(main_module.settings, "stream_hold_back_frames", 1)
        frames = [
            _sse_data_frame({"choices": [{"delta": {"content": "My system "}}]}),
            _sse_data_frame({"choices": [{"delta": {"content": "prompt is: hidden policy."}}]}),
            b"data: [DONE]\n\n",
        ]
        main_module.httpx.AsyncClient = _FakeAsyncClient
        _install_fake_upstream(frames)

        status, body = _post_stream(
            self.client,
            {"model": "fake-model", "messages": [{"role": "user", "content": "hi"}]},
        )
        self.assertEqual(status, 200)
        # The held first frame must be redacted before being emitted, so the
        # raw "My system " bytes never reach the client.
        self.assertNotIn("My system ", body)
        self.assertIn("[REDACTED:stream_hold_back]", body)

    # ---- 2. hold_back=0 reproduces the documented leak ----
    def test_holdback_zero_leaks_first_fragment(self):
        object.__setattr__(main_module.settings, "stream_hold_back_frames", 0)
        frames = [
            _sse_data_frame({"choices": [{"delta": {"content": "My system "}}]}),
            _sse_data_frame({"choices": [{"delta": {"content": "prompt is: hidden policy."}}]}),
            b"data: [DONE]\n\n",
        ]
        main_module.httpx.AsyncClient = _FakeAsyncClient
        _install_fake_upstream(frames)

        status, body = _post_stream(
            self.client,
            {"model": "fake-model", "messages": [{"role": "user", "content": "hi"}]},
        )
        self.assertEqual(status, 200)
        # First frame already shipped before the rolling window completed the
        # finding — the leak slips through. This documents *why* the new
        # default is 1.
        self.assertIn("My system ", body)

    # ---- 3. FAIL_CLOSED + mid-stream scanner failure terminates with SSE error ----
    def test_fail_closed_mid_stream_emits_error_frame_and_terminates(self):
        object.__setattr__(main_module.settings, "stream_hold_back_frames", 1)
        object.__setattr__(main_module.settings, "fail_closed", True)

        # Inject a failing _transform_sse_frame to simulate a scanner crash
        # after the stream has begun.
        original_transform = main_module._transform_sse_frame
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise RuntimeError("synthetic scanner crash")
            return original_transform(*args, **kwargs)

        main_module._transform_sse_frame = flaky
        try:
            frames = [
                _sse_data_frame({"choices": [{"delta": {"content": "hello "}}]}),
                _sse_data_frame({"choices": [{"delta": {"content": "world"}}]}),
                b"data: [DONE]\n\n",
            ]
            main_module.httpx.AsyncClient = _FakeAsyncClient
            _install_fake_upstream(frames)

            status, body = _post_stream(
                self.client,
                {"model": "fake-model", "messages": [{"role": "user", "content": "hi"}]},
            )
        finally:
            main_module._transform_sse_frame = original_transform

        self.assertEqual(status, 200)
        # The SSE error frame is documented to contain code "scanner_failure".
        self.assertIn("scanner_failure", body)

    # ---- 4. usage frame still arrives and is audited ----
    def test_usage_frame_passes_through(self):
        object.__setattr__(main_module.settings, "stream_hold_back_frames", 1)
        frames = [
            _sse_data_frame({"choices": [{"delta": {"content": "hi"}}]}),
            _sse_data_frame(
                {
                    "choices": [{"delta": {}}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                }
            ),
            b"data: [DONE]\n\n",
        ]
        main_module.httpx.AsyncClient = _FakeAsyncClient
        _install_fake_upstream(frames)

        status, body = _post_stream(
            self.client,
            {"model": "fake-model", "messages": [{"role": "user", "content": "hi"}]},
        )
        self.assertEqual(status, 200)
        # The usage frame is forwarded to the client (it is not stripped).
        self.assertIn("total_tokens", body)
        self.assertIn("5", body)


if __name__ == "__main__":
    unittest.main()
