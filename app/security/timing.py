"""Per-rule regex timeout helper.

Important caveat: CPython cannot interrupt a running `re` C-level call, and
`re.search`/`re.finditer` typically do not release the GIL for short inputs.
That means a runaway regex on a small adversarial string can still block the
worker thread for the full duration of its backtracking, regardless of any
Python-level timeout. We use `threading.Thread.join(timeout)` here as an
advisory safeguard that catches regexes long enough to release the GIL (large
inputs), and as a structural seam where a future migration to `regex` (with
its `timeout` argument) or `google/re2` can plug in.

The primary ReDoS defense is therefore *pattern hygiene* — see
`app/security/rules.py` for the tightened `[^\\n]{0,N}` patterns and the
`_DOTALL_RULE_IDS` whitelist. This helper is the second line of defense.
"""

from __future__ import annotations

import os
import threading
from typing import Callable, TypeVar

T = TypeVar("T")

TIMEOUT_SENTINEL: object = object()


def _env_timeout_ms() -> int:
    raw = os.getenv("SCANNER_RULE_TIMEOUT_MS")
    if raw is None:
        return 50
    try:
        value = int(raw)
    except ValueError:
        return 50
    return value if value > 0 else 0


def run_with_timeout(fn: Callable[[], T], timeout_ms: int | None = None) -> T | object:
    """Run `fn` with a wall-clock deadline.

    Returns the function's result, or `TIMEOUT_SENTINEL` if the deadline
    elapsed first. A non-positive `timeout_ms` disables the deadline and the
    function runs to completion on the calling thread.
    """

    effective_ms = _env_timeout_ms() if timeout_ms is None else timeout_ms
    if effective_ms <= 0:
        return fn()

    result: list[T] = []
    error: list[BaseException] = []

    def _runner() -> None:
        try:
            result.append(fn())
        except BaseException as exc:  # noqa: BLE001 - propagate after join
            error.append(exc)

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join(timeout=effective_ms / 1000.0)
    if thread.is_alive():
        return TIMEOUT_SENTINEL
    if error:
        raise error[0]
    return result[0]
