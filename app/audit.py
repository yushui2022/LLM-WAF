"""Audit sinks."""

from __future__ import annotations

import json
import queue
import sys
import threading
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any, Callable, Protocol, TextIO


class AuditSink(Protocol):
    def append(self, event: dict[str, Any]) -> None: ...

    def tail(self, limit: int = 50) -> list[dict[str, Any]]: ...


class FileAuditSink:
    def __init__(self, path: Path, rotate_max_bytes: int = 10_000_000, rotate_backups: int = 5):
        self.path = path
        self.rotate_max_bytes = max(0, rotate_max_bytes)
        self.rotate_backups = max(0, rotate_backups)
        self._lock = threading.Lock()

    def append(self, event: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._rotate_if_needed(len(line.encode("utf-8")) + 1)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        lines: list[str] = []
        for path in self._tail_paths():
            if not path.exists():
                continue
            try:
                lines.extend(path.read_text(encoding="utf-8").splitlines())
            except OSError:
                continue

        events: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def _rotate_if_needed(self, next_line_bytes: int) -> None:
        if self.rotate_max_bytes <= 0 or self.rotate_backups <= 0:
            return
        if not self.path.exists():
            return
        try:
            current_size = self.path.stat().st_size
        except OSError:
            return
        if current_size + next_line_bytes <= self.rotate_max_bytes:
            return

        oldest = self._backup_path(self.rotate_backups)
        if oldest.exists():
            oldest.unlink()

        for index in range(self.rotate_backups - 1, 0, -1):
            source = self._backup_path(index)
            if source.exists():
                source.replace(self._backup_path(index + 1))

        self.path.replace(self._backup_path(1))

    def _tail_paths(self) -> list[Path]:
        backups = [self._backup_path(index) for index in range(self.rotate_backups, 0, -1)]
        return [*backups, self.path]

    def _backup_path(self, index: int) -> Path:
        return Path(f"{self.path}.{index}")


class StdoutAuditSink:
    def __init__(self, stream: TextIO | None = None, max_recent: int = 1000):
        self.stream = stream if stream is not None else sys.stdout
        self._recent: deque[dict[str, Any]] = deque(maxlen=max(0, max_recent))
        self._lock = threading.Lock()

    def append(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        recent_event: dict[str, Any] = json.loads(line)
        with self._lock:
            self.stream.write(line + "\n")
            self.stream.flush()
            self._recent.append(recent_event)

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        with self._lock:
            return list(self._recent)[-limit:]


class HttpAuditSink:
    def __init__(
        self,
        url: str,
        timeout_seconds: float = 2.0,
        queue_size: int = 1000,
        bearer_token: str = "",
        max_recent: int = 1000,
        sender: Callable[[str], None] | None = None,
        start_worker: bool = True,
    ):
        if not url.strip():
            raise ValueError("AUDIT_HTTP_URL is required when AUDIT_SINK=http.")
        self.url = url
        self.timeout_seconds = max(0.1, timeout_seconds)
        self.bearer_token = bearer_token
        self._queue: queue.Queue[str] = queue.Queue(maxsize=max(1, queue_size))
        self._recent: deque[dict[str, Any]] = deque(maxlen=max(0, max_recent))
        self._lock = threading.Lock()
        self._dropped_count = 0
        self._failed_count = 0
        self._sender = sender if sender is not None else self._post
        if start_worker:
            self._worker = threading.Thread(target=self._run, name="llm-waf-audit-http", daemon=True)
            self._worker.start()

    @property
    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped_count

    @property
    def failed_count(self) -> int:
        with self._lock:
            return self._failed_count

    def append(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        recent_event: dict[str, Any] = json.loads(line)
        with self._lock:
            self._recent.append(recent_event)
        try:
            self._queue.put_nowait(line)
        except queue.Full:
            with self._lock:
                self._dropped_count += 1

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        with self._lock:
            return list(self._recent)[-limit:]

    def _run(self) -> None:
        while True:
            line = self._queue.get()
            try:
                self._sender(line)
            except Exception:
                with self._lock:
                    self._failed_count += 1
            finally:
                self._queue.task_done()

    def _post(self, line: str) -> None:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "LLM-WAF",
        }
        if self.bearer_token.strip():
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        request = urllib.request.Request(
            self.url,
            data=line.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds):
            return


def create_audit_sink(
    sink: str,
    path: Path,
    rotate_max_bytes: int = 10_000_000,
    rotate_backups: int = 5,
    http_url: str = "",
    http_timeout_seconds: float = 2.0,
    http_queue_size: int = 1000,
    http_bearer_token: str = "",
) -> AuditSink:
    normalized = sink.strip().lower()
    if normalized == "file":
        return FileAuditSink(path, rotate_max_bytes, rotate_backups)
    if normalized == "stdout":
        return StdoutAuditSink()
    if normalized == "http":
        return HttpAuditSink(http_url, http_timeout_seconds, http_queue_size, http_bearer_token)
    raise ValueError(f"Unsupported AUDIT_SINK {sink!r}; expected 'file', 'stdout', or 'http'.")


AuditLog = FileAuditSink
