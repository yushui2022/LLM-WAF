"""Audit sinks."""

from __future__ import annotations

import json
import sys
import threading
from collections import deque
from pathlib import Path
from typing import Any, Protocol, TextIO


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


def create_audit_sink(
    sink: str,
    path: Path,
    rotate_max_bytes: int = 10_000_000,
    rotate_backups: int = 5,
) -> AuditSink:
    normalized = sink.strip().lower()
    if normalized == "file":
        return FileAuditSink(path, rotate_max_bytes, rotate_backups)
    if normalized == "stdout":
        return StdoutAuditSink()
    raise ValueError(f"Unsupported AUDIT_SINK {sink!r}; expected 'file' or 'stdout'.")


AuditLog = FileAuditSink
