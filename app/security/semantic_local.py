"""Optional local semantic prompt-injection scanner.

The default gateway stays deterministic and dependency-light. This module is
loaded only when SEMANTIC_LOCAL=true, and heavy ML dependencies are imported
only on first scan.
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.security.models import Finding, ScanResult


class SemanticScoreModel(Protocol):
    def score(self, text: str) -> float:
        """Return a prompt-injection probability in [0, 1]."""


@dataclass(frozen=True)
class LocalSemanticConfig:
    model_path: Path
    tokenizer_path: Path
    threshold: float = 0.85
    action: str = "log_only"
    max_chars: int = 4000
    timeout_seconds: float = 2.0


class LocalSemanticScanner:
    def __init__(self, config: LocalSemanticConfig, model: SemanticScoreModel | None = None):
        self.config = config
        self._model = model

    async def scan_input(self, text: str) -> ScanResult:
        return await self._scan("input", text)

    async def scan_output(self, text: str) -> ScanResult:
        return await self._scan("output", text)

    async def _scan(self, direction: str, text: str) -> ScanResult:
        sample = text[: max(0, self.config.max_chars)]
        if not sample:
            return ScanResult()

        score = await asyncio.wait_for(
            asyncio.to_thread(self._score, sample),
            timeout=max(0.001, self.config.timeout_seconds),
        )
        if score < self.config.threshold:
            return ScanResult()

        action = self._action(direction)
        return ScanResult(
            findings=[
                Finding(
                    rule_id="semantic.prompt_injection.local",
                    category="prompt_injection",
                    severity=_severity(score),
                    action=action,
                    source="semantic_local",
                    evidence=_evidence(sample),
                    description="Local semantic scanner detected prompt-injection-like text.",
                    tags=("semantic", "local", direction),
                )
            ]
        )

    def _score(self, text: str) -> float:
        model = self._model
        if model is None:
            model = OnnxPromptInjectionModel(self.config.model_path, self.config.tokenizer_path)
            self._model = model
        return _clamp_probability(model.score(text))

    def _action(self, direction: str) -> str:
        configured = self.config.action.strip().lower()
        if direction == "input" and configured == "block":
            return "block"
        return "log_only"


class OnnxPromptInjectionModel:
    """Small ONNX binary classifier adapter.

    Expected model shape: tokenized text inputs named like Hugging Face exports
    (`input_ids`, `attention_mask`, optional `token_type_ids`) and one logits or
    probability output where the positive class is index 1.
    """

    def __init__(self, model_path: Path, tokenizer_path: Path):
        if not _path_configured(model_path):
            raise RuntimeError("SEMANTIC_LOCAL_MODEL_PATH is required when SEMANTIC_LOCAL=true.")
        if not _path_configured(tokenizer_path):
            raise RuntimeError("SEMANTIC_LOCAL_TOKENIZER_PATH is required when SEMANTIC_LOCAL=true.")

        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise RuntimeError('Local semantic scanning requires `pip install "llm-waf[semantic]"`.') from exc

        self._np = np
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        self._session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        self._input_names = {item.name for item in self._session.get_inputs()}

    def score(self, text: str) -> float:
        encoded = self._tokenizer.encode(text)
        inputs: dict[str, Any] = {}
        if "input_ids" in self._input_names:
            inputs["input_ids"] = self._np.asarray([encoded.ids], dtype=self._np.int64)
        if "attention_mask" in self._input_names:
            inputs["attention_mask"] = self._np.asarray([encoded.attention_mask], dtype=self._np.int64)
        if "token_type_ids" in self._input_names:
            inputs["token_type_ids"] = self._np.asarray([encoded.type_ids], dtype=self._np.int64)

        outputs = self._session.run(None, inputs)
        return _score_from_output(outputs[0])


def _score_from_output(output: Any) -> float:
    values = [float(value) for value in getattr(output, "flatten", lambda: output)()]
    if not values:
        return 0.0
    if len(values) == 1:
        value = values[0]
        return _clamp_probability(value if 0.0 <= value <= 1.0 else _sigmoid(value))
    return _softmax_positive(values)


def _path_configured(path: Path) -> bool:
    value = str(path).strip()
    return bool(value) and value != "."


def _softmax_positive(values: list[float]) -> float:
    shifted = [value - max(values) for value in values]
    exp_values = [math.exp(value) for value in shifted]
    total = sum(exp_values)
    if total <= 0:
        return 0.0
    return _clamp_probability(exp_values[min(1, len(exp_values) - 1)] / total)


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1 / (1 + z)
    z = math.exp(value)
    return z / (1 + z)


def _severity(score: float) -> str:
    if score >= 0.95:
        return "high"
    if score >= 0.85:
        return "medium"
    return "low"


def _clamp_probability(value: float) -> float:
    if math.isnan(value) or value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def _evidence(text: str, limit: int = 120) -> str:
    compact = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
