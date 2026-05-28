"""Model pricing table and usage cost estimation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


TOKENS_PER_MILLION = 1_000_000


@dataclass(frozen=True)
class ModelPrice:
    name: str
    input_per_1m: float
    output_per_1m: float
    currency: str = "USD"

    def estimate(self, usage: dict[str, int]) -> dict[str, Any]:
        prompt_tokens = _int_value(usage.get("prompt_tokens"))
        completion_tokens = _int_value(usage.get("completion_tokens"))
        total_tokens = _int_value(usage.get("total_tokens")) or (prompt_tokens + completion_tokens)

        input_cost = prompt_tokens * self.input_per_1m / TOKENS_PER_MILLION
        output_cost = completion_tokens * self.output_per_1m / TOKENS_PER_MILLION
        total_cost = input_cost + output_cost

        return {
            "model": self.name,
            "currency": self.currency,
            "input_cost": round(input_cost, 8),
            "output_cost": round(output_cost, 8),
            "total_cost": round(total_cost, 8),
            "total_tokens": total_tokens,
        }


class PricingStore:
    def __init__(self, prices: dict[str, ModelPrice]):
        self.prices = prices

    @classmethod
    def load(cls, path: Path) -> "PricingStore":
        if not path.exists():
            return cls({})

        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        if not isinstance(raw, dict):
            return cls({})

        default_currency = str(raw.get("currency", "USD"))
        models = raw.get("models", {}) or {}
        if not isinstance(models, dict):
            return cls({})

        prices: dict[str, ModelPrice] = {}
        for model_name, item in models.items():
            if not isinstance(item, dict):
                continue
            name = str(model_name).strip()
            if not name:
                continue
            currency = str(item.get("currency", default_currency))
            prices[name.lower()] = ModelPrice(
                name=name,
                input_per_1m=_float_value(item.get("input_per_1m")),
                output_per_1m=_float_value(item.get("output_per_1m")),
                currency=currency,
            )
        return cls(prices)

    def estimate(self, model: str, usage: dict[str, int]) -> dict[str, Any]:
        if not model or not usage:
            return {}

        price = self._find_price(model)
        if price is None:
            return {}
        return price.estimate(usage)

    def _find_price(self, model: str) -> ModelPrice | None:
        normalized = model.lower()
        exact = self.prices.get(normalized)
        if exact is not None:
            return exact

        best: tuple[int, ModelPrice] | None = None
        for pattern, price in self.prices.items():
            if not pattern.endswith("*"):
                continue
            prefix = pattern[:-1]
            if normalized.startswith(prefix) and (best is None or len(prefix) > best[0]):
                best = (len(prefix), price)
        return best[1] if best else None


def _int_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _float_value(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0

