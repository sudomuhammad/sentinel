"""Spend accounting for model API responses, so one dollar cap covers every provider.

Reads token usage from Anthropic Messages and OpenAI Responses bodies, streamed or not.
Standard library only: the proxy container imports this module as-is.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

INPUT_FIELDS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


def price_for(model: str, pricing: dict[str, tuple[float, float]]) -> tuple[float, float] | None:
    """Exact match, or the longest listed name the model starts with (dated snapshots)."""
    if model in pricing:
        return pricing[model]
    prefixes = [name for name in pricing if model.startswith(name + "-")]
    return pricing[max(prefixes, key=len)] if prefixes else None


def _documents(body: str) -> Iterator[dict[str, Any]]:
    """A JSON body, or each `data:` event of a server-sent event stream."""
    stripped = body.lstrip()
    if stripped.startswith("{"):
        yield json.loads(stripped)
        return
    for line in body.splitlines():
        if line.startswith("data:"):
            try:
                event = json.loads(line[5:].strip())
            except ValueError:
                continue  # e.g. "[DONE]"
            if isinstance(event, dict):
                yield event


def _usages(doc: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for holder in (doc, doc.get("message"), doc.get("response")):
        if isinstance(holder, dict) and isinstance(holder.get("usage"), dict):
            yield holder["usage"]


def tokens(body: str) -> tuple[int, int]:
    """(input, output) tokens in a response body.

    Streams report usage more than once and cumulatively, so take the largest figure seen.
    Cache reads count as full-price input, which overstates spend slightly. That's the safe
    direction for a cap.
    """
    input_tokens = output_tokens = 0
    for doc in _documents(body):
        for usage in _usages(doc):
            input_tokens = max(input_tokens, sum(usage.get(f) or 0 for f in INPUT_FIELDS))
            output_tokens = max(output_tokens, usage.get("output_tokens") or 0)
    return input_tokens, output_tokens


def cost(price: tuple[float, float], input_tokens: int, output_tokens: int) -> float:
    return (input_tokens * price[0] + output_tokens * price[1]) / 1_000_000
