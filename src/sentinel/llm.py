"""Tool-less, schema-constrained model calls for the host-side agents (reader and reviewer).

They have no tools, so injected text has nothing to act through. Their output must match a
JSON schema, and each caller trims it further before anything else sees it.
"""

from __future__ import annotations

import json
import re
from typing import Any

import anthropic
import openai

URL = re.compile(r"\b(?:https?|ftp|git|ssh)://\S+|\bwww\.\S+", re.IGNORECASE)


class ModelError(RuntimeError):
    pass


def strip_urls(text: Any, limit: int) -> str:
    return URL.sub("[link removed]", str(text))[:limit]


def _anthropic(model: str, system: str, schema: dict, name: str, text: str) -> str:
    response = anthropic.Anthropic().beta.messages.create(
        model=model,
        max_tokens=4000,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        output_config={"effort": "low", "format": {"type": "json_schema", "schema": schema}},
        system=system,
        messages=[{"role": "user", "content": text}],
    )
    if response.stop_reason == "refusal":
        raise ModelError(f"the {name} model declined the request")
    return next((block.text for block in response.content if block.type == "text"), "")


def _openai(model: str, system: str, schema: dict, name: str, text: str) -> str:
    response = openai.OpenAI().responses.create(
        model=model,
        instructions=system,
        input=text,
        store=False,
        text={"format": {"type": "json_schema", "name": name, "schema": schema, "strict": True}},
    )
    return response.output_text


PROVIDERS = {"anthropic": _anthropic, "openai": _openai}


def structured(provider: str, model: str, system: str, schema: dict, name: str, text: str):
    """One call, one JSON object back. Every failure becomes a ModelError."""
    try:
        raw = PROVIDERS[provider](model, system, schema, name, text)
    except (anthropic.APIError, openai.APIError) as exc:
        raise ModelError(f"the {provider} API refused the {name} request: {exc.message}") from exc
    if not raw:
        raise ModelError(f"the {name} model returned nothing")
    try:
        result = json.loads(raw)
    except ValueError as exc:
        raise ModelError(f"the {name} model returned malformed JSON") from exc
    if not isinstance(result, dict):
        raise ModelError(f"the {name} model did not return a JSON object")
    return result
