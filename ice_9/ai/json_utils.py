"""Helpers for pulling structured data out of free-form LLM responses."""

from __future__ import annotations

import json
from typing import Any


def extract_json(text: str) -> dict[str, Any] | None:
    """Extract the first JSON object embedded in an LLM response.

    Locates the outermost ``{ ... }`` span (models often wrap JSON in prose or
    Markdown fences) and parses it. Returns the decoded object, or ``None`` if
    no valid JSON object is present.
    """
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}") + 1
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start:end])
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None
