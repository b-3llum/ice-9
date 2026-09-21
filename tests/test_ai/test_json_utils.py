"""Tests for the shared LLM-response JSON extractor."""

from __future__ import annotations

from ice_9.ai.json_utils import extract_json


def test_plain_object():
    assert extract_json('{"a": 1, "b": "x"}') == {"a": 1, "b": "x"}


def test_object_wrapped_in_prose():
    text = 'Here is my analysis:\n{"score": 0.8}\nHope that helps!'
    assert extract_json(text) == {"score": 0.8}


def test_markdown_fenced_object():
    text = '```json\n{"ok": true}\n```'
    assert extract_json(text) == {"ok": True}


def test_no_json_returns_none():
    assert extract_json("no json here at all") is None


def test_empty_string_returns_none():
    assert extract_json("") is None


def test_invalid_json_returns_none():
    assert extract_json("{not valid json}") is None


def test_bare_array_returns_none():
    # The extractor targets JSON objects, not arrays.
    assert extract_json("[1, 2, 3]") is None
