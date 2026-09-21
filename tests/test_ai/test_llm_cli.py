"""Tests for the subscription-based Claude CLI provider."""

from __future__ import annotations

import json

import pytest
from ice_9.ai import llm as llm_mod
from ice_9.ai.llm import LLMClient
from ice_9.ai.providers import Provider, ProviderRegistry, ProviderType


class _FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_registry_maps_and_lists_claude_cli():
    reg = ProviderRegistry.from_config({"claude_cli": {"model": "sonnet"}})
    p = reg.get("claude_cli")
    assert p is not None
    assert p.provider_type == ProviderType.CLAUDE_CLI
    # No API key required to be considered available.
    assert p in reg.list_available()


def test_chat_claude_cli_builds_command_and_parses(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeProc(
            stdout=json.dumps(
                {"result": "hello world", "usage": {"input_tokens": 5, "output_tokens": 2}}
            )
        )

    monkeypatch.setattr(llm_mod.shutil, "which", lambda b: "/usr/bin/claude")
    monkeypatch.setattr(llm_mod.subprocess, "run", fake_run)

    client = LLMClient()
    provider = Provider(
        name="claude_cli", provider_type=ProviderType.CLAUDE_CLI, model="sonnet"
    )
    resp = client.chat(
        provider,
        [
            {"role": "system", "content": "You are a recon analyst."},
            {"role": "user", "content": "Analyze this."},
        ],
    )
    client.close()

    assert resp.content == "hello world"
    assert resp.usage == {"input_tokens": 5, "output_tokens": 2}

    cmd = captured["cmd"]
    assert cmd[0] == "/usr/bin/claude"
    assert "--print" in cmd
    assert cmd[cmd.index("--output-format") + 1] == "json"
    assert cmd[cmd.index("--model") + 1] == "sonnet"
    assert cmd[cmd.index("--system-prompt") + 1] == "You are a recon analyst."
    assert "Analyze this." in cmd  # user content is the positional prompt


def test_chat_claude_cli_falls_back_to_raw_stdout(monkeypatch):
    monkeypatch.setattr(llm_mod.shutil, "which", lambda b: "/usr/bin/claude")
    monkeypatch.setattr(
        llm_mod.subprocess, "run", lambda *a, **k: _FakeProc(stdout="plain text answer")
    )
    client = LLMClient()
    provider = Provider(name="claude_cli", provider_type=ProviderType.CLAUDE_CLI)
    resp = client.chat(provider, [{"role": "user", "content": "hi"}])
    client.close()
    assert resp.content == "plain text answer"


def test_chat_claude_cli_raises_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(llm_mod.shutil, "which", lambda b: "/usr/bin/claude")
    monkeypatch.setattr(
        llm_mod.subprocess, "run",
        lambda *a, **k: _FakeProc(stderr="boom", returncode=1),
    )
    client = LLMClient()
    provider = Provider(name="claude_cli", provider_type=ProviderType.CLAUDE_CLI)
    with pytest.raises(RuntimeError):
        client.chat(provider, [{"role": "user", "content": "hi"}])
    client.close()
