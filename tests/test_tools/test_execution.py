"""Tests for the local/SSH execution backend."""

from __future__ import annotations

import io

import pytest
from ice_9.tools import base as base_mod
from ice_9.tools.base import ToolResult, ToolWrapper
from ice_9.tools.execution import ExecutionBackend, get_backend, set_backend


@pytest.fixture(autouse=True)
def _reset_backend():
    """Keep the process-wide backend from leaking between tests."""
    original = get_backend()
    yield
    set_backend(original)


def test_local_backend_passes_command_through():
    b = ExecutionBackend()  # local
    assert b.is_remote is False
    assert b.wrap(["nmap", "-sV", "10.0.0.1"]) == ["nmap", "-sV", "10.0.0.1"]
    assert b.describe() == "local"


def test_ssh_backend_wraps_command():
    b = ExecutionBackend(
        backend="ssh", host="1.2.3.4", user="kali", port=2222, key_file="/tmp/k.pem"
    )
    assert b.is_remote is True
    wrapped = b.wrap(["/usr/bin/nmap", "-sV", "10.0.0.1"])

    assert wrapped[0] == "ssh"
    assert "-i" in wrapped and "/tmp/k.pem" in wrapped
    assert wrapped[wrapped.index("-p") + 1] == "2222"
    assert "kali@1.2.3.4" in wrapped
    # Remote command uses the bare binary name (remote PATH resolves it).
    assert wrapped[-1] == "nmap -sV 10.0.0.1"


def test_ssh_backend_needs_host():
    # backend=ssh but no host -> not remote, no wrapping.
    b = ExecutionBackend(backend="ssh", host="")
    assert b.is_remote is False
    assert b.wrap(["nmap"]) == ["nmap"]


class _DummyTool(ToolWrapper):
    name = "dummy"
    binary = "dummy"

    def build_command(self, target, **kwargs):
        return [self.get_binary_path(), target]

    def parse_output(self, result: ToolResult) -> dict:
        return {}


class _FakeProc:
    def __init__(self):
        self.stdout = iter(["out line\n"])
        self.stderr = io.StringIO("")
        self.returncode = 0

    def wait(self, timeout=None):
        return 0


def test_run_uses_ssh_wrapped_command(monkeypatch):
    set_backend(ExecutionBackend(backend="ssh", host="10.9.9.9", user="op"))

    captured = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        return _FakeProc()

    monkeypatch.setattr(base_mod.subprocess, "Popen", fake_popen)

    tool = _DummyTool()
    assert tool.is_available() is True  # remote backend -> assumed available
    result = tool.run("10.0.0.5")

    argv = captured["argv"]
    assert argv[0] == "ssh"
    assert "op@10.9.9.9" in argv
    assert argv[-1] == "dummy 10.0.0.5"
    # The recorded command is still the tool command, not the ssh wrapper.
    assert result.command[0].endswith("dummy") or result.command[0] == "dummy"
