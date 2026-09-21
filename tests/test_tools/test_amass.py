"""Tests for Amass tool wrapper."""

import json

from ice_9.tools.amass import AmassWrapper


def test_build_command_default_passive():
    tool = AmassWrapper()
    cmd = tool.build_command("example.com")
    assert "enum" in cmd
    assert "-d" in cmd
    assert "example.com" in cmd
    assert "-passive" in cmd
    assert "-json" in cmd
    # JSONL to stdout (works over an SSH execution backend).
    assert cmd[cmd.index("-json") + 1] == "/dev/stdout"


def test_build_command_active():
    tool = AmassWrapper()
    cmd = tool.build_command("example.com", passive=False)
    assert "-passive" not in cmd


def test_build_command_timeout():
    tool = AmassWrapper()
    cmd = tool.build_command("example.com", timeout_mins=10)
    assert "-timeout" in cmd
    idx = cmd.index("-timeout")
    assert cmd[idx + 1] == "10"


def test_parse_output_jsonl(mock_tool_result):
    tool = AmassWrapper()

    # Amass writes JSONL to stdout (-json /dev/stdout).
    records = [
        {"name": "sub1.example.com", "addresses": [{"ip": "1.2.3.4"}], "sources": ["crtsh"]},
        {"name": "sub2.example.com", "addresses": [{"ip": "1.2.3.5"}], "sources": ["dnsdumpster"]},
    ]
    stdout = "\n".join(json.dumps(r) for r in records)

    result = mock_tool_result(tool="amass", target="example.com", stdout=stdout)
    parsed = tool.parse_output(result)

    assert parsed["subdomain_count"] == 2
    assert "sub1.example.com" in parsed["subdomains"]
    assert "1.2.3.4" in parsed["addresses"]
    assert "crtsh" in parsed["sources"]


def test_parse_output_fallback_stdout(mock_tool_result):
    tool = AmassWrapper()

    result = mock_tool_result(
        tool="amass",
        target="example.com",
        stdout="sub1.example.com\nsub2.example.com\n",
    )
    parsed = tool.parse_output(result)
    assert parsed["subdomain_count"] == 2
    assert "sub1.example.com" in parsed["subdomains"]
