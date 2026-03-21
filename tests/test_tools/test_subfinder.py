"""Tests for Subfinder tool wrapper."""

from ice_9.tools.subfinder import SubfinderWrapper


def test_build_command_basic():
    tool = SubfinderWrapper()
    cmd = tool.build_command("example.com")
    assert "-d" in cmd
    assert "example.com" in cmd
    assert "-silent" in cmd


def test_parse_output(mock_tool_result):
    tool = SubfinderWrapper()
    result = mock_tool_result(
        tool="subfinder",
        target="example.com",
        stdout="sub1.example.com\nsub2.example.com\napi.example.com\n",
    )
    parsed = tool.parse_output(result)
    assert parsed["count"] == 3
    assert "sub1.example.com" in parsed["subdomains"]
    assert "api.example.com" in parsed["subdomains"]
