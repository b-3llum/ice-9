"""Tests for Responder tool wrapper."""

from ice_9.tools.responder import ResponderWrapper


def test_build_command_basic():
    tool = ResponderWrapper()
    cmd = tool.build_command("eth0")
    assert "-I" in cmd
    assert "eth0" in cmd


def test_build_command_analyze_mode():
    tool = ResponderWrapper()
    cmd = tool.build_command("eth0", analyze=True)
    assert "-A" in cmd


def test_parse_output_ntlmv2(mock_tool_result):
    tool = ResponderWrapper()
    result = mock_tool_result(
        tool="responder",
        target="eth0",
        stdout=(
            "[+] NTLMv2-SSP Hash: DOMAIN\\user::DOMAIN:abc123:hash:data\n"
            "[+] NTLMv2-SSP Hash: DOMAIN\\admin::DOMAIN:def456:hash:data\n"
        ),
    )
    parsed = tool.parse_output(result)
    assert parsed["total_hashes"] == 2
    assert len(parsed["ntlmv2_hashes"]) == 2
