"""Tests for Responder tool wrapper."""

import pytest

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


def test_build_command_disable_services():
    """Verify disable flag produces correct --disable-<service> args."""
    tool = ResponderWrapper()
    cmd = tool.build_command("eth0", disable="SMB,HTTP")
    assert "--disable-smb" in cmd
    assert "--disable-http" in cmd
    # Should NOT contain the old buggy --disable-ess
    assert "--disable-ess" not in cmd


def test_build_command_disable_single_service():
    tool = ResponderWrapper()
    cmd = tool.build_command("eth0", disable="smb")
    assert "--disable-smb" in cmd


def test_build_command_disable_ess_separate_flag():
    """Disabling ESS should use the dedicated disable_ess kwarg."""
    tool = ResponderWrapper()
    cmd = tool.build_command("eth0", disable_ess=True)
    assert "--disable-ess" in cmd


def test_build_command_disable_invalid_service():
    tool = ResponderWrapper()
    with pytest.raises(ValueError, match="Unknown Responder service"):
        tool.build_command("eth0", disable="FAKE_SERVICE")


def test_build_command_disable_with_whitespace():
    """Whitespace around service names should be stripped."""
    tool = ResponderWrapper()
    cmd = tool.build_command("eth0", disable=" smb , http ")
    assert "--disable-smb" in cmd
    assert "--disable-http" in cmd


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
