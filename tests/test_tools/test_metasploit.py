"""Tests for Metasploit tool wrapper — input validation and command building."""

from __future__ import annotations

import os

import pytest
from ice_9.tools.metasploit import MetasploitWrapper


@pytest.fixture
def msf() -> MetasploitWrapper:
    return MetasploitWrapper()


class TestBuildCommand:
    """Verify build_command produces a resource file and validates inputs."""

    def test_basic_module(self, msf: MetasploitWrapper) -> None:
        cmd = msf.build_command(
            "192.168.1.1",
            module="exploit/windows/smb/ms17_010_eternalblue",
        )
        assert cmd[0].endswith("msfconsole") or "msfconsole" in cmd[0]
        assert "-q" in cmd
        assert "-r" in cmd
        # Resource file should exist and contain the module
        rc_path = cmd[cmd.index("-r") + 1]
        content = open(rc_path).read()
        assert "use exploit/windows/smb/ms17_010_eternalblue" in content
        assert "set RHOSTS 192.168.1.1" in content
        assert "run -j" in content
        assert "exit" in content
        os.unlink(rc_path)

    def test_with_payload_and_options(self, msf: MetasploitWrapper) -> None:
        cmd = msf.build_command(
            "10.0.0.1",
            module="exploit/multi/handler",
            payload="windows/meterpreter/reverse_tcp",
            options={"LHOST": "10.0.0.5", "LPORT": "4444"},
        )
        rc_path = cmd[cmd.index("-r") + 1]
        content = open(rc_path).read()
        assert "set PAYLOAD windows/meterpreter/reverse_tcp" in content
        assert "set LHOST 10.0.0.5" in content
        assert "set LPORT 4444" in content
        os.unlink(rc_path)

    def test_no_semicolons_in_resource_file(self, msf: MetasploitWrapper) -> None:
        """Ensure commands are newline-separated, not semicolon-joined."""
        cmd = msf.build_command(
            "192.168.1.1",
            module="exploit/windows/smb/ms17_010_eternalblue",
        )
        rc_path = cmd[cmd.index("-r") + 1]
        content = open(rc_path).read()
        # Each command should be on its own line, no semicolons
        assert "; " not in content
        lines = [line for line in content.strip().splitlines() if line.strip()]
        assert len(lines) >= 4  # use, set RHOSTS, run, exit at minimum
        os.unlink(rc_path)


class TestInputValidation:
    """Verify that malicious inputs are rejected."""

    def test_module_injection_semicolon(self, msf: MetasploitWrapper) -> None:
        with pytest.raises(ValueError, match="Invalid module path"):
            msf.build_command("192.168.1.1", module="exploit/test; rm -rf /")

    def test_module_injection_backtick(self, msf: MetasploitWrapper) -> None:
        with pytest.raises(ValueError, match="Invalid module path"):
            msf.build_command("192.168.1.1", module="exploit/`whoami`")

    def test_module_injection_dollar(self, msf: MetasploitWrapper) -> None:
        with pytest.raises(ValueError, match="Invalid module path"):
            msf.build_command("192.168.1.1", module="exploit/$(id)")

    def test_target_injection(self, msf: MetasploitWrapper) -> None:
        with pytest.raises(ValueError, match="Invalid value for target"):
            msf.build_command("192.168.1.1; exit;", module="exploit/test")

    def test_option_key_injection(self, msf: MetasploitWrapper) -> None:
        with pytest.raises(ValueError, match="Invalid option key"):
            msf.build_command(
                "192.168.1.1",
                module="exploit/test",
                options={"LHOST; exit": "10.0.0.1"},
            )

    def test_option_value_injection(self, msf: MetasploitWrapper) -> None:
        with pytest.raises(ValueError, match="Invalid value for"):
            msf.build_command(
                "192.168.1.1",
                module="exploit/test",
                options={"LHOST": "10.0.0.1$(whoami)"},
            )

    def test_payload_injection(self, msf: MetasploitWrapper) -> None:
        with pytest.raises(ValueError, match="Invalid module path"):
            msf.build_command(
                "192.168.1.1",
                module="exploit/test",
                payload="windows/shell; exit",
            )

    def test_valid_module_paths(self, msf: MetasploitWrapper) -> None:
        """Ensure legitimate module paths pass validation."""
        # These should not raise
        for module in [
            "exploit/windows/smb/ms17_010_eternalblue",
            "auxiliary/scanner/ssh/ssh_login",
            "post/multi/gather/env",
            "exploit/multi/handler",
        ]:
            cmd = msf.build_command("192.168.1.1", module=module)
            rc_path = cmd[cmd.index("-r") + 1]
            os.unlink(rc_path)

    def test_valid_option_values(self, msf: MetasploitWrapper) -> None:
        """Ensure legitimate option values pass validation."""
        cmd = msf.build_command(
            "192.168.1.0/24",
            module="auxiliary/scanner/portscan/tcp",
            options={
                "PORTS": "22, 80, 443, 8080",
                "THREADS": "10",
                "RHOSTS": "192.168.1.0/24",
            },
        )
        rc_path = cmd[cmd.index("-r") + 1]
        os.unlink(rc_path)
