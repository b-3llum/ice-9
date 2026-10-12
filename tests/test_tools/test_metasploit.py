"""Tests for Metasploit tool wrapper — input validation and command building."""

from __future__ import annotations

import os

import httpx
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


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, raise_json: bool = False):
        self.status_code = status_code
        self._payload = payload or {}
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


class TestSearchModules:
    """search_modules must percent-encode the query into the URL."""

    def test_query_is_url_encoded(self, msf: MetasploitWrapper, monkeypatch) -> None:
        captured = {}

        def fake_api_call(method, endpoint, data=None):
            captured["method"] = method
            captured["endpoint"] = endpoint
            return {}

        monkeypatch.setattr(msf, "_api_call", fake_api_call)
        msf.search_modules("smb & rce #1")

        assert captured["method"] == "GET"
        # Spaces, & and # must be encoded, not passed through raw.
        assert " " not in captured["endpoint"]
        assert "&" not in captured["endpoint"]
        assert "#" not in captured["endpoint"]
        assert "%20" in captured["endpoint"]
        assert "%26" in captured["endpoint"]
        assert "%23" in captured["endpoint"]


class TestAuthenticate:
    """_authenticate reports failures instead of swallowing them."""

    def test_default_username_is_msf(self) -> None:
        assert MetasploitWrapper().username == "msf"

    def test_custom_username(self) -> None:
        assert MetasploitWrapper(username="operator").username == "operator"

    def test_success_sets_token(self, msf: MetasploitWrapper, monkeypatch) -> None:
        sent = {}

        def fake_post(url, json=None):
            sent["json"] = json
            return _FakeResponse(200, {"token": "abc123"})

        monkeypatch.setattr(msf._http, "post", fake_post)
        assert msf._authenticate() is True
        assert msf._token == "abc123"
        # Uses the configured username, not a hardcoded literal.
        assert sent["json"]["username"] == msf.username

    def test_connection_error_returns_false(self, msf: MetasploitWrapper, monkeypatch) -> None:
        def fake_post(url, json=None):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(msf._http, "post", fake_post)
        assert msf._authenticate() is False
        assert msf._token is None

    def test_non_200_returns_false(self, msf: MetasploitWrapper, monkeypatch) -> None:
        monkeypatch.setattr(msf._http, "post", lambda url, json=None: _FakeResponse(401))
        assert msf._authenticate() is False
        assert msf._token is None

    def test_non_json_body_returns_false(self, msf: MetasploitWrapper, monkeypatch) -> None:
        monkeypatch.setattr(
            msf._http, "post", lambda url, json=None: _FakeResponse(200, raise_json=True)
        )
        assert msf._authenticate() is False
        assert msf._token is None


class TestVerifyTls:
    """TLS verification is configurable and off by default (self-signed localhost)."""

    def test_default_is_off(self) -> None:
        assert MetasploitWrapper().verify_tls is False

    def test_can_enable(self) -> None:
        assert MetasploitWrapper(verify_tls=True).verify_tls is True


class TestResourceFileCleanup:
    """build_command writes a temp .rc file (delete=False); run() must remove it."""

    def test_run_removes_resource_file(self, msf: MetasploitWrapper, monkeypatch) -> None:
        # Use a harmless real binary so run() executes and reaches cleanup.
        monkeypatch.setattr(msf, "get_binary_path", lambda: "true")
        captured: dict[str, str] = {}
        orig = msf.build_command

        def spy(target, **kw):
            cmd = orig(target, **kw)
            captured["rc"] = msf._rc_file.name
            return cmd

        monkeypatch.setattr(msf, "build_command", spy)
        msf.run("1.2.3.4", module="exploit/windows/smb/ms17_010_eternalblue")
        assert msf._rc_file is None
        assert not os.path.exists(captured["rc"])
