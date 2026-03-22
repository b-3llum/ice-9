"""Tests for Impacket tool wrappers and shared auth builder."""

import pytest

from ice_9.tools.impacket_tools import (
    GetUserSPNs,
    ImpacketTool,
    PsExec,
    SecretsDump,
    WmiExec,
)


# ---------------------------------------------------------------------------
# _build_auth helper
# ---------------------------------------------------------------------------


class TestBuildAuth:
    """Tests for ImpacketTool._build_auth static method."""

    def test_full_auth_string(self):
        auth, extra = ImpacketTool._build_auth(
            "10.0.0.1",
            domain="CORP",
            username="admin",
            password="P@ss",
        )
        assert auth == "CORP/admin:P@ss@10.0.0.1"
        assert extra == []

    def test_hash_instead_of_password(self):
        auth, extra = ImpacketTool._build_auth(
            "10.0.0.1",
            domain="CORP",
            username="admin",
            nt_hash="aad3b435b51404ee",
        )
        assert auth == "CORP/admin@10.0.0.1"
        assert extra == ["-hashes", ":aad3b435b51404ee"]

    def test_password_and_hash_both_present(self):
        auth, extra = ImpacketTool._build_auth(
            "10.0.0.1",
            domain="CORP",
            username="admin",
            password="P@ss",
            nt_hash="aad3b435b51404ee",
        )
        assert auth == "CORP/admin:P@ss@10.0.0.1"
        assert extra == ["-hashes", ":aad3b435b51404ee"]

    def test_no_domain(self):
        auth, _ = ImpacketTool._build_auth(
            "10.0.0.1", username="admin", password="P@ss"
        )
        assert auth == "admin:P@ss@10.0.0.1"

    def test_no_password(self):
        auth, _ = ImpacketTool._build_auth(
            "10.0.0.1", domain="CORP", username="admin"
        )
        assert auth == "CORP/admin@10.0.0.1"

    def test_include_target_false(self):
        auth, _ = ImpacketTool._build_auth(
            "10.0.0.1",
            domain="CORP",
            username="admin",
            include_target=False,
        )
        assert auth == "CORP/admin"
        assert "@" not in auth

    def test_empty_inputs(self):
        auth, extra = ImpacketTool._build_auth("10.0.0.1")
        assert auth == "@10.0.0.1"
        assert extra == []


# ---------------------------------------------------------------------------
# SecretsDump
# ---------------------------------------------------------------------------


class TestSecretsDump:
    def test_build_command_full_auth(self):
        tool = SecretsDump()
        cmd = tool.build_command(
            "10.0.0.1", domain="CORP", username="admin", password="P@ss"
        )
        assert "CORP/admin:P@ss@10.0.0.1" in cmd

    def test_build_command_hash_auth(self):
        tool = SecretsDump()
        cmd = tool.build_command(
            "10.0.0.1",
            domain="CORP",
            username="admin",
            nt_hash="deadbeef",
        )
        assert "CORP/admin@10.0.0.1" in cmd
        assert "-hashes" in cmd
        idx = cmd.index("-hashes")
        assert cmd[idx + 1] == ":deadbeef"

    def test_build_command_options(self):
        tool = SecretsDump()
        cmd = tool.build_command(
            "10.0.0.1",
            username="admin",
            just_dc=True,
            sam=True,
            output_file="/tmp/dump.txt",
        )
        assert "-just-dc" in cmd
        assert "-sam" in cmd
        assert "-outputfile" in cmd
        idx = cmd.index("-outputfile")
        assert cmd[idx + 1] == "/tmp/dump.txt"


# ---------------------------------------------------------------------------
# GetUserSPNs
# ---------------------------------------------------------------------------


class TestGetUserSPNs:
    def test_build_command_no_target_in_auth(self):
        """GetUserSPNs uses domain/user (no @target) in the auth string."""
        tool = GetUserSPNs()
        cmd = tool.build_command(
            "10.0.0.1", domain="CORP", username="svc_sql", password="secret"
        )
        assert "CORP/svc_sql:secret" in cmd
        # Auth string should NOT contain @target
        auth_arg = [a for a in cmd if "CORP/svc_sql" in a][0]
        assert "@10.0.0.1" not in auth_arg

    def test_build_command_dc_ip(self):
        tool = GetUserSPNs()
        cmd = tool.build_command("10.0.0.1", domain="CORP", username="user")
        assert "-dc-ip" in cmd
        idx = cmd.index("-dc-ip")
        assert cmd[idx + 1] == "10.0.0.1"

    def test_build_command_request_default(self):
        tool = GetUserSPNs()
        cmd = tool.build_command("10.0.0.1", domain="CORP", username="user")
        assert "-request" in cmd

    def test_build_command_request_disabled(self):
        tool = GetUserSPNs()
        cmd = tool.build_command(
            "10.0.0.1", domain="CORP", username="user", request=False
        )
        assert "-request" not in cmd


# ---------------------------------------------------------------------------
# PsExec / WmiExec (identical auth pattern)
# ---------------------------------------------------------------------------


class TestPsExec:
    def test_build_command_auth(self):
        tool = PsExec()
        cmd = tool.build_command(
            "10.0.0.1", domain="CORP", username="admin", password="P@ss"
        )
        assert "CORP/admin:P@ss@10.0.0.1" in cmd

    def test_build_command_with_command(self):
        tool = PsExec()
        cmd = tool.build_command(
            "10.0.0.1", username="admin", command="whoami"
        )
        assert "-c" in cmd
        idx = cmd.index("-c")
        assert cmd[idx + 1] == "whoami"


class TestWmiExec:
    def test_build_command_auth(self):
        tool = WmiExec()
        cmd = tool.build_command(
            "10.0.0.1", domain="CORP", username="admin", nt_hash="deadbeef"
        )
        assert "CORP/admin@10.0.0.1" in cmd
        assert "-hashes" in cmd

    def test_build_command_with_command(self):
        tool = WmiExec()
        cmd = tool.build_command(
            "10.0.0.1", username="admin", command="ipconfig"
        )
        assert "-c" in cmd
        idx = cmd.index("-c")
        assert cmd[idx + 1] == "ipconfig"
