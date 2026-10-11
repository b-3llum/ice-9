"""Tests for Impacket tool wrappers and shared auth builder."""


import pytest
from ice_9.tools.impacket_tools import (
    GetNPUsers,
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


# ---------------------------------------------------------------------------
# GetNPUsers (AS-REP roasting)
# ---------------------------------------------------------------------------


class TestGetNPUsers:
    def test_authenticated_principal_and_dc_ip(self):
        """With credentials the principal carries user[:password] and -dc-ip
        keeps the DC address (regression: the old code overwrote -dc-ip)."""
        tool = GetNPUsers()
        cmd = tool.build_command(
            "10.0.0.1", domain="CORP", username="alice", password="pw", dc_ip="10.0.0.5"
        )
        assert "CORP/alice:pw" in cmd
        idx = cmd.index("-dc-ip")
        assert cmd[idx + 1] == "10.0.0.5"
        assert "-no-pass" not in cmd

    def test_username_without_password(self):
        tool = GetNPUsers()
        cmd = tool.build_command("10.0.0.1", domain="CORP", username="bob", dc_ip="10.0.0.5")
        assert "CORP/bob" in cmd
        assert "CORP/bob:" not in " ".join(cmd)
        assert "-no-pass" not in cmd

    def test_no_credentials_requests_no_pass(self):
        tool = GetNPUsers()
        cmd = tool.build_command("10.0.0.1", domain="CORP", dc_ip="10.0.0.5")
        assert "CORP/" in cmd
        assert "-no-pass" in cmd
        idx = cmd.index("-dc-ip")
        assert cmd[idx + 1] == "10.0.0.5"

    def test_dc_ip_defaults_to_target(self):
        tool = GetNPUsers()
        cmd = tool.build_command("10.0.0.1", domain="CORP", username="bob")
        idx = cmd.index("-dc-ip")
        assert cmd[idx + 1] == "10.0.0.1"

    def test_hashcat_format_and_usersfile(self):
        tool = GetNPUsers()
        cmd = tool.build_command("10.0.0.1", domain="CORP", usersfile="/tmp/users.txt")
        assert "-format" in cmd
        assert cmd[cmd.index("-format") + 1] == "hashcat"
        assert "-usersfile" in cmd
        assert cmd[cmd.index("-usersfile") + 1] == "/tmp/users.txt"

    def test_output_file_validated(self):
        tool = GetNPUsers()
        cmd = tool.build_command(
            "10.0.0.1", domain="CORP", output_file="/tmp/asrep.txt"
        )
        assert "-outputfile" in cmd
        assert "/tmp/asrep.txt" in cmd

    def test_output_file_rejects_traversal(self):
        tool = GetNPUsers()
        with pytest.raises(ValueError):
            tool.build_command(
                "10.0.0.1", domain="CORP", output_file="/etc/cron.d/evil"
            )


# ---------------------------------------------------------------------------
# Output-path confinement on the impacket writers
# ---------------------------------------------------------------------------


class TestImpacketOutputPaths:
    def test_secretsdump_rejects_escape(self):
        with pytest.raises(ValueError):
            SecretsDump().build_command(
                "10.0.0.1", username="admin", output_file="/root/.ssh/authorized_keys"
            )

    def test_secretsdump_accepts_tmp(self):
        cmd = SecretsDump().build_command(
            "10.0.0.1", username="admin", output_file="/tmp/dump.txt"
        )
        assert "/tmp/dump.txt" in cmd

    def test_getuserspns_default_output_allowed(self):
        cmd = GetUserSPNs().build_command("10.0.0.1", domain="CORP", username="svc")
        assert "/tmp/kerberoast.txt" in cmd

    def test_getuserspns_rejects_escape(self):
        with pytest.raises(ValueError):
            GetUserSPNs().build_command(
                "10.0.0.1", domain="CORP", username="svc",
                output_file="/etc/passwd",
            )
