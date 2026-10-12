"""Tests for CrackMapExec/NetExec command building and input validation."""

from __future__ import annotations

import pytest
from ice_9.tools.crackmapexec import CrackMapExecWrapper


def _cmd(target="10.0.0.1", **kw):
    return CrackMapExecWrapper().build_command(target, **kw)


class TestBuildCommand:
    def test_default_protocol_and_target(self):
        cmd = _cmd()
        assert cmd[1] == "smb"
        assert cmd[2] == "10.0.0.1"

    def test_auth_username_password(self):
        cmd = _cmd(username="admin", password="pw", domain="CORP")
        assert cmd[cmd.index("-u") + 1] == "admin"
        assert cmd[cmd.index("-p") + 1] == "pw"
        assert cmd[cmd.index("-d") + 1] == "CORP"

    def test_hash_auth(self):
        cmd = _cmd(username="admin", nt_hash="aad3b...:31d6c...")
        assert "-H" in cmd

    def test_exec_action(self):
        cmd = _cmd(action="exec", exec_command="whoami", exec_method="wmiexec")
        assert cmd[cmd.index("-x") + 1] == "whoami"
        assert cmd[cmd.index("--exec-method") + 1] == "wmiexec"

    def test_extra_args_appended(self):
        cmd = _cmd(args=["--shares", "--continue-on-success"])
        assert "--continue-on-success" in cmd


class TestValidation:
    def test_unknown_protocol_rejected(self):
        with pytest.raises(ValueError, match="Unknown protocol"):
            _cmd(protocol="telnet")

    def test_flag_like_protocol_rejected(self):
        with pytest.raises(ValueError, match="Unknown protocol"):
            _cmd(protocol="--evil")

    def test_all_known_protocols_accepted(self):
        for proto in ["smb", "winrm", "ldap", "ssh", "ftp", "mssql", "rdp", "vnc", "wmi", "nfs"]:
            cmd = _cmd(protocol=proto)
            assert cmd[1] == proto

    def test_unknown_exec_method_rejected(self):
        with pytest.raises(ValueError, match="Unknown exec_method"):
            _cmd(action="exec", exec_method="bogus")

    def test_bare_string_args_rejected(self):
        with pytest.raises(ValueError, match="list of strings"):
            _cmd(args="--shares")

    def test_non_string_arg_rejected(self):
        with pytest.raises(ValueError, match="must be a string"):
            _cmd(args=["--ok", 3])
