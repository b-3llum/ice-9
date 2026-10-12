"""Tests for NTLMRelayx target selection (explicit targets_file vs single -t)."""

from __future__ import annotations

from ice_9.tools.impacket_tools import NTLMRelayx


def _cmd(target="10.0.0.1", **kw):
    return NTLMRelayx().build_command(target, **kw)


def test_single_target_uses_dash_t():
    cmd = _cmd("10.0.0.1")
    assert "-t" in cmd
    assert cmd[cmd.index("-t") + 1] == "10.0.0.1"
    assert "-tf" not in cmd


def test_targets_file_uses_dash_tf():
    cmd = _cmd("ignored", targets_file="/home/op/targets.lst")
    assert "-tf" in cmd
    assert cmd[cmd.index("-tf") + 1] == "/home/op/targets.lst"
    assert "-t" not in [a for a in cmd if a == "-t"]


def test_txt_named_target_is_no_longer_special():
    # Regression: the old code picked -tf whenever the target ended in .txt.
    cmd = _cmd("hosts.txt")
    assert "-t" in cmd
    assert cmd[cmd.index("-t") + 1] == "hosts.txt"
    assert "-tf" not in cmd


def test_targets_file_takes_precedence_over_target():
    cmd = _cmd("10.0.0.1", targets_file="/tmp/t.lst")
    assert "-tf" in cmd
    assert "10.0.0.1" not in cmd


def test_options_smb2_default_and_flags():
    cmd = _cmd("10.0.0.1", socks=True, delegate_access=True, command="whoami")
    assert "-smb2support" in cmd
    assert "-socks" in cmd
    assert "--delegate-access" in cmd
    assert cmd[cmd.index("-c") + 1] == "whoami"


def test_smb2support_can_be_disabled():
    cmd = _cmd("10.0.0.1", smb2support=False)
    assert "-smb2support" not in cmd
