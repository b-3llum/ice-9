"""Tests for CrackMapExec output parsing and the per-host schema the phases read."""

from __future__ import annotations

from datetime import datetime, timezone

from ice_9.tools.base import ToolResult
from ice_9.tools.crackmapexec import CrackMapExecWrapper

SAMPLE = """\
SMB    10.0.0.5    445    DC01    [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB    10.0.0.5    445    DC01    [+] corp.local\\Administrator:P@ssw0rd (Pwn3d!)
SMB    10.0.0.5    445    DC01    [*] Enumerated shares
SMB    10.0.0.5    445    DC01    Share           Permissions     Remark
SMB    10.0.0.5    445    DC01    -----           -----------     ------
SMB    10.0.0.5    445    DC01    ADMIN$          READ,WRITE      Remote Admin
SMB    10.0.0.5    445    DC01    C$              READ            Default share
SMB    10.0.0.5    445    DC01    IPC$                            Remote IPC
SMB    10.0.0.9    445    WS02    [*] Windows 10 Build 19041 x64 (name:WS02) (domain:corp.local) (signing:False) (SMBv1:True)
SMB    10.0.0.9    445    WS02    [-] corp.local\\bob:bad STATUS_LOGON_FAILURE
"""


def _parsed(text=SAMPLE):
    now = datetime.now(timezone.utc)
    r = ToolResult(
        tool="crackmapexec", target="10.0.0.0/24", command=["nxc"],
        return_code=0, stdout=text, stderr="", started_at=now, completed_at=now,
    )
    return CrackMapExecWrapper().parse_output(r)


class TestParseHosts:
    def test_emits_hosts_key(self):
        hosts = _parsed()["hosts"]
        assert [h["ip"] for h in hosts] == ["10.0.0.5", "10.0.0.9"]

    def test_pwned_and_admin(self):
        hosts = {h["ip"]: h for h in _parsed()["hosts"]}
        assert hosts["10.0.0.5"]["pwned"] is True
        assert hosts["10.0.0.5"]["admin"] is True
        assert hosts["10.0.0.9"]["pwned"] is False

    def test_signing(self):
        hosts = {h["ip"]: h for h in _parsed()["hosts"]}
        assert hosts["10.0.0.5"]["signing"] is True
        assert hosts["10.0.0.9"]["signing"] is False

    def test_os_string(self):
        hosts = {h["ip"]: h for h in _parsed()["hosts"]}
        assert hosts["10.0.0.5"]["os"] == "Windows Server 2019 Build 17763 x64"

    def test_shares_readable_writable(self):
        hosts = {h["ip"]: h for h in _parsed()["hosts"]}
        shares = {s["name"]: s for s in hosts["10.0.0.5"]["shares"]}
        assert shares["ADMIN$"] == {"name": "ADMIN$", "readable": True, "writable": True}
        assert shares["C$"]["readable"] is True and shares["C$"]["writable"] is False
        # IPC$ has no permissions and must not appear as an accessible share.
        assert "IPC$" not in shares

    def test_backward_compat_keys_present(self):
        parsed = _parsed()
        assert "credentials" in parsed and "shares" in parsed and "raw_lines" in parsed

    def test_empty_output(self):
        assert _parsed("")["hosts"] == []


class TestAnalyzersNowFire:
    """End-to-end: the phase analyzers that read parsed['hosts'] must now
    produce findings (regression for the dead-detection bug)."""

    def _result(self):
        now = datetime.now(timezone.utc)
        r = ToolResult(
            tool="crackmapexec", target="10.0.0.0/24", command=["nxc"],
            return_code=0, stdout=SAMPLE, stderr="", started_at=now, completed_at=now,
        )
        r.parsed = CrackMapExecWrapper().parse_output(r)
        return r

    def test_execution_phase_flags_exec_and_signing(self, tmp_store, audit_logger):
        from ice_9.phases.execution import ExecutionPhase
        findings = ExecutionPhase(tmp_store, audit_logger)._analyze_cme(self._result())
        titles = [f.title for f in findings]
        assert any("Command execution confirmed on 10.0.0.5" in t for t in titles)
        assert any("SMB signing not required on 10.0.0.9" in t for t in titles)

    def test_priv_esc_flags_local_admin(self, tmp_store, audit_logger):
        from ice_9.phases.priv_esc import PrivEscPhase
        findings = PrivEscPhase(tmp_store, audit_logger)._analyze_cme(self._result())
        assert any("Local admin access on 10.0.0.5" in f.title for f in findings)

    def test_collection_flags_shares(self, tmp_store, audit_logger):
        from ice_9.phases.collection import CollectionPhase
        findings = CollectionPhase(tmp_store, audit_logger)._analyze_shares(self._result())
        titles = " ".join(f.title for f in findings)
        assert "Readable shares on 10.0.0.5" in titles
        assert "Writable shares on 10.0.0.5" in titles
