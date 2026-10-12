"""Tests for validate_target and its application across tool wrappers."""

from __future__ import annotations

import pytest
from ice_9.tools.amass import AmassWrapper
from ice_9.tools.base import validate_target
from ice_9.tools.crackmapexec import CrackMapExecWrapper
from ice_9.tools.kerb_map import KerbMapWrapper
from ice_9.tools.nmap import NmapWrapper
from ice_9.tools.nuclei import NucleiWrapper
from ice_9.tools.subfinder import SubfinderWrapper
from ice_9.tools.theharvester import TheHarvesterWrapper


class TestValidateTarget:
    def test_accepts_normal_targets(self):
        for t in ["10.0.0.1", "10.0.0.0/24", "example.com", "dc.corp.local", "https://x.io"]:
            assert validate_target(t) == t

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_target("")

    def test_rejects_none(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_target(None)

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError, match="null byte"):
            validate_target("a\x00b")

    def test_rejects_leading_dash(self):
        with pytest.raises(ValueError, match="flag"):
            validate_target("-oG")

    def test_custom_name_in_message(self):
        with pytest.raises(ValueError, match="dc"):
            validate_target("-x", "dc")


# Each positional-target wrapper must reject a flag-like target.
WRAPPERS = [
    (NmapWrapper, {}),
    (NucleiWrapper, {}),
    (AmassWrapper, {}),
    (SubfinderWrapper, {}),
    (TheHarvesterWrapper, {}),
    (CrackMapExecWrapper, {}),
    (KerbMapWrapper, {}),
]


@pytest.mark.parametrize("cls,kw", WRAPPERS)
def test_wrapper_rejects_flag_target(cls, kw):
    with pytest.raises(ValueError):
        cls().build_command("-oG", **kw)


@pytest.mark.parametrize("cls,kw", WRAPPERS)
def test_wrapper_accepts_normal_target(cls, kw):
    # Should not raise for an ordinary target.
    cls().build_command("example.com", **kw)


class TestNucleiSeverity:
    def test_single_valid(self):
        cmd = NucleiWrapper().build_command("example.com", severity="high")
        assert cmd[cmd.index("-severity") + 1] == "high"

    def test_multiple_valid(self):
        cmd = NucleiWrapper().build_command("example.com", severity="high,critical")
        assert cmd[cmd.index("-severity") + 1] == "high,critical"

    def test_invalid_rejected(self):
        with pytest.raises(ValueError, match="Unknown nuclei severity"):
            NucleiWrapper().build_command("example.com", severity="catastrophic")

    def test_args_validated(self):
        with pytest.raises(ValueError, match="list of strings"):
            NucleiWrapper().build_command("example.com", args="-debug")
