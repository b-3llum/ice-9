"""Tests for output-path validation shared across tool wrappers.

These guard the fix for the arbitrary-file-write surface: several wrappers
hand a caller-supplied output path to an offensive binary that then writes to
it, so the path must be confined to an allowed directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from ice_9.tools.base import ice9_data_dir, validate_output_path
from ice_9.tools.bloodhound import BloodHoundWrapper
from ice_9.tools.subfinder import SubfinderWrapper
from ice_9.tools.theharvester import TheHarvesterWrapper


class TestValidateOutputPath:
    def test_accepts_path_inside_allowed_root(self, tmp_path: Path):
        out = tmp_path / "scan.txt"
        assert validate_output_path(out, allowed_roots=[tmp_path]) == str(out.resolve())

    def test_accepts_nested_path(self, tmp_path: Path):
        out = tmp_path / "a" / "b" / "scan.txt"
        assert validate_output_path(out, allowed_roots=[tmp_path]) == str(out.resolve())

    def test_relative_path_resolves_under_first_root(self, tmp_path: Path):
        resolved = validate_output_path("report.txt", allowed_roots=[tmp_path])
        assert resolved == str((tmp_path / "report.txt").resolve())

    def test_rejects_absolute_escape(self, tmp_path: Path):
        with pytest.raises(ValueError):
            validate_output_path("/etc/cron.d/evil", allowed_roots=[tmp_path])

    def test_rejects_parent_traversal(self, tmp_path: Path):
        with pytest.raises(ValueError):
            validate_output_path(
                str(tmp_path / ".." / ".." / "etc" / "passwd"),
                allowed_roots=[tmp_path],
            )

    def test_rejects_empty(self, tmp_path: Path):
        with pytest.raises(ValueError):
            validate_output_path("", allowed_roots=[tmp_path])

    def test_rejects_null_byte(self, tmp_path: Path):
        with pytest.raises(ValueError):
            validate_output_path("ok\x00.txt", allowed_roots=[tmp_path])

    def test_rejects_when_no_roots(self):
        with pytest.raises(ValueError):
            validate_output_path("x", allowed_roots=[])

    def test_default_roots_allow_tmp(self):
        # /tmp is a default allowed root, so this must not raise.
        assert validate_output_path("/tmp/ice9-unit-test-out.txt").endswith(
            "ice9-unit-test-out.txt"
        )

    def test_default_roots_allow_data_dir(self):
        target = ice9_data_dir() / "evidence" / "out.txt"
        assert validate_output_path(target) == str(target.resolve())

    def test_ice9_data_dir_honours_env(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("ICE9_HOME", str(tmp_path))
        assert ice9_data_dir() == tmp_path


class TestWrappersRejectTraversal:
    def test_subfinder_rejects_escape(self):
        with pytest.raises(ValueError):
            SubfinderWrapper().build_command(
                "example.com", output_file="/etc/cron.d/evil"
            )

    def test_subfinder_accepts_tmp(self):
        cmd = SubfinderWrapper().build_command(
            "example.com", output_file="/tmp/ice9-subfinder.txt"
        )
        assert "/tmp/ice9-subfinder.txt" in cmd

    def test_theharvester_rejects_escape(self):
        with pytest.raises(ValueError):
            TheHarvesterWrapper().build_command(
                "example.com", output_file="/root/.ssh/authorized_keys"
            )

    def test_bloodhound_rejects_escape(self):
        with pytest.raises(ValueError):
            BloodHoundWrapper().build_command(
                "corp.local", output_dir="/etc/systemd/system"
            )

    def test_bloodhound_default_is_allowed(self):
        cmd = BloodHoundWrapper().build_command("corp.local")
        assert "/tmp/bloodhound" in cmd
