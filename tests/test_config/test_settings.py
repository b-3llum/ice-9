"""Tests for Settings data-dir resolution, including the ICE9_HOME override."""

from __future__ import annotations

from pathlib import Path

from ice_9.config.settings import Settings, load_settings


class TestDataDir:
    def test_default_without_env(self, monkeypatch):
        monkeypatch.delenv("ICE9_HOME", raising=False)
        assert Settings().data_dir == (Path.home() / ".ice9").resolve()

    def test_ice9_home_override(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("ICE9_HOME", str(tmp_path / "custom-home"))
        assert Settings().data_dir == (tmp_path / "custom-home").resolve()

    def test_explicit_data_dir_beats_env(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("ICE9_HOME", str(tmp_path / "ignored"))
        s = Settings(data_dir=str(tmp_path / "explicit"))
        assert s.data_dir == (tmp_path / "explicit").resolve()

    def test_derived_paths_follow_data_dir(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("ICE9_HOME", str(tmp_path / "home"))
        s = Settings()
        base = (tmp_path / "home").resolve()
        assert s.db_path == base / "ice9.db"
        assert s.evidence_dir == base / "evidence"
        assert s.audit_dir == base / "audit"


class TestLoadSettings:
    def test_config_data_dir_overrides_env(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("ICE9_HOME", str(tmp_path / "env-home"))
        cfg = tmp_path / "ice9.yaml"
        cfg.write_text(f"data_dir: {tmp_path / 'from-config'}\n")
        s = load_settings(cfg)
        assert s.data_dir == (tmp_path / "from-config").resolve()

    def test_config_without_data_dir_uses_env(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("ICE9_HOME", str(tmp_path / "env-home"))
        cfg = tmp_path / "ice9.yaml"
        cfg.write_text("providers: {}\n")
        s = load_settings(cfg)
        assert s.data_dir == (tmp_path / "env-home").resolve()


class TestMetasploitConfig:
    def test_defaults(self):
        mc = Settings().metasploit
        assert mc.host == "127.0.0.1"
        assert mc.port == 55553
        assert mc.username == "msf"
        assert mc.ssl is True
        assert mc.verify_tls is False

    def test_override(self):
        s = Settings(metasploit={"verify_tls": True, "host": "10.0.0.9", "port": 1234})
        assert s.metasploit.verify_tls is True
        assert s.metasploit.host == "10.0.0.9"
        assert s.metasploit.port == 1234
