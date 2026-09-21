"""Configuration management for ice_9."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_DATA_DIR = Path.home() / ".ice9"


class ProviderConfig(BaseModel):
    """LLM provider configuration."""

    base_url: str | None = None
    api_key: str | None = None
    model: str = ""
    models: list[str] = Field(default_factory=list)


class AgentConfig(BaseModel):
    """AI agent configuration."""

    provider: str = "ollama"
    model: str | None = None
    system_prompt: str = ""


class Settings(BaseModel):
    """Top-level ice_9 settings."""

    data_dir: Path = DEFAULT_DATA_DIR
    db_path: Path = Field(default=None)
    evidence_dir: Path = Field(default=None)
    audit_dir: Path = Field(default=None)
    tool_paths: list[str] = Field(default_factory=list)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    agents: dict[str, AgentConfig] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        import os

        # Expand ~ in paths (YAML doesn't expand tilde)
        self.data_dir = self.data_dir.expanduser().resolve()

        # Prepend tool_paths to $PATH so shutil.which() finds tool binaries
        if self.tool_paths:
            expanded = [str(Path(p).expanduser().resolve()) for p in self.tool_paths]
            current_path = os.environ.get("PATH", "")
            os.environ["PATH"] = os.pathsep.join(expanded) + os.pathsep + current_path
        if self.db_path is None:
            self.db_path = self.data_dir / "ice9.db"
        else:
            self.db_path = self.db_path.expanduser().resolve()
        if self.evidence_dir is None:
            self.evidence_dir = self.data_dir / "evidence"
        else:
            self.evidence_dir = self.evidence_dir.expanduser().resolve()
        if self.audit_dir is None:
            self.audit_dir = self.data_dir / "audit"
        else:
            self.audit_dir = self.audit_dir.expanduser().resolve()


def load_settings(config_path: Path | None = None) -> Settings:
    """Load settings from YAML config file, falling back to defaults."""
    paths_to_try = []
    if config_path:
        paths_to_try.append(config_path)
    paths_to_try.extend(
        [
            Path.cwd() / "config" / "ice9.yaml",
            Path.cwd() / "ice9.yaml",
            DEFAULT_DATA_DIR / "config.yaml",
        ]
    )

    for path in paths_to_try:
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            # Resolve env vars in API keys
            _resolve_env_vars(data)
            return Settings(**data)

    return Settings()


def _resolve_env_vars(data: dict) -> None:
    """Recursively resolve ${ENV_VAR} references in string values."""
    import os

    for key, value in data.items():
        if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            env_name = value[2:-1]
            data[key] = os.environ.get(env_name, "")
        elif isinstance(value, dict):
            _resolve_env_vars(value)
