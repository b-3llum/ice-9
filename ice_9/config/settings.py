"""Configuration management for ice_9."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field

DEFAULT_DATA_DIR = Path.home() / ".ice9"


class ProviderConfig(BaseModel):
    """LLM provider configuration."""

    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: str = ""
    models: list[str] = Field(default_factory=list)


class AgentConfig(BaseModel):
    """AI agent configuration."""

    provider: str = "ollama"
    model: Optional[str] = None
    system_prompt: str = ""


class Settings(BaseModel):
    """Top-level ice_9 settings."""

    data_dir: Path = DEFAULT_DATA_DIR
    db_path: Path = Field(default=None)
    evidence_dir: Path = Field(default=None)
    audit_dir: Path = Field(default=None)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    agents: dict[str, AgentConfig] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if self.db_path is None:
            self.db_path = self.data_dir / "ice9.db"
        if self.evidence_dir is None:
            self.evidence_dir = self.data_dir / "evidence"
        if self.audit_dir is None:
            self.audit_dir = self.data_dir / "audit"


def load_settings(config_path: Optional[Path] = None) -> Settings:
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
