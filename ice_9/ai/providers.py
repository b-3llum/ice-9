"""LLM provider registry — Ollama, Claude, OpenAI, Groq, Mistral."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ProviderType(str, Enum):
    OLLAMA = "ollama"
    CLAUDE = "claude"
    OPENAI = "openai"
    GROQ = "groq"
    MISTRAL = "mistral"


@dataclass
class Provider:
    """An LLM provider configuration."""

    name: str
    provider_type: ProviderType
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: str = ""
    models: list[str] = field(default_factory=list)
    enabled: bool = True

    @property
    def default_model(self) -> str:
        """Get the default model for this provider."""
        return self.model or (self.models[0] if self.models else "")


# Default base URLs
DEFAULT_URLS = {
    ProviderType.OLLAMA: "http://localhost:11434",
    ProviderType.OPENAI: "https://api.openai.com/v1",
    ProviderType.GROQ: "https://api.groq.com/openai/v1",
    ProviderType.MISTRAL: "https://api.mistral.ai/v1",
}


class ProviderRegistry:
    """Registry for LLM providers."""

    def __init__(self) -> None:
        self._providers: dict[str, Provider] = {}

    def register(self, provider: Provider) -> None:
        """Register a provider."""
        self._providers[provider.name] = provider

    def get(self, name: str) -> Optional[Provider]:
        """Get a provider by name."""
        return self._providers.get(name)

    def list_providers(self) -> list[Provider]:
        """List all registered providers."""
        return list(self._providers.values())

    def list_available(self) -> list[Provider]:
        """List enabled providers with credentials."""
        available = []
        for p in self._providers.values():
            if not p.enabled:
                continue
            # Ollama doesn't need an API key
            if p.provider_type == ProviderType.OLLAMA:
                available.append(p)
            elif p.api_key:
                available.append(p)
        return available

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> ProviderRegistry:
        """Build registry from ice9.yaml providers section."""
        registry = cls()

        for name, conf in config.items():
            # Determine type
            ptype = ProviderType(name) if name in ProviderType.__members__.values() else None
            if not ptype:
                # Try to infer from name
                type_map = {
                    "ollama": ProviderType.OLLAMA,
                    "claude": ProviderType.CLAUDE,
                    "anthropic": ProviderType.CLAUDE,
                    "openai": ProviderType.OPENAI,
                    "groq": ProviderType.GROQ,
                    "mistral": ProviderType.MISTRAL,
                }
                ptype = type_map.get(name.lower(), ProviderType.OPENAI)

            provider = Provider(
                name=name,
                provider_type=ptype,
                base_url=conf.get("base_url", DEFAULT_URLS.get(ptype)),
                api_key=conf.get("api_key", ""),
                model=conf.get("model", ""),
                models=conf.get("models", []),
                enabled=conf.get("enabled", True),
            )
            registry.register(provider)

        return registry
