"""Unified LLM client with provider abstraction and fallback chains."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from ice_9.ai.providers import Provider, ProviderType


@dataclass
class LLMResponse:
    """Response from an LLM call."""

    content: str
    model: str
    provider: str
    usage: dict[str, int] | None = None
    raw: dict[str, Any] | None = None


class LLMClient:
    """Unified client that routes to different LLM providers."""

    def __init__(self, timeout: int = 120) -> None:
        self.timeout = timeout
        self._http = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def chat(
        self,
        provider: Provider,
        messages: list[dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a chat completion request to the given provider."""
        use_model = model or provider.default_model

        if provider.provider_type == ProviderType.CLAUDE:
            return self._chat_claude(provider, messages, use_model, temperature, max_tokens)
        elif provider.provider_type == ProviderType.OLLAMA:
            return self._chat_ollama(provider, messages, use_model, temperature)
        else:
            # OpenAI-compatible: OpenAI, Groq, Mistral
            return self._chat_openai_compat(provider, messages, use_model, temperature, max_tokens)

    def _chat_claude(
        self,
        provider: Provider,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Call Claude/Anthropic API."""
        import anthropic

        client = anthropic.Anthropic(api_key=provider.api_key)

        # Extract system message if present
        system_msg = ""
        chat_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                chat_messages.append(msg)

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": chat_messages,
            "temperature": temperature,
        }
        if system_msg:
            kwargs["system"] = system_msg

        response = client.messages.create(**kwargs)

        return LLMResponse(
            content=response.content[0].text,
            model=model,
            provider=provider.name,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )

    def _chat_ollama(
        self,
        provider: Provider,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
    ) -> LLMResponse:
        """Call Ollama API."""
        url = f"{provider.base_url}/api/chat"
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }

        response = self._http.post(url, json=payload)
        response.raise_for_status()
        data = response.json()

        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=model,
            provider=provider.name,
            usage={
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
            },
            raw=data,
        )

    def _chat_openai_compat(
        self,
        provider: Provider,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Call OpenAI-compatible API (OpenAI, Groq, Mistral)."""
        from openai import OpenAI

        base_url = provider.base_url
        if provider.provider_type == ProviderType.GROQ:
            base_url = base_url or "https://api.groq.com/openai/v1"
        elif provider.provider_type == ProviderType.MISTRAL:
            base_url = base_url or "https://api.mistral.ai/v1"

        client = OpenAI(api_key=provider.api_key, base_url=base_url)

        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        choice = response.choices[0]
        usage = {}
        if response.usage:
            usage = {
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens,
            }

        return LLMResponse(
            content=choice.message.content or "",
            model=model,
            provider=provider.name,
            usage=usage,
        )


class LLMClientWithFallback:
    """LLM client with fallback chain support."""

    def __init__(self, client: LLMClient) -> None:
        self.client = client

    def chat_with_fallback(
        self,
        providers: list[Provider],
        messages: list[dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Try providers in order, falling back on failure."""
        last_error: Exception | None = None

        for provider in providers:
            try:
                return self.client.chat(
                    provider=provider,
                    messages=messages,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except Exception as e:
                last_error = e
                continue

        raise RuntimeError(
            f"All providers failed. Last error: {last_error}"
        )
