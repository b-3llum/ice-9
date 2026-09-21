"""Unified LLM client with provider abstraction and fallback chains."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

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
        model: str | None = None,
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

        # The content list can be empty or lead with a non-text block (e.g. on a
        # max_tokens stop or tool-use response), so guard against IndexError.
        text_blocks = [b.text for b in response.content if getattr(b, "type", None) == "text"]

        return LLMResponse(
            content=text_blocks[0] if text_blocks else "",
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
        """Call Ollama API with streaming for real-time token visibility."""
        from ice_9.core.events import Event, EventType, event_bus

        url = f"{provider.base_url}/api/chat"
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            "options": {"temperature": temperature},
        }

        content_parts: list[str] = []
        prompt_tokens = 0
        completion_tokens = 0
        chunk_buffer: list[str] = []

        with self._http.stream("POST", url, json=payload) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue

                token = chunk.get("message", {}).get("content", "")
                if token:
                    content_parts.append(token)
                    chunk_buffer.append(token)

                    # Emit AI_CHUNK every ~10 tokens to avoid flooding
                    if len(chunk_buffer) >= 10:
                        event_bus.emit(Event(
                            type=EventType.AI_CHUNK,
                            data={"model": model, "provider": provider.name, "tokens": "".join(chunk_buffer)},
                        ))
                        chunk_buffer = []

                if chunk.get("done"):
                    prompt_tokens = chunk.get("prompt_eval_count", 0)
                    completion_tokens = chunk.get("eval_count", 0)

        # Flush remaining buffer
        if chunk_buffer:
            event_bus.emit(Event(
                type=EventType.AI_CHUNK,
                data={"model": model, "provider": provider.name, "tokens": "".join(chunk_buffer)},
            ))

        return LLMResponse(
            content="".join(content_parts),
            model=model,
            provider=provider.name,
            usage={
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            },
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
        model: str | None = None,
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
