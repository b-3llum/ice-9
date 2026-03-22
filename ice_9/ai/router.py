"""Intelligent model router — selects optimal provider per task."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from ice_9.ai.providers import Provider, ProviderRegistry, ProviderType


class TaskComplexity(str, Enum):
    TRIVIAL = "trivial"      # Template fill, simple extraction
    LOW = "low"              # Summarization, formatting
    MEDIUM = "medium"        # Analysis, code review
    HIGH = "high"            # Multi-step reasoning, exploit research
    CRITICAL = "critical"    # Novel attack planning, complex synthesis


# Ordered for comparison
_COMPLEXITY_RANK = {
    TaskComplexity.TRIVIAL: 0,
    TaskComplexity.LOW: 1,
    TaskComplexity.MEDIUM: 2,
    TaskComplexity.HIGH: 3,
    TaskComplexity.CRITICAL: 4,
}


@dataclass
class RoutingDecision:
    """Result of model routing — which provider/model to use and why."""

    provider: Provider
    model: str
    reason: str
    complexity: TaskComplexity
    estimated_tokens: int = 0
    fallback_chain: list[Provider] = field(default_factory=list)


class ModelRouter:
    """Scores task complexity and routes to the optimal LLM provider.

    Uses regex-based heuristics to estimate prompt complexity, then selects
    between local (Ollama) and cloud (Claude/OpenAI/etc.) providers based
    on complexity, token budget, and latency history.
    """

    # Patterns that signal high complexity
    HIGH_COMPLEXITY_SIGNALS: list[str] = [
        r"(?:analyze|synthesize|compare)\s+(?:multiple|several|all)",
        r"(?:design|architect|plan)\s+(?:a|the)\s+\w+\s+system",
        r"(?:write|create|generate)\s+(?:a|the)\s+(?:full|complete|comprehensive)",
        r"(?:exploit|attack|bypass)\s+(?:chain|path|vector)",
        r"(?:why|how)\s+(?:does|would|could|should)\s+.{30,}",
        r"step.by.step",
        r"trade.?offs?",
    ]

    # Patterns that signal low complexity
    LOW_COMPLEXITY_SIGNALS: list[str] = [
        r"^(?:list|show|get|find|search|count)\s",
        r"^(?:format|convert|parse|extract)\s",
        r"^(?:what is|define|explain briefly)\s",
        r"(?:yes|no|true|false)\s*\??$",
        r"^summarize\s+(?:this|the)\s+\w+$",
    ]

    # Tasks that REQUIRE cloud models
    CLOUD_REQUIRED: list[str] = [
        r"(?:novel|zero.day|unknown)\s+(?:exploit|vulnerability)",
        r"(?:write|generate)\s+(?:a\s+)?(?:full|detailed)\s+report",
        r"(?:executive|client)\s+summary",
        r"multi.agent\s+synthesis",
    ]

    def __init__(
        self,
        provider_registry: ProviderRegistry,
        local_context_limit: int = 8192,
        cost_weight: float = 0.3,
        latency_weight: float = 0.3,
        quality_weight: float = 0.4,
    ) -> None:
        self.providers = provider_registry
        self.local_context_limit = local_context_limit
        self.cost_weight = cost_weight
        self.latency_weight = latency_weight
        self.quality_weight = quality_weight
        self._latency_history: dict[str, list[float]] = {}

    def route(
        self,
        prompt: str,
        context: str = "",
        force_provider: Optional[str] = None,
        min_quality: TaskComplexity = TaskComplexity.TRIVIAL,
    ) -> RoutingDecision:
        """Select the best provider for a given prompt.

        Args:
            prompt: The user/agent prompt text.
            context: Additional context (campaign data, memory, etc.).
            force_provider: Override — use this provider name directly.
            min_quality: Minimum complexity threshold for cloud routing.

        Returns:
            A RoutingDecision with the selected provider, model, and reasoning.
        """
        # Force override
        if force_provider:
            provider = self.providers.get(force_provider)
            if provider:
                return RoutingDecision(
                    provider=provider,
                    model=provider.default_model,
                    reason=f"Forced to {force_provider}",
                    complexity=self._score_complexity(prompt),
                )

        complexity = self._score_complexity(prompt)
        total_tokens = self._estimate_tokens(prompt, context)

        # Rule 1: If cloud is required by pattern, go cloud
        if self._requires_cloud(prompt):
            return self._select_cloud(
                complexity, total_tokens, "Pattern requires cloud model",
            )

        # Rule 2: If token count exceeds local context, go cloud
        if total_tokens > self.local_context_limit:
            return self._select_cloud(
                complexity,
                total_tokens,
                f"Token estimate ({total_tokens}) exceeds local limit ({self.local_context_limit})",
            )

        # Rule 3: High/critical complexity with quality floor
        if _COMPLEXITY_RANK[complexity] >= _COMPLEXITY_RANK[TaskComplexity.HIGH]:
            if _COMPLEXITY_RANK[min_quality] >= _COMPLEXITY_RANK[TaskComplexity.HIGH]:
                return self._select_cloud(
                    complexity,
                    total_tokens,
                    f"Complexity={complexity.value}, quality floor={min_quality.value}",
                )
            # HIGH can go local with a capable model
            return self._select_local_capable(complexity, total_tokens)

        # Rule 4: Default to local for TRIVIAL/LOW/MEDIUM
        return self._select_local(complexity, total_tokens)

    def _score_complexity(self, prompt: str) -> TaskComplexity:
        """Score task complexity from prompt text using heuristics."""
        prompt_lower = prompt.lower()
        score = 0

        for pattern in self.HIGH_COMPLEXITY_SIGNALS:
            if re.search(pattern, prompt_lower):
                score += 2

        for pattern in self.LOW_COMPLEXITY_SIGNALS:
            if re.search(pattern, prompt_lower):
                score -= 2

        # Length heuristic
        if len(prompt) > 2000:
            score += 2
        elif len(prompt) > 500:
            score += 1
        elif len(prompt) < 50:
            score -= 1

        # Multi-part questions
        if prompt.count("?") > 2:
            score += 1
        if prompt.count("\n") > 10:
            score += 1

        if score >= 4:
            return TaskComplexity.CRITICAL
        elif score >= 2:
            return TaskComplexity.HIGH
        elif score >= 0:
            return TaskComplexity.MEDIUM
        elif score >= -2:
            return TaskComplexity.LOW
        else:
            return TaskComplexity.TRIVIAL

    def _requires_cloud(self, prompt: str) -> bool:
        """Check if the prompt contains patterns that require cloud models."""
        prompt_lower = prompt.lower()
        return any(re.search(p, prompt_lower) for p in self.CLOUD_REQUIRED)

    def _estimate_tokens(self, prompt: str, context: str) -> int:
        """Rough token estimate: ~4 chars per token."""
        return (len(prompt) + len(context)) // 4

    def _select_cloud(
        self,
        complexity: TaskComplexity,
        tokens: int,
        reason: str,
    ) -> RoutingDecision:
        """Pick the best cloud provider. Prefer Claude, fallback to others."""
        preference_order = [
            ProviderType.CLAUDE,
            ProviderType.OPENAI,
            ProviderType.GROQ,
            ProviderType.MISTRAL,
        ]
        for ptype in preference_order:
            for p in self.providers.list_available():
                if p.provider_type == ptype:
                    fallbacks = [
                        fb
                        for fb in self.providers.list_available()
                        if fb.name != p.name
                        and fb.provider_type != ProviderType.OLLAMA
                    ]
                    return RoutingDecision(
                        provider=p,
                        model=p.default_model,
                        reason=reason,
                        complexity=complexity,
                        estimated_tokens=tokens,
                        fallback_chain=fallbacks,
                    )

        # No cloud available — fall back to most capable local
        return self._select_local_capable(complexity, tokens)

    def _select_local(
        self,
        complexity: TaskComplexity,
        tokens: int,
    ) -> RoutingDecision:
        """Pick the default local (Ollama) model."""
        for p in self.providers.list_available():
            if p.provider_type == ProviderType.OLLAMA:
                return RoutingDecision(
                    provider=p,
                    model=p.default_model,
                    reason=f"Local sufficient for {complexity.value}",
                    complexity=complexity,
                    estimated_tokens=tokens,
                    fallback_chain=list(self.providers.list_available()),
                )
        # No local available — go cloud
        return self._select_cloud(
            complexity, tokens, "No local provider available",
        )

    def _select_local_capable(
        self,
        complexity: TaskComplexity,
        tokens: int,
    ) -> RoutingDecision:
        """Pick the most capable local model (prefer larger parameter counts)."""
        large_model_tags = ["70b", "34b", "22b", "14b"]

        for p in self.providers.list_available():
            if p.provider_type == ProviderType.OLLAMA:
                capable_model = None
                for m in p.models:
                    if any(tag in m for tag in large_model_tags):
                        capable_model = m
                        break
                return RoutingDecision(
                    provider=p,
                    model=capable_model or p.default_model,
                    reason=f"Local capable model for {complexity.value}",
                    complexity=complexity,
                    estimated_tokens=tokens,
                    fallback_chain=[
                        fb
                        for fb in self.providers.list_available()
                        if fb.provider_type != ProviderType.OLLAMA
                    ],
                )
        return self._select_cloud(
            complexity, tokens, "No local provider available",
        )

    def record_latency(self, provider_name: str, latency_ms: float) -> None:
        """Track response latency for adaptive routing."""
        if provider_name not in self._latency_history:
            self._latency_history[provider_name] = []
        history = self._latency_history[provider_name]
        history.append(latency_ms)
        # Keep a sliding window
        if len(history) > 50:
            self._latency_history[provider_name] = history[-50:]

    def avg_latency(self, provider_name: str) -> float:
        """Get average latency for a provider in milliseconds."""
        history = self._latency_history.get(provider_name, [])
        return sum(history) / len(history) if history else 0.0
