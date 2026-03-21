"""Multi-agent team orchestrator — parallel dispatch and result merging."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ice_9.ai.agents import Agent, AgentRegistry, AgentRole
from ice_9.ai.llm import LLMClient, LLMClientWithFallback, LLMResponse
from ice_9.ai.providers import Provider, ProviderRegistry
from ice_9.core.models import Campaign
from ice_9.core.campaign import get_campaign_progress
from ice_9.core.audit import AuditLogger


@dataclass
class AgentResult:
    """Result from a single agent execution."""

    agent_role: str
    content: str
    model: str
    provider: str
    started_at: datetime
    completed_at: datetime
    usage: dict[str, int] | None = None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()


@dataclass
class TeamResult:
    """Aggregated results from a team run."""

    results: list[AgentResult] = field(default_factory=list)
    synthesis: str = ""  # Coordinator's synthesis of all results
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    @property
    def successful(self) -> list[AgentResult]:
        return [r for r in self.results if r.success]

    @property
    def failed(self) -> list[AgentResult]:
        return [r for r in self.results if not r.success]


class TeamOrchestrator:
    """Orchestrates multiple AI agents working in parallel."""

    def __init__(
        self,
        provider_registry: ProviderRegistry,
        agent_registry: AgentRegistry,
        audit: Optional[AuditLogger] = None,
    ) -> None:
        self.providers = provider_registry
        self.agents = agent_registry
        self.audit = audit
        self.client = LLMClient(timeout=120)
        self.fallback_client = LLMClientWithFallback(self.client)

    def close(self) -> None:
        self.client.close()

    def ask_agent(
        self,
        role: AgentRole | str,
        prompt: str,
        context: str = "",
        model: Optional[str] = None,
    ) -> AgentResult:
        """Send a prompt to a specific agent."""
        agent = self.agents.get(role)
        if not agent:
            return AgentResult(
                agent_role=str(role),
                content="",
                model="",
                provider="",
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                error=f"Agent not found: {role}",
            )

        return self._execute_agent(agent, prompt, context, model)

    def run_team(
        self,
        prompt: str,
        context: str = "",
        roles: list[AgentRole] | None = None,
        synthesize: bool = True,
    ) -> TeamResult:
        """Run multiple agents in parallel and optionally synthesize results."""
        team_result = TeamResult(started_at=datetime.utcnow())

        # Determine which agents to run
        target_roles = roles or [
            r for r in AgentRole if r != AgentRole.COORDINATOR
        ]
        agents_to_run = [
            self.agents.get(r) for r in target_roles
        ]
        agents_to_run = [a for a in agents_to_run if a and a.enabled]

        # Run agents in parallel using asyncio
        results = asyncio.get_event_loop().run_until_complete(
            self._run_parallel(agents_to_run, prompt, context)
        ) if len(agents_to_run) > 1 else [
            self._execute_agent(a, prompt, context) for a in agents_to_run
        ]

        team_result.results = results

        # Synthesize with Coordinator
        if synthesize and results:
            synthesis = self._synthesize(results, prompt, context)
            team_result.synthesis = synthesis

        team_result.completed_at = datetime.utcnow()

        # Audit log
        if self.audit:
            self.audit.log(
                "team.run",
                details={
                    "agents": [r.agent_role for r in results],
                    "successful": len(team_result.successful),
                    "failed": len(team_result.failed),
                    "has_synthesis": bool(team_result.synthesis),
                },
            )

        return team_result

    async def _run_parallel(
        self,
        agents: list[Agent],
        prompt: str,
        context: str,
    ) -> list[AgentResult]:
        """Run agents concurrently."""
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(
                None, self._execute_agent, agent, prompt, context, None
            )
            for agent in agents
        ]
        return await asyncio.gather(*tasks, return_exceptions=False)

    def _execute_agent(
        self,
        agent: Agent,
        prompt: str,
        context: str = "",
        model: Optional[str] = None,
    ) -> AgentResult:
        """Execute a single agent."""
        from ice_9.core.events import event_bus, Event, EventType

        started = datetime.utcnow()

        # Build provider fallback chain
        providers: list[Provider] = []
        primary = self.providers.get(agent.provider_name)
        if primary:
            providers.append(primary)
        for fb_name in agent.fallback_providers:
            fb = self.providers.get(fb_name)
            if fb:
                providers.append(fb)

        if not providers:
            return AgentResult(
                agent_role=agent.role.value,
                content="",
                model="",
                provider="",
                started_at=started,
                completed_at=datetime.utcnow(),
                error=f"No providers available for agent {agent.role.value}",
            )

        # Build messages
        messages = agent.build_messages(prompt, context)
        use_model = model or agent.model

        event_bus.emit(Event(
            type=EventType.AI_REQUEST,
            data={
                "agent": agent.role.value,
                "provider": agent.provider_name,
                "model": use_model or (primary.default_model if primary else ""),
                "prompt_preview": prompt[:200],
            },
        ))

        try:
            response = self.fallback_client.chat_with_fallback(
                providers=providers,
                messages=messages,
                model=use_model,
                temperature=agent.temperature,
                max_tokens=agent.max_tokens,
            )

            event_bus.emit(Event(
                type=EventType.AI_RESPONSE,
                data={
                    "agent": agent.role.value,
                    "provider": response.provider,
                    "model": response.model,
                    "content_length": len(response.content),
                    "content_preview": response.content[:200],
                },
            ))

            return AgentResult(
                agent_role=agent.role.value,
                content=response.content,
                model=response.model,
                provider=response.provider,
                started_at=started,
                completed_at=datetime.utcnow(),
                usage=response.usage,
            )
        except Exception as e:
            return AgentResult(
                agent_role=agent.role.value,
                content="",
                model="",
                provider="",
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e),
            )

    def _synthesize(
        self, results: list[AgentResult], original_prompt: str, context: str
    ) -> str:
        """Have the Coordinator synthesize results from other agents."""
        coordinator = self.agents.get(AgentRole.COORDINATOR)
        if not coordinator:
            return ""

        # Build synthesis prompt
        agent_outputs = []
        for r in results:
            if r.success:
                agent_outputs.append(
                    f"=== {r.agent_role.upper()} ===\n{r.content}\n"
                )

        synthesis_prompt = (
            f"Original task: {original_prompt}\n\n"
            f"Your team has analyzed this. Here are their outputs:\n\n"
            + "\n".join(agent_outputs)
            + "\n\nSynthesize these into a unified assessment. "
            "Highlight key findings, conflicts, and recommended next steps."
        )

        result = self._execute_agent(coordinator, synthesis_prompt, context)
        return result.content if result.success else f"Synthesis failed: {result.error}"

    def get_campaign_context(self, campaign: Campaign) -> str:
        """Build a context string from campaign data for agents."""
        progress = get_campaign_progress(campaign)
        scope = ", ".join(campaign.rules_of_engagement.scope)
        exclusions = ", ".join(campaign.rules_of_engagement.exclusions)

        lines = [
            f"Campaign: {campaign.name} (ID: {campaign.id})",
            f"Status: {campaign.status.value}",
            f"Scope: {scope}",
        ]
        if exclusions:
            lines.append(f"Exclusions: {exclusions}")
        if campaign.rules_of_engagement.testing_window:
            lines.append(f"Testing window: {campaign.rules_of_engagement.testing_window}")
        lines.append(f"Progress: {progress['progress_pct']}% ({progress['completed']}/{progress['total_phases']} phases)")
        lines.append(f"Total findings: {progress['findings']}")

        # Active phases
        active = [p for p in campaign.phases if p.status.value == "in_progress"]
        if active:
            lines.append(f"Active phases: {', '.join(p.name for p in active)}")

        return "\n".join(lines)
