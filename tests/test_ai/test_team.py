"""Tests for the multi-agent TeamOrchestrator dispatch."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from ice_9.ai.agents import AgentRole
from ice_9.ai.team import AgentResult, TeamOrchestrator


def _make_orchestrator(execute):
    """Build a TeamOrchestrator with stubbed registries and agent execution."""
    orch = TeamOrchestrator.__new__(TeamOrchestrator)
    orch.audit = None
    enabled_agent = MagicMock()
    enabled_agent.enabled = True
    orch.agents = MagicMock()
    orch.agents.get.return_value = enabled_agent
    orch._execute_agent = execute
    return orch


def _result(prompt: str) -> AgentResult:
    now = datetime.now(timezone.utc)
    return AgentResult(
        agent_role="tester",
        content=f"handled: {prompt}",
        model="m",
        provider="p",
        started_at=now,
        completed_at=now,
    )


def test_run_team_multi_agent_dispatch():
    """>1 agent must dispatch across threads without needing a running loop.

    Regression: previously used asyncio.get_event_loop().run_until_complete(),
    which raises RuntimeError on 3.12+ in a sync context and inside a running loop.
    """
    calls: list[str] = []

    def execute(agent, prompt, context, model=None):
        calls.append(prompt)
        return _result(prompt)

    orch = _make_orchestrator(execute)
    result = orch.run_team(
        "enumerate",
        roles=[AgentRole.RECON_ANALYST, AgentRole.EXPLOIT_RESEARCHER],
        synthesize=False,
    )

    assert len(result.results) == 2
    assert all(r.success for r in result.results)
    assert calls == ["enumerate", "enumerate"]


def test_run_team_single_agent_dispatch():
    def execute(agent, prompt, context, model=None):
        return _result(prompt)

    orch = _make_orchestrator(execute)
    result = orch.run_team(
        "single",
        roles=[AgentRole.RECON_ANALYST],
        synthesize=False,
    )

    assert len(result.results) == 1
    assert result.results[0].content == "handled: single"
