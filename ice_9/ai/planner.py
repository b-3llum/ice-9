"""AI-powered engagement planner — generates plans from scope and RoE."""

from __future__ import annotations

from ice_9.ai.agents import AgentRole
from ice_9.ai.team import TeamOrchestrator
from ice_9.core.models import Campaign


def generate_engagement_plan(
    orchestrator: TeamOrchestrator,
    campaign: Campaign,
) -> str:
    """Have the Coordinator generate an engagement plan."""
    context = orchestrator.get_campaign_context(campaign)

    prompt = (
        "Generate a detailed engagement plan for this red team operation.\n\n"
        "Include:\n"
        "1. Phase prioritization — which ATT&CK tactics to focus on and in what order\n"
        "2. Tool selection — which tools to use for each phase\n"
        "3. Risk assessment — what could go wrong and mitigations\n"
        "4. Timeline estimate — rough time allocation per phase\n"
        "5. Key objectives — what constitutes success\n"
        "6. Rules of engagement compliance — how to stay in scope\n\n"
        "Format as a structured plan with clear sections."
    )

    result = orchestrator.ask_agent(
        AgentRole.COORDINATOR, prompt, context=context
    )

    if result.success:
        return result.content
    return f"Plan generation failed: {result.error}"
