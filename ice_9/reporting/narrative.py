"""Attack narrative builder — kill-chain story from findings and tasks."""

from __future__ import annotations

from ice_9.ai.agents import AgentRole
from ice_9.ai.team import TeamOrchestrator
from ice_9.core.models import Campaign, Finding, PHASE_NAMES
from ice_9.db.store import Store


def generate_attack_narrative(
    orchestrator: TeamOrchestrator,
    campaign: Campaign,
    store: Store,
) -> str:
    """Generate an AI-written attack narrative (kill chain story)."""
    context = orchestrator.get_campaign_context(campaign)
    findings = store.get_all_findings(campaign.id)

    # Group findings by phase
    phase_findings: dict[str, list[str]] = {}
    for phase in campaign.phases:
        if phase.status.value in ("completed", "in_progress"):
            phase_key = f"{phase.phase_type.value} ({phase.name})"
            pf = [f for f in findings if f.phase_id == phase.id]
            if pf:
                phase_findings[phase_key] = [
                    f"[{f.severity.value.upper()}] {f.title}: {f.description[:200]}"
                    for f in pf
                ]

    if not phase_findings:
        return "No completed phases with findings to narrate."

    findings_by_phase = "\n\n".join(
        f"### {phase}\n" + "\n".join(f"- {f}" for f in flist)
        for phase, flist in phase_findings.items()
    )

    prompt = (
        "Write an attack narrative for a penetration test report. "
        "This should read as a story describing the attack chain — "
        "how the tester moved from initial reconnaissance through "
        "exploitation, step by step.\n\n"
        f"Campaign: {campaign.name}\n"
        f"Client: {campaign.client or 'N/A'}\n\n"
        f"Findings by phase:\n{findings_by_phase}\n\n"
        "Guidelines:\n"
        "1. Write in past tense, third person ('The tester discovered...')\n"
        "2. Follow the kill chain chronologically\n"
        "3. Reference specific findings and techniques\n"
        "4. Highlight where defenses failed or succeeded\n"
        "5. Keep it professional and factual\n"
        "6. Include ATT&CK technique references where relevant"
    )

    result = orchestrator.ask_agent(
        AgentRole.REPORT_WRITER, prompt, context=context
    )

    return result.content if result.success else "Narrative generation failed."
