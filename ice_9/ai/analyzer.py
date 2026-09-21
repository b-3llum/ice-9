"""AI-powered output analyzer — suggests next techniques based on findings."""

from __future__ import annotations

from ice_9.ai.agents import AgentRole
from ice_9.ai.team import TeamOrchestrator, TeamResult
from ice_9.core.models import Campaign, Finding
from ice_9.db.store import Store


def analyze_findings(
    orchestrator: TeamOrchestrator,
    campaign: Campaign,
    store: Store,
) -> TeamResult:
    """Have the team analyze all campaign findings and suggest next steps."""
    context = orchestrator.get_campaign_context(campaign)

    # Gather findings
    all_findings = store.get_all_findings(campaign.id)
    if not all_findings:
        result = orchestrator.ask_agent(
            AgentRole.COORDINATOR,
            "No findings have been recorded yet. Suggest initial reconnaissance steps based on the campaign scope.",
            context=context,
        )
        team_result = TeamResult()
        team_result.results = [result]
        team_result.synthesis = result.content if result.success else ""
        return team_result

    # Build findings summary
    findings_text = _format_findings(all_findings)

    prompt = (
        f"Analyze these {len(all_findings)} findings from the current engagement:\n\n"
        f"{findings_text}\n\n"
        "Based on these findings:\n"
        "1. What are the most critical attack paths?\n"
        "2. What techniques should we try next?\n"
        "3. Are there any quick wins we're missing?\n"
        "4. What additional information do we need to gather?"
    )

    # Run relevant agents in parallel
    return orchestrator.run_team(
        prompt=prompt,
        context=context,
        roles=[AgentRole.RECON_ANALYST, AgentRole.EXPLOIT_RESEARCHER],
        synthesize=True,
    )


def analyze_tool_output(
    orchestrator: TeamOrchestrator,
    tool_name: str,
    output: str,
    campaign: Campaign,
) -> str:
    """Have the recon analyst analyze raw tool output."""
    context = orchestrator.get_campaign_context(campaign)

    prompt = (
        f"Analyze this {tool_name} output and identify:\n"
        "1. Notable findings (vulnerabilities, misconfigurations)\n"
        "2. High-value targets\n"
        "3. Recommended next steps\n"
        "4. Severity assessment\n\n"
        f"Tool output:\n```\n{output[:8000]}\n```"
    )

    result = orchestrator.ask_agent(
        AgentRole.RECON_ANALYST, prompt, context=context
    )

    return result.content if result.success else f"Analysis failed: {result.error}"


def _format_findings(findings: list[Finding]) -> str:
    """Format findings into a text summary for LLM consumption."""
    lines = []
    for f in findings[:50]:  # Cap at 50 to stay within token limits
        line = f"- [{f.severity.value.upper()}] {f.title}"
        if f.cve_ids:
            line += f" (CVEs: {', '.join(f.cve_ids[:3])})"
        if f.att_ck_ids:
            line += f" [ATT&CK: {', '.join(f.att_ck_ids[:3])}]"
        if f.cvss:
            line += f" CVSS:{f.cvss}"
        lines.append(line)
    return "\n".join(lines)
