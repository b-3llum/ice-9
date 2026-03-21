"""AI-generated executive summary for pentest reports."""

from __future__ import annotations

from ice_9.ai.agents import AgentRole
from ice_9.ai.team import TeamOrchestrator
from ice_9.core.models import Campaign, Finding, Severity
from ice_9.db.store import Store


def generate_executive_summary(
    orchestrator: TeamOrchestrator,
    campaign: Campaign,
    store: Store,
) -> str:
    """Generate an AI-written executive summary."""
    findings = store.get_all_findings(campaign.id)
    context = orchestrator.get_campaign_context(campaign)

    # Build findings summary for the LLM
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    findings_brief = "\n".join(
        f"- [{f.severity.value.upper()}] {f.title}"
        + (f" (CVEs: {', '.join(f.cve_ids[:2])})" if f.cve_ids else "")
        for f in findings[:30]
    )

    prompt = (
        "Write a professional executive summary for a penetration test report.\n\n"
        f"Client: {campaign.client or campaign.name}\n"
        f"Total findings: {len(findings)}\n"
        f"Severity breakdown: {severity_counts}\n\n"
        f"Key findings:\n{findings_brief}\n\n"
        "The executive summary should:\n"
        "1. Be 2-3 paragraphs, suitable for C-level readers\n"
        "2. Highlight the most critical risks\n"
        "3. Provide a high-level risk rating (Critical/High/Medium/Low)\n"
        "4. Recommend immediate actions\n"
        "5. Use professional, non-technical language\n"
        "Do NOT include technical details — those go in the findings section."
    )

    result = orchestrator.ask_agent(
        AgentRole.REPORT_WRITER, prompt, context=context
    )

    if result.success:
        return result.content

    # Fallback: template-based summary
    return _template_summary(campaign, findings, severity_counts)


def _template_summary(
    campaign: Campaign,
    findings: list[Finding],
    severity_counts: dict[str, int],
) -> str:
    """Fallback template-based executive summary."""
    client = campaign.client or campaign.name
    total = len(findings)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)

    risk_level = "Low"
    if critical > 0:
        risk_level = "Critical"
    elif high > 0:
        risk_level = "High"
    elif severity_counts.get("medium", 0) > 0:
        risk_level = "Medium"

    return (
        f"A penetration test was conducted against {client}'s infrastructure "
        f"as defined in the rules of engagement. The assessment identified "
        f"{total} finding(s), with an overall risk rating of {risk_level}.\n\n"
        f"Of the {total} findings, {critical} were rated Critical and {high} "
        f"were rated High severity. These findings represent significant risks "
        f"that should be addressed as a priority.\n\n"
        f"Immediate remediation is recommended for all Critical and High severity "
        f"findings. A detailed remediation roadmap is provided in Section 6 of "
        f"this report."
    )
