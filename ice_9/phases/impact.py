"""Impact phase — TA0040: Assess potential impact and document attack paths."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class ImpactPhase(PhaseModule):
    """Impact — assess potential impact based on access obtained in prior phases."""

    phase_type = PhaseType.IMPACT
    name = "Impact"
    description = "Impact assessment and attack path documentation based on engagement findings"
    required_tools = []  # Assessment-only phase, no active scanning
    att_ck_techniques = ["T1486", "T1489", "T1490", "T1485"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan impact assessment tasks.

        This phase is primarily documentation-based. Optional connectivity
        checks verify critical service availability as a baseline.
        """
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        # Lightweight service availability check (non-destructive)
        for target in scope:
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": ["-sn", "-T3"],  # Ping only — no service disruption
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Assess potential impact based on engagement context.

        This analyzes what COULD be done with obtained access, not what WAS done.
        No destructive actions are taken or recommended.
        """
        findings = []

        # Count accessible hosts
        accessible_hosts = 0
        for result in results:
            if result.success and result.parsed:
                hosts = result.parsed.get("hosts", [])
                accessible_hosts += sum(
                    1 for h in hosts if h.get("state") == "up"
                )

        # Summarize prior phase findings for impact context
        critical_findings = [
            p for p in campaign.phases
            if any(
                f.severity.value in ("critical", "high")
                for f in p.findings
            )
        ]

        if critical_findings:
            phase_names = [p.name for p in critical_findings]
            findings.append(self._create_finding(
                title=f"High-impact attack paths identified across {len(critical_findings)} phases",
                severity=Severity.HIGH,
                description=(
                    f"Critical/high findings exist in phases: {', '.join(phase_names)}. "
                    f"Combined with access to {accessible_hosts} hosts, "
                    "significant business impact scenarios are feasible."
                ),
                remediation="Address all critical/high findings. Implement defense-in-depth controls.",
                att_ck_ids=["T1486"],
            ))

        # Document scope of access
        if accessible_hosts > 0:
            findings.append(self._create_finding(
                title=f"Scope of access: {accessible_hosts} hosts reachable",
                severity=Severity.INFO,
                description=(
                    f"{accessible_hosts} hosts remain reachable at end of engagement. "
                    "This represents the potential blast radius for impact scenarios."
                ),
                att_ck_ids=["T1489"],
            ))

        # Always add a summary finding
        total_findings = sum(len(p.findings) for p in campaign.phases)
        findings.append(self._create_finding(
            title=f"Engagement impact summary: {total_findings} total findings",
            severity=Severity.INFO,
            description=(
                f"Total findings across all phases: {total_findings}. "
                "Review the full report for detailed remediation guidance."
            ),
        ))

        return findings
