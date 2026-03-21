"""Resource Development phase — TA0042: Infrastructure setup and validation."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class ResourceDevPhase(PhaseModule):
    """Resource Development — validate C2 infrastructure, staging servers, and tooling."""

    phase_type = PhaseType.RESOURCE_DEV
    name = "Resource Development"
    description = "Infrastructure validation, C2 readiness checks, and staging verification"
    required_tools = ["nmap"]
    att_ck_techniques = ["T1583", "T1584", "T1587", "T1588"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan resource development validation tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        # Verify infrastructure is reachable and services are running
        for target in scope:
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "quick",
                    "args": ["-sn"],  # Host alive check
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze infrastructure readiness."""
        findings = []

        reachable = 0
        unreachable = 0

        for result in results:
            if not result.success:
                unreachable += 1
                continue
            hosts = result.parsed.get("hosts", [])
            for host in hosts:
                if host.get("state") == "up":
                    reachable += 1
                else:
                    unreachable += 1

        if reachable > 0:
            findings.append(self._create_finding(
                title=f"Infrastructure validation: {reachable} hosts reachable",
                severity=Severity.INFO,
                description=f"{reachable} target hosts confirmed reachable during resource development checks.",
                att_ck_ids=["T1583"],
            ))

        if unreachable > 0:
            findings.append(self._create_finding(
                title=f"Unreachable targets: {unreachable} hosts",
                severity=Severity.LOW,
                description=f"{unreachable} hosts in scope did not respond to connectivity checks.",
                remediation="Verify network routing, firewall rules, and host availability.",
                att_ck_ids=["T1583"],
            ))

        return findings
