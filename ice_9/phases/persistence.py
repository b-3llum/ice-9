"""Persistence phase — TA0003: Establish persistent access mechanisms."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class PersistencePhase(PhaseModule):
    """Persistence — identify and validate persistence mechanism opportunities."""

    phase_type = PhaseType.PERSISTENCE
    name = "Persistence"
    description = "Identify persistence opportunities via scheduled tasks, services, and startup"
    required_tools = ["nmap", "crackmapexec"]
    att_ck_techniques = ["T1136", "T1053", "T1547", "T1543"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan persistence assessment tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        for target in scope:
            # Check for writable shares / startup locations
            tasks.append({
                "tool": "crackmapexec",
                "target": target,
                "params": {
                    "protocol": "smb",
                    "args": ["--shares"],
                },
            })

            # Nmap for scheduled task and service enumeration
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-sV", "-p", "135,139,445,5985",
                        "--script", "smb-enum-shares,smb-enum-services",
                    ],
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze persistence opportunities."""
        findings = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            if result.tool == "crackmapexec":
                findings.extend(self._analyze_shares(result))
            elif result.tool == "nmap":
                findings.extend(self._analyze_services(result))

        return findings

    def _analyze_shares(self, result: ToolResult) -> list[Finding]:
        """Flag writable shares usable for persistence."""
        findings = []
        hosts = result.parsed.get("hosts", [])

        for host in hosts:
            ip = host.get("ip", "?")
            shares = host.get("shares", [])
            writable = [s for s in shares if s.get("writable")]
            if writable:
                share_names = ", ".join(s.get("name", "?") for s in writable)
                findings.append(self._create_finding(
                    title=f"Writable shares on {ip}: {share_names}",
                    severity=Severity.HIGH,
                    description=(
                        f"Writable SMB shares found on {ip}: {share_names}. "
                        "These could be used to plant persistence payloads."
                    ),
                    remediation="Restrict write access to shares. Monitor for unauthorized file changes.",
                    att_ck_ids=["T1547.001"],
                ))

        return findings

    def _analyze_services(self, result: ToolResult) -> list[Finding]:
        """Flag services vulnerable to persistence installation."""
        findings = []

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            for port_info in host.get("ports", []):
                if port_info.get("state") != "open":
                    continue
                port = port_info.get("port", 0)
                # RPC enables scheduled task creation
                if port == 135:
                    findings.append(self._create_finding(
                        title=f"RPC exposed on {ip} — scheduled task persistence possible",
                        severity=Severity.MEDIUM,
                        description=f"RPC on {ip}:135 allows remote scheduled task creation for persistence.",
                        remediation="Restrict RPC access. Monitor scheduled task creation events.",
                        att_ck_ids=["T1053.005"],
                    ))

        return findings
