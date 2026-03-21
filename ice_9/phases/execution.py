"""Execution phase — TA0002: Command execution and remote code execution validation."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class ExecutionPhase(PhaseModule):
    """Execution — validate command execution capabilities on compromised hosts."""

    phase_type = PhaseType.EXECUTION
    name = "Execution"
    description = "Command execution validation via WMI, SMB, and scheduled tasks"
    required_tools = ["crackmapexec"]
    att_ck_techniques = ["T1059", "T1047", "T1053", "T1569"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan execution validation tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        for target in scope:
            # CrackMapExec SMB execution check
            tasks.append({
                "tool": "crackmapexec",
                "target": target,
                "params": {
                    "protocol": "smb",
                    "args": ["--shares"],  # Enumerate shares as execution prerequisite
                },
            })

            # CrackMapExec WMI execution check
            tasks.append({
                "tool": "crackmapexec",
                "target": target,
                "params": {
                    "protocol": "winrm",
                },
            })

            # Nmap for script execution services
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-sV", "-p", "135,445,5985,5986,47001",
                        "--script", "smb-enum-shares,smb-os-discovery",
                    ],
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze execution capability results."""
        findings = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            if result.tool == "crackmapexec":
                findings.extend(self._analyze_cme(result))
            elif result.tool == "nmap":
                findings.extend(self._analyze_nmap(result))

        return findings

    def _analyze_cme(self, result: ToolResult) -> list[Finding]:
        """Analyze CrackMapExec results for execution capabilities."""
        findings = []
        hosts = result.parsed.get("hosts", [])

        for host in hosts:
            ip = host.get("ip", "?")
            if host.get("pwned"):
                findings.append(self._create_finding(
                    title=f"Command execution confirmed on {ip}",
                    severity=Severity.CRITICAL,
                    description=f"Successfully achieved command execution on {ip} via {host.get('protocol', 'SMB')}.",
                    remediation="Restrict administrative access. Enable credential guard.",
                    att_ck_ids=["T1059"],
                ))
            if host.get("signing") is False:
                findings.append(self._create_finding(
                    title=f"SMB signing not required on {ip}",
                    severity=Severity.HIGH,
                    description=f"SMB signing is not enforced on {ip}, enabling relay attacks.",
                    remediation="Enable and require SMB signing via Group Policy.",
                    att_ck_ids=["T1557.001"],
                ))

        return findings

    def _analyze_nmap(self, result: ToolResult) -> list[Finding]:
        """Flag WinRM and other execution-capable services."""
        findings = []

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            for port_info in host.get("ports", []):
                if port_info.get("state") != "open":
                    continue
                port = port_info.get("port", 0)
                if port in (5985, 5986):
                    findings.append(self._create_finding(
                        title=f"WinRM exposed on {ip}:{port}",
                        severity=Severity.MEDIUM,
                        description=f"WinRM service on {ip}:{port} enables remote command execution.",
                        remediation="Restrict WinRM access to management networks. Use certificate auth.",
                        att_ck_ids=["T1059.001", "T1021.006"],
                    ))

        return findings
