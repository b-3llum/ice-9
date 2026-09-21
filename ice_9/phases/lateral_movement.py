"""Lateral Movement phase — TA0008: Pivot tracking and movement analysis."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class LateralMovementPhase(PhaseModule):
    """Lateral movement — identify pivot opportunities, track movement paths."""

    phase_type = PhaseType.LATERAL_MOVEMENT
    name = "Lateral Movement"
    description = "Identify pivot points, RDP/SMB/WinRM access, pass-the-hash opportunities"
    required_tools = ["nmap"]
    att_ck_techniques = ["T1021", "T1021.001", "T1021.002", "T1021.006", "T1550"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan lateral movement analysis tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        for target in scope:
            # Scan for lateral movement protocols
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-p", "22,135,139,445,3389,5985,5986",
                        "-sV", "--script",
                        "smb2-security-mode,rdp-ntlm-info,ssh-auth-methods",
                        "-T3",
                    ],
                },
            })

            # WinRM detection
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-p", "5985,5986",
                        "-sV", "--script", "http-title",
                    ],
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze lateral movement opportunities."""
        findings = []
        pivot_map: dict[str, list[str]] = {}  # ip -> available protocols

        for result in results:
            if not result.success or not result.parsed:
                continue

            hosts = result.parsed.get("hosts", [])
            for host in hosts:
                ip = host.get("ip", "?")
                protocols = pivot_map.setdefault(ip, [])

                for port_info in host.get("ports", []):
                    if port_info.get("state") != "open":
                        continue

                    port = port_info.get("port", 0)
                    scripts = port_info.get("scripts", {})

                    # RDP
                    if port == 3389:
                        protocols.append("RDP")
                        # Check NLA
                        if "rdp-ntlm-info" in scripts:
                            findings.append(self._create_finding(
                                title=f"RDP accessible on {ip}",
                                severity=Severity.MEDIUM,
                                description=f"Remote Desktop Protocol is accessible on {ip}:3389",
                                remediation="Restrict RDP access via firewall. Enable NLA. Use jump servers.",
                                att_ck_ids=["T1021.001"],
                            ))

                    # SMB
                    elif port == 445:
                        protocols.append("SMB")
                        if "smb2-security-mode" in scripts:
                            output = scripts["smb2-security-mode"]
                            if "not required" in output.lower():
                                findings.append(self._create_finding(
                                    title=f"SMB signing not required on {ip}",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"SMB signing is not required on {ip}. "
                                        "This enables relay attacks (NTLM relay)."
                                    ),
                                    remediation="Enable and require SMB signing on all systems.",
                                    att_ck_ids=["T1557.001"],
                                ))

                    # WinRM
                    elif port in (5985, 5986):
                        proto = "WinRM-HTTPS" if port == 5986 else "WinRM"
                        protocols.append(proto)
                        findings.append(self._create_finding(
                            title=f"{proto} accessible on {ip}:{port}",
                            severity=Severity.MEDIUM,
                            description=f"Windows Remote Management is accessible on {ip}:{port}",
                            remediation="Restrict WinRM access. Use JEA (Just Enough Administration).",
                            att_ck_ids=["T1021.006"],
                        ))

                    # SSH
                    elif port == 22:
                        protocols.append("SSH")

        # Generate pivot map finding
        pivot_hosts = {ip: protos for ip, protos in pivot_map.items() if len(protos) >= 2}
        if pivot_hosts:
            detail_lines = [
                f"  {ip}: {', '.join(protos)}" for ip, protos in pivot_hosts.items()
            ]
            findings.append(self._create_finding(
                title=f"Potential pivot points identified ({len(pivot_hosts)} hosts)",
                severity=Severity.INFO,
                description=(
                    "Hosts with multiple remote access protocols available:\n"
                    + "\n".join(detail_lines[:20])
                ),
                att_ck_ids=["T1021"],
            ))

        return findings
