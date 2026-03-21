"""Discovery phase — TA0007: Internal network enumeration."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class DiscoveryPhase(PhaseModule):
    """Discovery phase — internal enumeration of systems, shares, and services."""

    phase_type = PhaseType.DISCOVERY
    name = "Discovery"
    description = "Internal network enumeration — systems, shares, services, AD objects"
    required_tools = ["nmap"]
    att_ck_techniques = ["T1018", "T1083", "T1135", "T1069", "T1087"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan discovery tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        for target in scope:
            # Service version detection
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": ["-sV", "-sC", "--script", "smb-enum-shares,smb-enum-users,smb-os-discovery", "-p", "445,139,135,88,389,636,3268,3269"],
                },
            })

            # SNMP enumeration
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": ["-sU", "-p", "161", "--script", "snmp-info,snmp-interfaces,snmp-processes"],
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze discovery results."""
        findings = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            hosts = result.parsed.get("hosts", [])
            for host in hosts:
                ip = host.get("ip", "?")
                for port_info in host.get("ports", []):
                    if port_info.get("state") != "open":
                        continue

                    scripts = port_info.get("scripts", {})

                    # SMB shares
                    if "smb-enum-shares" in scripts:
                        output = scripts["smb-enum-shares"]
                        if "READ" in output or "WRITE" in output:
                            findings.append(self._create_finding(
                                title=f"Accessible SMB shares on {ip}",
                                severity=Severity.MEDIUM,
                                description=f"SMB shares with read/write access found on {ip}:\n{output[:500]}",
                                remediation="Review share permissions. Remove unnecessary shares and restrict access.",
                                att_ck_ids=["T1135"],
                            ))

                    # SNMP community strings
                    if "snmp-info" in scripts:
                        findings.append(self._create_finding(
                            title=f"SNMP service accessible on {ip}",
                            severity=Severity.MEDIUM,
                            description=f"SNMP responded on {ip}, potentially with default community strings.",
                            remediation="Disable SNMP if not needed. Change community strings from defaults. Use SNMPv3.",
                            att_ck_ids=["T1602"],
                        ))

                    # Domain controller detection
                    port_num = port_info.get("port", 0)
                    if port_num == 88:  # Kerberos
                        findings.append(self._create_finding(
                            title=f"Domain Controller detected: {ip}",
                            severity=Severity.INFO,
                            description=f"Kerberos (88/tcp) is open on {ip}, indicating a Domain Controller.",
                            att_ck_ids=["T1018"],
                        ))

        return findings
