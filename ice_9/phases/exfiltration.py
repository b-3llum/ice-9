"""Exfiltration phase — TA0010: Assess outbound data exfiltration channels."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class ExfiltrationPhase(PhaseModule):
    """Exfiltration — assess available outbound channels for data exfiltration."""

    phase_type = PhaseType.EXFILTRATION
    name = "Exfiltration"
    description = "Outbound channel assessment for DNS, HTTP, ICMP, and protocol-based exfiltration"
    required_tools = ["nmap"]
    att_ck_techniques = ["T1048", "T1041", "T1567"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan exfiltration channel assessment tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        for target in scope:
            # Check outbound connectivity on common exfil ports
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-sV", "-p",
                        "22,53,80,443,8080,8443",
                    ],
                },
            })

            # DNS resolution check (port 53)
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-sU", "-p", "53,123,161",
                        "--script", "dns-recursion",
                    ],
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze exfiltration channel availability."""
        findings = []
        channels: dict[str, list[str]] = {}  # channel_type -> list of IPs

        for result in results:
            if not result.success or not result.parsed:
                continue

            for host in result.parsed.get("hosts", []):
                ip = host.get("ip", "?")
                for port_info in host.get("ports", []):
                    if port_info.get("state") != "open":
                        continue
                    port = port_info.get("port", 0)
                    channel = self._classify_channel(port)
                    if channel:
                        channels.setdefault(channel, []).append(f"{ip}:{port}")

                    # Check for DNS recursion (usable for DNS tunneling)
                    scripts = port_info.get("scripts", {})
                    if "dns-recursion" in scripts and "recursion" in scripts["dns-recursion"].lower():
                        channels.setdefault("DNS Tunnel", []).append(f"{ip}:53")

        # Generate findings per channel
        for channel, endpoints in channels.items():
            technique = {
                "HTTP/HTTPS": "T1041",
                "DNS": "T1048.003",
                "DNS Tunnel": "T1048.003",
                "SSH/SCP": "T1048.002",
                "Alt HTTP": "T1041",
            }.get(channel, "T1048")

            findings.append(self._create_finding(
                title=f"Exfiltration channel: {channel} ({len(endpoints)} endpoints)",
                severity=Severity.MEDIUM,
                description=f"{channel} exfiltration possible via: {', '.join(endpoints[:10])}",
                remediation=f"Implement egress filtering for {channel} traffic. Deploy DLP solutions.",
                att_ck_ids=[technique],
            ))

        if not channels:
            findings.append(self._create_finding(
                title="No obvious exfiltration channels detected",
                severity=Severity.INFO,
                description="No open outbound ports detected for common exfiltration protocols.",
                att_ck_ids=["T1048"],
            ))

        return findings

    def _classify_channel(self, port: int) -> str | None:
        """Classify a port as an exfiltration channel."""
        channel_map = {
            22: "SSH/SCP",
            53: "DNS",
            80: "HTTP/HTTPS",
            443: "HTTP/HTTPS",
            8080: "Alt HTTP",
            8443: "Alt HTTP",
        }
        return channel_map.get(port)
