"""Reconnaissance phase — TA0043: OSINT + network scanning orchestration."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class ReconPhase(PhaseModule):
    """Reconnaissance phase — network discovery, port scanning, service enumeration."""

    phase_type = PhaseType.RECON
    name = "Reconnaissance"
    description = "Network discovery, port scanning, service enumeration, and OSINT gathering"
    required_tools = ["nmap"]
    att_ck_techniques = ["T1595", "T1592", "T1590", "T1046", "T1589"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan recon tasks based on campaign scope."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        for target in scope:
            # Host discovery sweep
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "quick",
                    "args": ["-sn"],  # Ping sweep first
                },
            })

            # Standard port scan
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "standard",
                },
            })

            # Nuclei scan if available
            tasks.append({
                "tool": "nuclei",
                "target": target,
                "params": {
                    "severity": "critical,high,medium",
                    "tags": "network,misconfig",
                },
            })

            # OSINT tools for domain targets (not IP ranges)
            if self._is_domain(target):
                tasks.append({
                    "tool": "theharvester",
                    "target": target,
                    "params": {"source": "all", "limit": 500},
                })
                tasks.append({
                    "tool": "amass",
                    "target": target,
                    "params": {"passive": True},
                })
                tasks.append({
                    "tool": "subfinder",
                    "target": target,
                    "params": {},
                })

        return tasks

    @staticmethod
    def _is_domain(target: str) -> bool:
        """Check if a target looks like a domain (vs an IP/CIDR)."""
        return any(c.isalpha() for c in target) and "." in target

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze recon results for notable findings."""
        findings = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            if result.tool == "nmap":
                findings.extend(self._analyze_nmap(result))
            elif result.tool == "nuclei":
                findings.extend(self._analyze_nuclei(result))
            elif result.tool == "theharvester":
                findings.extend(self._analyze_theharvester(result))
            elif result.tool in ("amass", "subfinder"):
                findings.extend(self._analyze_subdomain_tool(result))

        return findings

    def _analyze_nmap(self, result: ToolResult) -> list[Finding]:
        """Extract findings from Nmap results."""
        findings = []
        hosts = result.parsed.get("hosts", [])

        for host in hosts:
            ip = host.get("ip", "?")
            open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]

            # Flag high-risk services
            risky_services = {
                21: ("FTP Exposed", Severity.MEDIUM, "T1071.002"),
                22: ("SSH Exposed", Severity.LOW, "T1021.004"),
                23: ("Telnet Exposed", Severity.HIGH, "T1021"),
                25: ("SMTP Exposed", Severity.MEDIUM, "T1071.003"),
                53: ("DNS Exposed", Severity.LOW, "T1071.004"),
                80: ("HTTP Exposed", Severity.INFO, "T1071.001"),
                110: ("POP3 Exposed", Severity.MEDIUM, "T1071.003"),
                135: ("RPC Exposed", Severity.MEDIUM, "T1021.003"),
                139: ("NetBIOS Exposed", Severity.MEDIUM, "T1021.002"),
                143: ("IMAP Exposed", Severity.MEDIUM, "T1071.003"),
                443: ("HTTPS Exposed", Severity.INFO, "T1071.001"),
                445: ("SMB Exposed", Severity.HIGH, "T1021.002"),
                1433: ("MSSQL Exposed", Severity.HIGH, "T1190"),
                1521: ("Oracle DB Exposed", Severity.HIGH, "T1190"),
                3306: ("MySQL Exposed", Severity.HIGH, "T1190"),
                3389: ("RDP Exposed", Severity.HIGH, "T1021.001"),
                5432: ("PostgreSQL Exposed", Severity.HIGH, "T1190"),
                5900: ("VNC Exposed", Severity.HIGH, "T1021.005"),
                6379: ("Redis Exposed", Severity.CRITICAL, "T1190"),
                8080: ("HTTP-Alt Exposed", Severity.LOW, "T1071.001"),
                8443: ("HTTPS-Alt Exposed", Severity.LOW, "T1071.001"),
                27017: ("MongoDB Exposed", Severity.CRITICAL, "T1190"),
            }

            for port_info in open_ports:
                port_num = port_info.get("port", 0)
                service = port_info.get("service", "unknown")
                product = port_info.get("product", "")
                version = port_info.get("version", "")

                if port_num in risky_services:
                    title, severity, technique = risky_services[port_num]
                    svc_detail = f"{service}"
                    if product:
                        svc_detail += f" ({product}"
                        if version:
                            svc_detail += f" {version}"
                        svc_detail += ")"

                    findings.append(self._create_finding(
                        title=f"{title} on {ip}:{port_num}",
                        severity=severity,
                        description=f"Host {ip} has {svc_detail} on port {port_num}/tcp",
                        remediation=f"Review if port {port_num} ({service}) needs to be exposed. Apply network segmentation or firewall rules.",
                        att_ck_ids=[technique],
                    ))

            # Flag excessive open ports
            if len(open_ports) > 20:
                findings.append(self._create_finding(
                    title=f"Excessive open ports on {ip} ({len(open_ports)} ports)",
                    severity=Severity.MEDIUM,
                    description=f"Host {ip} has {len(open_ports)} open ports, suggesting insufficient hardening.",
                    remediation="Review and close unnecessary services. Apply principle of least privilege.",
                ))

        return findings

    def _analyze_theharvester(self, result: ToolResult) -> list[Finding]:
        """Analyze theHarvester OSINT results."""
        findings = []
        emails = result.parsed.get("emails", [])
        subdomains = result.parsed.get("subdomains", [])

        if emails:
            findings.append(self._create_finding(
                title=f"OSINT: {len(emails)} email addresses discovered for {result.target}",
                severity=Severity.LOW,
                description=f"Email addresses found: {', '.join(emails[:20])}{'...' if len(emails) > 20 else ''}",
                remediation="Review exposed email addresses. Consider employee awareness training.",
                att_ck_ids=["T1589.002"],
            ))

        if subdomains:
            findings.append(self._create_finding(
                title=f"OSINT: {len(subdomains)} subdomains discovered for {result.target}",
                severity=Severity.INFO,
                description=f"Subdomains: {', '.join(subdomains[:20])}{'...' if len(subdomains) > 20 else ''}",
                remediation="Review exposed subdomains for unnecessary or sensitive services.",
                att_ck_ids=["T1590.002"],
            ))

        return findings

    def _analyze_subdomain_tool(self, result: ToolResult) -> list[Finding]:
        """Analyze amass/subfinder subdomain results."""
        findings = []
        subdomains = result.parsed.get("subdomains", [])
        count = len(subdomains)

        if count > 0:
            findings.append(self._create_finding(
                title=f"OSINT ({result.tool}): {count} subdomains for {result.target}",
                severity=Severity.INFO,
                description=f"Subdomains via {result.tool}: {', '.join(subdomains[:20])}{'...' if count > 20 else ''}",
                att_ck_ids=["T1590.002"],
            ))

        return findings

    def _analyze_nuclei(self, result: ToolResult) -> list[Finding]:
        """Convert Nuclei findings to ice_9 findings."""
        findings = []
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        for nf in result.parsed.get("findings", []):
            findings.append(self._create_finding(
                title=nf.get("template_name", nf.get("template_id", "Unknown")),
                severity=sev_map.get(nf.get("severity", "info"), Severity.INFO),
                description=nf.get("description", f"Matched at: {nf.get('matched_at', '')}"),
                cve_ids=nf.get("cve_ids", []),
                cvss=nf.get("cvss_score"),
            ))

        return findings
