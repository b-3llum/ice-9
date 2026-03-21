"""Collection phase — TA0009: Data collection from file shares, databases, and mail."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class CollectionPhase(PhaseModule):
    """Collection — identify accessible data stores, file shares, and sensitive information."""

    phase_type = PhaseType.COLLECTION
    name = "Collection"
    description = "File share enumeration, sensitive data discovery, and database access assessment"
    required_tools = ["crackmapexec", "nmap"]
    att_ck_techniques = ["T1005", "T1039", "T1114", "T1213"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan collection assessment tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        for target in scope:
            # SMB share enumeration and spidering
            tasks.append({
                "tool": "crackmapexec",
                "target": target,
                "params": {
                    "protocol": "smb",
                    "args": ["--shares"],
                },
            })

            # Nmap for file-sharing and database services
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-sV", "-p",
                        "21,111,139,443,445,873,1433,2049,3306,5432,27017",
                        "--script", "smb-enum-shares,ftp-anon,nfs-showmount",
                    ],
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze data collection opportunities."""
        findings = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            if result.tool == "crackmapexec":
                findings.extend(self._analyze_shares(result))
            elif result.tool == "nmap":
                findings.extend(self._analyze_data_services(result))

        return findings

    def _analyze_shares(self, result: ToolResult) -> list[Finding]:
        """Analyze accessible file shares."""
        findings = []

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            shares = host.get("shares", [])

            readable = [s for s in shares if s.get("readable")]
            writable = [s for s in shares if s.get("writable")]

            if readable:
                share_names = ", ".join(s.get("name", "?") for s in readable)
                findings.append(self._create_finding(
                    title=f"Readable shares on {ip}: {share_names}",
                    severity=Severity.MEDIUM,
                    description=f"Accessible SMB shares on {ip}: {share_names}. May contain sensitive data.",
                    remediation="Review share permissions. Apply least-privilege access.",
                    att_ck_ids=["T1039"],
                ))

            if writable:
                share_names = ", ".join(s.get("name", "?") for s in writable)
                findings.append(self._create_finding(
                    title=f"Writable shares on {ip}: {share_names}",
                    severity=Severity.HIGH,
                    description=f"Writable SMB shares on {ip}: {share_names}. Data exfiltration or tampering possible.",
                    remediation="Restrict write access. Monitor file modifications.",
                    att_ck_ids=["T1039"],
                ))

        return findings

    def _analyze_data_services(self, result: ToolResult) -> list[Finding]:
        """Flag accessible database and file services."""
        findings = []
        data_services = {
            21: ("FTP", "T1039"),
            111: ("NFS/RPC", "T1039"),
            873: ("Rsync", "T1039"),
            1433: ("MSSQL", "T1213"),
            2049: ("NFS", "T1039"),
            3306: ("MySQL", "T1213"),
            5432: ("PostgreSQL", "T1213"),
            27017: ("MongoDB", "T1213"),
        }

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            for port_info in host.get("ports", []):
                if port_info.get("state") != "open":
                    continue
                port = port_info.get("port", 0)
                if port in data_services:
                    svc_name, technique = data_services[port]
                    product = port_info.get("product", "")

                    # Check for anonymous access in scripts
                    scripts = port_info.get("scripts", {})
                    anon_access = any(
                        "anonymous" in v.lower() or "allowed" in v.lower()
                        for v in scripts.values()
                    )

                    severity = Severity.CRITICAL if anon_access else Severity.MEDIUM
                    desc = f"{svc_name} ({product}) accessible on {ip}:{port}"
                    if anon_access:
                        desc += " — anonymous/unauthenticated access detected"

                    findings.append(self._create_finding(
                        title=f"Data service exposed: {svc_name} on {ip}:{port}",
                        severity=severity,
                        description=desc,
                        remediation=f"Restrict {svc_name} access. Require authentication.",
                        att_ck_ids=[technique],
                    ))

        return findings
