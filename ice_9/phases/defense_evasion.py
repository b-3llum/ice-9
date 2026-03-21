"""Defense Evasion phase — TA0005: Security product detection and bypass assessment."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class DefenseEvasionPhase(PhaseModule):
    """Defense Evasion — map security products and identify detection gaps."""

    phase_type = PhaseType.DEFENSE_EVASION
    name = "Defense Evasion"
    description = "Security product enumeration, detection gap analysis, and evasion assessment"
    required_tools = ["nmap", "crackmapexec"]
    att_ck_techniques = ["T1562", "T1070", "T1036", "T1218"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan defense evasion assessment tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        for target in scope:
            # Detect security products via service banners
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-sV", "-p",
                        "135,139,443,445,3128,5985,8080,8443,9090",
                        "--script", "smb-os-discovery",
                    ],
                },
            })

            # CrackMapExec for AV/EDR enumeration
            tasks.append({
                "tool": "crackmapexec",
                "target": target,
                "params": {
                    "protocol": "smb",
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze security product landscape."""
        findings = []
        security_products_found: list[str] = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            if result.tool == "nmap":
                findings.extend(self._analyze_security_products(result, security_products_found))
            elif result.tool == "crackmapexec":
                findings.extend(self._analyze_cme_evasion(result, security_products_found))

        # Summary finding
        if security_products_found:
            findings.append(self._create_finding(
                title=f"Security products detected: {len(security_products_found)}",
                severity=Severity.INFO,
                description=f"Security products identified: {', '.join(set(security_products_found))}",
                att_ck_ids=["T1518.001"],
            ))
        else:
            findings.append(self._create_finding(
                title="No security products detected in scan results",
                severity=Severity.HIGH,
                description="No AV/EDR products were detected on scanned hosts, suggesting inadequate endpoint protection.",
                remediation="Deploy endpoint detection and response (EDR) on all hosts.",
                att_ck_ids=["T1562"],
            ))

        return findings

    def _analyze_security_products(
        self, result: ToolResult, products: list[str]
    ) -> list[Finding]:
        """Detect security products from service banners."""
        findings = []
        av_indicators = [
            "symantec", "norton", "mcafee", "kaspersky", "sophos",
            "crowdstrike", "sentinel", "carbon black", "cylance",
            "defender", "eset", "trend micro", "bitdefender",
            "palo alto", "fortinet", "cisco amp",
        ]

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            for port_info in host.get("ports", []):
                product = (port_info.get("product", "") + " " + port_info.get("extrainfo", "")).lower()
                for av in av_indicators:
                    if av in product:
                        products.append(av.title())
                        findings.append(self._create_finding(
                            title=f"Security product detected on {ip}: {av.title()}",
                            severity=Severity.INFO,
                            description=f"Security product '{av.title()}' detected on {ip}:{port_info.get('port', '?')}",
                            att_ck_ids=["T1518.001"],
                        ))

        return findings

    def _analyze_cme_evasion(
        self, result: ToolResult, products: list[str]
    ) -> list[Finding]:
        """Analyze CrackMapExec results for AV status."""
        findings = []

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            os_info = host.get("os", "").lower()
            if "windows" in os_info and host.get("signing") is False:
                findings.append(self._create_finding(
                    title=f"SMB signing disabled on Windows host {ip}",
                    severity=Severity.MEDIUM,
                    description=f"Windows host {ip} does not require SMB signing, enabling evasion via relay attacks.",
                    remediation="Enforce SMB signing via Group Policy.",
                    att_ck_ids=["T1557.001"],
                ))

        return findings
