"""Initial Access phase — TA0001: Exploit public-facing applications, poisoning, defaults."""

from __future__ import annotations

import ipaddress
from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class InitialAccessPhase(PhaseModule):
    """Initial Access — identify entry points via vuln scanning, poisoning, and default creds."""

    phase_type = PhaseType.INITIAL_ACCESS
    name = "Initial Access"
    description = "Public-facing vulnerability scanning, LLMNR poisoning, and default credential checks"
    required_tools = ["nuclei", "nmap"]
    att_ck_techniques = ["T1190", "T1566", "T1133", "T1078", "T1557.001"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan initial access tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        for target in scope:
            # Nuclei scan for exploitable vulns and default logins
            tasks.append({
                "tool": "nuclei",
                "target": target,
                "params": {
                    "severity": "critical,high",
                    "tags": "cve,rce,default-login,exposed-panels",
                },
            })

            # Nmap for common initial-access service ports
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-sV", "-p",
                        "21,22,23,25,80,443,445,1433,3306,3389,5432,5900,8080,8443",
                        "--script", "default,vuln",
                    ],
                },
            })

        # Responder in analyze mode on internal targets
        for target in scope:
            if self._is_internal(target):
                tasks.append({
                    "tool": "responder",
                    "target": target,
                    "params": {
                        "analyze": True,  # Listen only, no active poisoning
                    },
                })
                break  # Only one responder instance needed

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze initial access scan results."""
        findings = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            if result.tool == "nuclei":
                findings.extend(self._analyze_nuclei(result))
            elif result.tool == "nmap":
                findings.extend(self._analyze_nmap(result))
            elif result.tool == "responder":
                findings.extend(self._analyze_responder(result))

        return findings

    def _analyze_nuclei(self, result: ToolResult) -> list[Finding]:
        """Extract exploitable vulnerabilities from Nuclei."""
        findings = []
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        for nf in result.parsed.get("findings", []):
            severity = sev_map.get(nf.get("severity", "info"), Severity.INFO)
            template_name = nf.get("template_name", nf.get("template_id", "Unknown"))
            matched_at = nf.get("matched_at", "")

            findings.append(self._create_finding(
                title=f"Initial Access: {template_name}",
                severity=severity,
                description=f"Potential initial access vector: {template_name} at {matched_at}",
                remediation="Patch the vulnerability and restrict public-facing exposure.",
                cve_ids=nf.get("cve_ids", []),
                cvss=nf.get("cvss_score"),
                att_ck_ids=["T1190"],
            ))

        return findings

    def _analyze_nmap(self, result: ToolResult) -> list[Finding]:
        """Flag services with known default credential risk."""
        findings = []
        default_cred_services = {
            21: "FTP",
            23: "Telnet",
            80: "HTTP Admin Panel",
            443: "HTTPS Admin Panel",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP Management",
        }

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            for port_info in host.get("ports", []):
                if port_info.get("state") != "open":
                    continue
                port_num = port_info.get("port", 0)
                if port_num in default_cred_services:
                    svc_name = default_cred_services[port_num]
                    product = port_info.get("product", "")
                    findings.append(self._create_finding(
                        title=f"Potential default credentials: {svc_name} on {ip}:{port_num}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"{svc_name} ({product}) exposed on {ip}:{port_num}. "
                            "Test for default credentials."
                        ),
                        remediation="Change default credentials. Restrict access via firewall rules.",
                        att_ck_ids=["T1078"],
                    ))

        return findings

    def _analyze_responder(self, result: ToolResult) -> list[Finding]:
        """Flag captured hashes from Responder."""
        findings = []
        total = result.parsed.get("total_hashes", 0)

        if total > 0:
            findings.append(self._create_finding(
                title=f"LLMNR/NBT-NS poisoning: {total} hashes captured",
                severity=Severity.HIGH,
                description=(
                    f"Responder captured {total} Net-NTLM hashes via LLMNR/NBT-NS poisoning. "
                    f"NTLMv1: {len(result.parsed.get('ntlmv1_hashes', []))}, "
                    f"NTLMv2: {len(result.parsed.get('ntlmv2_hashes', []))}."
                ),
                remediation=(
                    "Disable LLMNR and NBT-NS via Group Policy. "
                    "Enable SMB signing. Deploy network segmentation."
                ),
                att_ck_ids=["T1557.001"],
            ))

        if result.parsed.get("total_cleartext", 0) > 0:
            findings.append(self._create_finding(
                title="Cleartext credentials captured via LLMNR poisoning",
                severity=Severity.CRITICAL,
                description="Cleartext passwords were captured during LLMNR/NBT-NS poisoning.",
                remediation="Enforce encrypted authentication. Disable legacy protocols.",
                att_ck_ids=["T1557.001", "T1040"],
            ))

        return findings

    def _is_internal(self, target: str) -> bool:
        """Check if a target looks like an internal IP/CIDR."""
        try:
            net = ipaddress.ip_network(target, strict=False)
            return net.is_private
        except ValueError:
            return False
