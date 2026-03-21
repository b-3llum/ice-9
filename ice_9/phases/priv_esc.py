"""Privilege Escalation phase — TA0004: Elevate access from standard to admin/SYSTEM."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class PrivEscPhase(PhaseModule):
    """Privilege Escalation — identify and assess local/domain priv esc paths."""

    phase_type = PhaseType.PRIV_ESC
    name = "Privilege Escalation"
    description = "Local and domain privilege escalation via misconfigurations, CVEs, and token abuse"
    required_tools = ["crackmapexec", "nmap"]
    att_ck_techniques = ["T1068", "T1548", "T1134", "T1078.002"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan privilege escalation assessment tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        if not scope:
            return tasks

        for target in scope:
            # CrackMapExec — check for local admin and Pwn3d status
            tasks.append({
                "tool": "crackmapexec",
                "target": target,
                "params": {
                    "protocol": "smb",
                },
            })

            # Nmap vuln scripts for known priv esc CVEs
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "vuln",
                },
            })

            # Nuclei for priv esc specific checks
            tasks.append({
                "tool": "nuclei",
                "target": target,
                "params": {
                    "severity": "critical,high",
                    "tags": "cve,privilege-escalation,misconfig",
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze privilege escalation opportunities."""
        findings = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            if result.tool == "crackmapexec":
                findings.extend(self._analyze_cme(result))
            elif result.tool == "nmap":
                findings.extend(self._analyze_nmap_vuln(result))
            elif result.tool == "nuclei":
                findings.extend(self._analyze_nuclei(result))

        return findings

    def _analyze_cme(self, result: ToolResult) -> list[Finding]:
        """Flag hosts where admin access is available."""
        findings = []

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            if host.get("admin") or host.get("pwned"):
                findings.append(self._create_finding(
                    title=f"Local admin access on {ip}",
                    severity=Severity.CRITICAL,
                    description=f"Administrative access confirmed on {ip}. SYSTEM-level escalation possible.",
                    remediation="Implement least privilege. Remove users from local admin groups.",
                    att_ck_ids=["T1078.002"],
                ))

        return findings

    def _analyze_nmap_vuln(self, result: ToolResult) -> list[Finding]:
        """Extract priv esc relevant vulnerabilities from Nmap vuln scripts."""
        findings = []

        for host in result.parsed.get("hosts", []):
            ip = host.get("ip", "?")
            for port_info in host.get("ports", []):
                scripts = port_info.get("scripts", {})
                for script_id, output in scripts.items():
                    if "VULNERABLE" in output.upper():
                        findings.append(self._create_finding(
                            title=f"Vulnerability on {ip}: {script_id}",
                            severity=Severity.HIGH,
                            description=f"Nmap script {script_id} detected a vulnerability on {ip}:{port_info.get('port', '?')}",
                            remediation="Apply relevant patches and updates.",
                            att_ck_ids=["T1068"],
                        ))

        return findings

    def _analyze_nuclei(self, result: ToolResult) -> list[Finding]:
        """Extract priv esc findings from Nuclei."""
        findings = []
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
        }

        for nf in result.parsed.get("findings", []):
            severity = sev_map.get(nf.get("severity", ""), None)
            if severity:
                findings.append(self._create_finding(
                    title=f"Priv Esc: {nf.get('template_name', nf.get('template_id', 'Unknown'))}",
                    severity=severity,
                    description=nf.get("description", f"Matched at: {nf.get('matched_at', '')}"),
                    cve_ids=nf.get("cve_ids", []),
                    cvss=nf.get("cvss_score"),
                    att_ck_ids=["T1068"],
                ))

        return findings
