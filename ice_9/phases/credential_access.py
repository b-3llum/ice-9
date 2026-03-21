"""Credential Access phase — TA0006: kerb-map + credential attacks."""

from __future__ import annotations

from typing import Any

from ice_9.core.models import Campaign, Finding, PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class CredentialAccessPhase(PhaseModule):
    """Credential access — Kerberos attacks, credential harvesting, password spraying."""

    phase_type = PhaseType.CREDENTIAL_ACCESS
    name = "Credential Access"
    description = "Kerberos attack surface mapping, credential harvesting"
    required_tools = ["kerb-map"]
    att_ck_techniques = ["T1558", "T1558.003", "T1558.004", "T1110", "T1003"]

    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Plan credential access tasks."""
        tasks = []
        scope = campaign.rules_of_engagement.scope

        for target in scope:
            # kerb-map full scan
            tasks.append({
                "tool": "kerb-map",
                "target": target,
                "params": {
                    "modules": "all",
                    "format": "json",
                },
            })

            # Nmap Kerberos scripts
            tasks.append({
                "tool": "nmap",
                "target": target,
                "params": {
                    "profile": "custom",
                    "args": [
                        "-p", "88,389,636",
                        "--script", "krb5-enum-users",
                        "-sV",
                    ],
                },
            })

        return tasks

    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze credential access results."""
        findings = []

        for result in results:
            if not result.success or not result.parsed:
                continue

            if result.tool == "kerb-map":
                findings.extend(self._analyze_kerbmap(result))
            elif result.tool == "nmap":
                findings.extend(self._analyze_nmap_krb(result))

        return findings

    def _analyze_kerbmap(self, result: ToolResult) -> list[Finding]:
        """Extract findings from kerb-map output."""
        findings = []
        parsed = result.parsed

        # SPN accounts (Kerberoastable)
        spn_accounts = parsed.get("spn_accounts", [])
        if spn_accounts:
            findings.append(self._create_finding(
                title=f"Kerberoastable accounts found ({len(spn_accounts)})",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(spn_accounts)} accounts with Service Principal Names "
                    "that can be targeted for Kerberoasting attacks."
                ),
                remediation=(
                    "Use managed service accounts (gMSA) where possible. "
                    "Ensure service account passwords are 25+ characters. "
                    "Monitor for TGS requests (Event ID 4769)."
                ),
                att_ck_ids=["T1558.003"],
            ))

        # AS-REP roastable accounts
        asrep = parsed.get("asrep_accounts", [])
        if asrep:
            findings.append(self._create_finding(
                title=f"AS-REP roastable accounts found ({len(asrep)})",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(asrep)} accounts with Kerberos pre-authentication disabled, "
                    "allowing AS-REP roasting attacks."
                ),
                remediation=(
                    "Enable Kerberos pre-authentication for all accounts. "
                    "Review accounts with DONT_REQUIRE_PREAUTH flag."
                ),
                att_ck_ids=["T1558.004"],
            ))

        # Delegation issues
        delegation = parsed.get("delegation_issues", [])
        if delegation:
            findings.append(self._create_finding(
                title=f"Dangerous delegation configurations ({len(delegation)})",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(delegation)} accounts with potentially dangerous delegation settings "
                    "(unconstrained or constrained delegation)."
                ),
                remediation=(
                    "Replace unconstrained delegation with constrained delegation or RBCD. "
                    "Review all delegation configurations."
                ),
                att_ck_ids=["T1134.001"],
            ))

        # Weak encryption
        encryption = parsed.get("encryption_issues", [])
        if encryption:
            findings.append(self._create_finding(
                title=f"Weak Kerberos encryption detected ({len(encryption)})",
                severity=Severity.MEDIUM,
                description=(
                    f"Found {len(encryption)} accounts using weak encryption types "
                    "(RC4/DES) for Kerberos authentication."
                ),
                remediation=(
                    "Migrate to AES256 encryption for all Kerberos authentication. "
                    "Disable RC4 and DES support where possible."
                ),
                att_ck_ids=["T1558"],
            ))

        # CVE findings
        cves = parsed.get("cve_findings", [])
        for cve in cves:
            cve_id = cve.get("cve_id", "Unknown")
            findings.append(self._create_finding(
                title=f"CVE detected: {cve_id}",
                severity=Severity.CRITICAL,
                description=cve.get("description", f"Vulnerability {cve_id} detected."),
                cve_ids=[cve_id],
                cvss=cve.get("cvss"),
                att_ck_ids=["T1190"],
            ))

        return findings

    def _analyze_nmap_krb(self, result: ToolResult) -> list[Finding]:
        """Analyze Nmap Kerberos script output."""
        findings = []
        hosts = result.parsed.get("hosts", [])

        for host in hosts:
            ip = host.get("ip", "?")
            for port_info in host.get("ports", []):
                scripts = port_info.get("scripts", {})
                if "krb5-enum-users" in scripts:
                    output = scripts["krb5-enum-users"]
                    findings.append(self._create_finding(
                        title=f"Kerberos user enumeration possible on {ip}",
                        severity=Severity.MEDIUM,
                        description=f"Kerberos user enumeration via AS-REQ on {ip}:\n{output[:300]}",
                        remediation="This is expected behavior for Kerberos. Monitor for brute-force attempts.",
                        att_ck_ids=["T1087.002"],
                    ))

        return findings
