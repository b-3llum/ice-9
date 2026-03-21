"""Nuclei vulnerability scanner wrapper with JSON output parsing."""

from __future__ import annotations

import json
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiWrapper(ToolWrapper):
    """Nuclei vulnerability scanner integration."""

    name = "nuclei"
    description = "Template-based vulnerability scanner"
    binary = "nuclei"
    att_ck_ids = ["T1595", "T1190"]  # Active Scanning, Exploit Public-Facing Application

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path()]

        # Target
        cmd.extend(["-target", target])

        # JSON output for structured parsing
        cmd.append("-jsonl")

        # Severity filter
        severity = kwargs.get("severity")
        if severity:
            cmd.extend(["-severity", severity])

        # Template tags
        tags = kwargs.get("tags")
        if tags:
            cmd.extend(["-tags", tags])

        # Template paths
        templates = kwargs.get("templates")
        if templates:
            cmd.extend(["-t", templates])

        # Rate limiting
        rate_limit = kwargs.get("rate_limit", 150)
        cmd.extend(["-rate-limit", str(rate_limit)])

        # Concurrency
        concurrency = kwargs.get("concurrency", 25)
        cmd.extend(["-concurrency", str(concurrency)])

        # Extra args
        extra = kwargs.get("args", [])
        if extra:
            cmd.extend(extra)

        # Silent mode — only results
        cmd.append("-silent")

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse Nuclei JSONL output."""
        findings = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                finding = {
                    "template_id": entry.get("template-id", ""),
                    "template_name": entry.get("info", {}).get("name", ""),
                    "severity": SEVERITY_MAP.get(
                        entry.get("info", {}).get("severity", "info"), "info"
                    ),
                    "type": entry.get("type", ""),
                    "host": entry.get("host", ""),
                    "matched_at": entry.get("matched-at", ""),
                    "description": entry.get("info", {}).get("description", ""),
                    "reference": entry.get("info", {}).get("reference", []),
                    "tags": entry.get("info", {}).get("tags", []),
                    "matcher_name": entry.get("matcher-name", ""),
                    "extracted_results": entry.get("extracted-results", []),
                    "curl_command": entry.get("curl-command", ""),
                    "cve_ids": [
                        ref
                        for ref in entry.get("info", {}).get("reference", [])
                        if ref.upper().startswith("CVE-")
                    ],
                }
                # Classification
                classification = entry.get("info", {}).get("classification", {})
                if classification:
                    finding["cvss_score"] = classification.get("cvss-score")
                    finding["cwe_id"] = classification.get("cwe-id", [])

                findings.append(finding)
            except json.JSONDecodeError:
                continue

        # Group by severity
        severity_counts = {}
        for f in findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "findings": findings,
            "total": len(findings),
            "severity_counts": severity_counts,
        }
