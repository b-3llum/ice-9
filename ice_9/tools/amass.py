"""Amass OSINT wrapper — attack surface mapping and subdomain enumeration."""

from __future__ import annotations

import json
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper


class AmassWrapper(ToolWrapper):
    """Amass integration — subdomain enumeration and attack surface mapping."""

    name = "amass"
    description = "OSINT — attack surface mapping and subdomain enumeration"
    binary = "amass"
    att_ck_ids = ["T1590", "T1590.002", "T1596"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path(), "enum", "-d", target]

        passive = kwargs.get("passive", True)
        if passive:
            cmd.append("-passive")

        timeout_mins = kwargs.get("timeout_mins")
        if timeout_mins:
            cmd.extend(["-timeout", str(timeout_mins)])

        # Emit JSONL to stdout so parsing works both locally and over an SSH
        # execution backend (a temp file would land on the remote host).
        cmd.extend(["-json", "/dev/stdout"])

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse Amass JSONL output (emitted to stdout) into structured data."""
        subdomains: list[str] = []
        addresses: list[str] = []
        sources: set[str] = set()

        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            name = record.get("name", "")
            if name and name not in subdomains:
                subdomains.append(name)
            for addr in record.get("addresses", []):
                ip = addr.get("ip", "")
                if ip and ip not in addresses:
                    addresses.append(ip)
            for src in record.get("sources", []):
                sources.add(src)

        # Fallback: plain subdomain-per-line output (no JSON records found).
        if not subdomains:
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line and "." in line and not line.startswith(("[", "{")):
                    subdomains.append(line)

        return {
            "subdomains": subdomains,
            "addresses": addresses,
            "sources": sorted(sources),
            "subdomain_count": len(subdomains),
            "address_count": len(addresses),
        }
