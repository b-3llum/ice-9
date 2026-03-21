"""Amass OSINT wrapper — attack surface mapping and subdomain enumeration."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper


class AmassWrapper(ToolWrapper):
    """Amass integration — subdomain enumeration and attack surface mapping."""

    name = "amass"
    description = "OSINT — attack surface mapping and subdomain enumeration"
    binary = "amass"
    att_ck_ids = ["T1590", "T1590.002", "T1596"]

    def __init__(self) -> None:
        super().__init__()
        self._json_output: str | None = None

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path(), "enum", "-d", target]

        passive = kwargs.get("passive", True)
        if passive:
            cmd.append("-passive")

        timeout_mins = kwargs.get("timeout_mins")
        if timeout_mins:
            cmd.extend(["-timeout", str(timeout_mins)])

        # JSON output for parsing
        if not kwargs.get("output_file"):
            tmp = NamedTemporaryFile(suffix=".json", delete=False)
            self._json_output = tmp.name
            tmp.close()
        else:
            self._json_output = kwargs["output_file"]
        cmd.extend(["-json", self._json_output])

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse Amass JSONL output into structured data."""
        subdomains: list[str] = []
        addresses: list[str] = []
        sources: set[str] = set()

        json_path = Path(self._json_output) if self._json_output else None
        if json_path and json_path.exists():
            result.artifacts.append(json_path)
            for line in json_path.read_text().strip().splitlines():
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

        # Fallback to stdout if no JSON
        if not subdomains and result.stdout:
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line and "." in line:
                    subdomains.append(line)

        return {
            "subdomains": subdomains,
            "addresses": addresses,
            "sources": sorted(sources),
            "subdomain_count": len(subdomains),
            "address_count": len(addresses),
        }
