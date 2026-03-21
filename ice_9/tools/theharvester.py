"""theHarvester OSINT wrapper — email, subdomain, and host harvesting."""

from __future__ import annotations

import re
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper


class TheHarvesterWrapper(ToolWrapper):
    """theHarvester integration — gather emails, subdomains, and IPs from public sources."""

    name = "theharvester"
    description = "OSINT — email, subdomain, host, and name harvesting from public sources"
    binary = "theHarvester"
    att_ck_ids = ["T1589", "T1589.002", "T1590.002"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path(), "-d", target]

        source = kwargs.get("source", "all")
        cmd.extend(["-b", source])

        limit = kwargs.get("limit", 500)
        cmd.extend(["-l", str(limit)])

        start = kwargs.get("start", 0)
        if start:
            cmd.extend(["-S", str(start)])

        output_file = kwargs.get("output_file")
        if output_file:
            cmd.extend(["-f", output_file])

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse theHarvester text output into structured data."""
        text = result.stdout
        emails = self._extract_section(text, r"\[\*\] Emails found:.*?\n(.*?)(?:\n\n|\[\*\]|\Z)")
        hosts = self._extract_section(text, r"\[\*\] Hosts found:.*?\n(.*?)(?:\n\n|\[\*\]|\Z)")
        ips = self._extract_section(text, r"\[\*\] IPs found:.*?\n(.*?)(?:\n\n|\[\*\]|\Z)")

        # Also try alternate section headers
        if not emails:
            emails = self._extract_section(text, r"Emails:.*?\n-+\n(.*?)(?:\n\n|\Z)")
        if not hosts:
            hosts = self._extract_section(text, r"Hosts:.*?\n-+\n(.*?)(?:\n\n|\Z)")

        return {
            "emails": emails,
            "subdomains": hosts,
            "ips": ips,
            "email_count": len(emails),
            "subdomain_count": len(hosts),
            "ip_count": len(ips),
        }

    def _extract_section(self, text: str, pattern: str) -> list[str]:
        """Extract a list of items from a text section."""
        match = re.search(pattern, text, re.DOTALL)
        if not match:
            return []
        section = match.group(1).strip()
        items = []
        for line in section.splitlines():
            line = line.strip()
            if line and not line.startswith("-"):
                items.append(line)
        return items
