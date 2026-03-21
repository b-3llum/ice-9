"""Subfinder wrapper — passive subdomain discovery via multiple sources."""

from __future__ import annotations

from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper


class SubfinderWrapper(ToolWrapper):
    """Subfinder integration — fast passive subdomain enumeration."""

    name = "subfinder"
    description = "Passive subdomain discovery via multiple sources"
    binary = "subfinder"
    att_ck_ids = ["T1590.002", "T1596"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        cmd = [self.get_binary_path(), "-d", target, "-silent"]

        sources = kwargs.get("sources")
        if sources:
            cmd.extend(["-sources", sources])

        exclude_sources = kwargs.get("exclude_sources")
        if exclude_sources:
            cmd.extend(["-exclude-sources", exclude_sources])

        threads = kwargs.get("threads")
        if threads:
            cmd.extend(["-t", str(threads)])

        output_file = kwargs.get("output_file")
        if output_file:
            cmd.extend(["-o", output_file])

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse Subfinder output — one subdomain per line."""
        subdomains = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line and "." in line and not line.startswith("["):
                subdomains.append(line)

        return {
            "subdomains": subdomains,
            "count": len(subdomains),
        }
