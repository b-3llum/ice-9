"""Nmap network scanner wrapper with XML output parsing."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper

# Scan profiles — common presets
SCAN_PROFILES = {
    "quick": ["-sV", "-T4", "--top-ports", "100"],
    "standard": ["-sV", "-sC", "-T3"],
    "full": ["-sV", "-sC", "-p-", "-T3"],
    "stealth": ["-sS", "-T2", "-f", "--data-length", "24"],
    "udp": ["-sU", "--top-ports", "50", "-T3"],
    "vuln": ["-sV", "--script", "vuln", "-T3"],
    "os": ["-O", "-sV", "-T3"],
}


class NmapWrapper(ToolWrapper):
    """Nmap network scanner integration."""

    name = "nmap"
    description = "Network scanner — host discovery, port scanning, service detection"
    binary = "nmap"
    att_ck_ids = ["T1046", "T1018", "T1135"]  # Network Service Scanning, Remote System Discovery, Network Share Discovery

    def __init__(self) -> None:
        super().__init__()
        self._xml_output: str | None = None

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        profile = kwargs.get("profile", "standard")
        extra_args = kwargs.get("args", [])
        output_file = kwargs.get("output_file")

        cmd = [self.get_binary_path()]

        # Apply profile
        if profile in SCAN_PROFILES:
            cmd.extend(SCAN_PROFILES[profile])
        elif profile == "custom":
            pass  # Only use extra_args
        else:
            cmd.extend(SCAN_PROFILES["standard"])

        # XML output for parsing
        if not output_file:
            self._xml_tmp = NamedTemporaryFile(suffix=".xml", delete=False)
            output_file = self._xml_tmp.name
        self._xml_output = output_file
        cmd.extend(["-oX", output_file])

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Target
        cmd.append(target)
        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse Nmap XML output into structured data."""
        if not self._xml_output:
            return self._parse_text(result.stdout)

        xml_path = Path(self._xml_output)
        if not xml_path.exists():
            return self._parse_text(result.stdout)

        result.artifacts.append(xml_path)
        return self._parse_xml(xml_path.read_text())

    def _parse_xml(self, xml_content: str) -> dict[str, Any]:
        """Parse Nmap XML output."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return {"error": "Failed to parse XML", "raw": xml_content[:500]}

        hosts = []
        for host_elem in root.findall("host"):
            host: dict[str, Any] = {}

            # Status
            status = host_elem.find("status")
            if status is not None:
                host["state"] = status.get("state", "unknown")

            # Addresses
            addresses = []
            for addr in host_elem.findall("address"):
                addresses.append({
                    "addr": addr.get("addr", ""),
                    "type": addr.get("addrtype", ""),
                })
            host["addresses"] = addresses
            host["ip"] = next(
                (a["addr"] for a in addresses if a["type"] == "ipv4"), ""
            )

            # Hostnames
            hostnames = []
            names_elem = host_elem.find("hostnames")
            if names_elem is not None:
                for hn in names_elem.findall("hostname"):
                    hostnames.append(hn.get("name", ""))
            host["hostnames"] = hostnames

            # Ports
            ports = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port: dict[str, Any] = {
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", "tcp"),
                    }
                    state = port_elem.find("state")
                    if state is not None:
                        port["state"] = state.get("state", "unknown")
                    service = port_elem.find("service")
                    if service is not None:
                        port["service"] = service.get("name", "")
                        port["product"] = service.get("product", "")
                        port["version"] = service.get("version", "")
                        port["extrainfo"] = service.get("extrainfo", "")
                    # Scripts
                    scripts = {}
                    for script_elem in port_elem.findall("script"):
                        scripts[script_elem.get("id", "")] = script_elem.get(
                            "output", ""
                        )
                    if scripts:
                        port["scripts"] = scripts
                    ports.append(port)
            host["ports"] = ports

            # OS detection
            os_matches = []
            os_elem = host_elem.find("os")
            if os_elem is not None:
                for match in os_elem.findall("osmatch"):
                    os_matches.append({
                        "name": match.get("name", ""),
                        "accuracy": int(match.get("accuracy", 0)),
                    })
            host["os"] = os_matches

            hosts.append(host)

        # Summary
        run_stats = root.find("runstats/finished")
        summary = {}
        if run_stats is not None:
            summary["elapsed"] = run_stats.get("elapsed", "")
            summary["exit"] = run_stats.get("exit", "")

        hosts_stat = root.find("runstats/hosts")
        if hosts_stat is not None:
            summary["hosts_up"] = int(hosts_stat.get("up", 0))
            summary["hosts_down"] = int(hosts_stat.get("down", 0))
            summary["hosts_total"] = int(hosts_stat.get("total", 0))

        return {
            "hosts": hosts,
            "summary": summary,
            "total_open_ports": sum(
                len([p for p in h.get("ports", []) if p.get("state") == "open"])
                for h in hosts
            ),
        }

    def _parse_text(self, text: str) -> dict[str, Any]:
        """Fallback: return raw text if XML is unavailable."""
        return {"raw": text}
