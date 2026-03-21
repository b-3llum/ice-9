"""Responder wrapper — LLMNR/NBT-NS/MDNS poisoner for capturing Net-NTLM hashes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper


class ResponderWrapper(ToolWrapper):
    """Responder integration — LLMNR/NBT-NS/MDNS poisoning and hash capture."""

    name = "responder"
    description = "LLMNR/NBT-NS/MDNS poisoner — capture Net-NTLM hashes on the local network"
    binary = "responder"
    att_ck_ids = ["T1557.001", "T1040"]

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Build Responder command. Target is the network interface (e.g. eth0)."""
        cmd = [self.get_binary_path(), "-I", target]

        if kwargs.get("analyze"):
            cmd.append("-A")  # Analyze mode — listen only, no poisoning

        if kwargs.get("wpad"):
            cmd.extend(["-w", "On"])

        if kwargs.get("verbose"):
            cmd.append("-v")

        if kwargs.get("force_wpad_auth"):
            cmd.append("-F")

        # Disable specific services if needed
        disable = kwargs.get("disable")
        if disable:
            # e.g. disable="SMB,HTTP"
            for svc in disable.split(","):
                cmd.extend([f"--disable-ess"])

        return cmd

    def run(
        self,
        target: str,
        timeout: int = 600,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute Responder with extended default timeout (10 min capture window)."""
        return super().run(target, timeout=timeout, **kwargs)

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse captured hashes from Responder output and log files."""
        ntlmv1_hashes: list[str] = []
        ntlmv2_hashes: list[str] = []
        cleartext: list[str] = []
        captured_from: list[dict[str, str]] = []

        # Parse stdout for hash captures
        for line in result.stdout.splitlines():
            line = line.strip()

            # NTLMv2 hash pattern
            if "NTLMv2-SSP Hash" in line or "NTLMv2 Hash" in line:
                hash_match = re.search(r":\s*(.+)$", line)
                if hash_match:
                    ntlmv2_hashes.append(hash_match.group(1))

            # NTLMv1 hash pattern
            elif "NTLMv1-SSP Hash" in line or "NTLMv1 Hash" in line:
                hash_match = re.search(r":\s*(.+)$", line)
                if hash_match:
                    ntlmv1_hashes.append(hash_match.group(1))

            # Cleartext password
            elif "Cleartext" in line and "Password" in line:
                hash_match = re.search(r":\s*(.+)$", line)
                if hash_match:
                    cleartext.append(hash_match.group(1))

            # Client connection
            client_match = re.match(
                r"\[.*?\]\s+\[.*?\]\s+.*?from\s+(\d+\.\d+\.\d+\.\d+)", line
            )
            if client_match:
                captured_from.append({
                    "ip": client_match.group(1),
                    "line": line[:200],
                })

        # Try to read Responder log files
        log_dirs = [
            Path("/opt/Responder/logs"),
            Path.home() / ".responder" / "logs",
            Path("/usr/share/responder/logs"),
        ]
        for log_dir in log_dirs:
            if log_dir.exists():
                self._parse_log_dir(log_dir, ntlmv1_hashes, ntlmv2_hashes, result)
                break

        return {
            "ntlmv1_hashes": ntlmv1_hashes,
            "ntlmv2_hashes": ntlmv2_hashes,
            "cleartext_passwords": cleartext,
            "captured_from": captured_from,
            "total_hashes": len(ntlmv1_hashes) + len(ntlmv2_hashes),
            "total_cleartext": len(cleartext),
        }

    def _parse_log_dir(
        self,
        log_dir: Path,
        ntlmv1_hashes: list[str],
        ntlmv2_hashes: list[str],
        result: ToolResult,
    ) -> None:
        """Parse hash files from Responder's log directory."""
        for log_file in log_dir.glob("*.txt"):
            result.artifacts.append(log_file)
            name_lower = log_file.name.lower()
            try:
                content = log_file.read_text()
            except OSError:
                continue

            for line in content.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "ntlmv2" in name_lower:
                    if line not in ntlmv2_hashes:
                        ntlmv2_hashes.append(line)
                elif "ntlmv1" in name_lower:
                    if line not in ntlmv1_hashes:
                        ntlmv1_hashes.append(line)
