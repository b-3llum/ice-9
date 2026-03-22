"""kerb-map integration — direct Python import of the kerb_map package."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper

KERB_MAP_PATH = Path.home() / "kerb-map"


class KerbMapWrapper(ToolWrapper):
    """Integration with kerb-map AD attack surface mapper."""

    name = "kerb-map"
    description = "Kerberos attack surface mapper — SPNs, AS-REP, delegation, encryption audit"
    binary = "kerb-map"
    att_ck_ids = [
        "T1558",  # Steal or Forge Kerberos Tickets
        "T1558.003",  # Kerberoasting
        "T1558.004",  # AS-REP Roasting
        "T1134",  # Access Token Manipulation
    ]

    def __init__(self) -> None:
        super().__init__()
        self._kerb_map_available: bool | None = None

    def is_available(self) -> bool:
        """Check if kerb-map is importable."""
        if self._kerb_map_available is not None:
            return self._kerb_map_available
        try:
            # Add kerb-map to path if needed
            if str(KERB_MAP_PATH) not in sys.path:
                sys.path.insert(0, str(KERB_MAP_PATH))
            importlib.import_module("kerb_map")
            self._kerb_map_available = True
        except ImportError:
            # Try as CLI fallback
            self._kerb_map_available = super().is_available()
        return self._kerb_map_available

    def get_info(self) -> dict[str, Any]:
        """Override to report availability via Python import, not shutil.which."""
        return {
            "name": self.name,
            "description": self.description,
            "binary": str(KERB_MAP_PATH / "kerb-map.py"),
            "available": self.is_available(),
            "binary_path": str(KERB_MAP_PATH / "kerb-map.py") if self.is_available() else None,
            "att_ck_ids": self.att_ck_ids,
        }

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Build kerb-map CLI command."""
        cmd = ["python3", str(KERB_MAP_PATH / "kerb-map.py")]

        # Domain controller / target
        cmd.extend(["--dc", target])

        # Domain
        domain = kwargs.get("domain", "")
        if domain:
            cmd.extend(["--domain", domain])

        # Auth
        username = kwargs.get("username", "")
        password = kwargs.get("password", "")
        if username:
            cmd.extend(["--username", username])
        if password:
            cmd.extend(["--password", password])

        # NTLM hash auth
        nt_hash = kwargs.get("nt_hash", "")
        if nt_hash:
            cmd.extend(["--hashes", f":{nt_hash}"])

        # Modules
        modules = kwargs.get("modules", "all")
        if modules != "all":
            cmd.extend(["--modules", modules])

        # Output format
        output_format = kwargs.get("format", "json")
        cmd.extend(["--format", output_format])

        # Aggressive mode
        if kwargs.get("aggressive", False):
            cmd.append("--aggressive")

        # Extra args
        extra = kwargs.get("args", [])
        if extra:
            cmd.extend(extra)

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse kerb-map output."""
        import json

        # Try JSON parsing first
        try:
            data = json.loads(result.stdout)
            return self._normalize_output(data)
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback to text parsing
        return {
            "raw": result.stdout,
            "modules_run": self._extract_modules(result.stdout),
        }

    def _normalize_output(self, data: Any) -> dict[str, Any]:
        """Normalize kerb-map JSON output into ice_9 format."""
        if isinstance(data, dict):
            return {
                "spn_accounts": data.get("spn_accounts", []),
                "asrep_accounts": data.get("asrep_accounts", []),
                "delegation_issues": data.get("delegation", []),
                "encryption_issues": data.get("encryption", []),
                "trust_relationships": data.get("trusts", []),
                "cve_findings": data.get("cves", []),
                "hygiene_issues": data.get("hygiene", []),
                "risk_score": data.get("risk_score"),
                "summary": data.get("summary", {}),
            }
        return {"raw": data}

    def _extract_modules(self, text: str) -> list[str]:
        """Extract which modules were run from text output."""
        modules = []
        module_markers = [
            "SPN Scanner", "AS-REP", "Delegation", "Encryption",
            "Trust Mapper", "CVE Scanner", "Hygiene",
        ]
        for marker in module_markers:
            if marker.lower() in text.lower():
                modules.append(marker)
        return modules
