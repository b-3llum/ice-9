"""Metasploit Framework integration via MSFRPC."""

from __future__ import annotations

import re
import tempfile
from typing import Any

import httpx

from ice_9.tools.base import ToolResult, ToolWrapper

# Allowed characters in Metasploit module paths (e.g. exploit/windows/smb/ms17_010)
_MODULE_PATH_RE = re.compile(r"^[a-zA-Z0-9_/.-]+$")
# Allowed characters in MSF option keys (e.g. RHOSTS, LPORT)
_OPTION_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Option values: alphanumeric, IPs, CIDRs, paths, colons, dots, slashes, dashes
_OPTION_VALUE_RE = re.compile(r"^[a-zA-Z0-9_./:@\-\[\], ]+$")


class MetasploitWrapper(ToolWrapper):
    """Metasploit Framework integration via REST API (msfrpcd)."""

    name = "metasploit"
    description = "Exploitation framework — module execution, session management"
    binary = "msfconsole"
    att_ck_ids = ["T1190", "T1210", "T1059"]  # Exploit Public-Facing, Exploitation of Remote Services, Command Execution

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        password: str = "msf",
        ssl: bool = True,
    ) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.password = password
        self.ssl = ssl
        self._token: str | None = None
        self._http = httpx.Client(timeout=30, verify=False)

    @property
    def base_url(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/api/v1"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Build msfconsole command for direct CLI execution.

        Uses a temporary resource file (-r) instead of inline -x to avoid
        command injection via semicolons in user-supplied values.
        """
        module = kwargs.get("module", "")
        payload = kwargs.get("payload", "")

        rc_lines: list[str] = []
        if module:
            self._validate_module_path(module)
            self._validate_option_value(target, "target")
            rc_lines.append(f"use {module}")
            rc_lines.append(f"set RHOSTS {target}")

            options = kwargs.get("options", {})
            for key, value in options.items():
                self._validate_option_key(key)
                self._validate_option_value(str(value), key)
                rc_lines.append(f"set {key} {value}")

            if payload:
                self._validate_module_path(payload)
                rc_lines.append(f"set PAYLOAD {payload}")

            rc_lines.append("run -j")
            rc_lines.append("sleep 10")
            rc_lines.append("sessions -l")
            rc_lines.append("exit")

        # Write commands to a temp resource file so msfconsole reads them
        # line-by-line instead of parsing a semicolon-joined string.
        self._rc_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".rc", prefix="ice9_msf_", delete=False,
        )
        self._rc_file.write("\n".join(rc_lines) + "\n")
        self._rc_file.flush()
        self._rc_file.close()

        return [self.get_binary_path(), "-q", "-r", self._rc_file.name]

    @staticmethod
    def _validate_module_path(value: str) -> None:
        """Validate a Metasploit module path or payload name."""
        if not _MODULE_PATH_RE.match(value):
            raise ValueError(
                f"Invalid module path: {value!r} — "
                "only alphanumeric, underscores, slashes, dots, and dashes allowed"
            )

    @staticmethod
    def _validate_option_key(key: str) -> None:
        """Validate an MSF option key (e.g. RHOSTS, LPORT)."""
        if not _OPTION_KEY_RE.match(key):
            raise ValueError(
                f"Invalid option key: {key!r} — "
                "must be alphanumeric/underscore, starting with a letter"
            )

    @staticmethod
    def _validate_option_value(value: str, name: str) -> None:
        """Validate an MSF option value against injection characters."""
        if not _OPTION_VALUE_RE.match(value):
            raise ValueError(
                f"Invalid value for {name}: {value!r} — "
                "contains disallowed characters"
            )

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse msfconsole output."""
        lines = result.stdout.strip().splitlines()
        sessions = []
        exploits_run = []

        for line in lines:
            # Session detection
            if "session" in line.lower() and ("opened" in line.lower() or "meterpreter" in line.lower()):
                sessions.append(line.strip())
            # Module results
            if "[+]" in line or "[*]" in line:
                exploits_run.append(line.strip())

        return {
            "sessions_opened": len(sessions),
            "session_details": sessions,
            "results": exploits_run[-30:],
            "raw_lines": len(lines),
        }

    # --- MSFRPC API methods ---

    def _authenticate(self) -> bool:
        """Authenticate to msfrpcd."""
        try:
            resp = self._http.post(
                f"{self.base_url}/auth/login",
                json={"username": "msf", "password": self.password},
            )
            if resp.status_code == 200:
                self._token = resp.json().get("token")
                return True
        except Exception:
            pass
        return False

    def _api_call(self, method: str, endpoint: str, data: dict | None = None) -> dict:
        """Make an authenticated API call."""
        if not self._token:
            self._authenticate()

        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}

        if method == "GET":
            resp = self._http.get(f"{self.base_url}{endpoint}", headers=headers)
        else:
            resp = self._http.post(
                f"{self.base_url}{endpoint}", json=data or {}, headers=headers
            )

        return resp.json() if resp.status_code == 200 else {"error": resp.text}

    def search_modules(self, query: str) -> dict[str, Any]:
        """Search for Metasploit modules."""
        return self._api_call("GET", f"/modules/search?query={query}")

    def list_sessions(self) -> dict[str, Any]:
        """List active sessions."""
        return self._api_call("GET", "/sessions")

    def run_module(
        self,
        module_type: str,
        module_name: str,
        target: str,
        options: dict[str, str] | None = None,
        payload: str = "",
    ) -> dict[str, Any]:
        """Execute a module via the API."""
        data = {
            "module_type": module_type,
            "module_name": module_name,
            "options": {"RHOSTS": target, **(options or {})},
        }
        if payload:
            data["options"]["PAYLOAD"] = payload

        return self._api_call("POST", "/modules/execute", data)
