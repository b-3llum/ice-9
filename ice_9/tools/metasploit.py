"""Metasploit Framework integration via MSFRPC."""

from __future__ import annotations

import json
import time
from typing import Any, Optional

import httpx

from ice_9.tools.base import ToolResult, ToolWrapper


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
        self._token: Optional[str] = None
        self._http = httpx.Client(timeout=30, verify=False)

    @property
    def base_url(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/api/v1"

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Build msfconsole command for direct CLI execution."""
        module = kwargs.get("module", "")
        payload = kwargs.get("payload", "")

        cmd = [self.get_binary_path(), "-q", "-x"]

        commands = []
        if module:
            commands.append(f"use {module}")
            commands.append(f"set RHOSTS {target}")

            # Set options
            options = kwargs.get("options", {})
            for key, value in options.items():
                commands.append(f"set {key} {value}")

            if payload:
                commands.append(f"set PAYLOAD {payload}")

            commands.append("run -j")  # Run as job
            commands.append("sleep 10")
            commands.append("sessions -l")
            commands.append("exit")

        cmd.append("; ".join(commands))
        return cmd

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
