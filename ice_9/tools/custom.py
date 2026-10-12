"""Generic custom tool runner — execute any CLI tool with output capture."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ice_9.tools.base import ToolResult, ToolWrapper, validate_arg_list

if TYPE_CHECKING:
    from ice_9.config.settings import Settings


class CustomToolWrapper(ToolWrapper):
    """Run any arbitrary CLI tool and capture output."""

    name = "custom"
    description = "Generic tool runner — execute any CLI command with structured output capture"
    binary = ""
    att_ck_ids = []

    def __init__(
        self,
        name: str = "custom",
        binary: str = "",
        description: str = "",
        att_ck_ids: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.name = name
        self.binary = binary
        self.description = description or f"Custom tool: {binary}"
        self.att_ck_ids = att_ck_ids or []

    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """Build command from binary + args + target."""
        cmd = [self.get_binary_path()]

        # Pre-target args
        cmd.extend(validate_arg_list(kwargs.get("pre_args"), "pre_args"))

        # Target (can be empty for some tools)
        if target:
            cmd.append(target)

        # Post-target args
        cmd.extend(validate_arg_list(kwargs.get("post_args"), "post_args"))

        # Generic args list
        cmd.extend(validate_arg_list(kwargs.get("args"), "args"))

        return cmd

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Try JSON parsing, fall back to line-based text."""
        # Try JSON
        try:
            return {"data": json.loads(result.stdout)}
        except (json.JSONDecodeError, ValueError):
            pass

        # Try JSONL
        lines = result.stdout.strip().splitlines()
        jsonl_entries = []
        for line in lines:
            try:
                jsonl_entries.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                break
        if jsonl_entries and len(jsonl_entries) == len(lines):
            return {"data": jsonl_entries, "format": "jsonl"}

        # Text output
        return {
            "lines": lines,
            "line_count": len(lines),
            "format": "text",
        }


# --- Tool Registry ---

_registry: dict[str, ToolWrapper] = {}


def register_tool(tool: ToolWrapper) -> None:
    """Register a tool in the global registry."""
    _registry[tool.name] = tool


def get_tool(name: str) -> ToolWrapper | None:
    """Get a tool by name."""
    return _registry.get(name)


def list_tools() -> list[ToolWrapper]:
    """List all registered tools."""
    return list(_registry.values())


def register_defaults(settings: Settings | None = None) -> None:
    """Register all built-in tool wrappers.

    When *settings* is given, the Metasploit wrapper is built from
    ``settings.metasploit`` (host, port, auth, TLS verification); otherwise
    it uses its own defaults (self-signed localhost msfrpcd).
    """
    from ice_9.tools.amass import AmassWrapper
    from ice_9.tools.bloodhound import BloodHoundWrapper
    from ice_9.tools.crackmapexec import CrackMapExecWrapper
    from ice_9.tools.impacket_tools import (
        GetNPUsers,
        GetUserSPNs,
        NTLMRelayx,
        PsExec,
        SecretsDump,
        WmiExec,
    )
    from ice_9.tools.kerb_map import KerbMapWrapper
    from ice_9.tools.metasploit import MetasploitWrapper
    from ice_9.tools.nmap import NmapWrapper
    from ice_9.tools.nuclei import NucleiWrapper
    from ice_9.tools.responder import ResponderWrapper
    from ice_9.tools.subfinder import SubfinderWrapper
    from ice_9.tools.theharvester import TheHarvesterWrapper

    register_tool(NmapWrapper())
    register_tool(NucleiWrapper())
    register_tool(KerbMapWrapper())
    register_tool(BloodHoundWrapper())
    if settings is not None and getattr(settings, "metasploit", None) is not None:
        mc = settings.metasploit
        register_tool(MetasploitWrapper(
            host=mc.host,
            port=mc.port,
            password=mc.password,
            ssl=mc.ssl,
            username=mc.username,
            verify_tls=mc.verify_tls,
        ))
    else:
        register_tool(MetasploitWrapper())
    register_tool(CrackMapExecWrapper())
    register_tool(SecretsDump())
    register_tool(GetNPUsers())
    register_tool(GetUserSPNs())
    register_tool(PsExec())
    register_tool(WmiExec())
    register_tool(NTLMRelayx())
    register_tool(TheHarvesterWrapper())
    register_tool(AmassWrapper())
    register_tool(SubfinderWrapper())
    register_tool(ResponderWrapper())
