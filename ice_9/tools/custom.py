"""Generic custom tool runner — execute any CLI tool with output capture."""

from __future__ import annotations

import json
from typing import Any

from ice_9.tools.base import ToolResult, ToolWrapper


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
        pre_args = kwargs.get("pre_args", [])
        if pre_args:
            cmd.extend(pre_args)

        # Target (can be empty for some tools)
        if target:
            cmd.append(target)

        # Post-target args
        post_args = kwargs.get("post_args", [])
        if post_args:
            cmd.extend(post_args)

        # Generic args list
        args = kwargs.get("args", [])
        if args:
            cmd.extend(args)

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


def register_defaults() -> None:
    """Register all built-in tool wrappers."""
    from ice_9.tools.nmap import NmapWrapper
    from ice_9.tools.nuclei import NucleiWrapper
    from ice_9.tools.kerb_map import KerbMapWrapper
    from ice_9.tools.bloodhound import BloodHoundWrapper
    from ice_9.tools.metasploit import MetasploitWrapper
    from ice_9.tools.crackmapexec import CrackMapExecWrapper
    from ice_9.tools.impacket_tools import (
        SecretsDump, GetNPUsers, GetUserSPNs, PsExec, WmiExec, NTLMRelayx,
    )
    from ice_9.tools.theharvester import TheHarvesterWrapper
    from ice_9.tools.amass import AmassWrapper
    from ice_9.tools.subfinder import SubfinderWrapper
    from ice_9.tools.responder import ResponderWrapper

    register_tool(NmapWrapper())
    register_tool(NucleiWrapper())
    register_tool(KerbMapWrapper())
    register_tool(BloodHoundWrapper())
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
