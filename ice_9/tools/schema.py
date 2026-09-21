"""Unified tool schema for LLM tool-use.

Provides a JSON schema format that can be passed to both local and cloud
models so they can select and invoke tools in a structured way.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolParameter:
    """A single parameter in a tool schema."""

    name: str
    type: str  # "string", "integer", "boolean", "array", "object"
    description: str
    required: bool = True
    enum: list[str] | None = None
    default: Any = None


@dataclass
class ToolSchema:
    """Describes a tool the LLM can invoke."""

    name: str
    description: str
    parameters: list[ToolParameter] = field(default_factory=list)
    category: str = "general"  # "shell", "python", "api", "recon", "exploit"
    requires_confirmation: bool = False
    max_runtime_seconds: int = 300

    def to_llm_schema(self) -> dict[str, Any]:
        """Convert to the OpenAI/Claude function-calling JSON format."""
        props: dict[str, Any] = {}
        required: list[str] = []
        for p in self.parameters:
            prop: dict[str, Any] = {
                "type": p.type,
                "description": p.description,
            }
            if p.enum:
                prop["enum"] = p.enum
            if p.default is not None:
                prop["default"] = p.default
            props[p.name] = prop
            if p.required:
                required.append(p.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            },
        }

    def to_text_description(self) -> str:
        """Human-readable description for injection into system prompts."""
        params = ", ".join(
            f"{p.name}: {p.type}" + (" (optional)" if not p.required else "")
            for p in self.parameters
        )
        return f"  {self.name}({params}) — {self.description}"


# ------------------------------------------------------------------
# Registry helpers
# ------------------------------------------------------------------

class ToolSchemaRegistry:
    """Collects tool schemas and formats them for LLM consumption."""

    def __init__(self) -> None:
        self._schemas: dict[str, ToolSchema] = {}

    def register(self, schema: ToolSchema) -> None:
        self._schemas[schema.name] = schema

    def get(self, name: str) -> ToolSchema | None:
        return self._schemas.get(name)

    def list_schemas(self) -> list[ToolSchema]:
        return list(self._schemas.values())

    def to_llm_tools(self) -> list[dict[str, Any]]:
        """Return all schemas in LLM function-calling format."""
        return [s.to_llm_schema() for s in self._schemas.values()]

    def to_text_block(self) -> str:
        """Return all schemas as a text block for system prompts."""
        return "\n".join(s.to_text_description() for s in self._schemas.values())


# ------------------------------------------------------------------
# Built-in schemas for ice_9 tools
# ------------------------------------------------------------------

BUILTIN_SCHEMAS: list[ToolSchema] = [
    ToolSchema(
        name="nmap",
        description="Network port scanner and service detection",
        parameters=[
            ToolParameter("target", "string", "Target host, IP, or CIDR range"),
            ToolParameter("profile", "string", "Scan profile", required=False, default="standard",
                          enum=["quick", "standard", "full", "stealth", "udp"]),
        ],
        category="recon",
    ),
    ToolSchema(
        name="nuclei",
        description="Template-based vulnerability scanner",
        parameters=[
            ToolParameter("target", "string", "Target URL or host"),
            ToolParameter("profile", "string", "Scan profile", required=False, default="standard",
                          enum=["quick", "standard", "full", "cve_critical"]),
        ],
        category="recon",
    ),
    ToolSchema(
        name="crackmapexec",
        description="AD/SMB credential testing and enumeration",
        parameters=[
            ToolParameter("target", "string", "Target host or range"),
            ToolParameter("protocol", "string", "Protocol to use", required=False, default="smb",
                          enum=["smb", "ldap", "winrm", "mssql", "ssh"]),
            ToolParameter("username", "string", "Username for authentication", required=False),
            ToolParameter("password", "string", "Password for authentication", required=False),
        ],
        category="exploit",
    ),
    ToolSchema(
        name="bloodhound",
        description="Active Directory attack path analysis",
        parameters=[
            ToolParameter("target", "string", "Domain or DC to collect from"),
            ToolParameter("username", "string", "Domain username", required=False),
            ToolParameter("password", "string", "Domain password", required=False),
        ],
        category="recon",
    ),
    ToolSchema(
        name="getnpusers",
        description="AS-REP roasting — find accounts without Kerberos pre-auth",
        parameters=[
            ToolParameter("target", "string", "Domain/user specification (e.g. corp.local/)"),
            ToolParameter("dc_ip", "string", "Domain controller IP", required=False),
            ToolParameter("no_pass", "boolean", "Attempt without credentials", required=False, default=True),
        ],
        category="exploit",
    ),
    ToolSchema(
        name="getuserspns",
        description="Kerberoasting — extract service ticket hashes",
        parameters=[
            ToolParameter("target", "string", "Domain/user:pass specification"),
            ToolParameter("dc_ip", "string", "Domain controller IP", required=False),
        ],
        category="exploit",
    ),
    ToolSchema(
        name="secretsdump",
        description="Extract SAM/LSA secrets and NTDS.dit hashes",
        parameters=[
            ToolParameter("target", "string", "Target specification (user:pass@host)"),
        ],
        category="exploit",
        requires_confirmation=True,
    ),
    ToolSchema(
        name="shell",
        description="Execute a shell command on the local system",
        parameters=[
            ToolParameter("command", "string", "The shell command to execute"),
            ToolParameter("timeout", "integer", "Timeout in seconds", required=False, default=60),
        ],
        category="shell",
        requires_confirmation=True,
    ),
    ToolSchema(
        name="python",
        description="Execute a Python script in a sandboxed subprocess",
        parameters=[
            ToolParameter("code", "string", "Python source code to execute"),
            ToolParameter("timeout", "integer", "Timeout in seconds", required=False, default=30),
        ],
        category="python",
    ),
    ToolSchema(
        name="ssh_exec",
        description="Execute a command on a remote host via SSH",
        parameters=[
            ToolParameter("hostname", "string", "Remote hostname or IP"),
            ToolParameter("command", "string", "Command to execute remotely"),
            ToolParameter("user", "string", "SSH username", required=False, default="root"),
            ToolParameter("port", "integer", "SSH port", required=False, default=22),
        ],
        category="shell",
        requires_confirmation=True,
    ),
]


def build_default_registry() -> ToolSchemaRegistry:
    """Create a registry pre-populated with all built-in tool schemas."""
    registry = ToolSchemaRegistry()
    for schema in BUILTIN_SCHEMAS:
        registry.register(schema)
    return registry
