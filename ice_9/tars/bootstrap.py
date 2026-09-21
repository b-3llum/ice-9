"""Bootstrap the TARS agent with all subsystems wired together.

Provides a single ``build_agent()`` factory that reads ice9.yaml,
initialises providers/router/memory/tools, and returns a ready-to-use
AgentLoop.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ice_9.ai.agent_loop import AgentLoop
from ice_9.ai.llm import LLMClient
from ice_9.ai.memory import MemoryManager
from ice_9.ai.providers import ProviderRegistry
from ice_9.ai.router import ModelRouter
from ice_9.config.settings import Settings, load_settings
from ice_9.tools.python_exec import execute_python
from ice_9.tools.remote import RemoteHost, remote_exec
from ice_9.tools.schema import build_default_registry

# ------------------------------------------------------------------
# Built-in tool implementations for the agent
# ------------------------------------------------------------------

def _shell_exec(command: str, timeout: int = 60) -> str:
    """Execute a shell command locally."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr] {result.stderr}"
        if result.returncode != 0:
            output += f"\n[exit code: {result.returncode}]"
        return output
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s"


def _python_exec(code: str, timeout: int = 30) -> str:
    """Execute sandboxed Python code."""
    result = execute_python(code, timeout=timeout)
    return result.output


def _ssh_exec(
    hostname: str,
    command: str,
    user: str = "root",
    port: int = 22,
) -> str:
    """Execute a command on a remote host."""
    host = RemoteHost(hostname=hostname, user=user, port=port)
    result = remote_exec(host, command)
    output = result.stdout
    if result.stderr:
        output += f"\n[stderr] {result.stderr}"
    return output


# ------------------------------------------------------------------
# Tool registry factory
# ------------------------------------------------------------------

def _build_tool_functions(settings: Settings) -> dict[str, Any]:
    """Map tool names to callable implementations.

    For ice_9 tool wrappers (nmap, nuclei, etc.) we create thin
    lambdas that instantiate the wrapper and call .run().
    """
    tools: dict[str, Any] = {
        "shell": _shell_exec,
        "python": _python_exec,
        "ssh_exec": _ssh_exec,
    }

    # Dynamically register available ice_9 tool wrappers
    _wrapper_map: dict[str, str] = {
        "nmap": "ice_9.tools.nmap:NmapWrapper",
        "nuclei": "ice_9.tools.nuclei:NucleiWrapper",
        "crackmapexec": "ice_9.tools.crackmapexec:CrackMapExecWrapper",
        "bloodhound": "ice_9.tools.bloodhound:BloodHoundWrapper",
        "getnpusers": "ice_9.tools.impacket_tools:GetNPUsersWrapper",
        "getuserspns": "ice_9.tools.impacket_tools:GetUserSPNsWrapper",
        "secretsdump": "ice_9.tools.impacket_tools:SecretsDumpWrapper",
    }

    for name, import_path in _wrapper_map.items():
        module_path, class_name = import_path.rsplit(":", 1)
        try:
            import importlib

            mod = importlib.import_module(module_path)
            wrapper_cls = getattr(mod, class_name)
            wrapper = wrapper_cls()
            if wrapper.is_available():
                # Create a closure that captures the wrapper instance
                def _make_runner(w):
                    def runner(target: str, **kwargs: Any) -> str:
                        result = w.run(target, **kwargs)
                        return result.stdout if result.success else result.stderr
                    return runner

                tools[name] = _make_runner(wrapper)
        except Exception:
            pass  # Tool not installed — skip

    return tools


# ------------------------------------------------------------------
# Agent factory
# ------------------------------------------------------------------

def build_agent(
    config_path: Path | None = None,
    enable_rag: bool = True,
) -> AgentLoop:
    """Build a fully-wired TARS AgentLoop.

    Reads configuration, initialises providers, router, memory, RAG,
    tool registry, and returns an AgentLoop ready for ``agent.run(goal)``.

    Args:
        config_path: Optional path to ice9.yaml.
        enable_rag: Whether to initialise the RAG subsystem.

    Returns:
        A configured AgentLoop instance.
    """
    settings = load_settings(config_path)

    # Providers
    provider_config = {
        k: v.model_dump() for k, v in settings.providers.items()
    }
    provider_registry = ProviderRegistry.from_config(provider_config)

    # LLM client
    llm = LLMClient(timeout=120)

    # Router
    router = ModelRouter(provider_registry)

    # RAG (optional)
    rag_store = None
    if enable_rag:
        try:
            from ice_9.ai.rag.store import RAGStore

            rag_store = RAGStore(
                persist_dir=str(settings.data_dir / "rag"),
                ollama_url=provider_config.get("ollama", {}).get(
                    "base_url", "http://localhost:11434",
                ),
            )
        except Exception:
            pass  # ChromaDB or Ollama not available

    # Memory
    memory = MemoryManager(
        db_path=str(settings.db_path),
        rag_store=rag_store,
    )

    # Tools
    schema_registry = build_default_registry()
    tool_functions = _build_tool_functions(settings)

    # Agent
    agent = AgentLoop(
        llm=llm,
        router=router,
        memory=memory,
        tool_registry=tool_functions,
        schema_registry=schema_registry,
    )

    return agent
