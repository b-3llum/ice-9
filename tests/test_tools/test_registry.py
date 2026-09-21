"""Tests for tool registry."""

from ice_9.tools.custom import (
    _registry,
    get_tool,
    list_tools,
    register_defaults,
)


def test_register_defaults_populates_registry():
    _registry.clear()
    register_defaults()
    tools = list_tools()
    names = {t.name for t in tools}

    # All original tools
    assert "nmap" in names
    assert "nuclei" in names
    assert "crackmapexec" in names

    # New OSINT tools
    assert "theharvester" in names
    assert "amass" in names
    assert "subfinder" in names
    assert "responder" in names

    # At least 16 tools
    assert len(tools) >= 16


def test_get_tool_returns_registered():
    _registry.clear()
    register_defaults()
    tool = get_tool("nmap")
    assert tool is not None
    assert tool.name == "nmap"


def test_get_tool_unknown_returns_none():
    _registry.clear()
    register_defaults()
    assert get_tool("nonexistent_tool") is None


def test_tool_get_info():
    _registry.clear()
    register_defaults()
    tool = get_tool("theharvester")
    assert tool is not None
    info = tool.get_info()
    assert info["name"] == "theharvester"
    assert info["binary"] == "theHarvester"
    assert "T1589" in info["att_ck_ids"]
