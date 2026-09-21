"""Tests for the Nmap tool wrapper (stdout XML parsing)."""

from __future__ import annotations

from ice_9.tools.nmap import NmapWrapper

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="web.example.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished elapsed="1.2" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"""


def test_build_command_emits_xml_to_stdout():
    tool = NmapWrapper()
    cmd = tool.build_command("10.0.0.0/24", profile="quick")
    # XML to stdout so it works over an SSH execution backend.
    assert cmd[cmd.index("-oX") + 1] == "-"
    assert "10.0.0.0/24" in cmd


def test_parse_output_from_stdout(mock_tool_result):
    tool = NmapWrapper()
    result = mock_tool_result(tool="nmap", target="10.0.0.5", stdout=_SAMPLE_XML)
    parsed = tool.parse_output(result)

    assert len(parsed["hosts"]) == 1
    host = parsed["hosts"][0]
    assert host["ip"] == "10.0.0.5"
    assert "web.example.com" in host["hostnames"]
    assert host["ports"][0]["port"] == 443
    assert host["ports"][0]["service"] == "https"
    assert parsed["total_open_ports"] == 1
    assert parsed["summary"]["hosts_up"] == 1


def test_parse_output_non_xml_falls_back(mock_tool_result):
    tool = NmapWrapper()
    result = mock_tool_result(tool="nmap", target="x", stdout="not xml output")
    parsed = tool.parse_output(result)
    assert parsed == {"raw": "not xml output"}
