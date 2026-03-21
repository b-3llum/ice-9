"""Tests for theHarvester tool wrapper."""

from ice_9.tools.theharvester import TheHarvesterWrapper


def test_build_command_defaults():
    tool = TheHarvesterWrapper()
    cmd = tool.build_command("example.com")
    assert cmd[1:] == ["-d", "example.com", "-b", "all", "-l", "500"]


def test_build_command_custom_source():
    tool = TheHarvesterWrapper()
    cmd = tool.build_command("example.com", source="bing", limit=100)
    assert "-b" in cmd
    idx = cmd.index("-b")
    assert cmd[idx + 1] == "bing"
    assert "-l" in cmd
    idx = cmd.index("-l")
    assert cmd[idx + 1] == "100"


def test_parse_output_emails(mock_tool_result):
    tool = TheHarvesterWrapper()
    result = mock_tool_result(
        tool="theharvester",
        target="example.com",
        stdout=(
            "[*] Emails found:\n"
            "admin@example.com\n"
            "user@example.com\n"
            "\n"
            "[*] Hosts found:\n"
            "mail.example.com\n"
            "www.example.com\n"
        ),
    )
    parsed = tool.parse_output(result)
    assert "admin@example.com" in parsed["emails"]
    assert "user@example.com" in parsed["emails"]
    assert parsed["email_count"] == 2
    assert "mail.example.com" in parsed["subdomains"]
    assert parsed["subdomain_count"] == 2
