"""Tests for Reconnaissance phase module."""

from ice_9.core.models import PhaseType, Severity
from ice_9.phases.recon import ReconPhase


def test_recon_phase_attributes():
    phase = ReconPhase.__new__(ReconPhase)
    assert phase.phase_type == PhaseType.RECON
    assert "nmap" in phase.required_tools
    assert "T1595" in phase.att_ck_techniques


def test_plan_generates_tasks(sample_campaign, tmp_store, audit_logger):
    phase = ReconPhase(tmp_store, audit_logger)
    tasks = phase.plan(sample_campaign)

    # 2 scope items: 192.168.1.0/24 (nmap x3) + example.com (nmap x3 + osint x3)
    assert len(tasks) >= 6
    tool_names = [t["tool"] for t in tasks]
    assert "nmap" in tool_names
    assert "nuclei" in tool_names


def test_plan_osint_for_domains(sample_campaign, tmp_store, audit_logger):
    phase = ReconPhase(tmp_store, audit_logger)
    tasks = phase.plan(sample_campaign)
    tool_names = [t["tool"] for t in tasks]

    # example.com is a domain, should trigger OSINT tools
    assert "theharvester" in tool_names
    assert "amass" in tool_names
    assert "subfinder" in tool_names


def test_plan_no_osint_for_ip(tmp_store, audit_logger):
    from ice_9.core.campaign import create_campaign

    campaign = create_campaign(
        name="IP only", scope=["10.0.0.0/24"], description="", client="", lead=""
    )
    phase = ReconPhase(tmp_store, audit_logger)
    tasks = phase.plan(campaign)
    tool_names = [t["tool"] for t in tasks]

    assert "theharvester" not in tool_names
    assert "amass" not in tool_names


def test_plan_empty_scope(tmp_store, audit_logger):
    from ice_9.core.campaign import create_campaign

    campaign = create_campaign(
        name="Empty", scope=[], description="", client="", lead=""
    )
    phase = ReconPhase(tmp_store, audit_logger)
    tasks = phase.plan(campaign)
    assert tasks == []


def test_analyze_nmap_risky_ports(sample_campaign, tmp_store, audit_logger, mock_tool_result):
    phase = ReconPhase(tmp_store, audit_logger)

    result = mock_tool_result(
        tool="nmap",
        target="192.168.1.1",
        parsed={
            "hosts": [
                {
                    "ip": "192.168.1.1",
                    "ports": [
                        {"port": 445, "state": "open", "service": "smb", "product": "Samba", "version": "4.15"},
                        {"port": 3389, "state": "open", "service": "ms-wbt-server", "product": "", "version": ""},
                        {"port": 80, "state": "open", "service": "http", "product": "nginx", "version": "1.18"},
                    ],
                }
            ]
        },
    )

    findings = phase.analyze_results(sample_campaign, [result])
    titles = [f.title for f in findings]
    assert any("SMB" in t for t in titles)
    assert any("RDP" in t for t in titles)


def test_analyze_theharvester_emails(sample_campaign, tmp_store, audit_logger, mock_tool_result):
    phase = ReconPhase(tmp_store, audit_logger)

    result = mock_tool_result(
        tool="theharvester",
        target="example.com",
        parsed={
            "emails": ["admin@example.com", "user@example.com"],
            "subdomains": ["mail.example.com"],
            "ips": [],
        },
    )

    findings = phase.analyze_results(sample_campaign, [result])
    assert any("email" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.LOW for f in findings)


def test_analyze_subdomain_tool(sample_campaign, tmp_store, audit_logger, mock_tool_result):
    phase = ReconPhase(tmp_store, audit_logger)

    result = mock_tool_result(
        tool="subfinder",
        target="example.com",
        parsed={"subdomains": ["a.example.com", "b.example.com"]},
    )

    findings = phase.analyze_results(sample_campaign, [result])
    assert len(findings) == 1
    assert "subfinder" in findings[0].title.lower()
