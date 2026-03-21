"""Tests for PhaseModule base class."""

from ice_9.core.models import PhaseType, Severity
from ice_9.phases.base import PhaseModule
from ice_9.tools.base import ToolResult


class DummyPhase(PhaseModule):
    """Minimal concrete phase for testing the base class."""

    phase_type = PhaseType.RECON
    name = "Dummy"
    required_tools = []
    att_ck_techniques = ["T9999"]

    def plan(self, campaign):
        return [{"tool": "nmap", "target": "127.0.0.1", "params": {}}]

    def analyze_results(self, campaign, results):
        return [
            self._create_finding(title="Test finding", severity=Severity.LOW)
        ]


def test_create_finding(tmp_store, audit_logger):
    phase = DummyPhase(tmp_store, audit_logger)
    finding = phase._create_finding(
        title="Vuln X",
        severity=Severity.HIGH,
        description="desc",
        cvss=7.5,
        cve_ids=["CVE-2024-1234"],
        att_ck_ids=["T1190"],
    )
    assert finding.title == "Vuln X"
    assert finding.severity == Severity.HIGH
    assert finding.cvss == 7.5
    assert "CVE-2024-1234" in finding.cve_ids


def test_plan_returns_tasks(sample_campaign, tmp_store, audit_logger):
    phase = DummyPhase(tmp_store, audit_logger)
    tasks = phase.plan(sample_campaign)
    assert len(tasks) == 1
    assert tasks[0]["tool"] == "nmap"


def test_analyze_results_returns_findings(sample_campaign, tmp_store, audit_logger):
    phase = DummyPhase(tmp_store, audit_logger)
    findings = phase.analyze_results(sample_campaign, [])
    assert len(findings) == 1
    assert findings[0].title == "Test finding"


def test_ai_plan_fallback_without_orchestrator(sample_campaign, tmp_store, audit_logger):
    """ai_plan() falls back to plan() when no orchestrator is provided."""
    phase = DummyPhase(tmp_store, audit_logger)
    tasks = phase.ai_plan(sample_campaign, orchestrator=None)
    assert len(tasks) == 1
    assert tasks[0]["tool"] == "nmap"


def test_get_phase_from_campaign(sample_campaign, tmp_store, audit_logger):
    phase = DummyPhase(tmp_store, audit_logger)
    p = phase._get_phase(sample_campaign)
    assert p is not None
    assert p.phase_type == PhaseType.RECON


def test_check_prerequisites_empty(tmp_store, audit_logger):
    phase = DummyPhase(tmp_store, audit_logger)
    phase.required_tools = []
    missing = phase.check_prerequisites()
    assert missing == []
