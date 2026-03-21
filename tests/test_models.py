"""Tests for core data models."""

from ice_9.core.models import (
    Campaign,
    CampaignStatus,
    Finding,
    Phase,
    PhaseStatus,
    PhaseType,
    Severity,
    Task,
    TaskStatus,
)
from ice_9.core.campaign import create_campaign


def test_create_campaign_generates_id():
    campaign = create_campaign(name="test", scope=["10.0.0.0/8"])
    assert campaign.id
    assert len(campaign.id) == 12
    assert campaign.name == "test"
    assert campaign.status == CampaignStatus.PLANNING


def test_create_campaign_has_all_phases():
    campaign = create_campaign(name="test", scope=[])
    assert len(campaign.phases) == len(PhaseType)
    phase_types = {p.phase_type for p in campaign.phases}
    assert phase_types == set(PhaseType)


def test_create_campaign_scope():
    campaign = create_campaign(name="test", scope=["192.168.1.0/24", "example.com"])
    assert campaign.rules_of_engagement.scope == ["192.168.1.0/24", "example.com"]


def test_finding_defaults():
    finding = Finding(title="test finding")
    assert finding.id
    assert finding.severity == Severity.INFO
    assert finding.cve_ids == []
    assert finding.att_ck_ids == []


def test_task_defaults():
    task = Task(tool="nmap", target="10.0.0.1")
    assert task.status == TaskStatus.QUEUED
    assert task.params == {}


def test_phase_name_property():
    phase = Phase(phase_type=PhaseType.RECON)
    assert phase.name == "Reconnaissance"

    phase2 = Phase(phase_type=PhaseType.LATERAL_MOVEMENT)
    assert phase2.name == "Lateral Movement"


def test_severity_ordering():
    severities = [Severity.INFO, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH, Severity.LOW]
    assert Severity.CRITICAL.value == "critical"
    assert Severity.INFO.value == "info"
