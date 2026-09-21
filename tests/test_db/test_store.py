"""Tests for SQLite Store CRUD operations."""

from ice_9.core.campaign import create_campaign
from ice_9.core.models import (
    CampaignStatus,
    Finding,
    PhaseType,
    Severity,
    Task,
    TaskStatus,
)


def test_save_and_get_campaign(tmp_store):
    campaign = create_campaign(
        name="Store Test",
        scope=["10.0.0.0/24"],
        description="test desc",
        client="ACME",
        lead="tester",
    )
    tmp_store.save_campaign(campaign)

    loaded = tmp_store.get_campaign(campaign.id)
    assert loaded is not None
    assert loaded.name == "Store Test"
    assert loaded.client == "ACME"
    assert loaded.status == CampaignStatus.PLANNING
    assert len(loaded.phases) == 13  # All ATT&CK phases


def test_get_campaign_not_found(tmp_store):
    assert tmp_store.get_campaign("nonexistent") is None


def test_list_campaigns(tmp_store):
    c1 = create_campaign(name="C1", scope=[], description="", client="", lead="")
    c2 = create_campaign(name="C2", scope=[], description="", client="", lead="")
    tmp_store.save_campaign(c1)
    tmp_store.save_campaign(c2)

    campaigns = tmp_store.list_campaigns()
    assert len(campaigns) >= 2
    names = {c.name for c in campaigns}
    assert "C1" in names
    assert "C2" in names


def test_list_campaigns_filter_status(tmp_store):
    c = create_campaign(name="Active", scope=[], description="", client="", lead="")
    from ice_9.core.campaign import transition_campaign
    transition_campaign(c, CampaignStatus.ACTIVE)
    tmp_store.save_campaign(c)

    active = tmp_store.list_campaigns(status=CampaignStatus.ACTIVE)
    assert any(ca.name == "Active" for ca in active)

    planning = tmp_store.list_campaigns(status=CampaignStatus.PLANNING)
    assert not any(ca.name == "Active" for ca in planning)


def test_delete_campaign(tmp_store):
    c = create_campaign(name="Delete Me", scope=[], description="", client="", lead="")
    tmp_store.save_campaign(c)
    assert tmp_store.delete_campaign(c.id) is True
    assert tmp_store.get_campaign(c.id) is None


def test_delete_campaign_not_found(tmp_store):
    assert tmp_store.delete_campaign("nonexistent") is False


def test_save_and_load_task(tmp_store):
    c = create_campaign(name="Task Test", scope=[], description="", client="", lead="")
    tmp_store.save_campaign(c)

    phase = c.phases[0]
    task = Task(
        tool="nmap",
        target="10.0.0.1",
        params={"profile": "quick"},
        status=TaskStatus.COMPLETED,
        output="scan results",
        att_ck_id="T1046",
        phase_id=phase.id,
        campaign_id=c.id,
    )
    tmp_store.save_task(task)

    # Reload campaign and check tasks
    loaded = tmp_store.get_campaign(c.id)
    loaded_phase = next(p for p in loaded.phases if p.id == phase.id)
    assert len(loaded_phase.tasks) == 1
    assert loaded_phase.tasks[0].tool == "nmap"
    assert loaded_phase.tasks[0].status == TaskStatus.COMPLETED


def test_get_all_findings_ordered_by_severity(tmp_store):
    """Findings must come back ordered by risk, not alphabetically by severity text."""
    c = create_campaign(name="Order Test", scope=[], description="", client="", lead="")
    tmp_store.save_campaign(c)
    phase = c.phases[0]

    for sev in [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH, Severity.MEDIUM]:
        tmp_store.save_finding(
            Finding(title=f"{sev.value} finding", severity=sev, phase_id=phase.id)
        )

    findings = tmp_store.get_all_findings(c.id)
    assert [f.severity for f in findings] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]


def test_get_campaign_uses_bounded_queries(tmp_store):
    """Hydration must not issue a query per phase (N+1).

    A campaign has 13 phases; the old code ran ~2 queries per phase. Batch
    loading keeps it to a small constant regardless of phase count.
    """
    c = create_campaign(name="Nplus1", scope=[], description="", client="", lead="")
    tmp_store.save_campaign(c)
    # Put a task and a finding in a couple of phases.
    for phase in c.phases[:3]:
        tmp_store.save_task(
            Task(tool="nmap", target="10.0.0.1", status=TaskStatus.COMPLETED,
                 phase_id=phase.id, campaign_id=c.id)
        )
        tmp_store.save_finding(
            Finding(title="f", severity=Severity.LOW, phase_id=phase.id)
        )

    count = 0

    def tracer(_sql):
        nonlocal count
        count += 1

    tmp_store.conn.set_trace_callback(tracer)
    try:
        loaded = tmp_store.get_campaign(c.id)
    finally:
        tmp_store.conn.set_trace_callback(None)

    assert len(loaded.phases) == 13
    assert sum(len(p.tasks) for p in loaded.phases) == 3
    assert sum(len(p.findings) for p in loaded.phases) == 3
    # campaign + phases + tasks + findings — a small constant, not ~28.
    assert count <= 5, f"expected bounded query count, got {count}"


def test_resave_task_preserves_finding_link(tmp_store):
    """Re-saving a task must not null the task_id of findings that reference it.

    Regression: INSERT OR REPLACE deletes the task row (firing the
    findings.task_id ON DELETE SET NULL cascade) before re-inserting.
    """
    c = create_campaign(name="Link Test", scope=[], description="", client="", lead="")
    tmp_store.save_campaign(c)
    phase = c.phases[0]

    task = Task(
        tool="nmap",
        target="10.0.0.1",
        status=TaskStatus.COMPLETED,
        phase_id=phase.id,
        campaign_id=c.id,
    )
    tmp_store.save_task(task)

    finding = Finding(
        title="Linked finding",
        severity=Severity.MEDIUM,
        phase_id=phase.id,
        task_id=task.id,
    )
    tmp_store.save_finding(finding)

    # Re-save the same task (e.g. status update) — the link must survive.
    task.output = "updated output"
    tmp_store.save_task(task)

    findings = tmp_store.get_all_findings(c.id)
    assert len(findings) == 1
    assert findings[0].task_id == task.id


def test_save_and_load_finding(tmp_store):
    c = create_campaign(name="Finding Test", scope=[], description="", client="", lead="")
    tmp_store.save_campaign(c)

    phase = c.phases[0]
    finding = Finding(
        title="Open SMB",
        severity=Severity.HIGH,
        description="SMB exposed on port 445",
        remediation="Block port 445",
        cvss=7.5,
        cve_ids=["CVE-2024-0001"],
        att_ck_ids=["T1021.002"],
        phase_id=phase.id,
    )
    tmp_store.save_finding(finding)

    # Reload via get_all_findings
    findings = tmp_store.get_all_findings(c.id)
    assert len(findings) == 1
    assert findings[0].title == "Open SMB"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cvss == 7.5
    assert "CVE-2024-0001" in findings[0].cve_ids


def test_campaign_round_trip_preserves_phases(tmp_store):
    c = create_campaign(
        name="Round Trip", scope=["example.com"], description="", client="", lead=""
    )
    tmp_store.save_campaign(c)

    loaded = tmp_store.get_campaign(c.id)
    phase_types = {p.phase_type for p in loaded.phases}
    assert PhaseType.RECON in phase_types
    assert PhaseType.IMPACT in phase_types
    assert len(phase_types) == 13
