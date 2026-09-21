"""Tests for automatic entity extraction on phase completion."""

from __future__ import annotations

from ice_9.core.campaign import create_campaign
from ice_9.core.models import Task, TaskStatus
from ice_9.db.store import Store
from ice_9.intel.hooks import _extract_phase_entities


def test_extract_phase_entities_from_persisted_parsed(tmp_path):
    """A completed phase's persisted _parsed output is turned into entities.

    Covers the previously-orphaned hook path together with the _parsed
    persistence fix (tasks now carry the tool's parsed output).
    """
    db_path = tmp_path / "hooks.db"
    store = Store(db_path, check_same_thread=False)
    campaign = create_campaign(
        name="Hook Test", scope=["10.0.0.0/24"], description="", client="", lead=""
    )
    store.save_campaign(campaign)
    phase = campaign.phases[0]

    # Shape base.py persists: params carry the tool's parsed output under _parsed.
    parsed = {
        "hosts": [
            {
                "ip": "10.0.0.5",
                "state": "up",
                "hostnames": ["web.corp.local"],
                "ports": [{"port": 443, "state": "open", "service": "https"}],
            }
        ]
    }
    store.save_task(
        Task(
            tool="nmap",
            target="10.0.0.0/24",
            params={"profile": "standard", "_parsed": parsed},
            status=TaskStatus.COMPLETED,
            output="raw nmap output",
            phase_id=phase.id,
            campaign_id=campaign.id,
        )
    )
    store.close()  # release before the hook opens its own connection

    _extract_phase_entities(db_path, campaign.id, phase.id)

    verify = Store(db_path, check_same_thread=False)
    try:
        entities = verify.get_entities(campaign.id)
        names = {e.name for e in entities}
        assert "10.0.0.5" in names  # host entity extracted
        assert "web.corp.local" in names  # domain entity extracted
    finally:
        verify.close()


def test_extract_phase_entities_noop_without_parsed(tmp_path):
    """Tasks with no _parsed produce no entities (and don't error)."""
    db_path = tmp_path / "hooks_empty.db"
    store = Store(db_path, check_same_thread=False)
    campaign = create_campaign(
        name="Empty", scope=[], description="", client="", lead=""
    )
    store.save_campaign(campaign)
    phase = campaign.phases[0]
    store.save_task(
        Task(
            tool="nmap",
            target="10.0.0.0/24",
            params={"profile": "standard"},
            status=TaskStatus.COMPLETED,
            output="raw",
            phase_id=phase.id,
            campaign_id=campaign.id,
        )
    )
    store.close()

    _extract_phase_entities(db_path, campaign.id, phase.id)

    verify = Store(db_path, check_same_thread=False)
    try:
        assert verify.get_entities(campaign.id) == []
    finally:
        verify.close()
