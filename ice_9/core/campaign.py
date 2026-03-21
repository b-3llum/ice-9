"""Campaign lifecycle management."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from ice_9.core.models import (
    Campaign,
    CampaignStatus,
    Phase,
    PhaseStatus,
    PhaseType,
    RulesOfEngagement,
)
from ice_9.core.state import validate_campaign_transition, validate_phase_transition


def create_campaign(
    name: str,
    scope: list[str] | None = None,
    description: str = "",
    client: str = "",
    lead: str = "",
    exclusions: list[str] | None = None,
) -> Campaign:
    """Create a new campaign with default phases."""
    roe = RulesOfEngagement(
        scope=scope or [],
        exclusions=exclusions or [],
    )
    campaign = Campaign(
        name=name,
        description=description,
        client=client,
        lead=lead,
        rules_of_engagement=roe,
    )
    # Pre-populate all ATT&CK phases
    for pt in PhaseType:
        phase = Phase(phase_type=pt, campaign_id=campaign.id)
        campaign.phases.append(phase)
    return campaign


def transition_campaign(campaign: Campaign, target: CampaignStatus) -> Campaign:
    """Transition campaign to a new status."""
    validate_campaign_transition(campaign.status, target)
    campaign.status = target
    campaign.updated_at = datetime.utcnow()
    return campaign


def start_phase(campaign: Campaign, phase_type: PhaseType) -> Phase:
    """Start a phase within a campaign."""
    phase = next((p for p in campaign.phases if p.phase_type == phase_type), None)
    if not phase:
        raise ValueError(f"Phase {phase_type.value} not found in campaign")
    validate_phase_transition(phase.status, PhaseStatus.IN_PROGRESS)
    phase.status = PhaseStatus.IN_PROGRESS
    phase.started_at = datetime.utcnow()
    campaign.updated_at = datetime.utcnow()
    # Auto-activate campaign if still planning
    if campaign.status == CampaignStatus.PLANNING:
        campaign.status = CampaignStatus.ACTIVE
    return phase


def complete_phase(campaign: Campaign, phase_type: PhaseType) -> Phase:
    """Mark a phase as completed."""
    phase = next((p for p in campaign.phases if p.phase_type == phase_type), None)
    if not phase:
        raise ValueError(f"Phase {phase_type.value} not found in campaign")
    validate_phase_transition(phase.status, PhaseStatus.COMPLETED)
    phase.status = PhaseStatus.COMPLETED
    phase.completed_at = datetime.utcnow()
    campaign.updated_at = datetime.utcnow()
    return phase


def skip_phase(campaign: Campaign, phase_type: PhaseType) -> Phase:
    """Skip a phase."""
    phase = next((p for p in campaign.phases if p.phase_type == phase_type), None)
    if not phase:
        raise ValueError(f"Phase {phase_type.value} not found in campaign")
    validate_phase_transition(phase.status, PhaseStatus.SKIPPED)
    phase.status = PhaseStatus.SKIPPED
    campaign.updated_at = datetime.utcnow()
    return phase


def get_active_phases(campaign: Campaign) -> list[Phase]:
    """Get all in-progress phases."""
    return [p for p in campaign.phases if p.status == PhaseStatus.IN_PROGRESS]


def get_campaign_progress(campaign: Campaign) -> dict:
    """Get campaign progress summary."""
    total = len(campaign.phases)
    completed = sum(1 for p in campaign.phases if p.status == PhaseStatus.COMPLETED)
    in_progress = sum(1 for p in campaign.phases if p.status == PhaseStatus.IN_PROGRESS)
    skipped = sum(1 for p in campaign.phases if p.status == PhaseStatus.SKIPPED)
    findings_count = sum(len(p.findings) for p in campaign.phases)
    return {
        "total_phases": total,
        "completed": completed,
        "in_progress": in_progress,
        "skipped": skipped,
        "pending": total - completed - in_progress - skipped,
        "findings": findings_count,
        "progress_pct": round((completed + skipped) / total * 100) if total else 0,
    }
