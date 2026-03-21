"""Campaign and phase state machine with valid transitions."""

from __future__ import annotations

from ice_9.core.models import CampaignStatus, PhaseStatus

# Valid state transitions
CAMPAIGN_TRANSITIONS: dict[CampaignStatus, set[CampaignStatus]] = {
    CampaignStatus.PLANNING: {CampaignStatus.ACTIVE, CampaignStatus.ABORTED},
    CampaignStatus.ACTIVE: {
        CampaignStatus.PAUSED,
        CampaignStatus.COMPLETED,
        CampaignStatus.ABORTED,
    },
    CampaignStatus.PAUSED: {CampaignStatus.ACTIVE, CampaignStatus.ABORTED},
    CampaignStatus.COMPLETED: set(),
    CampaignStatus.ABORTED: set(),
}

PHASE_TRANSITIONS: dict[PhaseStatus, set[PhaseStatus]] = {
    PhaseStatus.PENDING: {PhaseStatus.IN_PROGRESS, PhaseStatus.SKIPPED},
    PhaseStatus.IN_PROGRESS: {PhaseStatus.COMPLETED, PhaseStatus.PENDING},
    PhaseStatus.COMPLETED: {PhaseStatus.IN_PROGRESS},  # allow re-opening
    PhaseStatus.SKIPPED: {PhaseStatus.PENDING},
}


class InvalidTransition(Exception):
    """Raised when a state transition is not allowed."""

    def __init__(self, current: str, target: str, entity: str = ""):
        self.current = current
        self.target = target
        prefix = f"{entity}: " if entity else ""
        super().__init__(f"{prefix}cannot transition from {current} → {target}")


def validate_campaign_transition(
    current: CampaignStatus, target: CampaignStatus
) -> None:
    """Raise InvalidTransition if the transition is not allowed."""
    if target not in CAMPAIGN_TRANSITIONS.get(current, set()):
        raise InvalidTransition(current.value, target.value, "campaign")


def validate_phase_transition(current: PhaseStatus, target: PhaseStatus) -> None:
    """Raise InvalidTransition if the transition is not allowed."""
    if target not in PHASE_TRANSITIONS.get(current, set()):
        raise InvalidTransition(current.value, target.value, "phase")
