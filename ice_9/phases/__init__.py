"""ATT&CK-aligned phase modules — registry and factory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ice_9.core.models import PhaseType
from ice_9.phases.base import PhaseModule

if TYPE_CHECKING:
    from ice_9.core.audit import AuditLogger
    from ice_9.db.store import Store


def _load_modules() -> dict[PhaseType, type[PhaseModule]]:
    """Lazy-load all phase module classes."""
    from ice_9.phases.recon import ReconPhase
    from ice_9.phases.resource_dev import ResourceDevPhase
    from ice_9.phases.initial_access import InitialAccessPhase
    from ice_9.phases.execution import ExecutionPhase
    from ice_9.phases.persistence import PersistencePhase
    from ice_9.phases.priv_esc import PrivEscPhase
    from ice_9.phases.defense_evasion import DefenseEvasionPhase
    from ice_9.phases.credential_access import CredentialAccessPhase
    from ice_9.phases.discovery import DiscoveryPhase
    from ice_9.phases.lateral_movement import LateralMovementPhase
    from ice_9.phases.collection import CollectionPhase
    from ice_9.phases.exfiltration import ExfiltrationPhase
    from ice_9.phases.impact import ImpactPhase

    return {
        PhaseType.RECON: ReconPhase,
        PhaseType.RESOURCE_DEV: ResourceDevPhase,
        PhaseType.INITIAL_ACCESS: InitialAccessPhase,
        PhaseType.EXECUTION: ExecutionPhase,
        PhaseType.PERSISTENCE: PersistencePhase,
        PhaseType.PRIV_ESC: PrivEscPhase,
        PhaseType.DEFENSE_EVASION: DefenseEvasionPhase,
        PhaseType.CREDENTIAL_ACCESS: CredentialAccessPhase,
        PhaseType.DISCOVERY: DiscoveryPhase,
        PhaseType.LATERAL_MOVEMENT: LateralMovementPhase,
        PhaseType.COLLECTION: CollectionPhase,
        PhaseType.EXFILTRATION: ExfiltrationPhase,
        PhaseType.IMPACT: ImpactPhase,
    }


# Lazy-loaded module registry
_PHASE_MODULES: dict[PhaseType, type[PhaseModule]] | None = None


def get_phase_modules() -> dict[PhaseType, type[PhaseModule]]:
    """Get the phase module registry (lazy-loaded)."""
    global _PHASE_MODULES
    if _PHASE_MODULES is None:
        _PHASE_MODULES = _load_modules()
    return _PHASE_MODULES


def get_phase_module(
    phase_type: PhaseType, store: "Store", audit: "AuditLogger"
) -> PhaseModule:
    """Instantiate a phase module by type."""
    modules = get_phase_modules()
    cls = modules.get(phase_type)
    if not cls:
        raise ValueError(f"No module for phase {phase_type.value}")
    return cls(store, audit)
