"""Intelligence graph data models — entities, relationships, and subject profiles."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from ice_9.core.models import _new_id

# --- Enums ---


class EntityType(str, Enum):
    PERSON = "person"
    HOST = "host"
    DOMAIN = "domain"
    CREDENTIAL = "credential"
    EMAIL = "email"
    ORGANIZATION = "organization"
    SERVICE = "service"
    NETWORK = "network"
    CERTIFICATE = "certificate"


class RelType(str, Enum):
    """Relationship types between entities."""

    HAS_CREDENTIAL = "has_credential"
    ADMIN_OF = "admin_of"
    MEMBER_OF = "member_of"
    OWNS_EMAIL = "owns_email"
    RUNS_SERVICE = "runs_service"
    TRUSTS = "trusts"
    CONTROLS = "controls"
    HAS_SESSION = "has_session"
    RESOLVES_TO = "resolves_to"
    SUBDOMAIN_OF = "subdomain_of"
    BELONGS_TO = "belongs_to"
    PART_OF_NETWORK = "part_of_network"
    HAS_CERTIFICATE = "has_certificate"
    REPORTS_TO = "reports_to"


# --- Models ---


class Entity(BaseModel):
    """A node in the intelligence graph."""

    id: str = Field(default_factory=_new_id)
    entity_type: EntityType
    name: str
    properties: dict = Field(default_factory=dict)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)
    campaign_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Relationship(BaseModel):
    """An edge in the intelligence graph."""

    id: str = Field(default_factory=_new_id)
    source_id: str
    target_id: str
    rel_type: RelType
    properties: dict = Field(default_factory=dict)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)
    campaign_id: str = ""


class SubjectProfile(BaseModel):
    """Social engineering-focused intelligence dossier for a person entity."""

    id: str = Field(default_factory=_new_id)
    entity_id: str
    campaign_id: str = ""
    # OSINT intel
    emails: list[str] = Field(default_factory=list)
    social_accounts: dict = Field(default_factory=dict)
    organizational_role: str = ""
    department: str = ""
    reporting_chain: list[str] = Field(default_factory=list)
    # Behavioral analysis
    digital_footprint: dict = Field(default_factory=dict)
    communication_style: str = ""
    interests: list[str] = Field(default_factory=list)
    # SE attack surface
    susceptibility_scores: dict = Field(default_factory=dict)
    recommended_pretexts: list[dict] = Field(default_factory=list)
    behavioral_predictions: list[dict] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScenarioResult(BaseModel):
    """Result of a single social engineering scenario simulation."""

    scenario_name: str
    attack_vector: str  # "email", "phone", "sms", "in_person"
    pretext: str
    success_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    avg_response_time: str = ""
    common_failure_modes: list[str] = Field(default_factory=list)
    sample_interactions: list[dict] = Field(default_factory=list)
    confidence_interval: tuple[float, float] = (0.0, 0.0)


class SimulationResult(BaseModel):
    """Aggregated results of Monte Carlo behavioral simulations."""

    id: str = Field(default_factory=_new_id)
    subject_id: str
    campaign_id: str = ""
    scenarios: list[ScenarioResult] = Field(default_factory=list)
    overall_susceptibility: float = Field(default=0.0, ge=0.0, le=1.0)
    best_approach: dict = Field(default_factory=dict)
    report: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    simulated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
