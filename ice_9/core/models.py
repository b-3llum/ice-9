"""Core data models for ice_9 campaigns."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# --- Enums ---


class CampaignStatus(str, Enum):
    PLANNING = "planning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"


class PhaseType(str, Enum):
    """MITRE ATT&CK tactic IDs."""

    RECON = "TA0043"
    RESOURCE_DEV = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIV_ESC = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


PHASE_NAMES: dict[PhaseType, str] = {
    PhaseType.RECON: "Reconnaissance",
    PhaseType.RESOURCE_DEV: "Resource Development",
    PhaseType.INITIAL_ACCESS: "Initial Access",
    PhaseType.EXECUTION: "Execution",
    PhaseType.PERSISTENCE: "Persistence",
    PhaseType.PRIV_ESC: "Privilege Escalation",
    PhaseType.DEFENSE_EVASION: "Defense Evasion",
    PhaseType.CREDENTIAL_ACCESS: "Credential Access",
    PhaseType.DISCOVERY: "Discovery",
    PhaseType.LATERAL_MOVEMENT: "Lateral Movement",
    PhaseType.COLLECTION: "Collection",
    PhaseType.EXFILTRATION: "Exfiltration",
    PhaseType.IMPACT: "Impact",
}


class PhaseStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"


class TaskStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Models ---


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


class Evidence(BaseModel):
    """A piece of evidence tied to a finding or task."""

    id: str = Field(default_factory=_new_id)
    file_path: Optional[str] = None
    description: str = ""
    sha256: Optional[str] = None
    captured_at: datetime = Field(default_factory=datetime.utcnow)
    content_type: str = "text/plain"


class Finding(BaseModel):
    """A vulnerability or notable observation."""

    id: str = Field(default_factory=_new_id)
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    remediation: str = ""
    cvss: Optional[float] = None
    cve_ids: list[str] = Field(default_factory=list)
    att_ck_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    phase_id: Optional[str] = None
    task_id: Optional[str] = None


class Task(BaseModel):
    """A single tool execution or manual action within a phase."""

    id: str = Field(default_factory=_new_id)
    tool: str  # e.g. "nmap", "nuclei", "manual"
    target: str = ""
    params: dict = Field(default_factory=dict)
    status: TaskStatus = TaskStatus.QUEUED
    output: Optional[str] = None
    att_ck_id: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    phase_id: Optional[str] = None
    campaign_id: Optional[str] = None
    findings: list[Finding] = Field(default_factory=list)


class Phase(BaseModel):
    """A MITRE ATT&CK-aligned engagement phase."""

    id: str = Field(default_factory=_new_id)
    phase_type: PhaseType
    status: PhaseStatus = PhaseStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    campaign_id: Optional[str] = None
    tasks: list[Task] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    notes: str = ""

    @property
    def name(self) -> str:
        return PHASE_NAMES.get(self.phase_type, self.phase_type.value)


class RulesOfEngagement(BaseModel):
    """Scope and constraints for a campaign."""

    scope: list[str] = Field(default_factory=list)  # IP ranges, domains
    exclusions: list[str] = Field(default_factory=list)
    testing_window: Optional[str] = None  # e.g. "Mon-Fri 09:00-17:00"
    max_severity: Severity = Severity.CRITICAL
    notes: str = ""


class Campaign(BaseModel):
    """Top-level engagement container."""

    id: str = Field(default_factory=_new_id)
    name: str
    status: CampaignStatus = CampaignStatus.PLANNING
    rules_of_engagement: RulesOfEngagement = Field(default_factory=RulesOfEngagement)
    phases: list[Phase] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    description: str = ""
    client: str = ""
    lead: str = ""
