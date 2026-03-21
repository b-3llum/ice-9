"""FastAPI REST API for ice_9 remote campaign management."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, Field

from ice_9.config.settings import load_settings
from ice_9.core.audit import AuditLogger
from ice_9.core.campaign import (
    create_campaign,
    transition_campaign,
    start_phase,
    complete_phase,
    skip_phase,
    get_campaign_progress,
)
from ice_9.core.models import (
    Campaign,
    CampaignStatus,
    Finding,
    PhaseType,
    Severity,
    PHASE_NAMES,
)
from ice_9.core.state import InvalidTransition
from ice_9.db.store import Store

app = FastAPI(
    title="ice_9",
    description="Red team orchestration platform — REST API",
    version="0.1.0",
)

# --- Settings & Dependencies ---

_settings = None
_store = None
_audit = None

API_KEY = os.environ.get("ICE9_API_KEY", "")


def get_settings():
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def get_store():
    global _store
    if _store is None:
        settings = get_settings()
        _store = Store(settings.db_path)
    return _store


def get_audit():
    global _audit
    if _audit is None:
        settings = get_settings()
        _audit = AuditLogger(settings.audit_dir)
    return _audit


async def verify_api_key(x_api_key: str = Header(default="")):
    """Verify API key if ICE9_API_KEY is set."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# --- Request/Response Models ---


class CampaignCreate(BaseModel):
    name: str
    scope: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    description: str = ""
    client: str = ""
    lead: str = ""


class CampaignTransition(BaseModel):
    status: CampaignStatus


class PhaseAction(BaseModel):
    phase_type: str  # ATT&CK ID or friendly name


class FindingCreate(BaseModel):
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    remediation: str = ""
    cvss: Optional[float] = None
    cve_ids: list[str] = Field(default_factory=list)
    att_ck_ids: list[str] = Field(default_factory=list)
    phase_id: Optional[str] = None


class CampaignResponse(BaseModel):
    id: str
    name: str
    status: str
    scope: list[str]
    progress: dict
    phase_count: int
    finding_count: int
    created_at: str
    updated_at: str


class HealthResponse(BaseModel):
    status: str
    version: str


# --- Routes ---


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", version="0.1.0")


# --- Campaign endpoints ---


@app.post("/campaigns", dependencies=[Depends(verify_api_key)])
async def api_create_campaign(body: CampaignCreate):
    store = get_store()
    audit = get_audit()

    campaign = create_campaign(
        name=body.name,
        scope=body.scope,
        description=body.description,
        client=body.client,
        lead=body.lead,
        exclusions=body.exclusions,
    )
    store.save_campaign(campaign)
    audit.log(
        "api.campaign.create",
        campaign_id=campaign.id,
        details={"name": body.name, "scope": body.scope},
    )

    return _campaign_response(campaign)


@app.get("/campaigns", dependencies=[Depends(verify_api_key)])
async def api_list_campaigns(status: Optional[str] = None):
    store = get_store()
    filter_status = CampaignStatus(status) if status else None
    campaigns = store.list_campaigns(status=filter_status)
    return [_campaign_response(c) for c in campaigns]


@app.get("/campaigns/{campaign_id}", dependencies=[Depends(verify_api_key)])
async def api_get_campaign(campaign_id: str):
    store = get_store()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    return {
        **_campaign_response(campaign),
        "phases": [
            {
                "id": p.id,
                "type": p.phase_type.value,
                "name": p.name,
                "status": p.status.value,
                "tasks": len(p.tasks),
                "findings": len(p.findings),
            }
            for p in campaign.phases
        ],
        "rules_of_engagement": campaign.rules_of_engagement.model_dump(),
    }


@app.put("/campaigns/{campaign_id}/status", dependencies=[Depends(verify_api_key)])
async def api_transition_campaign(campaign_id: str, body: CampaignTransition):
    store = get_store()
    audit = get_audit()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    try:
        transition_campaign(campaign, body.status)
        store.save_campaign(campaign)
        audit.log(
            f"api.campaign.{body.status.value}",
            campaign_id=campaign.id,
        )
        return _campaign_response(campaign)
    except InvalidTransition as e:
        raise HTTPException(400, str(e))


@app.delete("/campaigns/{campaign_id}", dependencies=[Depends(verify_api_key)])
async def api_delete_campaign(campaign_id: str):
    store = get_store()
    audit = get_audit()
    deleted = store.delete_campaign(campaign_id)
    if not deleted:
        raise HTTPException(404, "Campaign not found")
    audit.log("api.campaign.delete", campaign_id=campaign_id)
    return {"deleted": True}


# --- Phase endpoints ---


@app.post(
    "/campaigns/{campaign_id}/phases/{phase_type}/start",
    dependencies=[Depends(verify_api_key)],
)
async def api_start_phase(campaign_id: str, phase_type: str):
    store = get_store()
    audit = get_audit()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    pt = _resolve_phase(phase_type)
    try:
        phase = start_phase(campaign, pt)
        store.save_campaign(campaign)
        audit.log(
            "api.phase.start",
            campaign_id=campaign.id,
            phase_id=phase.id,
            details={"phase": pt.value},
        )
        return {"phase_id": phase.id, "status": phase.status.value}
    except (InvalidTransition, ValueError) as e:
        raise HTTPException(400, str(e))


@app.post(
    "/campaigns/{campaign_id}/phases/{phase_type}/complete",
    dependencies=[Depends(verify_api_key)],
)
async def api_complete_phase(campaign_id: str, phase_type: str):
    store = get_store()
    audit = get_audit()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    pt = _resolve_phase(phase_type)
    try:
        phase = complete_phase(campaign, pt)
        store.save_campaign(campaign)
        audit.log("api.phase.complete", campaign_id=campaign.id, phase_id=phase.id)
        return {"phase_id": phase.id, "status": phase.status.value}
    except (InvalidTransition, ValueError) as e:
        raise HTTPException(400, str(e))


# --- Findings endpoints ---


@app.get(
    "/campaigns/{campaign_id}/findings",
    dependencies=[Depends(verify_api_key)],
)
async def api_list_findings(campaign_id: str):
    store = get_store()
    findings = store.get_all_findings(campaign_id)
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "cvss": f.cvss,
            "cve_ids": f.cve_ids,
            "att_ck_ids": f.att_ck_ids,
            "description": f.description,
            "remediation": f.remediation,
        }
        for f in findings
    ]


@app.post(
    "/campaigns/{campaign_id}/findings",
    dependencies=[Depends(verify_api_key)],
)
async def api_create_finding(campaign_id: str, body: FindingCreate):
    store = get_store()
    audit = get_audit()

    finding = Finding(
        title=body.title,
        severity=body.severity,
        description=body.description,
        remediation=body.remediation,
        cvss=body.cvss,
        cve_ids=body.cve_ids,
        att_ck_ids=body.att_ck_ids,
        phase_id=body.phase_id,
    )
    store.save_finding(finding)
    audit.log(
        "api.finding.create",
        campaign_id=campaign_id,
        details={"title": body.title, "severity": body.severity.value},
    )
    return {"id": finding.id, "title": finding.title}


# --- Audit endpoint ---


@app.get("/audit", dependencies=[Depends(verify_api_key)])
async def api_audit_log(limit: int = 50, campaign_id: Optional[str] = None):
    audit = get_audit()
    if campaign_id:
        return audit.search(campaign_id=campaign_id)[-limit:]
    return audit.read(limit=limit)


# --- Tools endpoint ---


@app.get("/tools", dependencies=[Depends(verify_api_key)])
async def api_list_tools():
    from ice_9.tools.custom import register_defaults, list_tools

    register_defaults()
    return [t.get_info() for t in list_tools()]


# --- Helpers ---


def _campaign_response(campaign: Campaign) -> dict:
    progress = get_campaign_progress(campaign)
    return {
        "id": campaign.id,
        "name": campaign.name,
        "status": campaign.status.value,
        "scope": campaign.rules_of_engagement.scope,
        "progress": progress,
        "phase_count": len(campaign.phases),
        "finding_count": progress["findings"],
        "created_at": campaign.created_at.isoformat(),
        "updated_at": campaign.updated_at.isoformat(),
    }


def _resolve_phase(phase_str: str) -> PhaseType:
    upper = phase_str.upper()
    for pt in PhaseType:
        if pt.value == upper:
            return pt
    # Friendly name map
    name_map = {
        "recon": PhaseType.RECON,
        "initial_access": PhaseType.INITIAL_ACCESS,
        "execution": PhaseType.EXECUTION,
        "persistence": PhaseType.PERSISTENCE,
        "priv_esc": PhaseType.PRIV_ESC,
        "defense_evasion": PhaseType.DEFENSE_EVASION,
        "credential_access": PhaseType.CREDENTIAL_ACCESS,
        "discovery": PhaseType.DISCOVERY,
        "lateral_movement": PhaseType.LATERAL_MOVEMENT,
        "collection": PhaseType.COLLECTION,
        "exfiltration": PhaseType.EXFILTRATION,
        "impact": PhaseType.IMPACT,
    }
    result = name_map.get(phase_str.lower())
    if not result:
        raise HTTPException(400, f"Unknown phase: {phase_str}")
    return result
