"""FastAPI REST API for ice_9 remote campaign management."""

from __future__ import annotations

import asyncio
import os
import secrets
import threading

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

from ice_9 import __version__
from ice_9.config.settings import load_settings
from ice_9.core.audit import AuditLogger
from ice_9.core.campaign import (
    complete_phase,
    create_campaign,
    get_campaign_progress,
    start_phase,
    transition_campaign,
)
from ice_9.core.models import (
    Campaign,
    CampaignStatus,
    Finding,
    PhaseType,
    Severity,
)
from ice_9.core.state import InvalidTransition
from ice_9.db.store import Store

app = FastAPI(
    title="ice_9",
    description="Red team orchestration platform — REST API",
    version=__version__,
)

# Browsers reject credentialed requests against a wildcard origin, so only
# enable credentials when explicit origins are configured.
_cors_origins = [o.strip() for o in os.environ.get("ICE9_CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
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
        # Configure the tool execution backend (local, or SSH to a remote host).
        from ice_9.tools.execution import ExecutionBackend, set_backend
        ec = _settings.execution
        set_backend(
            ExecutionBackend(
                backend=ec.backend, host=ec.host, user=ec.user,
                port=ec.port, key_file=ec.key_file,
            )
        )
    return _settings


def get_store():
    global _store
    if _store is None:
        settings = get_settings()
        # check_same_thread=False so blocking endpoints offloaded to a worker
        # thread can share this connection (SQLite is in serialized mode).
        _store = Store(settings.db_path, check_same_thread=False)
        # Enable automatic entity extraction on phase completion (idempotent).
        from ice_9.intel.hooks import register_intel_hooks
        register_intel_hooks(settings.db_path)
    return _store


def get_audit():
    global _audit
    if _audit is None:
        settings = get_settings()
        _audit = AuditLogger(settings.audit_dir)
    return _audit


async def verify_api_key(x_api_key: str = Header(default="")):
    """Verify API key if ICE9_API_KEY is set."""
    if API_KEY and not secrets.compare_digest(x_api_key, API_KEY):
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
    cvss: float | None = None
    cve_ids: list[str] = Field(default_factory=list)
    att_ck_ids: list[str] = Field(default_factory=list)
    phase_id: str | None = None


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
    return HealthResponse(status="ok", version=__version__)


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
async def api_list_campaigns(status: str | None = None):
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
        raise HTTPException(400, str(e)) from e


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
        raise HTTPException(400, str(e)) from e


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
        raise HTTPException(400, str(e)) from e


# --- Phase run endpoint (runs in API process for EventBus visibility) ---

# Track running phases to prevent double-runs
_running_phases: dict[str, str] = {}  # campaign_id -> phase_type
_running_lock = threading.Lock()


class PhaseRunResponse(BaseModel):
    status: str
    message: str
    phase_type: str


@app.post(
    "/campaigns/{campaign_id}/phases/{phase_type}/run",
    dependencies=[Depends(verify_api_key)],
    response_model=PhaseRunResponse,
)
async def api_run_phase(campaign_id: str, phase_type: str):
    """Run a phase module in a background thread (events visible via SSE)."""
    from ice_9.phases import get_phase_modules
    from ice_9.tools.custom import register_defaults

    store = get_store()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    pt = _resolve_phase(phase_type)

    # Check if already running
    with _running_lock:
        running = _running_phases.get(campaign_id)
        if running:
            raise HTTPException(409, f"Phase '{running}' already running for this campaign")
        _running_phases[campaign_id] = pt.value

    register_defaults()
    phase_modules = get_phase_modules()
    module_class = phase_modules.get(pt)
    if not module_class:
        with _running_lock:
            _running_phases.pop(campaign_id, None)
        raise HTTPException(400, f"No automated module for phase '{phase_type}'")

    if not campaign.rules_of_engagement.scope:
        with _running_lock:
            _running_phases.pop(campaign_id, None)
        raise HTTPException(400, "Campaign has no scope defined")

    audit = get_audit()

    def run_phase():
        thread_store = None
        try:
            # Each thread needs its own Store (SQLite thread safety)
            thread_store = Store(get_settings().db_path, check_same_thread=False)
            thread_campaign = thread_store.get_campaign(campaign_id)
            if not thread_campaign:
                return
            module = module_class(store=thread_store, audit=audit)
            module.run(thread_campaign)
        finally:
            if thread_store is not None:
                thread_store.close()
            with _running_lock:
                _running_phases.pop(campaign_id, None)

    thread = threading.Thread(target=run_phase, daemon=True)
    thread.start()

    return PhaseRunResponse(
        status="started",
        message=f"Phase '{pt.value}' started in background",
        phase_type=pt.value,
    )


@app.get(
    "/campaigns/{campaign_id}/phases/running",
    dependencies=[Depends(verify_api_key)],
)
async def api_running_phase(campaign_id: str):
    """Check if a phase is currently running for this campaign."""
    with _running_lock:
        running = _running_phases.get(campaign_id)
    return {"running": running}


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
async def api_audit_log(limit: int = 50, campaign_id: str | None = None):
    audit = get_audit()
    if campaign_id:
        return audit.search(campaign_id=campaign_id)[-limit:]
    return audit.read(limit=limit)


# --- Tools endpoint ---


@app.get("/tools", dependencies=[Depends(verify_api_key)])
async def api_list_tools():
    from ice_9.tools.custom import list_tools, register_defaults

    register_defaults()
    return [t.get_info() for t in list_tools()]


# --- Phase tasks/findings endpoints ---


@app.get(
    "/campaigns/{campaign_id}/phases/{phase_type}/tasks",
    dependencies=[Depends(verify_api_key)],
)
async def api_list_phase_tasks(campaign_id: str, phase_type: str):
    store = get_store()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    pt = _resolve_phase(phase_type)
    phase = next((p for p in campaign.phases if p.phase_type == pt), None)
    if not phase:
        raise HTTPException(404, "Phase not found")
    return [
        {
            "id": t.id,
            "tool": t.tool,
            "target": t.target,
            "status": t.status.value,
            "att_ck_id": t.att_ck_id,
            "started_at": t.started_at.isoformat() if t.started_at else None,
            "completed_at": t.completed_at.isoformat() if t.completed_at else None,
        }
        for t in phase.tasks
    ]


@app.get(
    "/campaigns/{campaign_id}/phases/{phase_type}/findings",
    dependencies=[Depends(verify_api_key)],
)
async def api_list_phase_findings(campaign_id: str, phase_type: str):
    store = get_store()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    pt = _resolve_phase(phase_type)
    phase = next((p for p in campaign.phases if p.phase_type == pt), None)
    if not phase:
        raise HTTPException(404, "Phase not found")
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
        for f in phase.findings
    ]


# --- AI endpoints ---


class AIAskRequest(BaseModel):
    prompt: str
    agent: str = "coordinator"


class AIAutoRequest(BaseModel):
    max_phases: int = 5


def _build_team_orchestrator():
    """Build TeamOrchestrator from settings (same as CLI _build_team)."""
    from ice_9.ai.agents import AgentRegistry
    from ice_9.ai.providers import ProviderRegistry
    from ice_9.ai.team import TeamOrchestrator

    settings = get_settings()
    prov_dict = {}
    for name, pc in settings.providers.items():
        prov_dict[name] = {
            "base_url": pc.base_url,
            "api_key": pc.api_key,
            "model": pc.model,
            "models": pc.models,
        }
    agent_dict = {}
    for name, ac in settings.agents.items():
        agent_dict[name] = {
            "provider": ac.provider,
            "model": ac.model,
            "system_prompt": ac.system_prompt,
        }

    provider_reg = ProviderRegistry.from_config(prov_dict)
    agent_reg = AgentRegistry.from_config(agent_dict)
    audit = get_audit()

    return TeamOrchestrator(provider_reg, agent_reg, audit)


@app.post(
    "/campaigns/{campaign_id}/ai/plan",
    dependencies=[Depends(verify_api_key)],
)
async def api_ai_plan(campaign_id: str):
    from ice_9.ai.planner import generate_engagement_plan

    def _impl():
        store = get_store()
        campaign = store.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")

        orchestrator = _build_team_orchestrator()
        try:
            return {"plan": generate_engagement_plan(orchestrator, campaign)}
        finally:
            orchestrator.close()

    # Offload the blocking LLM round-trip so it never stalls the event loop.
    return await asyncio.to_thread(_impl)


@app.post(
    "/campaigns/{campaign_id}/ai/analyze",
    dependencies=[Depends(verify_api_key)],
)
async def api_ai_analyze(campaign_id: str):
    from ice_9.ai.analyzer import analyze_findings

    def _impl():
        store = get_store()
        campaign = store.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")

        orchestrator = _build_team_orchestrator()
        try:
            team_result = analyze_findings(orchestrator, campaign, store)
            return {
                "results": [
                    {
                        "agent": r.agent_role,
                        "content": r.content,
                        "model": r.model,
                        "provider": r.provider,
                        "success": r.success,
                    }
                    for r in team_result.results
                ],
                "synthesis": team_result.synthesis,
            }
        finally:
            orchestrator.close()

    return await asyncio.to_thread(_impl)


@app.post(
    "/campaigns/{campaign_id}/ai/ask",
    dependencies=[Depends(verify_api_key)],
)
async def api_ai_ask(campaign_id: str, body: AIAskRequest):
    def _impl():
        store = get_store()
        campaign = store.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")

        orchestrator = _build_team_orchestrator()
        try:
            context = orchestrator.get_campaign_context(campaign)
            result = orchestrator.ask_agent(body.agent, body.prompt, context=context)
            return {
                "agent": result.agent_role,
                "content": result.content,
                "model": result.model,
                "provider": result.provider,
                "success": result.success,
                "error": result.error,
            }
        finally:
            orchestrator.close()

    return await asyncio.to_thread(_impl)


@app.post(
    "/campaigns/{campaign_id}/ai/auto",
    dependencies=[Depends(verify_api_key)],
)
async def api_ai_auto(campaign_id: str, body: AIAutoRequest):
    from ice_9.ai.orchestrator import CampaignOrchestrator

    def _impl():
        store = get_store()
        audit = get_audit()
        campaign = store.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")

        team = _build_team_orchestrator()
        try:
            auto = CampaignOrchestrator(team, store, audit)
            result = auto.auto_run(campaign, max_phases=body.max_phases)
            return {
                "phases_executed": result.phases_executed,
                "phases_skipped": result.phases_skipped,
                "total_findings": result.total_findings,
                "ai_plan": result.ai_plan[:5000],
                "ai_synthesis": result.ai_synthesis[:5000],
                "stopped_reason": result.stopped_reason,
            }
        finally:
            team.close()

    return await asyncio.to_thread(_impl)


@app.get("/ai/agents", dependencies=[Depends(verify_api_key)])
async def api_list_agents():
    from ice_9.ai.agents import AgentRegistry

    settings = get_settings()
    agent_dict = {}
    for name, ac in settings.agents.items():
        agent_dict[name] = {
            "provider": ac.provider,
            "model": ac.model,
            "system_prompt": ac.system_prompt,
        }
    agent_reg = AgentRegistry.from_config(agent_dict)
    return [
        {
            "role": a.role.value,
            "provider": a.provider_name,
            "model": a.model,
            "enabled": a.enabled,
        }
        for a in agent_reg.list_agents()
    ]


@app.get("/ai/providers", dependencies=[Depends(verify_api_key)])
async def api_list_providers():
    from ice_9.ai.providers import ProviderRegistry

    settings = get_settings()
    prov_dict = {}
    for name, pc in settings.providers.items():
        prov_dict[name] = {
            "base_url": pc.base_url,
            "api_key": pc.api_key,
            "model": pc.model,
            "models": pc.models,
        }
    provider_reg = ProviderRegistry.from_config(prov_dict)
    return [
        {
            "name": p.name,
            "type": p.provider_type.value,
            "model": p.default_model,
            "has_api_key": bool(p.api_key),
            "enabled": p.enabled,
        }
        for p in provider_reg.list_providers()
    ]


# --- Event stream endpoints ---


@app.get("/events/stream")
async def api_event_stream(
    campaign_id: str | None = Query(default=None),
    api_key: str = Query(default=""),
):
    """Server-Sent Events stream for real-time observability.

    EventSource clients cannot set request headers, so the API key (when
    configured) is accepted as a query parameter here.
    """
    if API_KEY and not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")

    from ice_9.core.events import Event, event_bus

    queue: asyncio.Queue[Event] = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def on_event(event: Event) -> None:
        # Pass through events with null campaign_id (tool events within a phase)
        # Only filter out events explicitly belonging to a different campaign
        if campaign_id and event.campaign_id is not None and event.campaign_id != campaign_id:
            return
        loop.call_soon_threadsafe(queue.put_nowait, event)

    unsubscribe = event_bus.subscribe(on_event)

    async def generate():
        try:
            # Initial comment to trigger EventSource onopen
            yield ": connected\n\n"

            # Send recent history for catch-up
            for event in event_bus.history(limit=20, campaign_id=campaign_id):
                yield event.to_sse()

            # Stream live events with periodic keepalive
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield event.to_sse()
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            unsubscribe()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/events/recent")
async def api_events_recent(
    campaign_id: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
):
    """Get recent events from the history buffer."""
    from ice_9.core.events import event_bus

    events = event_bus.history(limit=limit, campaign_id=campaign_id)
    return [e.to_dict() for e in events]


# --- Intelligence Graph endpoints ---


@app.get(
    "/campaigns/{campaign_id}/graph",
    dependencies=[Depends(verify_api_key)],
)
async def api_get_graph(campaign_id: str):
    """Full entity graph (nodes + edges) for a campaign."""
    store = get_store()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    entities = store.get_entities(campaign_id)
    relationships = store.get_relationships(campaign_id)
    return {
        "nodes": [_entity_response(e) for e in entities],
        "edges": [_relationship_response(r) for r in relationships],
        "node_count": len(entities),
        "edge_count": len(relationships),
    }


@app.get(
    "/campaigns/{campaign_id}/graph/entities",
    dependencies=[Depends(verify_api_key)],
)
async def api_list_entities(
    campaign_id: str,
    entity_type: str | None = None,
    search: str | None = None,
    min_confidence: float = 0.0,
):
    """List entities with optional filters."""
    from ice_9.core.intel import EntityType

    store = get_store()
    et = EntityType(entity_type) if entity_type else None
    entities = store.get_entities(
        campaign_id, entity_type=et, search=search, min_confidence=min_confidence
    )
    return [_entity_response(e) for e in entities]


@app.get(
    "/campaigns/{campaign_id}/graph/entities/{entity_id}",
    dependencies=[Depends(verify_api_key)],
)
async def api_get_entity(campaign_id: str, entity_id: str):
    """Full entity detail with its relationships."""
    store = get_store()
    entity = store.get_entity(entity_id)
    if not entity or entity.campaign_id != campaign_id:
        raise HTTPException(404, "Entity not found")

    relationships = store.get_relationships(campaign_id, entity_id=entity_id)
    return {
        **_entity_response(entity),
        "relationships": [_relationship_response(r) for r in relationships],
    }


@app.post(
    "/campaigns/{campaign_id}/graph/entities/{entity_id}/enrich",
    dependencies=[Depends(verify_api_key)],
)
async def api_enrich_entity(campaign_id: str, entity_id: str):
    """Trigger OSINT enrichment for an entity."""
    from ice_9.intel.enrichment import EnrichmentEngine

    def _impl():
        store = get_store()
        entity = store.get_entity(entity_id)
        if not entity or entity.campaign_id != campaign_id:
            raise HTTPException(404, "Entity not found")

        orchestrator = _build_team_orchestrator()
        try:
            engine = EnrichmentEngine(store, orchestrator)
            return _entity_response(engine.enrich(entity))
        finally:
            orchestrator.close()

    return await asyncio.to_thread(_impl)


@app.get(
    "/campaigns/{campaign_id}/graph/relationships",
    dependencies=[Depends(verify_api_key)],
)
async def api_list_relationships(
    campaign_id: str,
    entity_id: str | None = None,
    rel_type: str | None = None,
):
    """List relationships with optional filters."""
    from ice_9.core.intel import RelType

    store = get_store()
    rt = RelType(rel_type) if rel_type else None
    rels = store.get_relationships(campaign_id, entity_id=entity_id, rel_type=rt)
    return [_relationship_response(r) for r in rels]


# --- Subject Profile endpoints ---


@app.get(
    "/campaigns/{campaign_id}/subjects",
    dependencies=[Depends(verify_api_key)],
)
async def api_list_subjects(campaign_id: str):
    """List all subject profiles for a campaign."""
    store = get_store()
    profiles = store.get_subject_profiles(campaign_id)
    return [_subject_response(p) for p in profiles]


@app.get(
    "/campaigns/{campaign_id}/subjects/{subject_id}",
    dependencies=[Depends(verify_api_key)],
)
async def api_get_subject(campaign_id: str, subject_id: str):
    """Full subject dossier."""
    store = get_store()
    profile = store.get_subject_profile(subject_id)
    if not profile or profile.campaign_id != campaign_id:
        raise HTTPException(404, "Subject profile not found")

    entity = store.get_entity(profile.entity_id)
    return {
        **_subject_response(profile),
        "entity": _entity_response(entity) if entity else None,
    }


@app.post(
    "/campaigns/{campaign_id}/subjects/{entity_id}/profile",
    dependencies=[Depends(verify_api_key)],
)
async def api_create_subject_profile(campaign_id: str, entity_id: str):
    """Generate or refresh a subject profile for a person entity."""
    from ice_9.intel.profiler import SubjectProfiler

    def _impl():
        store = get_store()
        entity = store.get_entity(entity_id)
        if not entity or entity.campaign_id != campaign_id:
            raise HTTPException(404, "Entity not found")
        if entity.entity_type.value != "person":
            raise HTTPException(400, "Subject profiles require a person entity")

        orchestrator = _build_team_orchestrator()
        try:
            profiler = SubjectProfiler(store, orchestrator)
            return _subject_response(profiler.build_profile(entity, campaign_id))
        finally:
            orchestrator.close()

    return await asyncio.to_thread(_impl)


class SimulationRequest(BaseModel):
    num_simulations: int = Field(default=50, ge=1, le=500)
    scenarios: list[str] | None = None


@app.post(
    "/campaigns/{campaign_id}/subjects/{subject_id}/simulate",
    dependencies=[Depends(verify_api_key)],
)
async def api_simulate_subject(
    campaign_id: str, subject_id: str, body: SimulationRequest
):
    """Run behavioral simulation for a subject."""
    from ice_9.intel.simulation import BehavioralSimulator

    def _impl():
        store = get_store()
        profile = store.get_subject_profile(subject_id)
        if not profile or profile.campaign_id != campaign_id:
            raise HTTPException(404, "Subject profile not found")

        entities = store.get_entities(campaign_id)
        relationships = store.get_relationships(campaign_id)

        orchestrator = _build_team_orchestrator()
        try:
            simulator = BehavioralSimulator(orchestrator)
            result = simulator.simulate(
                subject=profile,
                entity_graph=entities,
                relationships=relationships,
                scenarios=body.scenarios,
                num_simulations=body.num_simulations,
                campaign_id=campaign_id,
            )
            # Store results in the subject profile
            profile.behavioral_predictions.append(result.model_dump(mode="json"))
            profile.susceptibility_scores = {
                s.scenario_name: s.success_rate for s in result.scenarios
            }
            store.save_subject_profile(profile)
            return result.model_dump(mode="json")
        finally:
            orchestrator.close()

    return await asyncio.to_thread(_impl)


# --- Intel extraction endpoint ---


@app.post(
    "/campaigns/{campaign_id}/graph/extract",
    dependencies=[Depends(verify_api_key)],
)
async def api_extract_entities(campaign_id: str):
    """Reprocess all task outputs to extract entities."""
    from ice_9.intel.extractor import EntityExtractor

    store = get_store()
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    extractor = EntityExtractor(store)
    total_entities = 0
    total_rels = 0

    for phase in campaign.phases:
        for task in phase.tasks:
            if task.output:
                parsed = task.params.get("_parsed", {})
                entities, rels = extractor.extract_and_store(
                    task.tool, parsed, task.target, campaign_id
                )
                total_entities += len(entities)
                total_rels += len(rels)

    return {
        "entities_extracted": total_entities,
        "relationships_extracted": total_rels,
    }


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
        "resource_dev": PhaseType.RESOURCE_DEV,
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


def _entity_response(entity) -> dict:
    """Format an Entity for API response."""
    return {
        "id": entity.id,
        "entity_type": entity.entity_type.value,
        "name": entity.name,
        "properties": entity.properties,
        "confidence": entity.confidence,
        "sources": entity.sources,
        "campaign_id": entity.campaign_id,
        "created_at": entity.created_at.isoformat(),
        "updated_at": entity.updated_at.isoformat(),
    }


def _relationship_response(rel) -> dict:
    """Format a Relationship for API response."""
    return {
        "id": rel.id,
        "source_id": rel.source_id,
        "target_id": rel.target_id,
        "rel_type": rel.rel_type.value,
        "properties": rel.properties,
        "confidence": rel.confidence,
        "sources": rel.sources,
    }


def _subject_response(profile) -> dict:
    """Format a SubjectProfile for API response."""
    return {
        "id": profile.id,
        "entity_id": profile.entity_id,
        "campaign_id": profile.campaign_id,
        "emails": profile.emails,
        "social_accounts": profile.social_accounts,
        "organizational_role": profile.organizational_role,
        "department": profile.department,
        "reporting_chain": profile.reporting_chain,
        "digital_footprint": profile.digital_footprint,
        "communication_style": profile.communication_style,
        "interests": profile.interests,
        "susceptibility_scores": profile.susceptibility_scores,
        "recommended_pretexts": profile.recommended_pretexts,
        "behavioral_predictions": profile.behavioral_predictions,
        "updated_at": profile.updated_at.isoformat(),
    }
