"""ice_9 CLI — campaign management and orchestration commands."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from ice_9.config.settings import load_settings
from ice_9.core.audit import AuditLogger
from ice_9.core.campaign import (
    complete_phase,
    create_campaign,
    get_campaign_progress,
    skip_phase,
    start_phase,
    transition_campaign,
)
from ice_9.core.models import CampaignStatus, PhaseType, PHASE_NAMES
from ice_9.core.state import InvalidTransition
from ice_9.db.store import Store
from ice_9.output.console import (
    console,
    print_audit_log,
    print_banner,
    print_campaign_detail,
    print_campaign_table,
    print_error,
    print_findings_table,
    print_info,
    print_success,
    print_warning,
)

app = typer.Typer(
    name="ice9",
    help="ice_9 — Red team orchestration platform",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

campaign_app = typer.Typer(help="Campaign management", no_args_is_help=True)
phase_app = typer.Typer(help="Phase management", no_args_is_help=True)
audit_app = typer.Typer(help="Audit log", no_args_is_help=True)

app.add_typer(campaign_app, name="campaign")
app.add_typer(phase_app, name="phase")
app.add_typer(audit_app, name="audit")


def _get_store() -> Store:
    settings = load_settings()
    return Store(settings.db_path)


def _get_audit() -> AuditLogger:
    settings = load_settings()
    return AuditLogger(settings.audit_dir)


# --- Campaign commands ---


@campaign_app.command("create")
def campaign_create(
    name: str = typer.Option(..., "--name", "-n", help="Campaign name"),
    scope: Optional[list[str]] = typer.Option(
        None, "--scope", "-s", help="Target scope (IP/CIDR/domain)"
    ),
    description: str = typer.Option("", "--desc", "-d", help="Description"),
    client: str = typer.Option("", "--client", "-c", help="Client name"),
    lead: str = typer.Option("", "--lead", "-l", help="Team lead"),
    exclusion: Optional[list[str]] = typer.Option(
        None, "--exclude", "-x", help="Excluded targets"
    ),
) -> None:
    """Create a new engagement campaign."""
    store = _get_store()
    audit = _get_audit()

    campaign = create_campaign(
        name=name,
        scope=scope or [],
        description=description,
        client=client,
        lead=lead,
        exclusions=exclusion or [],
    )
    store.save_campaign(campaign)
    audit.log(
        "campaign.create",
        campaign_id=campaign.id,
        details={"name": name, "scope": scope or []},
    )
    store.close()

    print_success(f"Campaign created: [cyan]{campaign.id}[/cyan]")
    print_info(f"Name: {name}")
    if scope:
        print_info(f"Scope: {', '.join(scope)}")
    print_info(f"Phases: {len(campaign.phases)} (ATT&CK-aligned)")


@campaign_app.command("list")
def campaign_list(
    status: Optional[str] = typer.Option(
        None, "--status", help="Filter by status"
    ),
) -> None:
    """List all campaigns."""
    store = _get_store()
    filter_status = CampaignStatus(status) if status else None
    campaigns = store.list_campaigns(status=filter_status)
    store.close()
    print_campaign_table(campaigns)


@campaign_app.command("show")
def campaign_show(
    campaign_id: str = typer.Argument(help="Campaign ID (prefix match)"),
) -> None:
    """Show detailed campaign view."""
    store = _get_store()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        return
    print_campaign_detail(campaign)
    store.close()


@campaign_app.command("activate")
def campaign_activate(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """Activate a campaign (planning → active)."""
    _transition_campaign(campaign_id, CampaignStatus.ACTIVE, "campaign.activate")


@campaign_app.command("pause")
def campaign_pause(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """Pause an active campaign."""
    _transition_campaign(campaign_id, CampaignStatus.PAUSED, "campaign.pause")


@campaign_app.command("resume")
def campaign_resume(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """Resume a paused campaign."""
    _transition_campaign(campaign_id, CampaignStatus.ACTIVE, "campaign.resume")


@campaign_app.command("complete")
def campaign_complete(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """Mark a campaign as completed."""
    _transition_campaign(campaign_id, CampaignStatus.COMPLETED, "campaign.complete")


@campaign_app.command("abort")
def campaign_abort(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """Abort a campaign."""
    confirm = typer.confirm("Are you sure you want to abort this campaign?")
    if not confirm:
        print_info("Aborted.")
        return
    _transition_campaign(campaign_id, CampaignStatus.ABORTED, "campaign.abort")


@campaign_app.command("delete")
def campaign_delete(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """Delete a campaign and all related data."""
    confirm = typer.confirm("Delete this campaign? This cannot be undone.")
    if not confirm:
        print_info("Cancelled.")
        return
    store = _get_store()
    audit = _get_audit()
    deleted = store.delete_campaign(campaign_id)
    if deleted:
        audit.log("campaign.delete", campaign_id=campaign_id)
        print_success("Campaign deleted.")
    else:
        print_error("Campaign not found.")
    store.close()


def _transition_campaign(
    campaign_id: str, target: CampaignStatus, action: str
) -> None:
    store = _get_store()
    audit = _get_audit()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        return
    try:
        transition_campaign(campaign, target)
        store.save_campaign(campaign)
        audit.log(action, campaign_id=campaign.id)
        print_success(f"Campaign → [bold]{target.value}[/bold]")
    except InvalidTransition as e:
        print_error(str(e))
    store.close()


# --- Phase commands ---


@phase_app.command("list")
def phase_list(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """List phases for a campaign."""
    store = _get_store()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        return
    print_campaign_detail(campaign)
    store.close()


@phase_app.command("start")
def phase_start(
    campaign_id: str = typer.Argument(help="Campaign ID"),
    phase: str = typer.Argument(help="Phase type (e.g. TA0043 or 'recon')"),
) -> None:
    """Start a phase."""
    store = _get_store()
    audit = _get_audit()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        return
    phase_type = _resolve_phase_type(phase)
    if not phase_type:
        store.close()
        return
    try:
        p = start_phase(campaign, phase_type)
        store.save_campaign(campaign)
        audit.log(
            "phase.start",
            campaign_id=campaign.id,
            phase_id=p.id,
            details={"phase": phase_type.value, "name": p.name},
        )
        print_success(f"Phase started: [bold]{p.name}[/bold] ({phase_type.value})")
    except (InvalidTransition, ValueError) as e:
        print_error(str(e))
    store.close()


@phase_app.command("complete")
def phase_complete_cmd(
    campaign_id: str = typer.Argument(help="Campaign ID"),
    phase: str = typer.Argument(help="Phase type"),
) -> None:
    """Mark a phase as completed."""
    store = _get_store()
    audit = _get_audit()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        return
    phase_type = _resolve_phase_type(phase)
    if not phase_type:
        store.close()
        return
    try:
        p = complete_phase(campaign, phase_type)
        store.save_campaign(campaign)
        audit.log(
            "phase.complete",
            campaign_id=campaign.id,
            phase_id=p.id,
            details={"phase": phase_type.value},
        )
        print_success(f"Phase completed: [bold]{p.name}[/bold]")
    except (InvalidTransition, ValueError) as e:
        print_error(str(e))
    store.close()


@phase_app.command("skip")
def phase_skip_cmd(
    campaign_id: str = typer.Argument(help="Campaign ID"),
    phase: str = typer.Argument(help="Phase type"),
) -> None:
    """Skip a phase."""
    store = _get_store()
    audit = _get_audit()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        return
    phase_type = _resolve_phase_type(phase)
    if not phase_type:
        store.close()
        return
    try:
        p = skip_phase(campaign, phase_type)
        store.save_campaign(campaign)
        audit.log(
            "phase.skip",
            campaign_id=campaign.id,
            phase_id=p.id,
            details={"phase": phase_type.value},
        )
        print_warning(f"Phase skipped: [bold]{p.name}[/bold]")
    except (InvalidTransition, ValueError) as e:
        print_error(str(e))
    store.close()


# --- Audit commands ---


@audit_app.command("show")
def audit_show(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of entries"),
    campaign_id: Optional[str] = typer.Option(
        None, "--campaign", "-c", help="Filter by campaign"
    ),
) -> None:
    """Show audit log entries."""
    audit = _get_audit()
    if campaign_id:
        entries = audit.search(campaign_id=campaign_id)[-limit:]
    else:
        entries = audit.read(limit=limit)
    print_audit_log(entries)


# --- Findings commands ---

findings_app = typer.Typer(help="Findings management", no_args_is_help=True)
app.add_typer(findings_app, name="findings")


@findings_app.command("list")
def findings_list(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """List all findings for a campaign."""
    store = _get_store()
    findings = store.get_all_findings(campaign_id)
    store.close()
    print_findings_table(findings)


# --- Helpers ---


def _resolve_campaign(store: Store, campaign_id: str):
    """Resolve a campaign by ID or prefix."""
    campaign = store.get_campaign(campaign_id)
    if campaign:
        return campaign
    # Try prefix match
    all_campaigns = store.list_campaigns()
    matches = [c for c in all_campaigns if c.id.startswith(campaign_id)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print_error(f"Ambiguous ID prefix '{campaign_id}' — matches {len(matches)} campaigns")
        return None
    print_error(f"Campaign not found: {campaign_id}")
    return None


def _resolve_phase_type(phase_str: str) -> Optional[PhaseType]:
    """Resolve phase type from ATT&CK ID or friendly name."""
    # Try direct ATT&CK ID
    upper = phase_str.upper()
    for pt in PhaseType:
        if pt.value == upper:
            return pt
    # Try friendly name match
    lower = phase_str.lower().replace(" ", "_").replace("-", "_")
    name_map = {
        "recon": PhaseType.RECON,
        "reconnaissance": PhaseType.RECON,
        "resource_dev": PhaseType.RESOURCE_DEV,
        "resource_development": PhaseType.RESOURCE_DEV,
        "initial_access": PhaseType.INITIAL_ACCESS,
        "access": PhaseType.INITIAL_ACCESS,
        "execution": PhaseType.EXECUTION,
        "persistence": PhaseType.PERSISTENCE,
        "priv_esc": PhaseType.PRIV_ESC,
        "privilege_escalation": PhaseType.PRIV_ESC,
        "privesc": PhaseType.PRIV_ESC,
        "defense_evasion": PhaseType.DEFENSE_EVASION,
        "evasion": PhaseType.DEFENSE_EVASION,
        "credential_access": PhaseType.CREDENTIAL_ACCESS,
        "creds": PhaseType.CREDENTIAL_ACCESS,
        "credentials": PhaseType.CREDENTIAL_ACCESS,
        "discovery": PhaseType.DISCOVERY,
        "lateral_movement": PhaseType.LATERAL_MOVEMENT,
        "lateral": PhaseType.LATERAL_MOVEMENT,
        "collection": PhaseType.COLLECTION,
        "exfiltration": PhaseType.EXFILTRATION,
        "exfil": PhaseType.EXFILTRATION,
        "impact": PhaseType.IMPACT,
    }
    result = name_map.get(lower)
    if not result:
        print_error(
            f"Unknown phase: '{phase_str}'. Use ATT&CK ID (e.g. TA0043) or name (e.g. recon)"
        )
    return result
