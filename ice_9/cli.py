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


@phase_app.command("run")
def phase_run(
    campaign_id: str = typer.Argument(help="Campaign ID"),
    phase: str = typer.Argument(help="Phase type (e.g. TA0043 or 'recon')"),
) -> None:
    """Run an automated phase module against campaign targets."""
    from ice_9.phases.recon import ReconPhase
    from ice_9.phases.discovery import DiscoveryPhase
    from ice_9.phases.credential_access import CredentialAccessPhase
    from ice_9.phases.lateral_movement import LateralMovementPhase
    from ice_9.tools.custom import register_defaults

    register_defaults()

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

    # Phase module registry
    phase_modules = {
        PhaseType.RECON: ReconPhase,
        PhaseType.DISCOVERY: DiscoveryPhase,
        PhaseType.CREDENTIAL_ACCESS: CredentialAccessPhase,
        PhaseType.LATERAL_MOVEMENT: LateralMovementPhase,
    }

    module_class = phase_modules.get(phase_type)
    if not module_class:
        print_error(
            f"No automated module for phase '{phase}'. "
            f"Available: {', '.join(PHASE_NAMES[pt] for pt in phase_modules)}"
        )
        store.close()
        return

    module = module_class(store=store, audit=audit)

    # Check scope
    if not campaign.rules_of_engagement.scope:
        print_error("Campaign has no scope defined. Add targets with 'campaign create --scope'.")
        store.close()
        return

    console.print(f"\n[bold red]{'='*60}[/bold red]")
    console.print(f"[bold]Phase: {module.name}[/bold] ({phase_type.value})")
    console.print(f"Campaign: {campaign.name} ({campaign.id[:8]})")
    console.print(f"Scope: {', '.join(campaign.rules_of_engagement.scope)}")
    console.print(f"[bold red]{'='*60}[/bold red]\n")

    module.run(campaign)
    store.close()


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

tool_app = typer.Typer(help="Tool management and execution", no_args_is_help=True)
app.add_typer(tool_app, name="tool")

team_app = typer.Typer(help="AI agent team management", no_args_is_help=True)
app.add_typer(team_app, name="team")

report_app = typer.Typer(help="Report generation", no_args_is_help=True)
app.add_typer(report_app, name="report")


@findings_app.command("list")
def findings_list(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """List all findings for a campaign."""
    store = _get_store()
    findings = store.get_all_findings(campaign_id)
    store.close()
    print_findings_table(findings)


# --- Team commands ---


def _build_team():
    """Build the team orchestrator from config."""
    from ice_9.ai.providers import ProviderRegistry
    from ice_9.ai.agents import AgentRegistry
    from ice_9.ai.team import TeamOrchestrator

    settings = load_settings()
    providers_conf = {
        name: vars(pc) if hasattr(pc, '__dict__') else pc.__dict__
        for name, pc in settings.providers.items()
    } if settings.providers else {}
    agents_conf = {
        name: vars(ac) if hasattr(ac, '__dict__') else ac.__dict__
        for name, ac in settings.agents.items()
    } if settings.agents else {}

    # Handle Pydantic models
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
    audit = _get_audit()

    return TeamOrchestrator(provider_reg, agent_reg, audit)


@team_app.command("status")
def team_status() -> None:
    """Show registered agents and their provider assignments."""
    from rich.table import Table
    from ice_9.ai.agents import AgentRegistry

    settings = load_settings()
    agent_dict = {}
    for name, ac in settings.agents.items():
        agent_dict[name] = {
            "provider": ac.provider,
            "model": ac.model,
            "system_prompt": ac.system_prompt,
        }
    agent_reg = AgentRegistry.from_config(agent_dict)

    table = Table(title="AI Agent Team", border_style="red")
    table.add_column("Role", style="cyan")
    table.add_column("Provider", style="bold")
    table.add_column("Model")
    table.add_column("Enabled")

    for agent in agent_reg.list_agents():
        table.add_row(
            agent.display_name,
            agent.provider_name,
            agent.model or "[dim]default[/dim]",
            "[green]yes[/green]" if agent.enabled else "[red]no[/red]",
        )

    console.print(table)


@team_app.command("ask")
def team_ask(
    prompt: str = typer.Argument(help="Question or task for the agent"),
    agent: str = typer.Option("coordinator", "--agent", "-a", help="Agent role"),
    campaign_id: Optional[str] = typer.Option(None, "--campaign", "-c", help="Campaign for context"),
) -> None:
    """Ask a specific agent a question."""
    orchestrator = _build_team()

    context = ""
    if campaign_id:
        store = _get_store()
        campaign = _resolve_campaign(store, campaign_id)
        if campaign:
            context = orchestrator.get_campaign_context(campaign)
        store.close()

    print_info(f"Asking [bold]{agent}[/bold]...")
    result = orchestrator.ask_agent(agent, prompt, context=context)

    if result.success:
        console.print(f"\n[bold cyan]{result.agent_role.upper()}[/bold cyan] ({result.provider}/{result.model}):\n")
        console.print(result.content)
        if result.usage:
            console.print(f"\n[dim]Tokens: {result.usage}[/dim]")
    else:
        print_error(f"Agent failed: {result.error}")

    orchestrator.close()


@team_app.command("run")
def team_run(
    campaign_id: str = typer.Argument(help="Campaign ID"),
    prompt: str = typer.Option(
        "Analyze all findings and suggest next steps",
        "--prompt", "-p",
        help="Task for the team",
    ),
) -> None:
    """Run the full AI team analysis on campaign data."""
    orchestrator = _build_team()
    store = _get_store()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        orchestrator.close()
        return

    context = orchestrator.get_campaign_context(campaign)

    console.print(f"\n[bold red]{'='*60}[/bold red]")
    console.print("[bold]Deploying AI Team[/bold]")
    console.print(f"Campaign: {campaign.name} ({campaign.id[:8]})")
    console.print(f"[bold red]{'='*60}[/bold red]\n")

    print_info("Dispatching agents in parallel...")
    team_result = orchestrator.run_team(prompt=prompt, context=context)

    # Show individual results
    for result in team_result.results:
        if result.success:
            console.print(
                f"\n[bold cyan]{result.agent_role.upper()}[/bold cyan] "
                f"({result.provider}/{result.model}) — {result.duration_seconds:.1f}s"
            )
            console.print(result.content[:2000])
            if len(result.content) > 2000:
                console.print(f"[dim]... ({len(result.content)} chars total)[/dim]")
        else:
            print_error(f"{result.agent_role}: {result.error}")

    # Show synthesis
    if team_result.synthesis:
        console.print(f"\n[bold red]{'='*60}[/bold red]")
        console.print("[bold]COORDINATOR SYNTHESIS[/bold]")
        console.print(f"[bold red]{'='*60}[/bold red]\n")
        console.print(team_result.synthesis)

    store.close()
    orchestrator.close()


@team_app.command("plan")
def team_plan(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """Generate an AI-powered engagement plan."""
    from ice_9.ai.planner import generate_engagement_plan

    orchestrator = _build_team()
    store = _get_store()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        orchestrator.close()
        return

    print_info("Generating engagement plan...")
    plan = generate_engagement_plan(orchestrator, campaign)

    console.print(f"\n[bold]Engagement Plan — {campaign.name}[/bold]\n")
    console.print(plan)

    store.close()
    orchestrator.close()


@team_app.command("analyze")
def team_analyze(
    campaign_id: str = typer.Argument(help="Campaign ID"),
) -> None:
    """AI team analyzes all findings and suggests next steps."""
    from ice_9.ai.analyzer import analyze_findings

    orchestrator = _build_team()
    store = _get_store()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        orchestrator.close()
        return

    print_info("Team analyzing findings...")
    team_result = analyze_findings(orchestrator, campaign, store)

    for result in team_result.results:
        if result.success:
            console.print(
                f"\n[bold cyan]{result.agent_role.upper()}[/bold cyan]:"
            )
            console.print(result.content[:3000])

    if team_result.synthesis:
        console.print(f"\n[bold red]{'='*60}[/bold red]")
        console.print("[bold]TEAM ASSESSMENT[/bold]")
        console.print(f"[bold red]{'='*60}[/bold red]\n")
        console.print(team_result.synthesis)

    store.close()
    orchestrator.close()


# --- Report commands ---


@report_app.command("generate")
def report_generate(
    campaign_id: str = typer.Argument(help="Campaign ID"),
    output: str = typer.Option("", "--output", "-o", help="Output file path"),
    ai_summary: bool = typer.Option(False, "--ai-summary", help="Generate AI executive summary"),
    ai_narrative: bool = typer.Option(False, "--ai-narrative", help="Generate AI attack narrative"),
) -> None:
    """Generate a DOCX penetration test report."""
    from ice_9.reporting.generator import ReportGenerator

    store = _get_store()
    audit = _get_audit()
    campaign = _resolve_campaign(store, campaign_id)
    if not campaign:
        store.close()
        return

    # Determine output path
    if output:
        output_path = Path(output)
    else:
        safe_name = campaign.name.replace(" ", "_").lower()
        output_path = Path.cwd() / f"ice9_report_{safe_name}_{campaign.id[:8]}.docx"

    exec_summary = ""
    narrative = ""

    # AI-generated content
    if ai_summary or ai_narrative:
        orchestrator = _build_team()
        if ai_summary:
            from ice_9.reporting.executive import generate_executive_summary
            print_info("Generating AI executive summary...")
            exec_summary = generate_executive_summary(orchestrator, campaign, store)
        if ai_narrative:
            from ice_9.reporting.narrative import generate_attack_narrative
            print_info("Generating AI attack narrative...")
            narrative = generate_attack_narrative(orchestrator, campaign, store)
        orchestrator.close()

    # Generate report
    print_info("Generating DOCX report...")
    generator = ReportGenerator(store)
    result_path = generator.generate(
        campaign=campaign,
        output_path=output_path,
        executive_summary=exec_summary,
        attack_narrative=narrative,
    )

    findings = store.get_all_findings(campaign.id)
    audit.log(
        "report.generate",
        campaign_id=campaign.id,
        details={"output": str(result_path), "findings": len(findings)},
    )

    print_success(f"Report generated: [cyan]{result_path}[/cyan]")
    print_info(f"Findings included: {len(findings)}")
    store.close()


# --- Tool commands ---


@tool_app.command("list")
def tool_list() -> None:
    """List all registered tools and their availability."""
    from rich.table import Table
    from ice_9.tools.custom import register_defaults, list_tools

    register_defaults()
    tools = list_tools()

    table = Table(title="Registered Tools", border_style="red")
    table.add_column("Name", style="cyan")
    table.add_column("Binary")
    table.add_column("Available")
    table.add_column("ATT&CK IDs")
    table.add_column("Description", max_width=50)

    for t in tools:
        available = "[green]yes[/green]" if t.is_available() else "[red]no[/red]"
        table.add_row(
            t.name,
            t.binary,
            available,
            ", ".join(t.att_ck_ids[:3]) if t.att_ck_ids else "[dim]-[/dim]",
            t.description[:50],
        )

    console.print(table)


@tool_app.command("run")
def tool_run(
    tool_name: str = typer.Argument(help="Tool name (e.g. nmap, nuclei, kerb-map)"),
    target: str = typer.Option(..., "--target", "-t", help="Target (IP/CIDR/domain)"),
    campaign_id: Optional[str] = typer.Option(
        None, "--campaign", "-c", help="Associate with campaign"
    ),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout in seconds"),
    args: Optional[list[str]] = typer.Option(None, "--arg", "-a", help="Extra arguments"),
) -> None:
    """Execute a tool against a target."""
    from datetime import datetime
    from ice_9.tools.custom import register_defaults, get_tool
    from ice_9.core.models import Task, TaskStatus

    register_defaults()
    tool = get_tool(tool_name)
    if not tool:
        print_error(f"Unknown tool: {tool_name}. Run 'ice9 tool list' to see available tools.")
        return

    if not tool.is_available():
        print_error(f"Tool '{tool_name}' is not installed. Binary '{tool.binary}' not found.")
        return

    # Resolve campaign if specified
    store = None
    campaign = None
    phase_id = None
    if campaign_id:
        store = _get_store()
        campaign = _resolve_campaign(store, campaign_id)
        if not campaign:
            store.close()
            return

    print_info(f"Running [bold]{tool_name}[/bold] against [cyan]{target}[/cyan]...")

    # Execute
    result = tool.run(target, timeout=timeout, profile=profile, args=args or [])

    if result.success:
        print_success(
            f"Completed in {result.duration_seconds:.1f}s "
            f"(exit code {result.return_code})"
        )
        # Show parsed summary
        if result.parsed:
            _print_tool_summary(tool_name, result.parsed)
    else:
        print_error(f"Failed (exit code {result.return_code})")
        if result.stderr:
            console.print(f"[dim]{result.stderr[:500]}[/dim]")

    # Save task to campaign if associated
    if campaign and store:
        audit = _get_audit()
        task = Task(
            tool=tool_name,
            target=target,
            params={"profile": profile, "args": args or []},
            status=TaskStatus.COMPLETED if result.success else TaskStatus.FAILED,
            output=result.stdout[:10000],  # Cap stored output
            att_ck_id=tool.att_ck_ids[0] if tool.att_ck_ids else None,
            started_at=result.started_at,
            completed_at=result.completed_at,
            campaign_id=campaign.id,
        )
        store.save_task(task)
        audit.log(
            "tool.run",
            campaign_id=campaign.id,
            task_id=task.id,
            details={
                "tool": tool_name,
                "target": target,
                "success": result.success,
                "duration": result.duration_seconds,
            },
        )
        print_info(f"Task saved to campaign [cyan]{campaign.id[:8]}[/cyan]")
        store.close()


@tool_app.command("add")
def tool_add_custom(
    name: str = typer.Option(..., "--name", "-n", help="Tool name"),
    binary: str = typer.Option(..., "--binary", "-b", help="Binary/command"),
    description: str = typer.Option("", "--desc", "-d", help="Description"),
    att_ck: Optional[list[str]] = typer.Option(None, "--attck", help="ATT&CK technique IDs"),
) -> None:
    """Register a custom tool."""
    from ice_9.tools.custom import CustomToolWrapper, register_tool, register_defaults

    register_defaults()
    tool = CustomToolWrapper(
        name=name,
        binary=binary,
        description=description,
        att_ck_ids=att_ck or [],
    )
    register_tool(tool)
    available = tool.is_available()
    if available:
        print_success(f"Tool '{name}' registered (binary: {binary})")
    else:
        print_warning(f"Tool '{name}' registered but binary '{binary}' not found in PATH")


def _print_tool_summary(tool_name: str, parsed: dict) -> None:
    """Print a summary of parsed tool output."""
    from rich.table import Table

    if tool_name == "nmap":
        hosts = parsed.get("hosts", [])
        summary = parsed.get("summary", {})
        console.print(
            f"  Hosts: {summary.get('hosts_up', len(hosts))} up, "
            f"{summary.get('hosts_down', 0)} down | "
            f"Open ports: {parsed.get('total_open_ports', 0)}"
        )
        for host in hosts[:10]:  # Show first 10 hosts
            ip = host.get("ip", "?")
            open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
            if open_ports:
                port_str = ", ".join(
                    f"{p['port']}/{p.get('service', '?')}" for p in open_ports[:8]
                )
                if len(open_ports) > 8:
                    port_str += f" (+{len(open_ports) - 8})"
                console.print(f"  [cyan]{ip}[/cyan]: {port_str}")

    elif tool_name == "nuclei":
        counts = parsed.get("severity_counts", {})
        total = parsed.get("total", 0)
        parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                color = {"critical": "bright_red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}[sev]
                parts.append(f"[{color}]{sev}: {counts[sev]}[/{color}]")
        console.print(f"  Findings: {total} — {', '.join(parts)}")

    elif tool_name == "kerb-map":
        for key in ["spn_accounts", "asrep_accounts", "delegation_issues", "cve_findings"]:
            items = parsed.get(key, [])
            if items:
                label = key.replace("_", " ").title()
                console.print(f"  {label}: {len(items)}")
    else:
        # Generic — show line count or data keys
        if "lines" in parsed:
            console.print(f"  Output: {parsed.get('line_count', 0)} lines")
        elif "data" in parsed:
            data = parsed["data"]
            if isinstance(data, list):
                console.print(f"  Results: {len(data)} entries")


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
