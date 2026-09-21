"""Rich console output for ice_9."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ice_9.core.campaign import get_campaign_progress
from ice_9.core.models import (
    Campaign,
    CampaignStatus,
    Finding,
    PhaseStatus,
    Severity,
)

console = Console()

# Status colors
STATUS_COLORS = {
    CampaignStatus.PLANNING: "blue",
    CampaignStatus.ACTIVE: "green",
    CampaignStatus.PAUSED: "yellow",
    CampaignStatus.COMPLETED: "bright_green",
    CampaignStatus.ABORTED: "red",
}

PHASE_STATUS_COLORS = {
    PhaseStatus.PENDING: "dim",
    PhaseStatus.IN_PROGRESS: "cyan",
    PhaseStatus.COMPLETED: "green",
    PhaseStatus.SKIPPED: "yellow",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def print_banner() -> None:
    """Print the ice_9 banner."""
    banner = Text()
    banner.append("ice", style="bold cyan")
    banner.append("_", style="bold white")
    banner.append("9", style="bold red")
    banner.append(" v0.1.0", style="dim")
    console.print(Panel(banner, subtitle="red team orchestration", border_style="red"))


def print_campaign_table(campaigns: list[Campaign]) -> None:
    """Print a table of campaigns."""
    if not campaigns:
        console.print("[dim]No campaigns found.[/dim]")
        return

    table = Table(title="Campaigns", border_style="red")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Status")
    table.add_column("Scope", max_width=40)
    table.add_column("Progress")
    table.add_column("Findings", justify="right")
    table.add_column("Updated")

    for c in campaigns:
        progress = get_campaign_progress(c)
        status_color = STATUS_COLORS.get(c.status, "white")
        scope_str = ", ".join(c.rules_of_engagement.scope[:3])
        if len(c.rules_of_engagement.scope) > 3:
            scope_str += f" (+{len(c.rules_of_engagement.scope) - 3})"

        table.add_row(
            c.id[:8],
            c.name,
            f"[{status_color}]{c.status.value}[/{status_color}]",
            scope_str or "[dim]none[/dim]",
            f"{progress['progress_pct']}%",
            str(progress["findings"]),
            c.updated_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


def print_campaign_detail(campaign: Campaign) -> None:
    """Print detailed campaign view with phases."""
    progress = get_campaign_progress(campaign)
    status_color = STATUS_COLORS.get(campaign.status, "white")

    # Header
    console.print(
        Panel(
            f"[bold]{campaign.name}[/bold]\n"
            f"ID: [cyan]{campaign.id}[/cyan]  "
            f"Status: [{status_color}]{campaign.status.value}[/{status_color}]  "
            f"Progress: {progress['progress_pct']}%\n"
            f"Client: {campaign.client or '[dim]n/a[/dim]'}  "
            f"Lead: {campaign.lead or '[dim]n/a[/dim]'}\n"
            f"Scope: {', '.join(campaign.rules_of_engagement.scope) or '[dim]none[/dim]'}",
            title="Campaign",
            border_style="red",
        )
    )

    # Phase table
    table = Table(title="Phases", border_style="dim")
    table.add_column("ATT&CK", style="cyan", no_wrap=True)
    table.add_column("Phase", style="bold")
    table.add_column("Status")
    table.add_column("Tasks", justify="right")
    table.add_column("Findings", justify="right")

    for phase in campaign.phases:
        ps_color = PHASE_STATUS_COLORS.get(phase.status, "white")
        table.add_row(
            phase.phase_type.value,
            phase.name,
            f"[{ps_color}]{phase.status.value}[/{ps_color}]",
            str(len(phase.tasks)),
            str(len(phase.findings)),
        )

    console.print(table)


def print_findings_table(findings: list[Finding]) -> None:
    """Print a table of findings."""
    if not findings:
        console.print("[dim]No findings recorded.[/dim]")
        return

    table = Table(title="Findings", border_style="red")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Title", style="bold")
    table.add_column("CVEs")
    table.add_column("CVSS", justify="right")
    table.add_column("ATT&CK")

    for f in findings:
        sev_color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f.id[:8],
            f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
            f.title,
            ", ".join(f.cve_ids[:2]) if f.cve_ids else "[dim]-[/dim]",
            f"{f.cvss:.1f}" if f.cvss else "[dim]-[/dim]",
            ", ".join(f.att_ck_ids[:2]) if f.att_ck_ids else "[dim]-[/dim]",
        )

    console.print(table)


def print_audit_log(entries: list[dict]) -> None:
    """Print audit log entries."""
    if not entries:
        console.print("[dim]No audit entries.[/dim]")
        return

    table = Table(title="Audit Log", border_style="dim")
    table.add_column("Timestamp", style="dim")
    table.add_column("Action", style="cyan")
    table.add_column("Campaign", no_wrap=True)
    table.add_column("Details", max_width=60)

    for e in entries:
        table.add_row(
            e.get("timestamp", "")[:19],
            e.get("action", ""),
            e.get("campaign_id", "")[:8],
            str(e.get("details", ""))[:60],
        )

    console.print(table)


def print_success(msg: str) -> None:
    console.print(f"[green][+][/green] {msg}")


def print_error(msg: str) -> None:
    console.print(f"[red][-][/red] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[cyan][*][/cyan] {msg}")


def print_warning(msg: str) -> None:
    console.print(f"[yellow][!][/yellow] {msg}")
