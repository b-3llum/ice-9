"""AI-driven campaign orchestrator — automated phase selection and execution."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ice_9.ai.agents import AgentRole
from ice_9.ai.analyzer import analyze_findings
from ice_9.ai.planner import generate_engagement_plan
from ice_9.ai.team import TeamOrchestrator
from ice_9.core.audit import AuditLogger
from ice_9.core.models import Campaign, PhaseStatus, PhaseType, PHASE_NAMES
from ice_9.db.store import Store
from ice_9.output.console import print_info, print_success, print_warning, print_error
from ice_9.tools.custom import register_defaults


@dataclass
class AutoRunResult:
    """Result from an automated campaign run."""

    phases_executed: list[str] = field(default_factory=list)
    phases_skipped: list[str] = field(default_factory=list)
    total_findings: int = 0
    ai_plan: str = ""
    ai_synthesis: str = ""
    stopped_reason: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None


class CampaignOrchestrator:
    """AI-driven campaign autopilot using the agent team to decide and execute phases."""

    def __init__(
        self,
        team: TeamOrchestrator,
        store: Store,
        audit: AuditLogger,
    ) -> None:
        self.team = team
        self.store = store
        self.audit = audit

    def suggest_next_phase(self, campaign: Campaign) -> PhaseType | None:
        """Ask the Coordinator which phase to run next."""
        context = self.team.get_campaign_context(campaign)

        # List completed and pending phases
        completed = [
            p.name for p in campaign.phases if p.status == PhaseStatus.COMPLETED
        ]
        pending = [
            p.name for p in campaign.phases
            if p.status in (PhaseStatus.PENDING, PhaseStatus.SKIPPED)
        ]

        if not pending:
            return None

        prompt = (
            "Based on the current campaign state, which phase should we execute next?\n\n"
            f"Completed phases: {', '.join(completed) if completed else 'None'}\n"
            f"Pending phases: {', '.join(pending)}\n\n"
            "Consider the logical progression of a red team engagement.\n"
            "Respond with ONLY the ATT&CK tactic ID (e.g. TA0043) of the recommended next phase."
        )

        result = self.team.ask_agent(AgentRole.COORDINATOR, prompt, context=context)

        if not result.success:
            return None

        return self._parse_phase_type(result.content)

    def auto_run(
        self,
        campaign: Campaign,
        max_phases: int = 5,
    ) -> AutoRunResult:
        """Autopilot: AI selects and executes phases sequentially.

        Args:
            campaign: The campaign to run.
            max_phases: Maximum number of phases to execute in one auto-run.
        """
        from ice_9.phases import get_phase_module

        register_defaults()
        run_result = AutoRunResult()

        # Generate initial plan
        print_info("Generating AI engagement plan...")
        run_result.ai_plan = generate_engagement_plan(self.team, campaign)

        self.audit.log(
            "auto.start",
            campaign_id=campaign.id,
            details={"max_phases": max_phases},
        )

        for i in range(max_phases):
            # Ask AI which phase to run next
            print_info(f"[{i + 1}/{max_phases}] AI selecting next phase...")
            next_phase = self.suggest_next_phase(campaign)

            if next_phase is None:
                run_result.stopped_reason = "No pending phases or AI could not determine next step"
                break

            phase_name = PHASE_NAMES.get(next_phase, next_phase.value)
            print_info(f"AI selected: {phase_name} ({next_phase.value})")

            # Get and run the phase module
            try:
                module = get_phase_module(next_phase, self.store, self.audit)
            except ValueError:
                print_warning(f"No module for {phase_name}, skipping")
                run_result.phases_skipped.append(phase_name)
                continue

            # Reload campaign from DB to get latest state
            campaign = self.store.get_campaign(campaign.id) or campaign

            try:
                module.run(campaign)
                run_result.phases_executed.append(phase_name)
                print_success(f"Phase completed: {phase_name}")
            except Exception as e:
                print_error(f"Phase {phase_name} failed: {e}")
                run_result.phases_skipped.append(phase_name)
                continue

            # Reload campaign and run team analysis after each phase
            campaign = self.store.get_campaign(campaign.id) or campaign
            print_info("AI team analyzing results...")
            team_result = analyze_findings(self.team, campaign, self.store)
            if team_result.synthesis:
                run_result.ai_synthesis = team_result.synthesis

            self.audit.log(
                "auto.phase_complete",
                campaign_id=campaign.id,
                details={
                    "phase": next_phase.value,
                    "phase_name": phase_name,
                    "iteration": i + 1,
                },
            )

        # Final tally
        campaign = self.store.get_campaign(campaign.id) or campaign
        run_result.total_findings = sum(len(p.findings) for p in campaign.phases)
        run_result.completed_at = datetime.utcnow()

        if not run_result.stopped_reason:
            run_result.stopped_reason = f"Completed {max_phases} phase iterations"

        self.audit.log(
            "auto.complete",
            campaign_id=campaign.id,
            details={
                "phases_executed": run_result.phases_executed,
                "total_findings": run_result.total_findings,
                "reason": run_result.stopped_reason,
            },
        )

        return run_result

    def _parse_phase_type(self, text: str) -> PhaseType | None:
        """Extract a PhaseType from AI response text."""
        # Look for ATT&CK tactic IDs
        match = re.search(r"TA\d{4}", text)
        if match:
            tactic_id = match.group(0).upper()
            for pt in PhaseType:
                if pt.value == tactic_id:
                    return pt

        # Try matching phase names
        text_lower = text.lower()
        name_map = {
            "reconnaissance": PhaseType.RECON,
            "recon": PhaseType.RECON,
            "resource development": PhaseType.RESOURCE_DEV,
            "initial access": PhaseType.INITIAL_ACCESS,
            "execution": PhaseType.EXECUTION,
            "persistence": PhaseType.PERSISTENCE,
            "privilege escalation": PhaseType.PRIV_ESC,
            "defense evasion": PhaseType.DEFENSE_EVASION,
            "credential access": PhaseType.CREDENTIAL_ACCESS,
            "discovery": PhaseType.DISCOVERY,
            "lateral movement": PhaseType.LATERAL_MOVEMENT,
            "collection": PhaseType.COLLECTION,
            "exfiltration": PhaseType.EXFILTRATION,
            "impact": PhaseType.IMPACT,
        }
        for name, pt in name_map.items():
            if name in text_lower:
                return pt

        return None
