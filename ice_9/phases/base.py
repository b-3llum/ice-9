"""Abstract base class for ATT&CK-aligned phase modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from ice_9.core.models import (
    Campaign,
    Finding,
    Phase,
    PhaseType,
    Severity,
    Task,
    TaskStatus,
)
from ice_9.core.campaign import start_phase, complete_phase
from ice_9.db.store import Store
from ice_9.core.audit import AuditLogger
from ice_9.tools.base import ToolResult, ToolWrapper
from ice_9.tools.custom import get_tool
from ice_9.output.console import print_info, print_success, print_error, print_warning, console


class PhaseModule(ABC):
    """Base class for engagement phase modules."""

    phase_type: PhaseType
    name: str = ""
    description: str = ""
    required_tools: list[str] = []  # Tool names needed for this phase
    att_ck_techniques: list[str] = []  # Techniques covered by this phase

    def __init__(self, store: Store, audit: AuditLogger) -> None:
        self.store = store
        self.audit = audit

    @abstractmethod
    def plan(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Generate a list of tasks to execute for this phase.

        Returns a list of task definitions:
        [{"tool": "nmap", "target": "192.168.1.0/24", "params": {...}}, ...]
        """
        ...

    @abstractmethod
    def analyze_results(
        self, campaign: Campaign, results: list[ToolResult]
    ) -> list[Finding]:
        """Analyze tool results and generate findings."""
        ...

    def ai_plan(
        self,
        campaign: Campaign,
        orchestrator: Any = None,
    ) -> list[dict[str, Any]]:
        """AI-enhanced task planning.

        Uses the ReconAnalyst agent to suggest additional tasks beyond the
        deterministic plan. Falls back to plan() if no AI is available.
        """
        base_tasks = self.plan(campaign)

        if orchestrator is None:
            return base_tasks

        try:
            from ice_9.ai.agents import AgentRole
            import json as _json
            import re as _re

            context = orchestrator.get_campaign_context(campaign)
            tool_names = ", ".join(self.required_tools) if self.required_tools else "none"

            prompt = (
                f"I'm planning tasks for the {self.name} phase ({self.phase_type.value}).\n"
                f"Available tools: {tool_names}\n"
                f"Current plan has {len(base_tasks)} tasks.\n"
                f"Techniques covered: {', '.join(self.att_ck_techniques)}\n\n"
                "Suggest any additional tasks or parameter adjustments. "
                "Respond with a JSON array of task objects: "
                '[{"tool": "name", "target": "target", "params": {...}}]'
            )

            result = orchestrator.ask_agent(
                AgentRole.RECON_ANALYST, prompt, context=context
            )

            if result.success and result.content:
                match = _re.search(r"\[.*\]", result.content, _re.DOTALL)
                if match:
                    ai_tasks = _json.loads(match.group(0))
                    if isinstance(ai_tasks, list):
                        base_tasks.extend(ai_tasks)
        except Exception:
            pass  # Silently fall back to deterministic plan

        return base_tasks

    def check_prerequisites(self) -> list[str]:
        """Check if required tools are available. Returns list of missing tools."""
        missing = []
        for tool_name in self.required_tools:
            tool = get_tool(tool_name)
            if not tool or not tool.is_available():
                missing.append(tool_name)
        return missing

    def run(self, campaign: Campaign) -> list[ToolResult]:
        """Execute the full phase workflow."""
        from ice_9.core.events import event_bus, Event, EventType

        # Check prerequisites
        missing = self.check_prerequisites()
        if missing:
            print_warning(
                f"Missing tools for {self.name}: {', '.join(missing)}. "
                "Some tasks will be skipped."
            )

        # Start the phase
        phase = self._get_phase(campaign)
        if not phase:
            print_error(f"Phase {self.phase_type.value} not found in campaign")
            return []

        start_phase(campaign, self.phase_type)
        self.store.save_campaign(campaign)
        self.audit.log(
            "phase.auto_start",
            campaign_id=campaign.id,
            phase_id=phase.id,
            details={"phase": self.phase_type.value, "name": self.name},
        )

        event_bus.emit(Event(
            type=EventType.PHASE_START,
            campaign_id=campaign.id,
            phase_id=phase.id,
            data={"phase": self.phase_type.value, "name": self.name},
        ))

        # Plan tasks
        task_plans = self.plan(campaign)
        print_info(f"Planned {len(task_plans)} tasks for {self.name}")

        event_bus.emit(Event(
            type=EventType.PHASE_PLAN,
            campaign_id=campaign.id,
            phase_id=phase.id,
            data={"task_count": len(task_plans), "phase": self.name},
        ))

        # Execute tasks
        results: list[ToolResult] = []
        for i, task_plan in enumerate(task_plans, 1):
            tool_name = task_plan["tool"]
            target = task_plan.get("target", "")
            params = task_plan.get("params", {})

            tool = get_tool(tool_name)
            if not tool or not tool.is_available():
                print_warning(f"  [{i}/{len(task_plans)}] Skipping {tool_name} — not available")
                continue

            print_info(f"  [{i}/{len(task_plans)}] Running {tool_name} → {target}")

            event_bus.emit(Event(
                type=EventType.PHASE_TASK_START,
                campaign_id=campaign.id,
                phase_id=phase.id,
                data={"tool": tool_name, "target": target, "task_num": i, "total_tasks": len(task_plans)},
            ))

            # Execute tool
            result = tool.run(target, **params)
            results.append(result)

            # Save task
            task = Task(
                tool=tool_name,
                target=target,
                params=params,
                status=TaskStatus.COMPLETED if result.success else TaskStatus.FAILED,
                output=result.stdout[:10000],
                att_ck_id=tool.att_ck_ids[0] if tool.att_ck_ids else None,
                started_at=result.started_at,
                completed_at=result.completed_at,
                phase_id=phase.id,
                campaign_id=campaign.id,
            )
            self.store.save_task(task)

            if result.success:
                print_success(f"    Completed in {result.duration_seconds:.1f}s")
            else:
                print_error(f"    Failed: {result.stderr[:200]}")

            event_bus.emit(Event(
                type=EventType.PHASE_TASK_COMPLETE,
                campaign_id=campaign.id,
                phase_id=phase.id,
                data={
                    "tool": tool_name, "target": target,
                    "success": result.success, "duration": result.duration_seconds,
                    "task_num": i, "total_tasks": len(task_plans),
                },
            ))

            self.audit.log(
                "task.complete",
                campaign_id=campaign.id,
                phase_id=phase.id,
                task_id=task.id,
                details={
                    "tool": tool_name,
                    "target": target,
                    "success": result.success,
                },
            )

        # Analyze results and generate findings
        findings = self.analyze_results(campaign, results)
        for finding in findings:
            finding.phase_id = phase.id
            self.store.save_finding(finding)
            event_bus.emit(Event(
                type=EventType.FINDING_NEW,
                campaign_id=campaign.id,
                phase_id=phase.id,
                data={"title": finding.title, "severity": finding.severity.value},
            ))

        if findings:
            print_success(f"Generated {len(findings)} findings")

        # Complete phase
        complete_phase(campaign, self.phase_type)
        self.store.save_campaign(campaign)
        self.audit.log(
            "phase.auto_complete",
            campaign_id=campaign.id,
            phase_id=phase.id,
            details={"findings": len(findings), "tasks": len(task_plans)},
        )

        event_bus.emit(Event(
            type=EventType.PHASE_COMPLETE,
            campaign_id=campaign.id,
            phase_id=phase.id,
            data={"phase": self.name, "findings": len(findings), "tasks": len(task_plans)},
        ))

        return results

    def _get_phase(self, campaign: Campaign) -> Optional[Phase]:
        """Get the phase object from the campaign."""
        return next(
            (p for p in campaign.phases if p.phase_type == self.phase_type), None
        )

    def _create_finding(
        self,
        title: str,
        severity: Severity = Severity.INFO,
        description: str = "",
        remediation: str = "",
        cvss: Optional[float] = None,
        cve_ids: list[str] | None = None,
        att_ck_ids: list[str] | None = None,
    ) -> Finding:
        """Helper to create a Finding."""
        return Finding(
            title=title,
            severity=severity,
            description=description,
            remediation=remediation,
            cvss=cvss,
            cve_ids=cve_ids or [],
            att_ck_ids=att_ck_ids or [],
        )
