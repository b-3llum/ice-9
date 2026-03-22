"""Behavioral prediction engine — Monte Carlo social engineering simulations.

Inspired by MiroFish's multi-agent simulation approach but built natively
on ice_9's TeamOrchestrator and EventBus infrastructure.

Pipeline:
  1. Knowledge graph context extraction
  2. Agent persona generation (target, attacker, environmental)
  3. Monte Carlo simulation (N parallel runs with parameter variation)
  4. Statistical analysis and aggregation
  5. Report generation
"""

from __future__ import annotations

import json
import random
from datetime import datetime
from typing import Optional

from ice_9.ai.agents import AgentRole
from ice_9.ai.team import TeamOrchestrator
from ice_9.core.events import Event, EventType, event_bus
from ice_9.core.intel import (
    Entity,
    Relationship,
    ScenarioResult,
    SimulationResult,
    SubjectProfile,
)


# Default SE scenarios to simulate
DEFAULT_SCENARIOS = [
    "IT Support Password Reset — attacker impersonates IT helpdesk requesting credential verification",
    "CEO Wire Transfer — attacker impersonates CEO requesting urgent financial action",
    "Vendor Invoice Update — attacker impersonates vendor requesting bank detail change",
    "Security Alert — attacker sends fake security alert requiring immediate credential entry",
    "Colleague Document Share — attacker impersonates colleague sharing a malicious document link",
]

ATTACK_VECTORS = {
    "IT Support Password Reset": "phone",
    "CEO Wire Transfer": "email",
    "Vendor Invoice Update": "email",
    "Security Alert": "email",
    "Colleague Document Share": "email",
}


class BehavioralSimulator:
    """Monte Carlo behavioral simulation engine for social engineering scenarios."""

    def __init__(self, orchestrator: TeamOrchestrator) -> None:
        self.orchestrator = orchestrator

    def simulate(
        self,
        subject: SubjectProfile,
        entity_graph: list[Entity],
        relationships: list[Relationship],
        scenarios: Optional[list[str]] = None,
        num_simulations: int = 50,
        campaign_id: str = "",
    ) -> SimulationResult:
        """Run Monte Carlo simulations across scenarios."""
        scenarios = scenarios or DEFAULT_SCENARIOS

        event_bus.emit(Event(
            type=EventType.SIMULATION_START,
            campaign_id=campaign_id,
            data={
                "subject_id": subject.id,
                "num_scenarios": len(scenarios),
                "num_simulations": num_simulations,
            },
        ))

        # Build target persona from OSINT data
        persona = self._build_target_persona(subject, entity_graph, relationships)

        # Run each scenario
        scenario_results: list[ScenarioResult] = []
        for i, scenario_desc in enumerate(scenarios):
            result = self._run_scenario(
                persona=persona,
                scenario=scenario_desc,
                num_runs=num_simulations,
                subject=subject,
            )
            scenario_results.append(result)

            event_bus.emit(Event(
                type=EventType.SIMULATION_PROGRESS,
                campaign_id=campaign_id,
                data={
                    "subject_id": subject.id,
                    "scenario": result.scenario_name,
                    "progress": f"{i + 1}/{len(scenarios)}",
                    "success_rate": result.success_rate,
                },
            ))

        # Aggregate results
        overall = self._calculate_overall_susceptibility(scenario_results)
        best = self._find_best_approach(scenario_results)

        # Generate narrative report
        report = self._generate_report(subject, scenario_results, persona)

        sim_result = SimulationResult(
            subject_id=subject.id,
            campaign_id=campaign_id,
            scenarios=scenario_results,
            overall_susceptibility=overall,
            best_approach=best,
            report=report,
            confidence=self._assess_confidence(subject),
            simulated_at=datetime.utcnow(),
        )

        event_bus.emit(Event(
            type=EventType.SIMULATION_COMPLETE,
            campaign_id=campaign_id,
            data={
                "subject_id": subject.id,
                "overall_susceptibility": overall,
                "best_scenario": best.get("scenario", ""),
                "confidence": sim_result.confidence,
            },
        ))

        return sim_result

    def _build_target_persona(
        self,
        subject: SubjectProfile,
        entities: list[Entity],
        relationships: list[Relationship],
    ) -> dict:
        """Build a behavioral persona from OSINT data for the simulation agents."""
        persona = {
            "name": "",
            "role": subject.organizational_role or "Employee",
            "department": subject.department or "Unknown",
            "communication_style": subject.communication_style or "professional",
            "emails": subject.emails,
            "interests": subject.interests,
            "risk_factors": subject.digital_footprint.get("risk_factors", []),
            "credential_exposure": subject.digital_footprint.get("credential_count", 0),
            "has_spn": subject.digital_footprint.get("has_spn", False),
        }

        # Find the person entity name
        for e in entities:
            if e.id == subject.entity_id:
                persona["name"] = e.name
                break

        # Add organizational context
        org_entities = [
            e for e in entities if e.entity_type.value == "organization"
        ]
        if org_entities:
            persona["organization"] = org_entities[0].name

        return persona

    def _run_scenario(
        self,
        persona: dict,
        scenario: str,
        num_runs: int,
        subject: SubjectProfile,
    ) -> ScenarioResult:
        """Run N simulations of a single scenario with parameter variation."""
        scenario_name = scenario.split("—")[0].strip() if "—" in scenario else scenario[:50]
        attack_vector = ATTACK_VECTORS.get(scenario_name, "email")

        # Run the batch simulation via AI
        sim_prompt = self._build_simulation_prompt(persona, scenario, num_runs)

        result = self.orchestrator.ask_agent(
            AgentRole.SOCIAL_ENGINEER,
            sim_prompt,
            context="",
        )

        if not result.success:
            return ScenarioResult(
                scenario_name=scenario_name,
                attack_vector=attack_vector,
                pretext=scenario,
                success_rate=0.0,
                common_failure_modes=["Simulation failed: " + (result.error or "unknown")],
            )

        return self._parse_simulation_result(
            result.content, scenario_name, attack_vector, scenario
        )

    def _build_simulation_prompt(
        self, persona: dict, scenario: str, num_runs: int
    ) -> str:
        """Build the prompt for running a batch simulation."""
        return (
            f"Run a Monte Carlo social engineering simulation.\n\n"
            f"TARGET PERSONA:\n{json.dumps(persona, indent=2)}\n\n"
            f"SCENARIO: {scenario}\n\n"
            f"Simulate {num_runs} independent interactions between an attacker "
            f"using this pretext and the target. For each run, vary:\n"
            f"- Time of day (morning urgency vs end-of-day fatigue)\n"
            f"- Urgency level of the pretext\n"
            f"- Communication channel nuances\n"
            f"- Minor pretext variations\n\n"
            f"For each simulated interaction, determine if the target would:\n"
            f"(a) comply with the attacker's request (SUCCESS)\n"
            f"(b) become suspicious but still comply (PARTIAL)\n"
            f"(c) refuse or ignore (FAIL)\n"
            f"(d) report to IT/security (DETECTED)\n\n"
            f"Respond in JSON:\n"
            f"{{\n"
            f'  "success_count": <int>,\n'
            f'  "partial_count": <int>,\n'
            f'  "fail_count": <int>,\n'
            f'  "detected_count": <int>,\n'
            f'  "avg_response_time": "<e.g. 15 minutes>",\n'
            f'  "failure_modes": ["<why it failed when it did>"],\n'
            f'  "sample_interactions": [\n'
            f'    {{"outcome": "success|fail", "summary": "<2-3 sentence narrative>"}}\n'
            f"  ],\n"
            f'  "key_factors": ["<what made it work or fail>"]\n'
            f"}}"
        )

    def _parse_simulation_result(
        self,
        ai_response: str,
        scenario_name: str,
        attack_vector: str,
        pretext: str,
    ) -> ScenarioResult:
        """Parse AI simulation response into a ScenarioResult."""
        try:
            start = ai_response.find("{")
            end = ai_response.rfind("}") + 1
            if start < 0 or end <= start:
                raise ValueError("No JSON found")

            data = json.loads(ai_response[start:end])

            success = data.get("success_count", 0)
            partial = data.get("partial_count", 0)
            fail = data.get("fail_count", 0)
            detected = data.get("detected_count", 0)
            total = success + partial + fail + detected

            success_rate = (success + partial * 0.5) / total if total > 0 else 0.0

            # Calculate confidence interval (simple binomial approximation)
            if total > 0:
                p = success_rate
                margin = 1.96 * (p * (1 - p) / total) ** 0.5
                ci = (max(0, p - margin), min(1, p + margin))
            else:
                ci = (0.0, 0.0)

            return ScenarioResult(
                scenario_name=scenario_name,
                attack_vector=attack_vector,
                pretext=pretext,
                success_rate=round(success_rate, 3),
                avg_response_time=data.get("avg_response_time", ""),
                common_failure_modes=data.get("failure_modes", []),
                sample_interactions=data.get("sample_interactions", [])[:3],
                confidence_interval=(round(ci[0], 3), round(ci[1], 3)),
            )

        except (json.JSONDecodeError, ValueError):
            return ScenarioResult(
                scenario_name=scenario_name,
                attack_vector=attack_vector,
                pretext=pretext,
                success_rate=0.0,
                common_failure_modes=["Failed to parse simulation results"],
            )

    def _calculate_overall_susceptibility(
        self, results: list[ScenarioResult]
    ) -> float:
        """Calculate overall susceptibility as weighted average of scenario results."""
        if not results:
            return 0.0

        # Weight by the scenario's best success rate
        total_rate = sum(r.success_rate for r in results)
        avg = total_rate / len(results)

        # Boost if any single scenario has very high success
        max_rate = max(r.success_rate for r in results)
        weighted = avg * 0.6 + max_rate * 0.4

        return round(min(weighted, 1.0), 3)

    def _find_best_approach(self, results: list[ScenarioResult]) -> dict:
        """Find the most effective attack scenario."""
        if not results:
            return {}

        best = max(results, key=lambda r: r.success_rate)
        return {
            "scenario": best.scenario_name,
            "attack_vector": best.attack_vector,
            "success_rate": best.success_rate,
            "pretext": best.pretext,
            "confidence_interval": list(best.confidence_interval),
        }

    def _assess_confidence(self, subject: SubjectProfile) -> float:
        """Assess simulation confidence based on OSINT data quality."""
        score = 0.2  # Base confidence

        if subject.emails:
            score += 0.1
        if subject.organizational_role:
            score += 0.15
        if subject.department:
            score += 0.1
        if subject.communication_style:
            score += 0.1
        if subject.interests:
            score += 0.1
        if subject.digital_footprint.get("credential_count", 0) > 0:
            score += 0.15
        if subject.social_accounts:
            score += 0.1

        return round(min(score, 1.0), 2)

    def _generate_report(
        self,
        subject: SubjectProfile,
        results: list[ScenarioResult],
        persona: dict,
    ) -> str:
        """Generate a narrative report using the report writer agent."""
        results_summary = []
        for r in results:
            results_summary.append({
                "scenario": r.scenario_name,
                "vector": r.attack_vector,
                "success_rate": r.success_rate,
                "failure_modes": r.common_failure_modes[:3],
            })

        prompt = (
            f"Write a concise social engineering assessment report.\n\n"
            f"TARGET: {persona.get('name', 'Unknown')} "
            f"({persona.get('role', 'Unknown')}, {persona.get('department', 'Unknown')})\n\n"
            f"SIMULATION RESULTS:\n{json.dumps(results_summary, indent=2)}\n\n"
            f"Include:\n"
            f"1. Executive summary (2-3 sentences)\n"
            f"2. Key findings ranked by risk\n"
            f"3. Recommended attack approach for the engagement\n"
            f"4. Suggested mitigations for the client report\n"
            f"Keep it under 500 words."
        )

        result = self.orchestrator.ask_agent(AgentRole.REPORT_WRITER, prompt)
        return result.content if result.success else "Report generation failed."
