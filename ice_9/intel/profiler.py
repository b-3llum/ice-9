"""Subject profiler — builds SE-focused intelligence dossiers for person entities."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ice_9.ai.agents import AgentRole
from ice_9.ai.team import TeamOrchestrator
from ice_9.core.events import Event, EventType, event_bus
from ice_9.core.intel import Entity, Relationship, SubjectProfile
from ice_9.db.store import Store


class SubjectProfiler:
    """Builds social engineering-focused profiles for person entities."""

    def __init__(self, store: Store, orchestrator: TeamOrchestrator) -> None:
        self.store = store
        self.orchestrator = orchestrator

    def build_profile(self, entity: Entity, campaign_id: str) -> SubjectProfile:
        """Build or update a subject profile for a person entity."""
        # Check for existing profile
        existing = self.store.get_subject_by_entity(campaign_id, entity.id)

        profile = existing or SubjectProfile(
            entity_id=entity.id,
            campaign_id=campaign_id,
        )

        # Gather connected data
        relationships = self.store.get_relationships(campaign_id, entity_id=entity.id)
        connected = self._gather_connected(entity.id, relationships)

        # Populate profile from graph data
        self._populate_from_graph(profile, entity, relationships, connected)

        # AI-powered analysis
        self._analyze_with_ai(profile, entity, connected)

        profile.updated_at = datetime.now(timezone.utc)
        self.store.save_subject_profile(profile)

        event_bus.emit(Event(
            type=EventType.SUBJECT_PROFILED,
            campaign_id=campaign_id,
            data={
                "profile_id": profile.id,
                "entity_id": entity.id,
                "name": entity.name,
            },
        ))

        return profile

    def _gather_connected(
        self, entity_id: str, relationships: list[Relationship]
    ) -> dict[str, list[Entity]]:
        """Gather connected entities grouped by type."""
        grouped: dict[str, list[Entity]] = {}
        for rel in relationships:
            other_id = rel.target_id if rel.source_id == entity_id else rel.source_id
            other = self.store.get_entity(other_id)
            if other:
                key = other.entity_type.value
                grouped.setdefault(key, []).append(other)
        return grouped

    def _populate_from_graph(
        self,
        profile: SubjectProfile,
        entity: Entity,
        relationships: list[Relationship],
        connected: dict[str, list[Entity]],
    ) -> None:
        """Populate profile fields from entity graph data."""
        # Emails
        for email_entity in connected.get("email", []):
            if email_entity.name not in profile.emails:
                profile.emails.append(email_entity.name)

        # Credentials → digital footprint
        creds = connected.get("credential", [])
        if creds:
            profile.digital_footprint["credential_count"] = len(creds)
            hash_types = list({c.properties.get("hash_type", "") for c in creds})
            profile.digital_footprint["captured_hash_types"] = hash_types

        # Organizational data from entity properties
        if entity.properties.get("ad_username"):
            profile.digital_footprint["ad_username"] = entity.properties["ad_username"]
        if entity.properties.get("has_spn"):
            profile.digital_footprint["has_spn"] = True
        if entity.properties.get("no_preauth"):
            profile.digital_footprint["no_preauth"] = True

        # AI profile data if enrichment was run
        ai_profile = entity.properties.get("ai_profile", {})
        if ai_profile:
            profile.organizational_role = ai_profile.get(
                "organizational_role", profile.organizational_role
            )
            profile.department = ai_profile.get("department", profile.department)
            profile.communication_style = ai_profile.get(
                "communication_style", profile.communication_style
            )
            if ai_profile.get("interests"):
                profile.interests = ai_profile["interests"]

    def _analyze_with_ai(
        self,
        profile: SubjectProfile,
        entity: Entity,
        connected: dict[str, list[Entity]],
    ) -> None:
        """Use AI agents to generate SE susceptibility analysis."""
        context = self._build_analysis_context(profile, entity, connected)

        # Social engineer agent generates susceptibility assessment
        se_result = self.orchestrator.ask_agent(
            AgentRole.SOCIAL_ENGINEER,
            f"Analyze this target for social engineering susceptibility:\n\n{context}\n\n"
            "Respond in JSON with:\n"
            "- susceptibility_scores: {{phishing: 0-1, pretexting: 0-1, baiting: 0-1, "
            "  vishing: 0-1, tailgating: 0-1}}\n"
            "- recommended_pretexts: [{{name, description, attack_vector, "
            "  estimated_success_rate}}]\n"
            "- communication_style: brief description\n"
            "- risk_factors: [string list]",
            context="",
        )

        if se_result.success:
            self._apply_se_analysis(profile, se_result.content)

    def _build_analysis_context(
        self,
        profile: SubjectProfile,
        entity: Entity,
        connected: dict[str, list[Entity]],
    ) -> str:
        """Build context string for AI analysis."""
        lines = [
            f"Target: {entity.name}",
            f"Role: {profile.organizational_role or 'Unknown'}",
            f"Department: {profile.department or 'Unknown'}",
            f"Emails: {', '.join(profile.emails) or 'None discovered'}",
        ]

        if profile.digital_footprint:
            lines.append(f"Digital footprint: {json.dumps(profile.digital_footprint)}")

        cred_count = len(connected.get("credential", []))
        if cred_count:
            lines.append(f"Captured credentials: {cred_count}")

        orgs = connected.get("organization", [])
        if orgs:
            lines.append(f"Organizations: {', '.join(o.name for o in orgs)}")

        return "\n".join(lines)

    def _apply_se_analysis(self, profile: SubjectProfile, ai_response: str) -> None:
        """Parse AI SE analysis and update profile."""
        try:
            start = ai_response.find("{")
            end = ai_response.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(ai_response[start:end])

                if "susceptibility_scores" in data:
                    profile.susceptibility_scores = data["susceptibility_scores"]
                if "recommended_pretexts" in data:
                    profile.recommended_pretexts = data["recommended_pretexts"]
                if "communication_style" in data:
                    profile.communication_style = data["communication_style"]
                if "risk_factors" in data:
                    profile.digital_footprint["risk_factors"] = data["risk_factors"]
        except (json.JSONDecodeError, ValueError):
            pass
