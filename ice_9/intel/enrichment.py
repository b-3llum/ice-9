"""OSINT enrichment engine — automated intelligence gathering for entities."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ice_9.ai.agents import AgentRole
from ice_9.ai.json_utils import extract_json
from ice_9.ai.team import TeamOrchestrator
from ice_9.core.events import Event, EventType, event_bus
from ice_9.core.intel import Entity, EntityType, Relationship, RelType
from ice_9.db.store import Store


class EnrichmentEngine:
    """Enriches entities with OSINT data and AI analysis."""

    def __init__(self, store: Store, orchestrator: TeamOrchestrator) -> None:
        self.store = store
        self.orchestrator = orchestrator

    def enrich(self, entity: Entity) -> Entity:
        """Run enrichment pipeline for an entity based on its type."""
        enrichers = {
            EntityType.PERSON: self._enrich_person,
            EntityType.EMAIL: self._enrich_email,
            EntityType.DOMAIN: self._enrich_domain,
            EntityType.HOST: self._enrich_host,
        }

        enricher = enrichers.get(entity.entity_type)
        if not enricher:
            return entity

        enricher(entity)
        entity.updated_at = datetime.now(timezone.utc)
        self.store.save_entity(entity)

        event_bus.emit(Event(
            type=EventType.INTEL_ENRICHED,
            campaign_id=entity.campaign_id,
            data={
                "entity_id": entity.id,
                "entity_type": entity.entity_type.value,
                "name": entity.name,
            },
        ))

        return entity

    def _enrich_person(self, entity: Entity) -> None:
        """Enrich a person entity using AI analysis of available data."""
        # Gather all connected data
        relationships = self.store.get_relationships(
            entity.campaign_id, entity_id=entity.id
        )
        connected_entities = []
        for rel in relationships:
            other_id = rel.target_id if rel.source_id == entity.id else rel.source_id
            other = self.store.get_entity(other_id)
            if other:
                connected_entities.append(other)

        # Build context for AI analysis
        context = self._build_person_context(entity, relationships, connected_entities)

        result = self.orchestrator.ask_agent(
            AgentRole.SOCIAL_ENGINEER,
            f"Analyze this person entity and provide intelligence insights:\n\n{context}\n\n"
            "Respond in JSON with keys: organizational_role, department, "
            "communication_style, interests, risk_factors, "
            "se_susceptibility (phishing, pretexting, baiting — each 0.0-1.0).",
            context="",
        )

        if result.success:
            self._apply_ai_analysis(entity, result.content)

    def _enrich_email(self, entity: Entity) -> None:
        """Enrich an email entity — check breach exposure patterns."""
        email = entity.name
        domain = email.split("@")[-1] if "@" in email else ""

        entity.properties["domain"] = domain
        entity.properties["enriched"] = True

        # Link to domain entity if one exists
        if domain:
            domain_entity = self.store.find_entity(
                entity.campaign_id, EntityType.DOMAIN, domain
            )
            if domain_entity:
                existing_rel = self.store.find_relationship(
                    entity.campaign_id, entity.id, domain_entity.id, RelType.BELONGS_TO
                )
                if not existing_rel:
                    self.store.save_relationship(Relationship(
                        source_id=entity.id,
                        target_id=domain_entity.id,
                        rel_type=RelType.BELONGS_TO,
                        confidence=0.9,
                        sources=["enrichment"],
                        campaign_id=entity.campaign_id,
                    ))

        entity.confidence = min(entity.confidence + 0.1, 1.0)

    def _enrich_domain(self, entity: Entity) -> None:
        """Enrich a domain entity — aggregate DNS/certificate data."""
        entity.properties["enriched"] = True
        entity.confidence = min(entity.confidence + 0.1, 1.0)

        # Use AI to analyze the domain context
        result = self.orchestrator.ask_agent(
            AgentRole.RECON_ANALYST,
            f"Given the domain '{entity.name}', analyze what we know:\n"
            f"Properties: {json.dumps(entity.properties)}\n\n"
            "Provide insights about: likely organization type, technology stack "
            "indicators, and reconnaissance recommendations. Keep it brief.",
            context="",
        )

        if result.success:
            entity.properties["ai_analysis"] = result.content[:500]

    def _enrich_host(self, entity: Entity) -> None:
        """Enrich a host entity — correlate services and vulnerabilities."""
        entity.properties["enriched"] = True
        entity.confidence = min(entity.confidence + 0.1, 1.0)

        # Gather connected services
        relationships = self.store.get_relationships(
            entity.campaign_id, entity_id=entity.id, rel_type=RelType.RUNS_SERVICE
        )
        services = []
        for rel in relationships:
            svc = self.store.get_entity(rel.target_id)
            if svc:
                services.append(svc.properties)

        if services:
            result = self.orchestrator.ask_agent(
                AgentRole.EXPLOIT_RESEARCHER,
                f"Analyze this host's service profile for attack opportunities:\n"
                f"Host: {entity.name}\n"
                f"Services: {json.dumps(services)}\n\n"
                "Identify: high-risk services, common vulnerabilities, "
                "and recommended exploitation paths. Keep it brief.",
                context="",
            )

            if result.success:
                entity.properties["attack_analysis"] = result.content[:500]

    def _build_person_context(
        self,
        entity: Entity,
        relationships: list[Relationship],
        connected: list[Entity],
    ) -> str:
        """Build a text context summary for AI analysis of a person."""
        lines = [
            f"Name: {entity.name}",
            f"Properties: {json.dumps(entity.properties)}",
            f"Sources: {', '.join(entity.sources)}",
            "",
            "Connected entities:",
        ]

        for other in connected:
            rel = next(
                (r for r in relationships
                 if r.source_id == other.id or r.target_id == other.id),
                None,
            )
            rel_desc = rel.rel_type.value if rel else "related"
            lines.append(
                f"  - [{other.entity_type.value}] {other.name} ({rel_desc})"
            )

        return "\n".join(lines)

    def _apply_ai_analysis(self, entity: Entity, ai_response: str) -> None:
        """Parse AI analysis response and update entity properties."""
        data = extract_json(ai_response)
        if data is not None:
            entity.properties["ai_profile"] = data
            entity.confidence = min(entity.confidence + 0.15, 1.0)
        else:
            entity.properties["ai_analysis_raw"] = ai_response[:500]
