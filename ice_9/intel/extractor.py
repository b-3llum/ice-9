"""Entity extraction pipeline — parse tool outputs into graph entities and relationships."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ice_9.core.intel import Entity, EntityType, Relationship, RelType
from ice_9.core.models import Task
from ice_9.db.store import Store


class EntityExtractor:
    """Extracts entities and relationships from tool result data.

    Each tool has a dedicated extraction method that understands its output
    format and maps it to Entity/Relationship objects.
    """

    def __init__(self, store: Store) -> None:
        self.store = store
        self._extractors: dict[str, Any] = {
            "nmap": self._extract_nmap,
            "theharvester": self._extract_theharvester,
            "amass": self._extract_amass,
            "subfinder": self._extract_subfinder,
            "bloodhound": self._extract_bloodhound,
            "responder": self._extract_responder,
            "secretsdump": self._extract_secretsdump,
            "getuserspns": self._extract_kerberoast,
            "getnpusers": self._extract_asreproast,
        }

    def extract_from_task(self, task: Task, campaign_id: str) -> tuple[list[Entity], list[Relationship]]:
        """Extract entities and relationships from a completed task."""
        if not task.output:
            return [], []

        extractor = self._extractors.get(task.tool)
        if not extractor:
            return [], []

        # Task.output stores the raw stdout; task.params may have parsed data
        parsed = task.params.get("_parsed", {})
        return extractor(parsed, task.target, campaign_id, task.tool)

    def extract_from_parsed(
        self, tool: str, parsed: dict, target: str, campaign_id: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract entities from already-parsed tool output."""
        extractor = self._extractors.get(tool)
        if not extractor:
            return [], []
        return extractor(parsed, target, campaign_id, tool)

    def extract_and_store(
        self, tool: str, parsed: dict, target: str, campaign_id: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract entities and persist them, deduplicating against existing data."""
        entities, relationships = self.extract_from_parsed(tool, parsed, target, campaign_id)

        deduped_entities = self._deduplicate_entities(entities, campaign_id)
        self.store.save_entities(deduped_entities)

        # Remap relationship IDs to deduped entity IDs
        entity_map = {e.name + e.entity_type.value: e.id for e in deduped_entities}
        deduped_rels = self._remap_relationships(relationships, entities, entity_map, campaign_id)
        self.store.save_relationships(deduped_rels)

        return deduped_entities, deduped_rels

    def _deduplicate_entities(self, entities: list[Entity], campaign_id: str) -> list[Entity]:
        """Merge new entities with existing ones by (type, name)."""
        result = []
        for entity in entities:
            existing = self.store.find_entity(campaign_id, entity.entity_type, entity.name)
            if existing:
                # Merge: keep higher confidence, union sources, merge properties
                existing.confidence = max(existing.confidence, entity.confidence)
                existing.sources = list(set(existing.sources + entity.sources))
                existing.properties.update(entity.properties)
                existing.updated_at = datetime.now(timezone.utc)
                result.append(existing)
            else:
                result.append(entity)
        return result

    def _remap_relationships(
        self,
        relationships: list[Relationship],
        original_entities: list[Entity],
        entity_map: dict[str, str],
        campaign_id: str,
    ) -> list[Relationship]:
        """Remap relationship source/target IDs after deduplication."""
        # Build lookup from original entity IDs to keys
        id_to_key: dict[str, str] = {}
        for e in original_entities:
            id_to_key[e.id] = e.name + e.entity_type.value

        result = []
        for rel in relationships:
            source_key = id_to_key.get(rel.source_id)
            target_key = id_to_key.get(rel.target_id)
            if source_key and target_key:
                new_source = entity_map.get(source_key, rel.source_id)
                new_target = entity_map.get(target_key, rel.target_id)

                # Check for existing relationship
                existing = self.store.find_relationship(
                    campaign_id, new_source, new_target, rel.rel_type
                )
                if existing:
                    existing.confidence = max(existing.confidence, rel.confidence)
                    existing.sources = list(set(existing.sources + rel.sources))
                    existing.properties.update(rel.properties)
                    result.append(existing)
                else:
                    rel.source_id = new_source
                    rel.target_id = new_target
                    result.append(rel)
        return result

    # --- Tool-specific extractors ---

    def _extract_nmap(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract host, service, and domain entities from nmap output."""
        entities: list[Entity] = []
        relationships: list[Relationship] = []

        for host_data in parsed.get("hosts", []):
            ip = host_data.get("ip", "")
            if not ip:
                continue

            # Host entity
            host_props: dict[str, Any] = {"ip": ip, "state": host_data.get("state", "up")}
            if host_data.get("os"):
                host_props["os"] = host_data["os"][0].get("name", "")
                host_props["os_accuracy"] = host_data["os"][0].get("accuracy", 0)
            if host_data.get("addresses"):
                mac = next(
                    (a["addr"] for a in host_data["addresses"] if a["type"] == "mac"), ""
                )
                if mac:
                    host_props["mac"] = mac

            host = Entity(
                entity_type=EntityType.HOST,
                name=ip,
                properties=host_props,
                confidence=0.9,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(host)

            # Hostname → domain entities
            for hostname in host_data.get("hostnames", []):
                if hostname:
                    domain = Entity(
                        entity_type=EntityType.DOMAIN,
                        name=hostname,
                        properties={"resolved_ip": ip},
                        confidence=0.8,
                        sources=[tool],
                        campaign_id=campaign_id,
                    )
                    entities.append(domain)
                    relationships.append(Relationship(
                        source_id=domain.id,
                        target_id=host.id,
                        rel_type=RelType.RESOLVES_TO,
                        confidence=0.8,
                        sources=[tool],
                        campaign_id=campaign_id,
                    ))

            # Service entities per open port
            for port_data in host_data.get("ports", []):
                if port_data.get("state") != "open":
                    continue

                port_num = port_data.get("port", 0)
                protocol = port_data.get("protocol", "tcp")
                service_name = port_data.get("service", "unknown")
                product = port_data.get("product", "")
                version = port_data.get("version", "")

                svc_props: dict[str, Any] = {
                    "port": port_num,
                    "protocol": protocol,
                    "service": service_name,
                }
                if product:
                    svc_props["product"] = product
                if version:
                    svc_props["version"] = version

                service = Entity(
                    entity_type=EntityType.SERVICE,
                    name=f"{ip}:{port_num}/{protocol}",
                    properties=svc_props,
                    confidence=0.9,
                    sources=[tool],
                    campaign_id=campaign_id,
                )
                entities.append(service)
                relationships.append(Relationship(
                    source_id=host.id,
                    target_id=service.id,
                    rel_type=RelType.RUNS_SERVICE,
                    properties={"port": port_num, "protocol": protocol},
                    confidence=0.9,
                    sources=[tool],
                    campaign_id=campaign_id,
                ))

        return entities, relationships

    def _extract_theharvester(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract email, person, and domain entities from theHarvester output."""
        entities: list[Entity] = []
        relationships: list[Relationship] = []

        # Target domain as organization entity
        org = Entity(
            entity_type=EntityType.ORGANIZATION,
            name=target,
            properties={"domain": target},
            confidence=0.7,
            sources=[tool],
            campaign_id=campaign_id,
        )
        entities.append(org)

        # Emails → email entities + inferred person entities
        for email in parsed.get("emails", []):
            email_entity = Entity(
                entity_type=EntityType.EMAIL,
                name=email,
                properties={"domain": email.split("@")[-1] if "@" in email else ""},
                confidence=0.8,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(email_entity)

            # Infer a person from the email local part
            local_part = email.split("@")[0] if "@" in email else ""
            person_name = _email_to_name(local_part)
            if person_name:
                person = Entity(
                    entity_type=EntityType.PERSON,
                    name=person_name,
                    properties={"inferred_from": email},
                    confidence=0.4,
                    sources=[tool],
                    campaign_id=campaign_id,
                )
                entities.append(person)
                relationships.append(Relationship(
                    source_id=person.id,
                    target_id=email_entity.id,
                    rel_type=RelType.OWNS_EMAIL,
                    confidence=0.5,
                    sources=[tool],
                    campaign_id=campaign_id,
                ))
                relationships.append(Relationship(
                    source_id=person.id,
                    target_id=org.id,
                    rel_type=RelType.MEMBER_OF,
                    confidence=0.4,
                    sources=[tool],
                    campaign_id=campaign_id,
                ))

        # Subdomains
        for subdomain in parsed.get("subdomains", []):
            domain_entity = Entity(
                entity_type=EntityType.DOMAIN,
                name=subdomain,
                properties={},
                confidence=0.7,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(domain_entity)

            # Link subdomain to parent
            if subdomain.endswith(f".{target}"):
                relationships.append(Relationship(
                    source_id=domain_entity.id,
                    target_id=org.id,
                    rel_type=RelType.SUBDOMAIN_OF,
                    confidence=0.8,
                    sources=[tool],
                    campaign_id=campaign_id,
                ))

        # IPs discovered
        for ip in parsed.get("ips", []):
            host = Entity(
                entity_type=EntityType.HOST,
                name=ip,
                properties={"ip": ip},
                confidence=0.6,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(host)

        return entities, relationships

    def _extract_amass(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract domain and host entities from amass output."""
        entities: list[Entity] = []
        relationships: list[Relationship] = []

        for subdomain in parsed.get("subdomains", []):
            domain = Entity(
                entity_type=EntityType.DOMAIN,
                name=subdomain,
                properties={"discovered_by": parsed.get("sources", [])},
                confidence=0.8,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(domain)

        for ip in parsed.get("addresses", []):
            host = Entity(
                entity_type=EntityType.HOST,
                name=ip,
                properties={"ip": ip},
                confidence=0.7,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(host)

        return entities, relationships

    def _extract_subfinder(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract domain entities from subfinder output."""
        entities: list[Entity] = []
        for subdomain in parsed.get("subdomains", []):
            entities.append(Entity(
                entity_type=EntityType.DOMAIN,
                name=subdomain,
                properties={},
                confidence=0.7,
                sources=[tool],
                campaign_id=campaign_id,
            ))
        return entities, []

    def _extract_bloodhound(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract AD entities from bloodhound-python collection output."""
        entities: list[Entity] = []
        collected = parsed.get("collected", {})

        # Create summary entities for the domain
        if collected.get("users", 0) > 0:
            entities.append(Entity(
                entity_type=EntityType.ORGANIZATION,
                name=target,
                properties={
                    "ad_domain": target,
                    "user_count": collected.get("users", 0),
                    "computer_count": collected.get("computers", 0),
                    "group_count": collected.get("groups", 0),
                },
                confidence=0.9,
                sources=[tool],
                campaign_id=campaign_id,
            ))

        return entities, []

    def _extract_responder(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract credential and host entities from responder output."""
        entities: list[Entity] = []
        relationships: list[Relationship] = []

        # Create credential entities from captured hashes
        for hash_val in parsed.get("ntlmv2_hashes", []):
            parts = hash_val.split(":")
            username = parts[0] if parts else "unknown"

            cred = Entity(
                entity_type=EntityType.CREDENTIAL,
                name=f"NTLMv2:{username}",
                properties={"hash_type": "NTLMv2", "username": username, "hash": hash_val},
                confidence=0.95,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(cred)

            # Infer a person entity
            person = Entity(
                entity_type=EntityType.PERSON,
                name=username,
                properties={"ad_username": username},
                confidence=0.6,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(person)
            relationships.append(Relationship(
                source_id=person.id,
                target_id=cred.id,
                rel_type=RelType.HAS_CREDENTIAL,
                confidence=0.9,
                sources=[tool],
                campaign_id=campaign_id,
            ))

        for hash_val in parsed.get("ntlmv1_hashes", []):
            parts = hash_val.split(":")
            username = parts[0] if parts else "unknown"
            cred = Entity(
                entity_type=EntityType.CREDENTIAL,
                name=f"NTLMv1:{username}",
                properties={"hash_type": "NTLMv1", "username": username, "hash": hash_val},
                confidence=0.95,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(cred)

        # Hosts that connected
        for captured in parsed.get("captured_from", []):
            ip = captured.get("ip", "")
            if ip:
                entities.append(Entity(
                    entity_type=EntityType.HOST,
                    name=ip,
                    properties={"ip": ip, "responded_to_poisoning": True},
                    confidence=0.9,
                    sources=[tool],
                    campaign_id=campaign_id,
                ))

        return entities, relationships

    def _extract_secretsdump(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract credential entities from secretsdump output."""
        entities: list[Entity] = []
        relationships: list[Relationship] = []

        # Host entity for the target
        host = Entity(
            entity_type=EntityType.HOST,
            name=target,
            properties={"ip": target, "dumped": True},
            confidence=0.9,
            sources=[tool],
            campaign_id=campaign_id,
        )
        entities.append(host)

        for hash_line in parsed.get("hashes", []):
            # Format: domain\user:RID:LM:NTLM:::
            parts = hash_line.split(":")
            if len(parts) < 4:
                continue
            user_part = parts[0]
            username = user_part.split("\\")[-1] if "\\" in user_part else user_part

            cred = Entity(
                entity_type=EntityType.CREDENTIAL,
                name=f"NTLM:{username}",
                properties={
                    "hash_type": "NTLM",
                    "username": username,
                    "hash": hash_line,
                    "source_host": target,
                },
                confidence=0.95,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(cred)

            person = Entity(
                entity_type=EntityType.PERSON,
                name=username,
                properties={"ad_username": username},
                confidence=0.7,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(person)
            relationships.append(Relationship(
                source_id=person.id,
                target_id=cred.id,
                rel_type=RelType.HAS_CREDENTIAL,
                confidence=0.95,
                sources=[tool],
                campaign_id=campaign_id,
            ))

        return entities, relationships

    def _extract_kerberoast(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract credential entities from Kerberoast output."""
        entities: list[Entity] = []
        relationships: list[Relationship] = []

        for hash_val in parsed.get("tgs_hashes", []):
            # $krb5tgs$23$*user$realm$spn*$...
            match = re.search(r"\$krb5tgs\$\d+\$\*?([^$*]+)", hash_val)
            username = match.group(1) if match else "unknown"

            cred = Entity(
                entity_type=EntityType.CREDENTIAL,
                name=f"TGS:{username}",
                properties={"hash_type": "krb5tgs", "username": username, "hash": hash_val},
                confidence=0.95,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(cred)

            person = Entity(
                entity_type=EntityType.PERSON,
                name=username,
                properties={"ad_username": username, "has_spn": True},
                confidence=0.7,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(person)
            relationships.append(Relationship(
                source_id=person.id,
                target_id=cred.id,
                rel_type=RelType.HAS_CREDENTIAL,
                confidence=0.95,
                sources=[tool],
                campaign_id=campaign_id,
            ))

        return entities, relationships

    def _extract_asreproast(
        self, parsed: dict, target: str, campaign_id: str, tool: str
    ) -> tuple[list[Entity], list[Relationship]]:
        """Extract credential entities from AS-REP roast output."""
        entities: list[Entity] = []
        relationships: list[Relationship] = []

        for hash_val in parsed.get("asrep_hashes", []):
            match = re.search(r"\$krb5asrep\$\d+\$([^@:]+)", hash_val)
            username = match.group(1) if match else "unknown"

            cred = Entity(
                entity_type=EntityType.CREDENTIAL,
                name=f"ASREP:{username}",
                properties={
                    "hash_type": "krb5asrep",
                    "username": username,
                    "hash": hash_val,
                    "no_preauth": True,
                },
                confidence=0.95,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(cred)

            person = Entity(
                entity_type=EntityType.PERSON,
                name=username,
                properties={
                    "ad_username": username,
                    "no_preauth": True,
                },
                confidence=0.7,
                sources=[tool],
                campaign_id=campaign_id,
            )
            entities.append(person)
            relationships.append(Relationship(
                source_id=person.id,
                target_id=cred.id,
                rel_type=RelType.HAS_CREDENTIAL,
                confidence=0.95,
                sources=[tool],
                campaign_id=campaign_id,
            ))

        return entities, relationships


def _email_to_name(local_part: str) -> str:
    """Attempt to infer a human name from an email local part.

    Handles common patterns: john.doe, jdoe, john_doe, john-doe.
    Returns empty string if the local part doesn't look like a name.
    """
    if not local_part or len(local_part) < 2:
        return ""

    # Skip generic addresses
    generic = {"info", "admin", "support", "contact", "sales", "noreply", "no-reply",
               "webmaster", "postmaster", "hostmaster", "abuse", "security", "help",
               "billing", "marketing", "hr", "it", "ops", "dev", "team"}
    if local_part.lower() in generic:
        return ""

    # Try splitting by common separators
    for sep in [".", "_", "-"]:
        if sep in local_part:
            parts = local_part.split(sep)
            if len(parts) >= 2 and all(p.isalpha() for p in parts):
                return " ".join(p.capitalize() for p in parts)

    return ""
