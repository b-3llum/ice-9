"""Tests for intelligence graph data models and DB CRUD operations."""

from __future__ import annotations

import pytest
from pathlib import Path

from ice_9.core.intel import (
    Entity,
    EntityType,
    Relationship,
    RelType,
    SubjectProfile,
    ScenarioResult,
    SimulationResult,
)
from ice_9.core.campaign import create_campaign
from ice_9.db.store import Store

CAMPAIGN_ID = "test_camp_01"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "test.db", check_same_thread=False)
    campaign = create_campaign(name="Test", scope=["10.0.0.0/8"])
    campaign.id = CAMPAIGN_ID
    s.save_campaign(campaign)
    yield s
    s.close()


class TestEntityModels:
    def test_entity_defaults(self):
        e = Entity(entity_type=EntityType.HOST, name="192.168.1.1")
        assert len(e.id) == 12
        assert e.confidence == 0.5
        assert e.sources == []
        assert e.properties == {}

    def test_entity_custom_fields(self):
        e = Entity(
            entity_type=EntityType.PERSON,
            name="John Doe",
            properties={"role": "admin"},
            confidence=0.9,
            sources=["nmap", "theharvester"],
            campaign_id="abc123def456",
        )
        assert e.entity_type == EntityType.PERSON
        assert e.properties["role"] == "admin"
        assert e.confidence == 0.9
        assert len(e.sources) == 2

    def test_relationship_defaults(self):
        r = Relationship(
            source_id="aaa111bbb222",
            target_id="ccc333ddd444",
            rel_type=RelType.ADMIN_OF,
        )
        assert len(r.id) == 12
        assert r.confidence == 0.5

    def test_subject_profile_defaults(self):
        p = SubjectProfile(entity_id="abc123def456")
        assert len(p.id) == 12
        assert p.emails == []
        assert p.susceptibility_scores == {}
        assert p.behavioral_predictions == []

    def test_scenario_result(self):
        s = ScenarioResult(
            scenario_name="Phishing Test",
            attack_vector="email",
            pretext="IT Password Reset",
            success_rate=0.65,
            confidence_interval=(0.55, 0.75),
        )
        assert s.success_rate == 0.65
        assert s.confidence_interval == (0.55, 0.75)

    def test_simulation_result(self):
        sr = SimulationResult(
            subject_id="abc123def456",
            overall_susceptibility=0.7,
        )
        assert len(sr.id) == 12
        assert sr.overall_susceptibility == 0.7


class TestEntityCRUD:
    def test_save_and_get_entity(self, store: Store):
        e = Entity(
            entity_type=EntityType.HOST,
            name="10.0.0.1",
            properties={"ip": "10.0.0.1", "os": "Linux"},
            confidence=0.9,
            sources=["nmap"],
            campaign_id=CAMPAIGN_ID,
        )
        store.save_entity(e)

        loaded = store.get_entity(e.id)
        assert loaded is not None
        assert loaded.name == "10.0.0.1"
        assert loaded.entity_type == EntityType.HOST
        assert loaded.properties["os"] == "Linux"
        assert loaded.confidence == 0.9

    def test_save_entities_batch(self, store: Store):
        entities = [
            Entity(entity_type=EntityType.HOST, name=f"10.0.0.{i}", campaign_id=CAMPAIGN_ID)
            for i in range(5)
        ]
        store.save_entities(entities)

        loaded = store.get_entities(CAMPAIGN_ID)
        assert len(loaded) == 5

    def test_get_entities_filter_type(self, store: Store):
        store.save_entity(Entity(entity_type=EntityType.HOST, name="h1", campaign_id=CAMPAIGN_ID))
        store.save_entity(Entity(entity_type=EntityType.PERSON, name="p1", campaign_id=CAMPAIGN_ID))
        store.save_entity(Entity(entity_type=EntityType.HOST, name="h2", campaign_id=CAMPAIGN_ID))

        hosts = store.get_entities(CAMPAIGN_ID, entity_type=EntityType.HOST)
        assert len(hosts) == 2

        persons = store.get_entities(CAMPAIGN_ID, entity_type=EntityType.PERSON)
        assert len(persons) == 1

    def test_get_entities_filter_confidence(self, store: Store):
        store.save_entity(Entity(entity_type=EntityType.HOST, name="h1", confidence=0.3, campaign_id=CAMPAIGN_ID))
        store.save_entity(Entity(entity_type=EntityType.HOST, name="h2", confidence=0.8, campaign_id=CAMPAIGN_ID))

        high = store.get_entities(CAMPAIGN_ID, min_confidence=0.5)
        assert len(high) == 1
        assert high[0].name == "h2"

    def test_get_entities_search(self, store: Store):
        store.save_entity(Entity(entity_type=EntityType.HOST, name="webserver-01", campaign_id=CAMPAIGN_ID))
        store.save_entity(Entity(entity_type=EntityType.HOST, name="db-primary", campaign_id=CAMPAIGN_ID))

        found = store.get_entities(CAMPAIGN_ID, search="web")
        assert len(found) == 1
        assert found[0].name == "webserver-01"

    def test_find_entity(self, store: Store):
        store.save_entity(Entity(entity_type=EntityType.DOMAIN, name="example.com", campaign_id=CAMPAIGN_ID))

        found = store.find_entity(CAMPAIGN_ID, EntityType.DOMAIN, "example.com")
        assert found is not None
        assert found.name == "example.com"

        not_found = store.find_entity(CAMPAIGN_ID, EntityType.DOMAIN, "other.com")
        assert not_found is None

    def test_delete_entity(self, store: Store):
        e = Entity(entity_type=EntityType.HOST, name="h1", campaign_id=CAMPAIGN_ID)
        store.save_entity(e)
        assert store.get_entity(e.id) is not None

        deleted = store.delete_entity(e.id)
        assert deleted is True
        assert store.get_entity(e.id) is None

    def test_upsert_entity(self, store: Store):
        e = Entity(entity_type=EntityType.HOST, name="h1", confidence=0.5, campaign_id=CAMPAIGN_ID)
        store.save_entity(e)

        e.confidence = 0.9
        e.properties["updated"] = True
        store.save_entity(e)

        loaded = store.get_entity(e.id)
        assert loaded.confidence == 0.9
        assert loaded.properties["updated"] is True


class TestRelationshipCRUD:
    def test_save_and_get_relationships(self, store: Store):
        e1 = Entity(entity_type=EntityType.PERSON, name="user1", campaign_id=CAMPAIGN_ID)
        e2 = Entity(entity_type=EntityType.CREDENTIAL, name="cred1", campaign_id=CAMPAIGN_ID)
        store.save_entities([e1, e2])

        rel = Relationship(
            source_id=e1.id,
            target_id=e2.id,
            rel_type=RelType.HAS_CREDENTIAL,
            confidence=0.95,
            sources=["responder"],
            campaign_id=CAMPAIGN_ID,
        )
        store.save_relationship(rel)

        rels = store.get_relationships(CAMPAIGN_ID)
        assert len(rels) == 1
        assert rels[0].rel_type == RelType.HAS_CREDENTIAL

    def test_get_relationships_by_entity(self, store: Store):
        e1 = Entity(entity_type=EntityType.PERSON, name="u1", campaign_id=CAMPAIGN_ID)
        e2 = Entity(entity_type=EntityType.CREDENTIAL, name="cr1", campaign_id=CAMPAIGN_ID)
        e3 = Entity(entity_type=EntityType.HOST, name="h1", campaign_id=CAMPAIGN_ID)
        store.save_entities([e1, e2, e3])

        store.save_relationship(Relationship(
            source_id=e1.id, target_id=e2.id, rel_type=RelType.HAS_CREDENTIAL, campaign_id=CAMPAIGN_ID,
        ))
        store.save_relationship(Relationship(
            source_id=e3.id, target_id=e1.id, rel_type=RelType.HAS_SESSION, campaign_id=CAMPAIGN_ID,
        ))

        user_rels = store.get_relationships(CAMPAIGN_ID, entity_id=e1.id)
        assert len(user_rels) == 2

        host_rels = store.get_relationships(CAMPAIGN_ID, entity_id=e3.id)
        assert len(host_rels) == 1

    def test_find_relationship(self, store: Store):
        e1 = Entity(entity_type=EntityType.PERSON, name="u1", campaign_id=CAMPAIGN_ID)
        e2 = Entity(entity_type=EntityType.CREDENTIAL, name="cr1", campaign_id=CAMPAIGN_ID)
        store.save_entities([e1, e2])

        store.save_relationship(Relationship(
            source_id=e1.id, target_id=e2.id, rel_type=RelType.HAS_CREDENTIAL, campaign_id=CAMPAIGN_ID,
        ))

        found = store.find_relationship(CAMPAIGN_ID, e1.id, e2.id, RelType.HAS_CREDENTIAL)
        assert found is not None

        not_found = store.find_relationship(CAMPAIGN_ID, e1.id, e2.id, RelType.ADMIN_OF)
        assert not_found is None


class TestSubjectProfileCRUD:
    def test_save_and_get_profile(self, store: Store):
        e = Entity(entity_type=EntityType.PERSON, name="John Doe", campaign_id=CAMPAIGN_ID)
        store.save_entity(e)

        profile = SubjectProfile(
            entity_id=e.id,
            campaign_id=CAMPAIGN_ID,
            emails=["john.doe@example.com"],
            organizational_role="IT Admin",
            department="IT",
            susceptibility_scores={"phishing": 0.7, "pretexting": 0.5},
        )
        store.save_subject_profile(profile)

        loaded = store.get_subject_profile(profile.id)
        assert loaded is not None
        assert loaded.emails == ["john.doe@example.com"]
        assert loaded.organizational_role == "IT Admin"
        assert loaded.susceptibility_scores["phishing"] == 0.7

    def test_get_subject_by_entity(self, store: Store):
        e = Entity(entity_type=EntityType.PERSON, name="Jane", campaign_id=CAMPAIGN_ID)
        store.save_entity(e)

        profile = SubjectProfile(entity_id=e.id, campaign_id=CAMPAIGN_ID)
        store.save_subject_profile(profile)

        found = store.get_subject_by_entity(CAMPAIGN_ID, e.id)
        assert found is not None
        assert found.id == profile.id

    def test_list_subject_profiles(self, store: Store):
        for i in range(3):
            e = Entity(entity_type=EntityType.PERSON, name=f"user{i}", campaign_id=CAMPAIGN_ID)
            store.save_entity(e)
            store.save_subject_profile(SubjectProfile(entity_id=e.id, campaign_id=CAMPAIGN_ID))

        profiles = store.get_subject_profiles(CAMPAIGN_ID)
        assert len(profiles) == 3

    def test_graph_query(self, store: Store):
        e1 = Entity(entity_type=EntityType.HOST, name="h1", campaign_id=CAMPAIGN_ID)
        e2 = Entity(entity_type=EntityType.SERVICE, name="s1", campaign_id=CAMPAIGN_ID)
        store.save_entities([e1, e2])
        store.save_relationship(Relationship(
            source_id=e1.id, target_id=e2.id, rel_type=RelType.RUNS_SERVICE, campaign_id=CAMPAIGN_ID,
        ))

        graph = store.get_graph(CAMPAIGN_ID)
        assert len(graph["nodes"]) == 2
        assert len(graph["edges"]) == 1
