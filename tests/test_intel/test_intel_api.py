"""Tests for intelligence graph API endpoints."""

from __future__ import annotations

from ice_9.core.intel import Entity, EntityType, Relationship, RelType, SubjectProfile


def test_get_empty_graph(api_client, tmp_store, sample_campaign):
    """Empty campaign returns empty graph."""
    tmp_store.save_campaign(sample_campaign)
    resp = api_client.get(f"/campaigns/{sample_campaign.id}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert data["node_count"] == 0
    assert data["edge_count"] == 0
    assert data["nodes"] == []
    assert data["edges"] == []


def test_get_graph_with_entities(api_client, tmp_store, sample_campaign):
    """Graph returns entities and relationships."""
    tmp_store.save_campaign(sample_campaign)

    e1 = Entity(entity_type=EntityType.HOST, name="10.0.0.1", campaign_id=sample_campaign.id)
    e2 = Entity(entity_type=EntityType.SERVICE, name="ssh/22", campaign_id=sample_campaign.id)
    tmp_store.save_entities([e1, e2])
    tmp_store.save_relationship(Relationship(
        source_id=e1.id, target_id=e2.id,
        rel_type=RelType.RUNS_SERVICE, campaign_id=sample_campaign.id,
    ))

    resp = api_client.get(f"/campaigns/{sample_campaign.id}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert data["node_count"] == 2
    assert data["edge_count"] == 1
    assert data["nodes"][0]["entity_type"] in ("host", "service")


def test_list_entities_with_filter(api_client, tmp_store, sample_campaign):
    """Entity list supports type filtering."""
    tmp_store.save_campaign(sample_campaign)

    tmp_store.save_entity(Entity(entity_type=EntityType.HOST, name="h1", campaign_id=sample_campaign.id))
    tmp_store.save_entity(Entity(entity_type=EntityType.PERSON, name="p1", campaign_id=sample_campaign.id))

    resp = api_client.get(
        f"/campaigns/{sample_campaign.id}/graph/entities?entity_type=host"
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["entity_type"] == "host"


def test_get_entity_detail(api_client, tmp_store, sample_campaign):
    """Entity detail includes relationships."""
    tmp_store.save_campaign(sample_campaign)

    e = Entity(entity_type=EntityType.HOST, name="10.0.0.1", campaign_id=sample_campaign.id)
    tmp_store.save_entity(e)

    resp = api_client.get(f"/campaigns/{sample_campaign.id}/graph/entities/{e.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "10.0.0.1"
    assert "relationships" in data


def test_get_entity_not_found(api_client, tmp_store, sample_campaign):
    """Missing entity returns 404."""
    tmp_store.save_campaign(sample_campaign)
    resp = api_client.get(f"/campaigns/{sample_campaign.id}/graph/entities/nonexistent")
    assert resp.status_code == 404


def test_list_relationships(api_client, tmp_store, sample_campaign):
    """Relationship list endpoint works."""
    tmp_store.save_campaign(sample_campaign)

    e1 = Entity(entity_type=EntityType.HOST, name="h1", campaign_id=sample_campaign.id)
    e2 = Entity(entity_type=EntityType.SERVICE, name="s1", campaign_id=sample_campaign.id)
    tmp_store.save_entities([e1, e2])
    tmp_store.save_relationship(Relationship(
        source_id=e1.id, target_id=e2.id,
        rel_type=RelType.RUNS_SERVICE, campaign_id=sample_campaign.id,
    ))

    resp = api_client.get(f"/campaigns/{sample_campaign.id}/graph/relationships")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_list_subjects_empty(api_client, tmp_store, sample_campaign):
    """Empty subject list returns empty array."""
    tmp_store.save_campaign(sample_campaign)
    resp = api_client.get(f"/campaigns/{sample_campaign.id}/subjects")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_subjects(api_client, tmp_store, sample_campaign):
    """Subject list returns profiles."""
    tmp_store.save_campaign(sample_campaign)

    e = Entity(entity_type=EntityType.PERSON, name="John", campaign_id=sample_campaign.id)
    tmp_store.save_entity(e)
    profile = SubjectProfile(entity_id=e.id, campaign_id=sample_campaign.id, emails=["john@test.com"])
    tmp_store.save_subject_profile(profile)

    resp = api_client.get(f"/campaigns/{sample_campaign.id}/subjects")
    assert resp.status_code == 200
    subjects = resp.json()
    assert len(subjects) == 1
    assert subjects[0]["emails"] == ["john@test.com"]


def test_get_subject_detail(api_client, tmp_store, sample_campaign):
    """Subject detail includes entity data."""
    tmp_store.save_campaign(sample_campaign)

    e = Entity(entity_type=EntityType.PERSON, name="John Doe", campaign_id=sample_campaign.id)
    tmp_store.save_entity(e)
    profile = SubjectProfile(
        entity_id=e.id,
        campaign_id=sample_campaign.id,
        organizational_role="IT Admin",
    )
    tmp_store.save_subject_profile(profile)

    resp = api_client.get(f"/campaigns/{sample_campaign.id}/subjects/{profile.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["organizational_role"] == "IT Admin"
    assert data["entity"]["name"] == "John Doe"


def test_get_subject_not_found(api_client, tmp_store, sample_campaign):
    """Missing subject returns 404."""
    tmp_store.save_campaign(sample_campaign)
    resp = api_client.get(f"/campaigns/{sample_campaign.id}/subjects/nonexistent")
    assert resp.status_code == 404


def test_create_profile_requires_person(api_client, tmp_store, sample_campaign):
    """Profile creation rejects non-person entities."""
    tmp_store.save_campaign(sample_campaign)

    e = Entity(entity_type=EntityType.HOST, name="h1", campaign_id=sample_campaign.id)
    tmp_store.save_entity(e)

    resp = api_client.post(f"/campaigns/{sample_campaign.id}/subjects/{e.id}/profile")
    assert resp.status_code == 400


def test_graph_campaign_not_found(api_client):
    """Graph for missing campaign returns 404."""
    resp = api_client.get("/campaigns/nonexistent/graph")
    assert resp.status_code == 404


def test_extract_entities_endpoint(api_client, tmp_store, sample_campaign):
    """Entity extraction endpoint returns counts."""
    tmp_store.save_campaign(sample_campaign)

    resp = api_client.post(f"/campaigns/{sample_campaign.id}/graph/extract")
    assert resp.status_code == 200
    data = resp.json()
    assert "entities_extracted" in data
    assert "relationships_extracted" in data
