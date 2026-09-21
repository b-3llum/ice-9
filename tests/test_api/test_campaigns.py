"""Tests for FastAPI campaign and core endpoints."""


def test_health(api_client):
    resp = api_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


def test_create_campaign(api_client):
    resp = api_client.post(
        "/campaigns",
        json={
            "name": "API Test",
            "scope": ["10.0.0.0/24"],
            "description": "test",
            "client": "ACME",
            "lead": "tester",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "API Test"
    assert data["status"] == "planning"
    assert "10.0.0.0/24" in data["scope"]


def test_list_campaigns(api_client):
    # Create one first
    api_client.post("/campaigns", json={"name": "List Test", "scope": []})
    resp = api_client.get("/campaigns")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
    assert len(resp.json()) >= 1


def test_get_campaign(api_client):
    create_resp = api_client.post(
        "/campaigns", json={"name": "Get Test", "scope": ["example.com"]}
    )
    cid = create_resp.json()["id"]

    resp = api_client.get(f"/campaigns/{cid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Get Test"
    assert "phases" in data
    assert len(data["phases"]) == 13


def test_get_campaign_not_found(api_client):
    resp = api_client.get("/campaigns/nonexistent")
    assert resp.status_code == 404


def test_transition_campaign(api_client):
    create_resp = api_client.post(
        "/campaigns", json={"name": "Transition Test", "scope": []}
    )
    cid = create_resp.json()["id"]

    resp = api_client.put(
        f"/campaigns/{cid}/status", json={"status": "active"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"


def test_transition_invalid(api_client):
    create_resp = api_client.post(
        "/campaigns", json={"name": "Bad Transition", "scope": []}
    )
    cid = create_resp.json()["id"]

    resp = api_client.put(
        f"/campaigns/{cid}/status", json={"status": "completed"}
    )
    assert resp.status_code == 400


def test_delete_campaign(api_client):
    create_resp = api_client.post(
        "/campaigns", json={"name": "Delete Me", "scope": []}
    )
    cid = create_resp.json()["id"]

    resp = api_client.delete(f"/campaigns/{cid}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True

    resp = api_client.get(f"/campaigns/{cid}")
    assert resp.status_code == 404


def test_start_and_complete_phase(api_client):
    create_resp = api_client.post(
        "/campaigns", json={"name": "Phase Test", "scope": []}
    )
    cid = create_resp.json()["id"]

    # Activate first
    api_client.put(f"/campaigns/{cid}/status", json={"status": "active"})

    resp = api_client.post(f"/campaigns/{cid}/phases/recon/start")
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"

    resp = api_client.post(f"/campaigns/{cid}/phases/recon/complete")
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


def test_create_and_list_findings(api_client):
    create_resp = api_client.post(
        "/campaigns", json={"name": "Finding Test", "scope": []}
    )
    cid = create_resp.json()["id"]

    # Create a finding
    resp = api_client.post(
        f"/campaigns/{cid}/findings",
        json={
            "title": "Open SMB",
            "severity": "high",
            "description": "SMB on 445",
            "cvss": 7.5,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Open SMB"


def test_tools_endpoint(api_client):
    resp = api_client.get("/tools")
    assert resp.status_code == 200
    tools = resp.json()
    assert isinstance(tools, list)
    names = {t["name"] for t in tools}
    assert "nmap" in names
    assert "theharvester" in names


def test_api_key_auth(tmp_store, audit_logger):
    """Test that API key auth rejects unauthorized requests."""
    from fastapi.testclient import TestClient
    from ice_9 import api

    api._store = tmp_store
    api._audit = audit_logger
    api.API_KEY = "secret123"

    client = TestClient(api.app)

    # No key — rejected
    resp = client.get("/campaigns")
    assert resp.status_code == 401

    # Wrong key — rejected
    resp = client.get("/campaigns", headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401

    # Correct key — accepted
    resp = client.get("/campaigns", headers={"X-API-Key": "secret123"})
    assert resp.status_code == 200

    # Reset
    api.API_KEY = ""
