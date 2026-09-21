"""Shared fixtures for ice_9 tests."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from ice_9.core.audit import AuditLogger
from ice_9.core.campaign import create_campaign
from ice_9.core.models import Campaign
from ice_9.db.store import Store
from ice_9.tools.base import ToolResult


@pytest.fixture
def tmp_store(tmp_path: Path) -> Store:
    """Fresh SQLite store in a temp directory."""
    store = Store(tmp_path / "test.db", check_same_thread=False)
    yield store
    store.close()


@pytest.fixture
def audit_logger(tmp_path: Path) -> AuditLogger:
    """Audit logger writing to temp directory."""
    return AuditLogger(tmp_path / "audit")


@pytest.fixture
def sample_campaign() -> Campaign:
    """Campaign with scope and all phases pre-populated."""
    return create_campaign(
        name="Test Campaign",
        scope=["192.168.1.0/24", "example.com"],
        description="Test engagement",
        client="TestCorp",
        lead="tester",
    )


@pytest.fixture
def mock_tool_result():
    """Factory fixture for ToolResult objects."""
    def _make(
        tool: str = "nmap",
        target: str = "192.168.1.1",
        stdout: str = "",
        stderr: str = "",
        parsed: dict[str, Any] | None = None,
        success: bool = True,
    ) -> ToolResult:
        now = datetime.now(timezone.utc)
        r = ToolResult(
            tool=tool,
            target=target,
            command=["test", tool],
            return_code=0 if success else 1,
            stdout=stdout,
            stderr=stderr,
            started_at=now,
            completed_at=now,
        )
        if parsed is not None:
            r.parsed = parsed
        return r
    return _make


@pytest.fixture
def api_client(tmp_store: Store, audit_logger: AuditLogger):
    """FastAPI TestClient with patched store and audit."""
    from fastapi.testclient import TestClient
    from ice_9 import api

    api._store = tmp_store
    api._audit = audit_logger
    api._settings = None  # Will use defaults

    # Unset API key for tests
    original = os.environ.get("ICE9_API_KEY")
    os.environ.pop("ICE9_API_KEY", None)
    api.API_KEY = ""

    client = TestClient(api.app)
    yield client

    if original is not None:
        os.environ["ICE9_API_KEY"] = original
