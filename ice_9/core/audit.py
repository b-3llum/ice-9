"""Immutable JSONL audit trail for all ice_9 actions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSONL audit log."""

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "audit.jsonl"

    def log(
        self,
        action: str,
        *,
        campaign_id: str | None = None,
        phase_id: str | None = None,
        task_id: str | None = None,
        details: dict[str, Any] | None = None,
        operator: str = "ice9",
    ) -> dict[str, Any]:
        """Write an audit entry. Returns the entry dict."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "operator": operator,
        }
        if campaign_id:
            entry["campaign_id"] = campaign_id
        if phase_id:
            entry["phase_id"] = phase_id
        if task_id:
            entry["task_id"] = task_id
        if details:
            entry["details"] = details

        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

        return entry

    def read(self, limit: int = 50) -> list[dict[str, Any]]:
        """Read the last N audit entries."""
        if not self.log_file.exists():
            return []
        lines = self.log_file.read_text().strip().splitlines()
        entries = [json.loads(line) for line in lines[-limit:]]
        return entries

    def search(
        self,
        *,
        campaign_id: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        """Filter audit entries by campaign or action."""
        entries = []
        if not self.log_file.exists():
            return entries
        for line in self.log_file.read_text().strip().splitlines():
            entry = json.loads(line)
            if campaign_id and entry.get("campaign_id") != campaign_id:
                continue
            if action and entry.get("action") != action:
                continue
            entries.append(entry)
        return entries
