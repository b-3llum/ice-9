"""SQLite persistence layer for ice_9 campaigns."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from ice_9.core.models import (
    Campaign,
    CampaignStatus,
    Finding,
    Phase,
    Severity,
    Task,
)

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'planning',
    description TEXT DEFAULT '',
    client TEXT DEFAULT '',
    lead TEXT DEFAULT '',
    rules_of_engagement TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS phases (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    phase_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TEXT,
    completed_at TEXT,
    notes TEXT DEFAULT '',
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    phase_id TEXT,
    campaign_id TEXT,
    tool TEXT NOT NULL,
    target TEXT DEFAULT '',
    params TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued',
    output TEXT,
    att_ck_id TEXT,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (phase_id) REFERENCES phases(id) ON DELETE CASCADE,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    description TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    cvss REAL,
    cve_ids TEXT DEFAULT '[]',
    att_ck_ids TEXT DEFAULT '[]',
    evidence TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    phase_id TEXT,
    task_id TEXT,
    FOREIGN KEY (phase_id) REFERENCES phases(id) ON DELETE SET NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL
);
"""


class Store:
    """SQLite-backed persistence for campaign data."""

    def __init__(self, db_path: Path, check_same_thread: bool = True) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=check_same_thread)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        cursor = self.conn.cursor()
        cursor.executescript(SCHEMA)
        # Check / set version
        row = cursor.execute(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
        ).fetchone()
        if not row:
            cursor.execute(
                "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
            )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- Campaign CRUD ---

    def save_campaign(self, campaign: Campaign) -> None:
        """Insert or replace a campaign and its phases."""
        c = self.conn.cursor()
        c.execute(
            """INSERT OR REPLACE INTO campaigns
               (id, name, status, description, client, lead, rules_of_engagement, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                campaign.id,
                campaign.name,
                campaign.status.value,
                campaign.description,
                campaign.client,
                campaign.lead,
                campaign.rules_of_engagement.model_dump_json(),
                campaign.created_at.isoformat(),
                campaign.updated_at.isoformat(),
            ),
        )
        # Upsert phases
        for phase in campaign.phases:
            c.execute(
                """INSERT OR REPLACE INTO phases
                   (id, campaign_id, phase_type, status, started_at, completed_at, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    phase.id,
                    campaign.id,
                    phase.phase_type.value,
                    phase.status.value,
                    phase.started_at.isoformat() if phase.started_at else None,
                    phase.completed_at.isoformat() if phase.completed_at else None,
                    phase.notes,
                ),
            )
        self.conn.commit()

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Load a campaign by ID with its phases."""
        row = self.conn.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_campaign(row)

    def list_campaigns(
        self, status: Optional[CampaignStatus] = None
    ) -> list[Campaign]:
        """List all campaigns, optionally filtered by status."""
        if status:
            rows = self.conn.execute(
                "SELECT * FROM campaigns WHERE status = ? ORDER BY updated_at DESC",
                (status.value,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM campaigns ORDER BY updated_at DESC"
            ).fetchall()
        return [self._row_to_campaign(r) for r in rows]

    def delete_campaign(self, campaign_id: str) -> bool:
        """Delete a campaign and all related data."""
        c = self.conn.cursor()
        c.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
        deleted = c.rowcount > 0
        self.conn.commit()
        return deleted

    def _row_to_campaign(self, row: sqlite3.Row) -> Campaign:
        from ice_9.core.models import RulesOfEngagement

        phases = self._get_phases(row["id"])
        roe = RulesOfEngagement.model_validate_json(row["rules_of_engagement"])
        return Campaign(
            id=row["id"],
            name=row["name"],
            status=CampaignStatus(row["status"]),
            description=row["description"],
            client=row["client"],
            lead=row["lead"],
            rules_of_engagement=roe,
            phases=phases,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _get_phases(self, campaign_id: str) -> list[Phase]:
        from ice_9.core.models import PhaseStatus, PhaseType

        rows = self.conn.execute(
            "SELECT * FROM phases WHERE campaign_id = ?", (campaign_id,)
        ).fetchall()
        phases = []
        for r in rows:
            tasks = self._get_tasks(phase_id=r["id"])
            findings = self._get_findings(phase_id=r["id"])
            phases.append(
                Phase(
                    id=r["id"],
                    phase_type=PhaseType(r["phase_type"]),
                    status=PhaseStatus(r["status"]),
                    started_at=(
                        datetime.fromisoformat(r["started_at"])
                        if r["started_at"]
                        else None
                    ),
                    completed_at=(
                        datetime.fromisoformat(r["completed_at"])
                        if r["completed_at"]
                        else None
                    ),
                    campaign_id=campaign_id,
                    tasks=tasks,
                    findings=findings,
                    notes=r["notes"] or "",
                )
            )
        return phases

    # --- Task CRUD ---

    def save_task(self, task: Task) -> None:
        """Insert or replace a task."""
        self.conn.execute(
            """INSERT OR REPLACE INTO tasks
               (id, phase_id, campaign_id, tool, target, params, status, output, att_ck_id, started_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task.id,
                task.phase_id,
                task.campaign_id,
                task.tool,
                task.target,
                json.dumps(task.params),
                task.status.value,
                task.output,
                task.att_ck_id,
                task.started_at.isoformat() if task.started_at else None,
                task.completed_at.isoformat() if task.completed_at else None,
            ),
        )
        self.conn.commit()

    def _get_tasks(self, phase_id: str) -> list[Task]:
        from ice_9.core.models import TaskStatus

        rows = self.conn.execute(
            "SELECT * FROM tasks WHERE phase_id = ?", (phase_id,)
        ).fetchall()
        return [
            Task(
                id=r["id"],
                tool=r["tool"],
                target=r["target"],
                params=json.loads(r["params"]),
                status=TaskStatus(r["status"]),
                output=r["output"],
                att_ck_id=r["att_ck_id"],
                phase_id=r["phase_id"],
                campaign_id=r["campaign_id"],
                started_at=(
                    datetime.fromisoformat(r["started_at"])
                    if r["started_at"]
                    else None
                ),
                completed_at=(
                    datetime.fromisoformat(r["completed_at"])
                    if r["completed_at"]
                    else None
                ),
            )
            for r in rows
        ]

    # --- Finding CRUD ---

    def save_finding(self, finding: Finding) -> None:
        """Insert or replace a finding."""
        self.conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, title, severity, description, remediation, cvss, cve_ids, att_ck_ids, evidence, created_at, phase_id, task_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id,
                finding.title,
                finding.severity.value,
                finding.description,
                finding.remediation,
                finding.cvss,
                json.dumps(finding.cve_ids),
                json.dumps(finding.att_ck_ids),
                json.dumps([e.model_dump() for e in finding.evidence], default=str),
                finding.created_at.isoformat(),
                finding.phase_id,
                finding.task_id,
            ),
        )
        self.conn.commit()

    def _get_findings(self, phase_id: str) -> list[Finding]:
        from ice_9.core.models import Evidence

        rows = self.conn.execute(
            "SELECT * FROM findings WHERE phase_id = ?", (phase_id,)
        ).fetchall()
        findings = []
        for r in rows:
            evidence_data = json.loads(r["evidence"]) if r["evidence"] else []
            evidence = [Evidence.model_validate(e) for e in evidence_data]
            findings.append(
                Finding(
                    id=r["id"],
                    title=r["title"],
                    severity=Severity(r["severity"]),
                    description=r["description"],
                    remediation=r["remediation"],
                    cvss=r["cvss"],
                    cve_ids=json.loads(r["cve_ids"]) if r["cve_ids"] else [],
                    att_ck_ids=json.loads(r["att_ck_ids"]) if r["att_ck_ids"] else [],
                    evidence=evidence,
                    created_at=datetime.fromisoformat(r["created_at"]),
                    phase_id=r["phase_id"],
                    task_id=r["task_id"],
                )
            )
        return findings

    def get_all_findings(self, campaign_id: str) -> list[Finding]:
        """Get all findings for a campaign across all phases."""
        from ice_9.core.models import Evidence

        rows = self.conn.execute(
            """SELECT f.* FROM findings f
               JOIN phases p ON f.phase_id = p.id
               WHERE p.campaign_id = ?
               ORDER BY f.severity, f.created_at""",
            (campaign_id,),
        ).fetchall()
        findings = []
        for r in rows:
            evidence_data = json.loads(r["evidence"]) if r["evidence"] else []
            evidence = [Evidence.model_validate(e) for e in evidence_data]
            findings.append(
                Finding(
                    id=r["id"],
                    title=r["title"],
                    severity=Severity(r["severity"]),
                    description=r["description"],
                    remediation=r["remediation"],
                    cvss=r["cvss"],
                    cve_ids=json.loads(r["cve_ids"]) if r["cve_ids"] else [],
                    att_ck_ids=json.loads(r["att_ck_ids"]) if r["att_ck_ids"] else [],
                    evidence=evidence,
                    created_at=datetime.fromisoformat(r["created_at"]),
                    phase_id=r["phase_id"],
                    task_id=r["task_id"],
                )
            )
        return findings
