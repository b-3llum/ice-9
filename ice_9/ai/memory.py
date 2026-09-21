"""TARS memory system — working, episodic, and semantic memory.

Three memory tiers:
    - WorkingMemory: Sliding-window conversation context with auto-summarization.
    - EpisodicMemory: SQLite-backed task history (what happened, what worked).
    - MemoryManager: Unified interface that combines all tiers + RAG retrieval.
"""

from __future__ import annotations

import json
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ------------------------------------------------------------------
# Working Memory
# ------------------------------------------------------------------

@dataclass
class MemoryEntry:
    """A single message in working memory."""

    role: str  # "user", "assistant", "tool", "system"
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


class WorkingMemory:
    """Short-term conversation context with automatic summarization.

    Maintains a bounded deque of recent messages and a running summary
    of older messages that have been compressed out.
    """

    def __init__(
        self,
        max_messages: int = 20,
        summary_threshold: int = 15,
    ) -> None:
        self.messages: deque[MemoryEntry] = deque(maxlen=max_messages)
        self.max_messages = max_messages
        self.summary_threshold = summary_threshold
        self.running_summary: str = ""

    def add(self, role: str, content: str, **metadata: Any) -> None:
        """Append a message to working memory."""
        self.messages.append(
            MemoryEntry(role=role, content=content, metadata=metadata),
        )

    def get_context(self) -> list[dict[str, str]]:
        """Return messages formatted for LLM input.

        If a running summary exists it is prepended as a system message.
        """
        result: list[dict[str, str]] = []
        if self.running_summary:
            result.append(
                {
                    "role": "system",
                    "content": (
                        f"Summary of earlier conversation:\n{self.running_summary}"
                    ),
                }
            )
        for entry in self.messages:
            result.append({"role": entry.role, "content": entry.content})
        return result

    def should_summarize(self) -> bool:
        """Check if working memory is large enough to warrant compression."""
        return len(self.messages) >= self.summary_threshold

    def compress(self, summary: str) -> None:
        """Replace older messages with *summary*, keeping recent ones."""
        keep_count = max(self.max_messages // 3, 3)
        recent = list(self.messages)[-keep_count:]
        self.running_summary = summary
        self.messages.clear()
        for msg in recent:
            self.messages.append(msg)

    def clear(self) -> None:
        """Reset working memory entirely."""
        self.messages.clear()
        self.running_summary = ""

    @property
    def token_estimate(self) -> int:
        """Rough token count of the current context (~4 chars/token)."""
        total = len(self.running_summary)
        total += sum(len(e.content) for e in self.messages)
        return total // 4


# ------------------------------------------------------------------
# Episodic Memory
# ------------------------------------------------------------------

EPISODIC_DDL = """
CREATE TABLE IF NOT EXISTS episodic_memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_description TEXT NOT NULL,
    actions_taken TEXT NOT NULL,
    outcome TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    lesson TEXT DEFAULT '',
    campaign_id TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class EpisodicMemory:
    """Long-term task execution history stored in SQLite.

    Records what the agent did, whether it worked, and any lessons learned.
    Used during planning to avoid repeating past mistakes.
    """

    def __init__(self, db_path: str | None = None, conn: sqlite3.Connection | None = None) -> None:
        if conn is not None:
            self._conn = conn
            self._owns_conn = False
        else:
            from pathlib import Path

            db = Path(db_path or "~/.ice9/ice9.db").expanduser()
            db.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(db))
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._owns_conn = True
        self._ensure_table()

    def _ensure_table(self) -> None:
        self._conn.executescript(EPISODIC_DDL)

    def close(self) -> None:
        if self._owns_conn:
            self._conn.close()

    def record(
        self,
        task: str,
        actions: list[str],
        outcome: str,
        success: bool,
        lesson: str = "",
        campaign_id: str = "",
    ) -> None:
        """Write an episode to long-term memory."""
        self._conn.execute(
            "INSERT INTO episodic_memory "
            "(task_description, actions_taken, outcome, success, lesson, campaign_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (task, json.dumps(actions), outcome, int(success), lesson, campaign_id),
        )
        self._conn.commit()

    def recall_similar(self, task: str, limit: int = 5) -> list[dict[str, Any]]:
        """Retrieve past episodes relevant to *task* via keyword overlap."""
        keywords = set(task.lower().split())
        rows = self._conn.execute(
            "SELECT task_description, actions_taken, outcome, success, lesson "
            "FROM episodic_memory ORDER BY created_at DESC LIMIT 200",
        ).fetchall()

        scored: list[tuple[int, dict[str, Any]]] = []
        for row in rows:
            desc_words = set(row[0].lower().split())
            overlap = len(keywords & desc_words)
            if overlap > 0:
                scored.append(
                    (
                        overlap,
                        {
                            "task": row[0],
                            "actions": json.loads(row[1]),
                            "outcome": row[2],
                            "success": bool(row[3]),
                            "lesson": row[4],
                        },
                    )
                )

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s[1] for s in scored[:limit]]

    def recall_failures(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent failures for self-reflection."""
        rows = self._conn.execute(
            "SELECT task_description, actions_taken, outcome, lesson "
            "FROM episodic_memory WHERE success = 0 "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "task": r[0],
                "actions": json.loads(r[1]),
                "outcome": r[2],
                "lesson": r[3],
            }
            for r in rows
        ]

    def count(self) -> int:
        """Total number of recorded episodes."""
        row = self._conn.execute("SELECT COUNT(*) FROM episodic_memory").fetchone()
        return row[0] if row else 0


# ------------------------------------------------------------------
# Memory Manager
# ------------------------------------------------------------------

class MemoryManager:
    """Unified memory interface combining working, episodic, and semantic (RAG) memory."""

    def __init__(
        self,
        db_path: str | None = None,
        conn: sqlite3.Connection | None = None,
        rag_store: Any = None,
    ) -> None:
        self.working = WorkingMemory()
        self.episodic = EpisodicMemory(db_path=db_path, conn=conn)
        self.rag = rag_store  # Optional RAGStore instance

    def close(self) -> None:
        self.episodic.close()

    def build_context(self, current_prompt: str) -> str:
        """Build full context from all memory sources for the LLM.

        Combines:
          - Relevant past task episodes (episodic memory).
          - Relevant knowledge chunks (RAG / semantic memory).
        """
        parts: list[str] = []

        # Episodic: similar past tasks
        similar = self.episodic.recall_similar(current_prompt, limit=3)
        if similar:
            parts.append("RELEVANT PAST EXPERIENCE:")
            for ep in similar:
                status = "SUCCESS" if ep["success"] else "FAILED"
                parts.append(f"  [{status}] {ep['task']}")
                if ep["lesson"]:
                    parts.append(f"    Lesson: {ep['lesson']}")

        # Semantic: RAG retrieval
        if self.rag is not None:
            try:
                docs = self.rag.query(current_prompt, n_results=3)
                if docs:
                    parts.append("\nRELEVANT KNOWLEDGE:")
                    for doc in docs:
                        source = doc["metadata"].get("source", "?")
                        content_preview = doc["content"][:300]
                        parts.append(f"  [{source}] {content_preview}")
            except Exception:
                pass  # RAG is optional — don't break if Ollama/Chroma is down

        return "\n".join(parts)
