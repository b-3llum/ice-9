"""Evidence collection and chain-of-custody management."""

from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path

from ice_9.core.models import Evidence


class EvidenceManager:
    """Manages evidence files with SHA256 integrity hashing."""

    def __init__(self, evidence_dir: Path) -> None:
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def _campaign_dir(self, campaign_id: str) -> Path:
        d = self.evidence_dir / campaign_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def store_file(
        self,
        campaign_id: str,
        source_path: Path,
        description: str = "",
        content_type: str = "application/octet-stream",
    ) -> Evidence:
        """Copy a file into the evidence store and return an Evidence record."""
        dest_dir = self._campaign_dir(campaign_id)
        dest = dest_dir / source_path.name
        # Avoid overwriting — append counter if exists
        counter = 1
        while dest.exists():
            dest = dest_dir / f"{source_path.stem}_{counter}{source_path.suffix}"
            counter += 1
        shutil.copy2(source_path, dest)
        sha = self._hash_file(dest)
        return Evidence(
            file_path=str(dest),
            description=description,
            sha256=sha,
            captured_at=datetime.now(timezone.utc),
            content_type=content_type,
        )

    def store_text(
        self,
        campaign_id: str,
        filename: str,
        content: str,
        description: str = "",
    ) -> Evidence:
        """Store text content as an evidence file."""
        dest_dir = self._campaign_dir(campaign_id)
        dest = dest_dir / filename
        counter = 1
        while dest.exists():
            stem = Path(filename).stem
            suffix = Path(filename).suffix
            dest = dest_dir / f"{stem}_{counter}{suffix}"
            counter += 1
        dest.write_text(content)
        sha = self.hash_bytes(content.encode())
        return Evidence(
            file_path=str(dest),
            description=description,
            sha256=sha,
            captured_at=datetime.now(timezone.utc),
            content_type="text/plain",
        )

    def verify(self, evidence: Evidence) -> bool:
        """Verify evidence file integrity against stored hash."""
        if not evidence.file_path or not evidence.sha256:
            return False
        path = Path(evidence.file_path)
        if not path.exists():
            return False
        return self._hash_file(path) == evidence.sha256

    def list_evidence(self, campaign_id: str) -> list[Path]:
        """List all evidence files for a campaign."""
        d = self._campaign_dir(campaign_id)
        return sorted(d.iterdir()) if d.exists() else []
