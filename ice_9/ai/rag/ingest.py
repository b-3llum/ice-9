"""Document ingestion pipeline for the TARS knowledge base."""

from __future__ import annotations

from pathlib import Path

from ice_9.ai.rag.store import RAGStore

# Default file extensions to ingest
DEFAULT_EXTENSIONS: set[str] = {
    ".txt",
    ".md",
    ".pdf",
    ".json",
    ".yaml",
    ".yml",
    ".log",
    ".xml",
    ".html",
    ".csv",
    ".rst",
    ".nse",  # Nmap scripts
}


def ingest_directory(
    rag: RAGStore,
    directory: str | Path,
    source: str = "bulk",
    extensions: set[str] | None = None,
    max_file_size_mb: float = 10.0,
) -> int:
    """Recursively ingest all supported files from a directory.

    Args:
        rag: The RAGStore instance to ingest into.
        directory: Path to the directory to scan.
        source: Label to tag all ingested chunks with.
        extensions: Allowlist of file extensions. Uses DEFAULT_EXTENSIONS if None.
        max_file_size_mb: Skip files larger than this (in megabytes).

    Returns:
        Total number of chunks ingested.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return 0

    extensions = extensions or DEFAULT_EXTENSIONS
    max_bytes = int(max_file_size_mb * 1024 * 1024)
    total = 0

    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in extensions:
            continue
        if path.stat().st_size > max_bytes:
            continue

        try:
            count = rag.ingest_file(path, source=source)
            total += count
        except Exception:
            continue

    return total


def ingest_text(
    rag: RAGStore,
    text: str,
    source: str = "inline",
    metadata: dict | None = None,
) -> int:
    """Ingest a raw text string into the knowledge base.

    Useful for ingesting command output, API responses, or notes on the fly.
    """
    if not text.strip():
        return 0
    metas = [metadata] if metadata else None
    return rag.ingest([text], metadatas=metas, source=source)
