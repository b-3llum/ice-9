"""RAG (Retrieval-Augmented Generation) subsystem for TARS."""

from ice_9.ai.rag.ingest import ingest_directory
from ice_9.ai.rag.store import RAGStore

__all__ = ["RAGStore", "ingest_directory"]
