"""RAG (Retrieval-Augmented Generation) subsystem for TARS."""

from ice_9.ai.rag.store import RAGStore
from ice_9.ai.rag.ingest import ingest_directory

__all__ = ["RAGStore", "ingest_directory"]
