"""Vector store for RAG — backed by ChromaDB with Ollama embeddings."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Optional

import httpx


class RAGStore:
    """Persistent vector store for retrieval-augmented generation.

    Uses ChromaDB for vector storage and Ollama's embedding endpoint
    for generating embeddings locally — no API keys needed.
    """

    def __init__(
        self,
        persist_dir: str = "~/.ice9/rag",
        collection_name: str = "tars_knowledge",
        embedding_model: str = "nomic-embed-text",
        ollama_url: str = "http://localhost:11434",
    ) -> None:
        import chromadb
        from chromadb.config import Settings as ChromaSettings

        self.persist_dir = Path(persist_dir).expanduser()
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.embedding_model = embedding_model
        self.ollama_url = ollama_url.rstrip("/")

        self.client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Get embeddings from Ollama's /api/embeddings endpoint."""
        embeddings: list[list[float]] = []
        for text in texts:
            resp = httpx.post(
                f"{self.ollama_url}/api/embeddings",
                json={"model": self.embedding_model, "prompt": text},
                timeout=30,
            )
            resp.raise_for_status()
            embeddings.append(resp.json()["embedding"])
        return embeddings

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(
        self,
        documents: list[str],
        metadatas: list[dict[str, Any]] | None = None,
        source: str = "manual",
    ) -> int:
        """Chunk and ingest documents into the vector store.

        Args:
            documents: Raw text documents to ingest.
            metadatas: Optional per-document metadata dicts.
            source: Label for the ingestion source.

        Returns:
            Number of chunks stored.
        """
        chunks: list[str] = []
        chunk_metas: list[dict[str, Any]] = []
        chunk_ids: list[str] = []

        for i, doc in enumerate(documents):
            doc_chunks = self._chunk_text(doc)
            for j, chunk in enumerate(doc_chunks):
                chunk_id = hashlib.sha256(chunk.encode()).hexdigest()[:16]
                chunks.append(chunk)
                meta: dict[str, Any] = {
                    "source": source,
                    "doc_index": i,
                    "chunk_index": j,
                }
                if metadatas and i < len(metadatas):
                    meta.update(metadatas[i])
                chunk_metas.append(meta)
                chunk_ids.append(f"{source}_{chunk_id}")

        if not chunks:
            return 0

        embeddings = self.embed(chunks)

        self.collection.upsert(
            ids=chunk_ids,
            embeddings=embeddings,
            documents=chunks,
            metadatas=chunk_metas,
        )
        return len(chunks)

    def ingest_file(self, path: str | Path, source: str | None = None) -> int:
        """Ingest a single file into the vector store."""
        path = Path(path)
        source = source or path.name

        if path.suffix.lower() == ".pdf":
            text = self._extract_pdf(path)
        else:
            text = path.read_text(errors="ignore")

        if not text.strip():
            return 0

        return self.ingest(
            [text],
            metadatas=[{"filename": path.name, "path": str(path)}],
            source=source,
        )

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def query(
        self,
        query: str,
        n_results: int = 5,
        where: dict[str, Any] | None = None,
        max_distance: float = 0.7,
    ) -> list[dict[str, Any]]:
        """Retrieve relevant chunks for a query.

        Args:
            query: Natural-language query string.
            n_results: Maximum number of results to return.
            where: Optional ChromaDB metadata filter.
            max_distance: Discard results with cosine distance above this.

        Returns:
            List of dicts with ``content``, ``metadata``, and ``distance`` keys.
        """
        query_embedding = self.embed([query])[0]

        kwargs: dict[str, Any] = {
            "query_embeddings": [query_embedding],
            "n_results": n_results,
        }
        if where:
            kwargs["where"] = where

        results = self.collection.query(**kwargs)

        retrieved: list[dict[str, Any]] = []
        if not results["documents"] or not results["documents"][0]:
            return retrieved

        for i in range(len(results["documents"][0])):
            distance = results["distances"][0][i]
            if distance <= max_distance:
                retrieved.append(
                    {
                        "content": results["documents"][0][i],
                        "metadata": results["metadatas"][0][i],
                        "distance": distance,
                    }
                )
        return retrieved

    def count(self) -> int:
        """Return the total number of chunks in the collection."""
        return self.collection.count()

    def delete_source(self, source: str) -> None:
        """Delete all chunks from a given source."""
        self.collection.delete(where={"source": source})

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _chunk_text(
        self,
        text: str,
        chunk_size: int = 512,
        overlap: int = 64,
    ) -> list[str]:
        """Split text into overlapping chunks by sentences."""
        sentences = re.split(r"(?<=[.!?])\s+", text)
        chunks: list[str] = []
        current_chunk: list[str] = []
        current_len = 0

        for sentence in sentences:
            slen = len(sentence.split())
            if current_len + slen > chunk_size and current_chunk:
                chunks.append(" ".join(current_chunk))
                # Keep overlap
                overlap_words: list[str] = []
                overlap_len = 0
                for s in reversed(current_chunk):
                    wlen = len(s.split())
                    if overlap_len + wlen > overlap:
                        break
                    overlap_words.insert(0, s)
                    overlap_len += wlen
                current_chunk = overlap_words
                current_len = overlap_len
            current_chunk.append(sentence)
            current_len += slen

        if current_chunk:
            chunks.append(" ".join(current_chunk))

        return chunks

    @staticmethod
    def _extract_pdf(path: Path) -> str:
        """Extract text from a PDF file."""
        try:
            import pymupdf

            doc = pymupdf.open(str(path))
            return "\n".join(page.get_text() for page in doc)
        except ImportError:
            return ""
