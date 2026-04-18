from __future__ import annotations

import json
import math
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List


@dataclass
class RAGDocument:
    doc_type: str
    text_key: str
    title: str
    content: str
    metadata: Dict[str, Any]
    score_hint: float = 0.0
    content_vector: List[float] | None = None


class SQLiteRAGStore:
    VECTOR_DIM = 256

    def __init__(self, db_path: str, embedder: Callable[[List[str]], List[List[float]] | None] | None = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.embedder = embedder

    def initialize(self) -> None:
        with self._managed_connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rag_documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    doc_type TEXT NOT NULL,
                    text_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    content_vector_json TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT NOT NULL,
                    score_hint REAL NOT NULL DEFAULT 0.0,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._ensure_column_exists(conn, "rag_documents", "content_vector_json", "TEXT NOT NULL DEFAULT '[]'")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rag_doc_type ON rag_documents(doc_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rag_text_key ON rag_documents(text_key)")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_rag_doc ON rag_documents(doc_type, text_key)")

    def reindex(self, documents: List[RAGDocument]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._managed_connect() as conn:
            conn.execute("DELETE FROM rag_documents")
            doc_texts = [f"{doc.title} {doc.content}" for doc in documents]
            vectors = self._embed_texts(doc_texts)
            for doc in documents:
                vector = doc.content_vector if doc.content_vector is not None else vectors.pop(0)
                conn.execute(
                    """
                    INSERT INTO rag_documents (
                        doc_type, text_key, title, content, content_vector_json, metadata_json, score_hint, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        doc.doc_type,
                        doc.text_key,
                        doc.title,
                        doc.content,
                        json.dumps(vector, ensure_ascii=False),
                        json.dumps(doc.metadata, ensure_ascii=False),
                        float(doc.score_hint),
                        now,
                    ),
                )
        return self.stats()

    def stats(self) -> Dict[str, Any]:
        with self._managed_connect() as conn:
            total = conn.execute("SELECT COUNT(1) FROM rag_documents").fetchone()[0]
            by_type_rows = conn.execute(
                "SELECT doc_type, COUNT(1) as cnt FROM rag_documents GROUP BY doc_type ORDER BY doc_type"
            ).fetchall()
        return {
            "db_path": str(self.db_path),
            "total_docs": int(total),
            "by_type": {str(row[0]): int(row[1]) for row in by_type_rows},
        }

    def query(self, query_terms: List[str], top_k: int = 10) -> List[Dict[str, Any]]:
        terms = [t.strip().lower() for t in query_terms if t and t.strip()]
        if not terms:
            return []
        exact_terms = list(dict.fromkeys(terms))[:20]
        like_terms = [f"%{t}%" for t in exact_terms[:10]]
        query_vector = self._embed_texts([" ".join(exact_terms)])[0]

        scored: Dict[int, Dict[str, Any]] = {}
        with self._managed_connect() as conn:
            placeholders = ",".join(["?"] * len(exact_terms))
            exact_rows = conn.execute(
                f"""
                SELECT id, doc_type, text_key, title, content, content_vector_json, metadata_json, score_hint
                FROM rag_documents
                WHERE lower(text_key) IN ({placeholders})
                """,
                exact_terms,
            ).fetchall()
            for row in exact_rows:
                scored[row[0]] = self._to_row_payload(row, bonus=2.0)

            if like_terms:
                like_clause = " OR ".join(["lower(title) LIKE ? OR lower(content) LIKE ?"] * len(like_terms))
                like_params: List[str] = []
                for x in like_terms:
                    like_params.extend([x, x])
                fuzzy_rows = conn.execute(
                    f"""
                    SELECT id, doc_type, text_key, title, content, content_vector_json, metadata_json, score_hint
                    FROM rag_documents
                    WHERE {like_clause}
                    LIMIT 600
                    """,
                    like_params,
                ).fetchall()
                for row in fuzzy_rows:
                    payload = self._to_row_payload(row, bonus=0.5)
                    current = scored.get(row[0])
                    if not current or payload["score"] > current["score"]:
                        scored[row[0]] = payload

            # Vector retrieval branch: semantic-like nearest neighbors over stored vectors.
            vector_rows = conn.execute(
                """
                SELECT id, doc_type, text_key, title, content, content_vector_json, metadata_json, score_hint
                FROM rag_documents
                LIMIT 1500
                """
            ).fetchall()
            for row in vector_rows:
                payload = self._to_row_payload(row, bonus=0.0)
                vector_sim = self._cosine_similarity(query_vector, payload.get("content_vector", []))
                if vector_sim <= 0:
                    continue
                payload["score"] = round(payload["score"] + vector_sim * 1.35, 4)
                payload["vector_similarity"] = round(vector_sim, 4)
                current = scored.get(payload["id"])
                if not current or payload["score"] > current["score"]:
                    scored[payload["id"]] = payload

        ranked = sorted(scored.values(), key=lambda x: x["score"], reverse=True)
        return ranked[: max(1, top_k)]

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _managed_connect(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _to_row_payload(row: sqlite3.Row | tuple, bonus: float) -> Dict[str, Any]:
        metadata = {}
        content_vector: List[float] = []
        try:
            if not isinstance(row, sqlite3.Row):
                if len(row) >= 8:
                    content_vector = json.loads(row[5]) if row[5] else []
                    metadata = json.loads(row[6]) if row[6] else {}
                else:
                    metadata = json.loads(row[5]) if row[5] else {}
            else:
                if "content_vector_json" in row.keys():
                    content_vector = json.loads(row["content_vector_json"] or "[]")
                metadata = json.loads(row["metadata_json"] or "{}")
        except Exception:
            metadata = {}
            content_vector = []
        if not isinstance(row, sqlite3.Row):
            score_idx = 7 if len(row) >= 8 else 6
            score_hint = float(row[score_idx])
        else:
            score_hint = float(row["score_hint"])
        return {
            "id": int(row[0] if not isinstance(row, sqlite3.Row) else row["id"]),
            "doc_type": str(row[1] if not isinstance(row, sqlite3.Row) else row["doc_type"]),
            "text_key": str(row[2] if not isinstance(row, sqlite3.Row) else row["text_key"]),
            "title": str(row[3] if not isinstance(row, sqlite3.Row) else row["title"]),
            "content": str(row[4] if not isinstance(row, sqlite3.Row) else row["content"]),
            "content_vector": content_vector,
            "metadata": metadata,
            "score": round(score_hint + bonus, 4),
        }

    @staticmethod
    def _ensure_column_exists(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing = {str(r[1]) for r in rows}
        if column in existing:
            return
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    @classmethod
    def _text_to_vector(cls, text: str) -> List[float]:
        tokens = re.findall(r"[a-zA-Z0-9_\-./]+", (text or "").lower())
        if not tokens:
            return [0.0] * cls.VECTOR_DIM
        vec = [0.0] * cls.VECTOR_DIM
        for token in tokens:
            idx = hash(token) % cls.VECTOR_DIM
            vec[idx] += 1.0
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [round(x / norm, 8) for x in vec]

    def _embed_texts(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        if self.embedder:
            try:
                vectors = self.embedder(texts)
                if isinstance(vectors, list) and len(vectors) == len(texts):
                    normalized: List[List[float]] = []
                    for i, vector in enumerate(vectors):
                        if not isinstance(vector, list) or not vector:
                            normalized.append(self._text_to_vector(texts[i]))
                            continue
                        normalized.append(self._normalize_vector(vector))
                    return normalized
            except Exception:
                pass
        return [self._text_to_vector(text) for text in texts]

    @staticmethod
    def _normalize_vector(vector: List[float]) -> List[float]:
        cleaned = [float(x) for x in vector]
        norm = math.sqrt(sum(x * x for x in cleaned)) or 1.0
        return [round(x / norm, 8) for x in cleaned]

    @staticmethod
    def _cosine_similarity(v1: List[float], v2: List[float]) -> float:
        if not v1 or not v2:
            return 0.0
        size = min(len(v1), len(v2))
        if size == 0:
            return 0.0
        dot = sum(v1[i] * v2[i] for i in range(size))
        n1 = math.sqrt(sum(v1[i] * v1[i] for i in range(size)))
        n2 = math.sqrt(sum(v2[i] * v2[i] for i in range(size)))
        if n1 <= 0 or n2 <= 0:
            return 0.0
        return max(0.0, min(1.0, dot / (n1 * n2)))
