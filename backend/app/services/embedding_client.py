from __future__ import annotations

import json
import time
import urllib.request
from typing import List, Optional

from ..domain.config import ModelConfig


class EmbeddingClient:
    """OpenAI-compatible embedding client for domestic providers when available."""

    def __init__(self, config: ModelConfig) -> None:
        self.config = config
        self._disabled_until = 0.0
        self._failure_count = 0
        self._max_batch_size = 64

    def embed_texts(self, texts: List[str]) -> Optional[List[List[float]]]:
        if not texts:
            return []
        now = time.time()
        if now < self._disabled_until:
            return None
        if not self.config.api_key or not self.config.embedding_endpoint or not self.config.embedding_model_name:
            return None

        all_vectors: List[List[float]] = []
        for idx in range(0, len(texts), self._max_batch_size):
            batch = texts[idx : idx + self._max_batch_size]
            vectors = self._embed_batch(batch)
            if vectors is None:
                self._failure_count += 1
                # Circuit breaker: avoid repeated long waits when endpoint/model is unavailable.
                cooldown = min(120, 10 * self._failure_count)
                self._disabled_until = time.time() + cooldown
                return None
            all_vectors.extend(vectors)

        self._failure_count = 0
        self._disabled_until = 0.0
        return all_vectors

    def _embed_batch(self, texts: List[str]) -> Optional[List[List[float]]]:
        if not texts:
            return []

        body = {
            "model": self.config.embedding_model_name,
            "input": texts,
        }
        request = urllib.request.Request(
            self.config.embedding_endpoint,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=self.config.embedding_timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
            data = payload.get("data", [])
            if not isinstance(data, list):
                return None
            vectors: List[List[float]] = []
            for item in data:
                if not isinstance(item, dict):
                    vectors.append([])
                    continue
                vector = item.get("embedding", [])
                if not isinstance(vector, list):
                    vectors.append([])
                    continue
                vectors.append([float(x) for x in vector])
            if len(vectors) != len(texts):
                return None
            return vectors
        except Exception:
            return None
