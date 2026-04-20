from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, Optional

from ..domain.config import ModelConfig


class LLMClient:
    """
    Lightweight client for model APIs (Qwen/ChatGLM/OpenAI-compatible endpoint).
    If endpoint/api_key is missing, returns None and upstream modules use rule-based fallback.
    """

    def __init__(self, config: Optional[ModelConfig] = None) -> None:
        self.config = config or ModelConfig()
        self._usage_stats = {
            "requests": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }

    def reset_stats(self) -> None:
        self._usage_stats = {
            "requests": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }

    def snapshot_stats(self) -> Dict[str, int]:
        return dict(self._usage_stats)

    def _record_usage(self, payload: Dict[str, Any]) -> None:
        usage = payload.get("usage", {}) if isinstance(payload, dict) else {}
        self._usage_stats["requests"] += 1
        self._usage_stats["prompt_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
        self._usage_stats["completion_tokens"] += int(usage.get("completion_tokens", 0) or 0)
        self._usage_stats["total_tokens"] += int(usage.get("total_tokens", 0) or 0)

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        use_online_search: bool = False,
        temperature: float = 0.2,
    ) -> Dict[str, Any] | None:
        if not self.config.endpoint or not self.config.api_key:
            return None

        body = {
            "model": self.config.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": float(temperature),
        }
        if use_online_search:
            # For Qwen-compatible endpoints, this flag enables built-in search when supported.
            body["enable_search"] = True

        request = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
            self._record_usage(payload)
            content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
            if isinstance(content, list):
                content = "".join(str(x.get("text", "")) for x in content if isinstance(x, dict))
            return json.loads(content) if isinstance(content, str) and content.strip() else None
        except Exception:
            return None

    def generate_text(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
    ) -> str | None:
        if not self.config.endpoint or not self.config.api_key:
            return None

        body = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": float(temperature),
        }

        request = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
            self._record_usage(payload)
            content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
            if isinstance(content, list):
                return "".join(str(x.get("text", "")) for x in content if isinstance(x, dict)).strip()
            if isinstance(content, str):
                return content.strip()
            return None
        except Exception:
            return None
