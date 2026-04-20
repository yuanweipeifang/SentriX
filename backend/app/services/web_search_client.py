from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.request
import warnings
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from urllib.parse import quote_plus
from typing import Any, Callable, Dict, List, Tuple

from ..domain.config import ModelConfig

warnings.filterwarnings(
    "ignore",
    message=r".*duckduckgo_search.*renamed to `ddgs`.*",
    category=RuntimeWarning,
)
warnings.filterwarnings(
    "ignore",
    message=r".*backend='api' is deprecated.*",
    category=UserWarning,
)


class WebSearchClient:
    """Unified online-search adapter with retry, circuit-breaker and cache."""

    def __init__(self, model_config: ModelConfig) -> None:
        self.model_config = model_config
        self.retry_max = max(0, int(os.getenv("WEB_SEARCH_RETRY_MAX", "1")))
        self.circuit_fail_threshold = max(1, int(os.getenv("WEB_SEARCH_CIRCUIT_FAIL_THRESHOLD", "3")))
        self.circuit_open_seconds = max(1, int(os.getenv("WEB_SEARCH_CIRCUIT_OPEN_SECONDS", "60")))
        self.cache_ttl_seconds = max(0, int(os.getenv("WEB_SEARCH_CACHE_TTL_SECONDS", "300")))
        self.request_timeout_seconds = max(
            1, int(os.getenv("WEB_SEARCH_TIMEOUT_SECONDS", str(self.model_config.timeout_seconds)))
        )
        self._cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self._provider_state: Dict[str, Dict[str, float]] = {}

    def enabled(self, force: bool = False) -> bool:
        if not force and not self.model_config.enable_online_rag:
            return False
        if force:
            return any(self._provider_is_enabled(p) for p in self._provider_order())
        provider = self.model_config.web_search_provider.lower()
        if provider == "langchain_duckduckgo":
            return True
        if provider == "duckduckgo":
            return True
        return bool(self.model_config.web_search_endpoint) and bool(self.model_config.web_search_api_key)

    def search(self, query: str, top_k: int | None = None, force: bool = False) -> List[Dict[str, Any]]:
        if not self.enabled(force=force):
            return []
        clean_query = (query or "").strip()
        if not clean_query:
            return []
        limit = max(1, top_k or self.model_config.web_search_top_k)

        cache_key = self._cache_key(clean_query, limit)
        cached = self._cache_get(cache_key)
        if cached:
            return cached[:limit]

        for provider in self._provider_order():
            if not self._provider_is_enabled(provider):
                continue
            if self._provider_is_open(provider):
                continue

            method = self._provider_method(provider)
            if not method:
                continue

            success = False
            results: List[Dict[str, Any]] = []
            for _ in range(self.retry_max + 1):
                rows = self._run_with_timeout(method, clean_query, limit)
                rows = self._normalize_results(rows, source=provider, top_k=limit)
                if rows:
                    results = rows
                    success = True
                    break
            if success:
                self._provider_on_success(provider)
                self._cache_set(cache_key, results)
                return results[:limit]
            self._provider_on_failure(provider)
        return []

    def _provider_order(self) -> List[str]:
        preferred = self.model_config.web_search_provider.lower()
        raw = os.getenv("WEB_SEARCH_PROVIDER_ORDER", "").strip()
        if raw:
            order = [x.strip().lower() for x in raw.split(",") if x.strip()]
            return list(dict.fromkeys(order))
        if preferred == "langchain_duckduckgo":
            return ["langchain_duckduckgo", "duckduckgo", "serper"]
        if preferred == "duckduckgo":
            return ["duckduckgo", "langchain_duckduckgo", "serper"]
        return [preferred, "duckduckgo", "langchain_duckduckgo"]

    def _provider_is_enabled(self, provider: str) -> bool:
        if provider in {"langchain_duckduckgo", "duckduckgo"}:
            return True
        if provider == "serper":
            return bool(self.model_config.web_search_endpoint) and bool(self.model_config.web_search_api_key)
        return False

    def _provider_method(self, provider: str) -> Callable[[str, int], List[Dict[str, Any]]] | None:
        mapping: Dict[str, Callable[[str, int], List[Dict[str, Any]]]] = {
            "langchain_duckduckgo": self._search_langchain_duckduckgo,
            "duckduckgo": self._search_duckduckgo,
            "serper": self._search_serper,
        }
        return mapping.get(provider)

    def _provider_is_open(self, provider: str) -> bool:
        state = self._provider_state.get(provider, {})
        return float(state.get("opened_until", 0.0)) > time.time()

    def _provider_on_failure(self, provider: str) -> None:
        state = self._provider_state.setdefault(provider, {"failures": 0.0, "opened_until": 0.0})
        state["failures"] = float(state.get("failures", 0.0)) + 1.0
        if state["failures"] >= self.circuit_fail_threshold:
            state["opened_until"] = time.time() + self.circuit_open_seconds

    def _provider_on_success(self, provider: str) -> None:
        self._provider_state[provider] = {"failures": 0.0, "opened_until": 0.0}

    def _run_with_timeout(
        self,
        fn: Callable[[str, int], List[Dict[str, Any]]],
        query: str,
        top_k: int,
    ) -> List[Dict[str, Any]]:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(fn, query, top_k)
            try:
                result = future.result(timeout=self.request_timeout_seconds)
                return result if isinstance(result, list) else []
            except FuturesTimeoutError:
                return []
            except Exception:
                return []

    def _cache_key(self, query: str, top_k: int) -> str:
        digest = hashlib.sha1(f"{query}|{top_k}".encode("utf-8", errors="ignore")).hexdigest()
        return digest

    def _cache_get(self, key: str) -> List[Dict[str, Any]]:
        row = self._cache.get(key)
        if not row:
            return []
        expire_at, payload = row
        if expire_at <= time.time():
            self._cache.pop(key, None)
            return []
        return payload

    def _cache_set(self, key: str, payload: List[Dict[str, Any]]) -> None:
        if self.cache_ttl_seconds <= 0:
            return
        self._cache[key] = (time.time() + self.cache_ttl_seconds, payload)

    @staticmethod
    def _normalize_results(rows: List[Dict[str, Any]], source: str, top_k: int) -> List[Dict[str, Any]]:
        output: List[Dict[str, Any]] = []
        seen_urls = set()
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url", row.get("link", ""))).strip()
            title = str(row.get("title", "")).strip()
            snippet = str(row.get("snippet", row.get("body", ""))).strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            output.append({"title": title, "url": url, "snippet": snippet, "source": source})
            if len(output) >= max(1, top_k):
                break
        return output

    def _search_langchain_duckduckgo(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                from langchain_community.utilities import DuckDuckGoSearchAPIWrapper
                wrapper = DuckDuckGoSearchAPIWrapper(max_results=max(1, top_k), backend="auto")
                raw_rows = wrapper.results(query, max_results=max(1, top_k))
                rows = list(raw_rows) if not isinstance(raw_rows, list) else raw_rows
        except Exception:
            return []

        results: List[Dict[str, Any]] = []
        if isinstance(rows, list):
            for row in rows[:top_k]:
                if not isinstance(row, dict):
                    continue
                results.append(
                    {
                        "title": str(row.get("title", "")),
                        "url": str(row.get("link", row.get("url", ""))),
                        "snippet": str(row.get("snippet", row.get("body", ""))),
                        "source": "langchain_duckduckgo",
                    }
                )
        return results

    def _search_serper(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        body = {"q": query, "num": max(1, top_k)}
        request = urllib.request.Request(
            self.model_config.web_search_endpoint,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-API-KEY": self.model_config.web_search_api_key,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.model_config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception:
            return []

        results: List[Dict[str, Any]] = []
        for item in payload.get("organic", [])[:top_k]:
            results.append(
                {
                    "title": item.get("title", ""),
                    "url": item.get("link", ""),
                    "snippet": item.get("snippet", ""),
                    "source": "serper",
                }
            )
        return results

    def _search_duckduckgo(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        encoded = quote_plus(query)
        url = f"https://duckduckgo.com/html/?q={encoded}"
        request = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.model_config.timeout_seconds) as response:
                html = response.read().decode("utf-8", errors="ignore")
        except Exception:
            return []

        links = re.findall(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html, flags=re.IGNORECASE)
        snippets = re.findall(
            r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>|<div[^>]+class="result__snippet"[^>]*>(.*?)</div>',
            html,
            flags=re.IGNORECASE,
        )

        results: List[Dict[str, Any]] = []
        for idx, (href, title_html) in enumerate(links[:top_k]):
            title = re.sub(r"<[^>]+>", "", title_html).strip()
            snippet = ""
            if idx < len(snippets):
                snippet = (snippets[idx][0] or snippets[idx][1] or "").strip()
                snippet = re.sub(r"<[^>]+>", "", snippet)
            results.append(
                {
                    "title": title,
                    "url": href,
                    "snippet": snippet,
                    "source": "duckduckgo",
                }
            )
        return results
