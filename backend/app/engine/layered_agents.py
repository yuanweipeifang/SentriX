from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List

from ..domain.models import Incident, ThreatIntel


@dataclass
class ProfessionalLayeredAgents:
    """
    Lightweight layered agents that preserve current core pipeline:
    triage -> rag -> planning -> audit.
    """

    def __init__(self) -> None:
        self.cache_ttl_seconds = max(0, int(os.getenv("LAYERED_AGENT_CACHE_TTL_SECONDS", "300")))
        self._cache: Dict[str, tuple[float, Dict[str, Any]]] = {}

    def run(self, incident: Incident, intel: ThreatIntel) -> Dict[str, Any]:
        cache_key = self._cache_key(incident)
        cached = self._cache_get(cache_key)
        if cached is not None:
            cached["cache_hit"] = True
            return cached

        started = time.perf_counter()
        context_profile = self._context_profile(incident)

        t1 = time.perf_counter()
        identified = self._identify_threats(incident, intel, context_profile)
        identify_ms = int((time.perf_counter() - t1) * 1000)

        t2 = time.perf_counter()
        prioritized = self._prioritize_threats(identified, intel)
        prioritize_ms = int((time.perf_counter() - t2) * 1000)

        t3 = time.perf_counter()
        hunt_queries = self._build_hunt_queries(prioritized, incident)
        hunt_ms = int((time.perf_counter() - t3) * 1000)

        result = {
            "enabled": True,
            "context_profile": context_profile,
            "identified_threats": identified,
            "prioritized_threats": prioritized,
            "hunt_queries": hunt_queries,
            "stage_runtime_ms": {
                "identify": identify_ms,
                "analyze": prioritize_ms,
                "hunt": hunt_ms,
            },
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "cache_hit": False,
        }
        self._cache_set(cache_key, result)
        return result

    def _context_profile(self, incident: Incident) -> Dict[str, Any]:
        business_context = os.getenv("BUSINESS_CONTEXT_TEXT", "").strip()
        critical_assets = [a for a in incident.affected_assets if re.search(r"prod|db|core|auth", a, re.IGNORECASE)]
        return {
            "business_context": business_context or "default_soc_context",
            "critical_assets": critical_assets[:8],
            "asset_count": len(incident.affected_assets),
            "ioc_count": len(incident.ioc.ip) + len(incident.ioc.domain) + len(incident.ioc.cve) + len(incident.ioc.process),
        }

    def _identify_threats(
        self,
        incident: Incident,
        intel: ThreatIntel,
        context_profile: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        threats: List[Dict[str, Any]] = []
        for row in intel.rule_findings[:6]:
            threat_text = (
                str(row.get("threat", "")).strip()
                or str(row.get("rule_id", "")).strip()
                or str(row.get("pattern", "")).strip()
                or "rule_match"
            )
            threats.append(
                {
                    "type": "rule_match",
                    "threat": threat_text,
                    "rule_id": row.get("rule_id", ""),
                    "ttp": row.get("ttp", "Unknown"),
                    "severity": float(row.get("severity", 0.0)),
                    "confidence": float(row.get("confidence", 0.0)),
                    "source": "rule_findings",
                }
            )
        for row in intel.cve_findings[:4]:
            threat_text = (
                str(row.get("threat", "")).strip()
                or str(row.get("description", "")).strip()
                or str(row.get("cve", "")).strip()
                or "cve_risk"
            )
            threats.append(
                {
                    "type": "cve_risk",
                    "threat": threat_text,
                    "cve": row.get("cve", ""),
                    "severity": float(row.get("severity", 0.0)),
                    "confidence": float(row.get("confidence", 0.0)),
                    "source": "cve_findings",
                }
            )
        if not threats:
            threats.append(
                {
                    "type": "behavioral_anomaly",
                    "threat": incident.event_summary[:180],
                    "severity": 0.4,
                    "confidence": 0.5,
                    "source": "fallback",
                }
            )

        if context_profile.get("critical_assets"):
            for item in threats:
                item["asset_priority_boost"] = 0.1
        return threats

    def _prioritize_threats(self, identified: List[Dict[str, Any]], intel: ThreatIntel) -> List[Dict[str, Any]]:
        prioritized: List[Dict[str, Any]] = []
        for item in identified:
            severity = float(item.get("severity", 0.0))
            confidence = float(item.get("confidence", 0.0))
            boost = float(item.get("asset_priority_boost", 0.0))
            evidence_bonus = 0.05 if (intel.ioc_findings or intel.asset_findings) else 0.0
            score = round(severity * 0.65 + confidence * 0.35 + boost + evidence_bonus, 4)
            prioritized.append({**item, "priority_score": score})
        prioritized.sort(key=lambda x: float(x.get("priority_score", 0.0)), reverse=True)
        return prioritized[:8]

    def _build_hunt_queries(self, prioritized: List[Dict[str, Any]], incident: Incident) -> List[Dict[str, Any]]:
        queries: List[Dict[str, Any]] = []
        ioc_terms = list(dict.fromkeys([*incident.ioc.ip, *incident.ioc.domain, *incident.ioc.cve, *incident.ioc.process]))
        for item in prioritized[:5]:
            ttp = str(item.get("ttp", ""))
            threat = str(item.get("threat", ""))[:120]
            selected_terms = ioc_terms[:4] if ioc_terms else [threat]
            terms = " OR ".join([f"\"{x}\"" for x in selected_terms])
            stage = self._infer_stage(item)
            templates = self._build_query_templates(selected_terms, stage, ttp or "Unknown", threat)
            queries.append(
                {
                    "stage": stage,
                    "threat": threat,
                    "query_type": "log_search",
                    "query": f"({terms}) AND stage:{stage}",
                    "confidence": min(0.99, max(0.3, float(item.get("priority_score", 0.5)))),
                    "ttp": ttp or "Unknown",
                    "query_terms": selected_terms,
                    "templates": templates,
                }
            )
        return queries

    @staticmethod
    def _infer_stage(item: Dict[str, Any]) -> str:
        text = f"{item.get('threat', '')} {item.get('ttp', '')}".lower()
        if "t1059" in text or "command" in text:
            return "execution"
        if "t1005" in text or "../" in text:
            return "collection"
        if "cve-" in text or "exploit" in text:
            return "initial_access"
        if "dns" in text or "beacon" in text:
            return "command_and_control"
        return "discovery"

    def _build_query_templates(self, terms: List[str], stage: str, ttp: str, threat: str) -> Dict[str, Any]:
        sql_terms = " OR ".join([f"message ILIKE '%{self._sql_escape(term)}%'" for term in terms])
        spl_terms = " OR ".join([f'message="*{self._splunk_escape(term)}*"' for term in terms])
        should_clauses = []
        for term in terms:
            should_clauses.extend(
                [
                    {"match_phrase": {"message": term}},
                    {"match_phrase": {"ioc": term}},
                ]
            )

        sql = (
            "SELECT timestamp, src_ip, dst_ip, message, stage, asset "
            "FROM security_events "
            f"WHERE ({sql_terms}) AND stage = '{self._sql_escape(stage)}' "
            f"ORDER BY timestamp DESC LIMIT 100;"
        )
        elasticsearch_dsl = {
            "size": 100,
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp", "src_ip", "dst_ip", "message", "stage", "asset", "ttp"],
            "query": {
                "bool": {
                    "must": [{"term": {"stage.keyword": stage}}],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                    "filter": [{"term": {"ttp.keyword": ttp}}] if ttp and ttp != "Unknown" else [],
                }
            },
        }
        splunk_spl = (
            'search index=security_events '
            f'({spl_terms}) stage="{self._splunk_escape(stage)}" '
            + (f'ttp="{self._splunk_escape(ttp)}" ' if ttp and ttp != "Unknown" else "")
            + "| table _time src_ip dst_ip stage asset ttp message | sort - _time | head 100"
        )
        return {
            "sql": sql,
            "elasticsearch_dsl": elasticsearch_dsl,
            "splunk_spl": splunk_spl,
            "metadata": {
                "stage": stage,
                "ttp": ttp,
                "threat": threat,
                "term_count": len(terms),
            },
        }

    @staticmethod
    def _sql_escape(value: str) -> str:
        return str(value).replace("'", "''")

    @staticmethod
    def _splunk_escape(value: str) -> str:
        return str(value).replace('"', '\\"')

    def _cache_key(self, incident: Incident) -> str:
        blob = json.dumps(
            {
                "summary": incident.event_summary,
                "ioc": incident.ioc.__dict__,
                "assets": incident.affected_assets[:20],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha1(blob.encode("utf-8", errors="ignore")).hexdigest()

    def _cache_get(self, key: str) -> Dict[str, Any] | None:
        row = self._cache.get(key)
        if not row:
            return None
        expire_at, payload = row
        if expire_at <= time.time():
            self._cache.pop(key, None)
            return None
        return copy.deepcopy(payload)

    def _cache_set(self, key: str, payload: Dict[str, Any]) -> None:
        if self.cache_ttl_seconds <= 0:
            return
        self._cache[key] = (time.time() + self.cache_ttl_seconds, copy.deepcopy(payload))
