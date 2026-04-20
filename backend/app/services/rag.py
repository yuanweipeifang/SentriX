import copy
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
import time
from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple

from ..domain.config import DEFAULT_ASSET_DB, DEFAULT_CVE_DB, DEFAULT_IOC_INTEL, DEFAULT_RULE_DB, ModelConfig
from ..domain.models import Incident, ThreatIntel
from .case_memory import LocalCaseMemory
from .embedding_client import EmbeddingClient
from .ingestion import DataIngestion
from .llm_client import LLMClient
from .rag_store import RAGDocument, SQLiteRAGStore
from .web_search_client import WebSearchClient


class ThreatIntelligenceRetrieval:
    """RAG retrieval + context compression for IOC-driven enrichment."""

    def __init__(
        self,
        cve_db: Dict[str, Dict[str, Any]] | None = None,
        ioc_intel: Dict[str, Dict[str, Any]] | None = None,
        asset_db: Dict[str, Dict[str, Any]] | None = None,
        rule_db: Dict[str, Dict[str, Any]] | None = None,
        model_config: ModelConfig | None = None,
        llm_client: LLMClient | None = None,
    ) -> None:
        self.model_config = model_config or ModelConfig.from_env()
        self.llm_client = llm_client or LLMClient(self.model_config)
        self.cve_db = cve_db or DEFAULT_CVE_DB
        self.ioc_intel = ioc_intel or DEFAULT_IOC_INTEL
        self.asset_db = asset_db or DEFAULT_ASSET_DB
        self.rule_db = rule_db or DEFAULT_RULE_DB
        self.embedding_client = EmbeddingClient(self.model_config)
        self.web_search_client = WebSearchClient(self.model_config)
        self.case_memory = LocalCaseMemory()
        self.rag_store = (
            SQLiteRAGStore(self.model_config.rag_db_path, embedder=self.embedding_client.embed_texts)
            if self.model_config.rag_use_db
            else None
        )
        if self.rag_store:
            self.rag_store.initialize()
            if self.model_config.rag_auto_reindex and self.rag_store.stats().get("total_docs", 0) == 0:
                self.reindex_database()
        self._analysis_cache: Dict[str, Tuple[float, ThreatIntel]] = {}

    def retrieve(self, incident: Incident) -> ThreatIntel:
        cache_key = self._cache_key_for_incident(incident)
        cached = self._cache_get(cache_key)
        if cached is not None:
            cached.rag_context = dict(cached.rag_context or {})
            cached.rag_context["cache_hit"] = True
            return cached

        evidence_counter = 1
        cve_findings: List[Dict[str, Any]] = []
        ioc_findings: List[Dict[str, Any]] = []
        asset_findings: List[Dict[str, Any]] = []
        rule_findings: List[Dict[str, Any]] = []

        if self.rag_store:
            cve_findings, ioc_findings, asset_findings, rule_findings, evidence_counter = self._retrieve_from_db(
                incident=incident,
                evidence_counter=evidence_counter,
            )
        cve_findings, ioc_findings, asset_findings, rule_findings, evidence_counter = self._supplement_from_local_maps(
            incident=incident,
            cve_findings=cve_findings,
            ioc_findings=ioc_findings,
            asset_findings=asset_findings,
            rule_findings=rule_findings,
            evidence_counter=evidence_counter,
        )

        # 本地优先增强：若已命中 RULE-CVE-* 规则，则优先在本地数据库中反推对应 CVE 详情。
        cve_findings, evidence_counter = self._backfill_cves_from_rules(
            cve_findings=cve_findings,
            rule_findings=rule_findings,
            evidence_counter=evidence_counter,
        )

        local_match_count = len(cve_findings) + len(ioc_findings) + len(asset_findings) + len(rule_findings)
        auto_online_on_empty_local = os.getenv("ONLINE_RAG_AUTO_ON_EMPTY_LOCAL", "true").lower() == "true"
        auto_online_on_empty_cve = os.getenv("ONLINE_RAG_AUTO_ON_EMPTY_CVE", "true").lower() == "true"
        force_online = (auto_online_on_empty_local and local_match_count == 0) or (
            auto_online_on_empty_cve and len(cve_findings) == 0
        )

        online_findings = self._retrieve_online_findings_via_langchain(
            incident,
            current_rule_hits=len(rule_findings),
            force_online=force_online,
        )
        if not online_findings:
            online_findings = self._retrieve_online_findings_via_llm(incident, force_online=force_online)
        online_findings = self._deduplicate_and_fuse(online_findings, start_counter=evidence_counter)

        online_cve_findings = self._enrich_cves_from_online(
            incident=incident,
            online_findings=online_findings,
            existing_cves={str(x.get("cve", "")).upper() for x in cve_findings},
            start_counter=evidence_counter + len(online_findings),
            force_online=force_online,
        )
        if online_cve_findings:
            cve_findings.extend(online_cve_findings)

        persist_stats: Dict[str, Any] = {"upserted": 0}
        if self.rag_store and (online_findings or online_cve_findings):
            persist_stats = self._persist_online_findings_to_db(
                online_findings=online_findings,
                cve_findings=online_cve_findings,
            )

        similar_cases = self._retrieve_similar_cases(incident)
        historical_feedback = self.case_memory.historical_feedback(incident)
        recommended_mitigations = self._derive_mitigations(rule_findings, cve_findings)
        asset_constraints = self._derive_asset_constraints(asset_findings)
        rag_context = {
            "threat_summary": "; ".join(
                [
                    f"CVE={len(cve_findings)}",
                    f"IOC={len(ioc_findings) + len(online_findings)}",
                    f"RULE={len(rule_findings)}",
                    f"SIMILAR_CASES={len(similar_cases)}",
                ]
            ),
            "matched_iocs": ioc_findings + online_findings,
            "matched_rules": rule_findings,
            "matched_cves": cve_findings,
            "similar_cases": similar_cases,
            "historical_case_feedback": historical_feedback,
            "recommended_mitigations": recommended_mitigations,
            "asset_constraints": asset_constraints,
            "downgrade_reasons": _collect_risk_downgrade_reasons(incident),
            "downgrade_reason_details": _explain_risk_downgrade_reasons(_collect_risk_downgrade_reasons(incident)),
            "cache_hit": False,
            "local_match_count": local_match_count,
            "online_fallback_forced": force_online,
            "online_trigger_reason": (
                "empty_local" if (auto_online_on_empty_local and local_match_count == 0)
                else ("empty_cve" if (auto_online_on_empty_cve and len(cve_findings) == 0) else "not_forced")
            ),
            "online_findings_count": len(online_findings),
            "online_cve_enriched_count": len(online_cve_findings),
            "online_db_upserted": int(persist_stats.get("upserted", 0) or 0),
        }
        compressed_context = self._compress(cve_findings, ioc_findings, asset_findings, rule_findings, online_findings)
        summary = "RAG检索完成（本地情报）"
        if self.rag_store:
            summary = "RAG检索完成（SQLite数据库检索 + 本地补全 + 规则特征）"
        if online_findings:
            summary = f"{summary} + 在线搜索融合"
        intel = ThreatIntel(
            summary=summary,
            cve_findings=cve_findings,
            ioc_findings=ioc_findings + online_findings,
            asset_findings=asset_findings,
            rule_findings=rule_findings,
            compressed_context=compressed_context,
            rag_context=rag_context,
        )
        self._cache_set(cache_key, intel)
        return intel

    def _cache_key_for_incident(self, incident: Incident) -> str:
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

    def _cache_get(self, key: str) -> ThreatIntel | None:
        row = self._analysis_cache.get(key)
        if not row:
            return None
        expire_at, payload = row
        if expire_at <= time.time():
            self._analysis_cache.pop(key, None)
            return None
        return copy.deepcopy(payload)

    def _cache_set(self, key: str, intel: ThreatIntel) -> None:
        ttl = max(0, int(self.model_config.analysis_cache_ttl_seconds))
        if ttl <= 0:
            return
        self._analysis_cache[key] = (time.time() + ttl, copy.deepcopy(intel))

    def _retrieve_similar_cases(self, incident: Incident) -> List[Dict[str, Any]]:
        case_memory_rows = self.case_memory.search_similar(incident, limit=3)
        dataset_files = [
            Path(__file__).resolve().parents[2] / "dataset" / "incident_examples.json",
            Path(__file__).resolve().parents[2] / "dataset" / "incident_examples_min.json",
        ]
        query_terms = set(self._build_query_terms(incident))
        if not query_terms:
            return []
        candidates: List[Dict[str, Any]] = []
        for file in dataset_files:
            if not file.exists():
                continue
            try:
                payload = json.loads(file.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            instructions = payload.get("instructions", [])
            answers = payload.get("answers", [])
            for idx, text in enumerate(instructions[:200]):
                body = str(text).lower()
                overlap = sum(1 for t in query_terms if t and t in body)
                if overlap <= 0:
                    continue
                candidates.append(
                    {
                        "case_id": f"{file.name}:{idx}",
                        "score": overlap,
                        "instruction_preview": str(text)[:240],
                        "answer_preview": str(answers[idx])[:200] if idx < len(answers) else "",
                    }
                )
        candidates.extend(
            [
                {
                    "case_id": row.get("case_id", ""),
                    "score": row.get("score", 0),
                    "instruction_preview": row.get("event_summary", ""),
                    "answer_preview": f"label={row.get('effective_label', '')}; top_threat={row.get('top_threat', '')}",
                    "source": "case_memory",
                }
                for row in case_memory_rows
            ]
        )
        candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
        return candidates[:5]

    @staticmethod
    def _derive_mitigations(rule_findings: List[Dict[str, Any]], cve_findings: List[Dict[str, Any]]) -> List[str]:
        out: List[str] = []
        for rule in rule_findings[:5]:
            ttp = str(rule.get("ttp", "")).lower()
            if "t1059" in ttp:
                out.append("Restrict script interpreter execution and enforce command-line auditing.")
            if "t1071" in ttp:
                out.append("Apply egress filtering and detect beacon-like outbound traffic.")
        for cve in cve_findings[:5]:
            cid = str(cve.get("cve", "")).upper()
            if cid:
                out.append(f"Patch or mitigate {cid} on affected assets.")
        return list(dict.fromkeys(out))[:8]

    @staticmethod
    def _derive_asset_constraints(asset_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for asset in asset_findings[:10]:
            out.append(
                {
                    "asset": asset.get("asset", ""),
                    "criticality": asset.get("criticality", "low"),
                    "owner": asset.get("owner", ""),
                    "constraint": "high_criticality_requires_change_window"
                    if str(asset.get("criticality", "low")).lower() == "high"
                    else "standard_change",
                }
            )
        return out

    def reindex_database(
        self,
        external_cve_db: Dict[str, Dict[str, Any]] | None = None,
        external_ioc_db: Dict[str, Dict[str, Any]] | None = None,
        external_rule_db: Dict[str, Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        if not self.rag_store:
            return {"enabled": False, "message": "RAG DB disabled"}
        merged_cve_db = dict(self.cve_db)
        merged_ioc_db = dict(self.ioc_intel)
        merged_rule_db = dict(self.rule_db)
        external_count = 0
        external_ioc_count = 0
        external_rule_count = 0
        if external_cve_db:
            for cve_id, payload in external_cve_db.items():
                merged_cve_db[str(cve_id).upper()] = payload
            external_count = len(external_cve_db)
        if external_ioc_db:
            for ioc_key, payload in external_ioc_db.items():
                merged_ioc_db[str(ioc_key).lower()] = payload
            external_ioc_count = len(external_ioc_db)
        if external_rule_db:
            for rule_id, payload in external_rule_db.items():
                merged_rule_db[str(rule_id)] = payload
            external_rule_count = len(external_rule_db)
        docs: List[RAGDocument] = []
        for cve, payload in merged_cve_db.items():
            docs.append(
                RAGDocument(
                    doc_type="cve",
                    text_key=str(cve).upper(),
                    title=f"CVE {str(cve).upper()}",
                    content=(
                        f"CVE={str(cve).upper()} severity={payload.get('severity', 0)} "
                        f"description={payload.get('description', '')} ttp={payload.get('ttp', '')}"
                    ),
                    metadata={
                        "severity": payload.get("severity", 0),
                        "description": payload.get("description", ""),
                        "ttp": payload.get("ttp", ""),
                        "cwe": payload.get("cwe", []) or [],
                        "vuln_alias": payload.get("vuln_alias", str(cve).upper()),
                        "software_versions": payload.get("software_versions", []) or [],
                        "fixed_versions": payload.get("fixed_versions", []) or [],
                        "source_url": payload.get("source_url", f"https://nvd.nist.gov/vuln/detail/{str(cve).upper()}"),
                        "source_type": "sqlite_cve_db",
                    },
                    score_hint=float(payload.get("severity", 0)) / 10.0,
                )
            )
        for ioc, payload in merged_ioc_db.items():
            docs.append(
                RAGDocument(
                    doc_type="ioc",
                    text_key=str(ioc).lower(),
                    title=f"IOC {str(ioc)}",
                    content=f"ioc={ioc} threat={payload.get('threat', '')} confidence={payload.get('confidence', 0)}",
                    metadata={
                        "threat": payload.get("threat", ""),
                        "confidence": payload.get("confidence", 0),
                        "source_url": payload.get("source_url", f"https://example.local/ioc/{ioc}"),
                        "source_type": "sqlite_ioc_db",
                    },
                    score_hint=float(payload.get("confidence", 0)),
                )
            )
        criticality_rank = {"high": 0.95, "medium": 0.65, "low": 0.35}
        for asset, payload in self.asset_db.items():
            criticality = str(payload.get("criticality", "low")).lower()
            docs.append(
                RAGDocument(
                    doc_type="asset",
                    text_key=str(asset).lower(),
                    title=f"Asset {asset}",
                    content=f"asset={asset} criticality={criticality} owner={payload.get('owner', '')}",
                    metadata={
                        "criticality": criticality,
                        "owner": payload.get("owner", ""),
                        "source_url": f"https://example.local/asset/{asset}",
                        "source_type": "sqlite_asset_db",
                    },
                    score_hint=criticality_rank.get(criticality, 0.35),
                )
            )
        for rule_id, payload in merged_rule_db.items():
            rule_type = str(payload.get("rule_type", "custom"))
            title = str(payload.get("title", rule_id))
            pattern = str(payload.get("pattern", ""))
            ttp = str(payload.get("ttp", "Unknown"))
            severity = float(payload.get("severity", 0.5))
            confidence = float(payload.get("confidence", 0.6))
            docs.append(
                RAGDocument(
                    doc_type="rule",
                    text_key=str(rule_id).lower(),
                    title=f"Rule {title}",
                    content=f"rule_id={rule_id} type={rule_type} ttp={ttp} pattern={pattern}",
                    metadata={
                        "rule_id": str(rule_id),
                        "rule_type": rule_type,
                        "pattern": pattern,
                        "ttp": ttp,
                        "severity": severity,
                        "confidence": confidence,
                        "source": str(payload.get("source", "local_rules")),
                        "version": str(payload.get("version", "v1")),
                        "source_url": str(payload.get("source_url", "")),
                        "source_type": "sqlite_rule_db",
                    },
                    score_hint=(severity + confidence) / 2.0,
                )
            )
        stats = self.rag_store.reindex(docs)
        return {
            "enabled": True,
            "external_cve_docs": external_count,
            "total_cve_docs": len(merged_cve_db),
            "external_ioc_docs": external_ioc_count,
            "total_ioc_docs": len(merged_ioc_db),
            "external_rule_docs": external_rule_count,
            "total_rule_docs": len(merged_rule_db),
            **stats,
        }

    def _retrieve_from_db(
        self,
        incident: Incident,
        evidence_counter: int,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], int]:
        if not self.rag_store:
            return [], [], [], [], evidence_counter
        query_terms = self._build_query_terms(incident)
        rows = self.rag_store.query(query_terms=query_terms, top_k=self.model_config.rag_top_k)
        cve_findings: List[Dict[str, Any]] = []
        ioc_findings: List[Dict[str, Any]] = []
        asset_findings: List[Dict[str, Any]] = []
        rule_findings: List[Dict[str, Any]] = []
        explicit_cve_terms = {str(x).upper() for x in (incident.ioc.cve or [])}
        text_blob = f"{incident.event_summary}\n" + "\n".join(incident.raw_logs[:20])
        explicit_cve_terms.update({x.upper() for x in re.findall(r"CVE-\d{4}-\d{4,7}", text_blob, flags=re.IGNORECASE)})
        seen = set()
        for row in rows:
            key = (row.get("doc_type", ""), row.get("text_key", ""))
            if key in seen:
                continue
            seen.add(key)
            meta = row.get("metadata", {}) or {}
            if row.get("doc_type") == "cve":
                cve_key = str(row.get("text_key", "")).upper()
                if explicit_cve_terms and cve_key not in explicit_cve_terms:
                    continue
                if not explicit_cve_terms:
                    continue
                cve_findings.append(
                    {
                        "cve": cve_key,
                        "severity": float(meta.get("severity", 0)),
                        "description": str(meta.get("description", "")),
                        "ttp": str(meta.get("ttp", "")),
                        "cwe": list(meta.get("cwe", []) or []),
                        "vuln_alias": str(meta.get("vuln_alias", cve_key)),
                        "software_versions": list(meta.get("software_versions", []) or []),
                        "fixed_versions": list(meta.get("fixed_versions", []) or []),
                        "evidence_id": f"EVID-{evidence_counter:04d}",
                        "source_url": str(meta.get("source_url", "")),
                        "source_type": str(meta.get("source_type", "sqlite_cve_db")),
                    }
                )
            elif row.get("doc_type") == "ioc":
                ioc_findings.append(
                    {
                        "ioc": str(row.get("text_key", "")),
                        "threat": str(meta.get("threat", "")),
                        "confidence": float(meta.get("confidence", 0.0)),
                        "evidence_id": f"EVID-{evidence_counter:04d}",
                        "source_url": str(meta.get("source_url", "")),
                        "source_type": str(meta.get("source_type", "sqlite_ioc_db")),
                    }
                )
            elif row.get("doc_type") == "asset":
                asset_findings.append(
                    {
                        "asset": str(row.get("text_key", "")),
                        "criticality": str(meta.get("criticality", "low")),
                        "owner": str(meta.get("owner", "")),
                        "evidence_id": f"EVID-{evidence_counter:04d}",
                        "source_url": str(meta.get("source_url", "")),
                        "source_type": str(meta.get("source_type", "sqlite_asset_db")),
                    }
                )
            elif row.get("doc_type") == "rule":
                rule_findings.append(
                    {
                        "rule_id": str(meta.get("rule_id", row.get("text_key", ""))),
                        "rule_type": str(meta.get("rule_type", "custom")),
                        "pattern": str(meta.get("pattern", "")),
                        "ttp": str(meta.get("ttp", "Unknown")),
                        "severity": float(meta.get("severity", 0.5)),
                        "confidence": float(meta.get("confidence", 0.6)),
                        "source": str(meta.get("source", "local_rules")),
                        "version": str(meta.get("version", "v1")),
                        "evidence_id": f"EVID-{evidence_counter:04d}",
                        "source_url": str(meta.get("source_url", "")),
                        "source_type": str(meta.get("source_type", "sqlite_rule_db")),
                    }
                )
            evidence_counter += 1
        return cve_findings, ioc_findings, asset_findings, rule_findings, evidence_counter

    @staticmethod
    def _build_query_terms(incident: Incident) -> List[str]:
        query_terms = [
            *(incident.ioc.cve or []),
            *(incident.ioc.ip or []),
            *(incident.ioc.domain or []),
            *(incident.ioc.process or []),
            *(incident.affected_assets or []),
        ]
        query_terms.extend(re.findall(r"[A-Za-z0-9_\-\.]+", incident.event_summary.lower())[:12])
        for line in incident.raw_logs[:10]:
            query_terms.extend(re.findall(r"[A-Za-z0-9_\-\.]+", str(line).lower())[:6])
        return list(dict.fromkeys([x for x in query_terms if x]))[:40]

    def _supplement_from_local_maps(
        self,
        incident: Incident,
        cve_findings: List[Dict[str, Any]],
        ioc_findings: List[Dict[str, Any]],
        asset_findings: List[Dict[str, Any]],
        rule_findings: List[Dict[str, Any]],
        evidence_counter: int,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], int]:
        existing_cve = {x.get("cve", "").upper() for x in cve_findings}
        for cve in incident.ioc.cve:
            cve_key = str(cve).upper()
            if cve_key in existing_cve:
                continue
            if cve_key in self.cve_db:
                cve_findings.append(
                    {
                        "cve": cve_key,
                        **self.cve_db[cve_key],
                        "evidence_id": f"EVID-{evidence_counter:04d}",
                        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_key}",
                        "source_type": "local_cve_db",
                    }
                )
                evidence_counter += 1

        existing_ioc = {str(x.get("ioc", "")).lower() for x in ioc_findings}
        for ioc in incident.ioc.ip + incident.ioc.domain + incident.ioc.process:
            ioc_key = str(ioc).lower()
            if ioc_key in existing_ioc:
                continue
            if ioc_key in self.ioc_intel:
                ioc_findings.append(
                    {
                        "ioc": ioc_key,
                        **self.ioc_intel[ioc_key],
                        "evidence_id": f"EVID-{evidence_counter:04d}",
                        "source_url": f"https://example.local/ioc/{ioc_key}",
                        "source_type": "local_ioc_db",
                    }
                )
                evidence_counter += 1

        existing_assets = {str(x.get("asset", "")).lower() for x in asset_findings}
        for asset in incident.affected_assets:
            asset_key = str(asset).lower()
            if asset_key in existing_assets:
                continue
            if asset_key in self.asset_db:
                asset_findings.append(
                    {
                        "asset": asset_key,
                        **self.asset_db[asset_key],
                        "evidence_id": f"EVID-{evidence_counter:04d}",
                        "source_url": f"https://example.local/asset/{asset_key}",
                        "source_type": "local_asset_db",
                    }
                )
                evidence_counter += 1
        existing_rules = {str(x.get("rule_id", "")) for x in rule_findings}
        haystack = " ".join([incident.event_summary, *incident.raw_logs]).lower()
        for rule_id, payload in self.rule_db.items():
            if rule_id in existing_rules:
                continue
            pattern = str(payload.get("pattern", "")).lower().strip()
            if not pattern:
                continue
            if pattern in haystack:
                rule_findings.append(
                    {
                        "rule_id": str(rule_id),
                        "rule_type": str(payload.get("rule_type", "custom")),
                        "pattern": str(payload.get("pattern", "")),
                        "ttp": str(payload.get("ttp", "Unknown")),
                        "severity": float(payload.get("severity", 0.5)),
                        "confidence": float(payload.get("confidence", 0.6)),
                        "source": str(payload.get("source", "local_rules")),
                        "version": str(payload.get("version", "v1")),
                        "evidence_id": f"EVID-{evidence_counter:04d}",
                        "source_url": str(payload.get("source_url", "")),
                        "source_type": "local_rule_db",
                    }
                )
                evidence_counter += 1

        return cve_findings, ioc_findings, asset_findings, rule_findings, evidence_counter

    def _backfill_cves_from_rules(
        self,
        cve_findings: List[Dict[str, Any]],
        rule_findings: List[Dict[str, Any]],
        evidence_counter: int,
    ) -> Tuple[List[Dict[str, Any]], int]:
        existing_cve = {str(x.get("cve", "")).upper() for x in cve_findings}
        extracted: List[str] = []
        for row in rule_findings:
            rule_id = str(row.get("rule_id", ""))
            for m in re.findall(r"CVE[_-](\d{4})[_-](\d{4,7})", rule_id, flags=re.IGNORECASE):
                extracted.append(f"CVE-{m[0]}-{m[1]}")
            for m in re.findall(r"\bCVE-(\d{4})-(\d{4,7})\b", str(row.get("pattern", "")), flags=re.IGNORECASE):
                extracted.append(f"CVE-{m[0]}-{m[1]}")

        for cve_id in list(dict.fromkeys([x.upper() for x in extracted])):
            if cve_id in existing_cve:
                continue
            payload = self.cve_db.get(cve_id, {}) or {}
            cve_findings.append(
                {
                    "cve": cve_id,
                    "severity": float(payload.get("severity", 0.0)),
                    "description": str(payload.get("description", "")),
                    "ttp": str(payload.get("ttp", "Unknown")),
                    "cwe": list(payload.get("cwe", []) or []),
                    "vuln_alias": str(payload.get("vuln_alias", cve_id)),
                    "software_versions": list(payload.get("software_versions", []) or []),
                    "fixed_versions": list(payload.get("fixed_versions", []) or []),
                    "evidence_id": f"EVID-{evidence_counter:04d}",
                    "source_url": str(payload.get("source_url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")),
                    "source_type": "local_rule_to_cve_backfill",
                }
            )
            evidence_counter += 1
            existing_cve.add(cve_id)

        return cve_findings, evidence_counter

    def _retrieve_online_findings_via_langchain(
        self,
        incident: Incident,
        current_rule_hits: int,
        force_online: bool = False,
    ) -> List[Dict[str, Any]]:
        if not self.model_config.enable_online_rag and not force_online:
            return []
        if not force_online and current_rule_hits >= max(0, int(self.model_config.online_rag_min_rule_hits)):
            return []
        if not self.web_search_client.enabled(force=force_online):
            return []

        query_terms = self._build_query_terms(incident)
        priority_terms: List[str] = []
        priority_terms.extend([str(x).strip() for x in (incident.ioc.cve or []) if str(x).strip()])
        priority_terms.extend([str(x).strip() for x in (incident.ioc.ip or []) if str(x).strip()])
        priority_terms.extend([str(x).strip() for x in (incident.ioc.domain or []) if str(x).strip()])
        if incident.event_summary.strip():
            priority_terms.append(incident.event_summary.strip()[:160])
        if query_terms:
            priority_terms.append(" ".join(query_terms[:8]))
        search_queries = list(dict.fromkeys(priority_terms))[:1]

        findings: List[Dict[str, Any]] = []
        seen_urls = set()
        for query in search_queries:
            search_rows = self.web_search_client.search(query=query, top_k=2, force=force_online)
            for row in search_rows:
                url = str(row.get("url", "")).strip()
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                title = str(row.get("title", "")).strip()
                snippet = str(row.get("snippet", "")).strip()
                confidence = 0.72 if "cve-" in query.lower() else 0.62
                findings.append(
                    {
                        "query": query,
                        "threat": title or "Online threat intelligence finding",
                        "confidence": confidence,
                        "source_url": url,
                        "snippet": snippet,
                        "source_type": "online_search_via_langchain",
                    }
                )
            if len(findings) >= 4:
                break
        return findings[:4]

    def _retrieve_online_findings_via_llm(self, incident: Incident, force_online: bool = False) -> List[Dict[str, Any]]:
        if not self.model_config.enable_online_rag and not force_online:
            return []
        payload = {
            "incident_summary": incident.event_summary,
            "ioc": incident.ioc.__dict__,
            "affected_assets": incident.affected_assets,
            "request": (
                "请开启在线搜索，返回最多8条高价值情报。"
                "输出JSON: {\"online_findings\":[{\"query\":\"\",\"threat\":\"\",\"confidence\":0~1,"
                "\"source_url\":\"\",\"snippet\":\"\"}]}。"
            ),
        }
        response = self.llm_client.generate_json(
            system_prompt=(
                "你是SOC情报检索代理。使用模型在线搜索功能进行联网检索，"
                "只返回JSON，不要markdown。source_url必须是可追溯URL。"
            ),
            user_prompt=json.dumps(payload, ensure_ascii=False),
            use_online_search=True,
        )
        if not response:
            return []
        findings = response.get("online_findings", [])
        if not isinstance(findings, list):
            return []
        output = []
        for item in findings[:8]:
            if not isinstance(item, dict):
                continue
            output.append(
                {
                    "query": str(item.get("query", "")).strip(),
                    "threat": str(item.get("threat", "")).strip(),
                    "confidence": float(item.get("confidence", 0.6)),
                    "source_url": str(item.get("source_url", "")).strip(),
                    "snippet": str(item.get("snippet", "")).strip(),
                    "source_type": "online_search_via_llm",
                }
            )
        return output

    def _enrich_cves_from_online(
        self,
        incident: Incident,
        online_findings: List[Dict[str, Any]],
        existing_cves: set[str],
        start_counter: int,
        force_online: bool = False,
    ) -> List[Dict[str, Any]]:
        if not online_findings:
            return []
        cve_ids: List[str] = []
        for row in online_findings:
            text = " ".join(
                [
                    str(row.get("ioc", "")),
                    str(row.get("threat", "")),
                    str(row.get("snippet", "")),
                    str(row.get("source_url", "")),
                ]
            )
            for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE):
                cve_ids.append(cve.upper())

        # 从规则ID中补抓 CVE，例如 RULE-CVE-CVE_2021_22941
        for row in (incident.raw_logs or [])[:20]:
            for m in re.findall(r"RULE-CVE-(CVE_\d{4}_\d{4,7})", str(row), flags=re.IGNORECASE):
                cve_ids.append(m.replace("_", "-").upper())

        cve_ids = list(dict.fromkeys([x for x in cve_ids if x and x not in existing_cves]))[:5]
        if not cve_ids:
            return []

        out: List[Dict[str, Any]] = []
        counter = start_counter
        for cve_id in cve_ids:
            detail = self._fetch_cve_detail_via_llm_search(cve_id, force_online=force_online)
            if not detail:
                continue
            out.append(
                {
                    "cve": cve_id,
                    "severity": float(detail.get("severity", 0.0)),
                    "description": str(detail.get("description", "")),
                    "ttp": str(detail.get("ttp", "Unknown")),
                    "cwe": list(detail.get("cwe", []) or []),
                    "vuln_alias": str(detail.get("vuln_alias", cve_id)),
                    "software_versions": list(detail.get("software_versions", []) or []),
                    "fixed_versions": list(detail.get("fixed_versions", []) or []),
                    "evidence_id": f"EVID-{counter:04d}",
                    "source_url": str(detail.get("source_url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")),
                    "source_type": "online_cve_enriched",
                }
            )
            counter += 1
        return out

    def _fetch_cve_detail_via_llm_search(self, cve_id: str, force_online: bool = False) -> Dict[str, Any] | None:
        if not self.model_config.enable_online_rag and not force_online:
            return None
        payload = {
            "cve_id": cve_id,
            "request": (
                "联网检索并返回该CVE结构化信息。"
                "只返回JSON字段: severity, description, ttp, cwe, vuln_alias, software_versions, fixed_versions, source_url。"
                "ttp优先返回ATT&CK技术ID格式，如 T1190 或 T1059.001。"
            ),
        }
        response = self.llm_client.generate_json(
            system_prompt="你是漏洞情报助手。仅返回JSON，不输出解释。",
            user_prompt=json.dumps(payload, ensure_ascii=False),
            use_online_search=True,
        )
        if not isinstance(response, dict):
            return None
        severity = response.get("severity", 0.0)
        try:
            severity = float(severity)
        except Exception:
            severity = 0.0
        cwe = response.get("cwe", [])
        if isinstance(cwe, str):
            cwe = [x.strip() for x in cwe.split(",") if x.strip()]
        if not isinstance(cwe, list):
            cwe = []
        software_versions = response.get("software_versions", [])
        if isinstance(software_versions, str):
            software_versions = [x.strip() for x in software_versions.split(",") if x.strip()]
        if not isinstance(software_versions, list):
            software_versions = []
        fixed_versions = response.get("fixed_versions", [])
        if isinstance(fixed_versions, str):
            fixed_versions = [x.strip() for x in fixed_versions.split(",") if x.strip()]
        if not isinstance(fixed_versions, list):
            fixed_versions = []
        return {
            "severity": severity,
            "description": str(response.get("description", "")),
            "ttp": str(response.get("ttp", "Unknown")),
            "cwe": [str(x).upper() for x in cwe if str(x).strip()],
            "vuln_alias": str(response.get("vuln_alias", cve_id)),
            "software_versions": [str(x) for x in software_versions if str(x).strip()],
            "fixed_versions": [str(x) for x in fixed_versions if str(x).strip()],
            "source_url": str(response.get("source_url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")),
        }

    def _persist_online_findings_to_db(self, online_findings: List[Dict[str, Any]], cve_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not self.rag_store:
            return {"upserted": 0}
        docs: List[RAGDocument] = []

        for row in online_findings:
            text_key_raw = str(row.get("ioc", "")).strip() or str(row.get("source_url", "")).strip()
            if not text_key_raw:
                continue
            text_key = re.sub(r"\s+", "_", text_key_raw.lower())[:240]
            docs.append(
                RAGDocument(
                    doc_type="ioc",
                    text_key=text_key,
                    title=str(row.get("threat", "Online Intel")).strip()[:120],
                    content=str(row.get("snippet", ""))[:1000],
                    metadata={
                        "threat": str(row.get("threat", "")),
                        "confidence": float(row.get("confidence", 0.6)),
                        "source_url": str(row.get("source_url", "")),
                        "source_type": "online_fused",
                        "all_source_urls": list(row.get("all_source_urls", []) or []),
                    },
                    score_hint=float(row.get("confidence", 0.6)),
                )
            )

        for row in cve_findings:
            cve_id = str(row.get("cve", "")).upper().strip()
            if not cve_id:
                continue
            docs.append(
                RAGDocument(
                    doc_type="cve",
                    text_key=cve_id,
                    title=f"CVE {cve_id}",
                    content=(
                        f"CVE={cve_id} severity={row.get('severity', 0)} "
                        f"description={row.get('description', '')} ttp={row.get('ttp', 'Unknown')}"
                    ),
                    metadata={
                        "severity": float(row.get("severity", 0.0)),
                        "description": str(row.get("description", "")),
                        "ttp": str(row.get("ttp", "Unknown")),
                        "cwe": list(row.get("cwe", []) or []),
                        "vuln_alias": str(row.get("vuln_alias", cve_id)),
                        "software_versions": list(row.get("software_versions", []) or []),
                        "fixed_versions": list(row.get("fixed_versions", []) or []),
                        "source_url": str(row.get("source_url", f"https://nvd.nist.gov/vuln/detail/{cve_id}")),
                        "source_type": "online_cve_enriched",
                    },
                    score_hint=max(0.0, min(1.0, float(row.get("severity", 0.0)) / 10.0)),
                )
            )

        if not docs:
            return {"upserted": 0}
        return self.rag_store.upsert_documents(docs)

    def _deduplicate_and_fuse(self, findings: List[Dict[str, Any]], start_counter: int) -> List[Dict[str, Any]]:
        """
        1) 去重：按URL + 标题语义key聚合，移除近重复结果
        2) 融合：对同簇置信度做融合，保留支撑证据URL列表
        """
        if not findings:
            return []

        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            key = self._canonical_key(f)
            buckets.setdefault(key, []).append(f)

        fused: List[Dict[str, Any]] = []
        counter = start_counter
        for _, group in buckets.items():
            group = sorted(group, key=lambda x: len(str(x.get("snippet", ""))), reverse=True)
            representative = group[0]
            confs = [max(0.0, min(1.0, float(x.get("confidence", 0.5)))) for x in group]
            fused_conf = self._fuse_confidence(confs)
            source_urls = [str(x.get("source_url", "")) for x in group if str(x.get("source_url", "")).startswith("http")]
            source_urls = list(dict.fromkeys(source_urls))

            fused.append(
                {
                    "ioc": representative.get("query", ""),
                    "threat": representative.get("threat", ""),
                    "confidence": round(fused_conf, 3),
                    "source_url": source_urls[0] if source_urls else "",
                    "all_source_urls": source_urls,
                    "snippet": representative.get("snippet", ""),
                    "source_type": "online_fused",
                    "support_count": len(group),
                    "evidence_id": f"EVID-{counter:04d}",
                }
            )
            counter += 1
        fused.sort(key=lambda x: (x.get("confidence", 0), x.get("support_count", 0)), reverse=True)
        return fused[:8]

    @staticmethod
    def _canonical_key(finding: Dict[str, Any]) -> str:
        url = str(finding.get("source_url", "")).strip().lower()
        netloc = urlparse(url).netloc
        threat = re.sub(r"\s+", " ", str(finding.get("threat", "")).strip().lower())
        snippet = re.sub(r"\s+", " ", str(finding.get("snippet", "")).strip().lower())[:120]
        if url:
            return f"url::{url}"
        return f"sem::{netloc}::{threat[:120]}::{snippet}"

    @staticmethod
    def _fuse_confidence(confidences: List[float]) -> float:
        """
        置信度融合（独立证据近似）:
        fused = 1 - Π(1-c_i)
        """
        if not confidences:
            return 0.0
        prod = 1.0
        for c in confidences:
            prod *= (1.0 - max(0.0, min(1.0, c)))
        fused = 1.0 - prod
        return max(0.0, min(1.0, fused))

    def _compress(
        self,
        cve_findings: List[Dict[str, Any]],
        ioc_findings: List[Dict[str, Any]],
        asset_findings: List[Dict[str, Any]],
        rule_findings: List[Dict[str, Any]],
        online_findings: List[Dict[str, Any]],
    ) -> str:
        priority = {"high": 3, "medium": 2, "low": 1}
        top_cve = sorted(cve_findings, key=lambda x: x.get("severity", 0), reverse=True)[:2]
        top_ioc = sorted(ioc_findings, key=lambda x: x.get("confidence", 0), reverse=True)[:3]
        top_assets = sorted(
            asset_findings,
            key=lambda x: priority.get(str(x.get("criticality", "low")).lower(), 1),
            reverse=True,
        )[:2]
        top_rules = sorted(
            rule_findings,
            key=lambda x: float(x.get("severity", 0.5)) * 0.7 + float(x.get("confidence", 0.6)) * 0.3,
            reverse=True,
        )[:3]
        top_online = online_findings[:3]
        evidence_refs = self._build_evidence_refs(top_cve, top_ioc, top_assets, top_rules, top_online)

        if self.model_config.rag_use_llm_compression:
            llm_summary = self._compress_with_llm(top_cve, top_ioc, top_assets, top_rules, top_online, evidence_refs)
            if llm_summary:
                return llm_summary

        return (
            f"CVE关键项: {top_cve}. "
            f"IOC关键项: {top_ioc}. "
            f"资产关键项: {top_assets}. "
            f"规则关键项: {top_rules}. "
            f"联网情报: {top_online}. "
            f"证据映射: {evidence_refs}."
        )

    def _compress_with_llm(
        self,
        top_cve: List[Dict[str, Any]],
        top_ioc: List[Dict[str, Any]],
        top_assets: List[Dict[str, Any]],
        top_rules: List[Dict[str, Any]],
        top_online: List[Dict[str, Any]],
        evidence_refs: List[Dict[str, str]],
    ) -> str:
        payload = {
            "cve": top_cve,
            "ioc": top_ioc,
            "assets": top_assets,
            "rules": top_rules,
            "online_intel": top_online,
            "evidence_refs": evidence_refs,
        }
        response = self.llm_client.generate_json(
            system_prompt=(
                "你是威胁情报分析助手。将输入压缩为高信号摘要。"
                "每条关键结论后必须附证据ID（如 [EVID-0003]）。"
                "并在末尾附“EvidenceMap: EVID-xxxx -> URL”。"
                "仅返回JSON对象，字段: compressed_context。"
            ),
            user_prompt=json.dumps(payload, ensure_ascii=False),
        )
        if not response:
            return ""
        return str(response.get("compressed_context", "")).strip()

    @staticmethod
    def _build_evidence_refs(
        top_cve: List[Dict[str, Any]],
        top_ioc: List[Dict[str, Any]],
        top_assets: List[Dict[str, Any]],
        top_rules: List[Dict[str, Any]],
        top_online: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        refs: List[Dict[str, str]] = []
        for item in (top_cve + top_ioc + top_assets + top_rules + top_online):
            evidence_id = str(item.get("evidence_id", "")).strip()
            source_url = str(item.get("source_url", "")).strip()
            if not evidence_id:
                continue
            refs.append({"evidence_id": evidence_id, "url": source_url})
            for i, extra in enumerate(item.get("all_source_urls", []) or []):
                refs.append({"evidence_id": f"{evidence_id}-S{i+1}", "url": str(extra)})
        # 去重
        uniq = []
        seen = set()
        for r in refs:
            key = (r["evidence_id"], r["url"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(r)
        return uniq


def rebuild_rag_database() -> Dict[str, Any]:
    rag = ThreatIntelligenceRetrieval()
    return rag.reindex_database()


def import_cve_json_to_rag(cve_dir: str = "", cve_file: str = "") -> Dict[str, Any]:
    rag = ThreatIntelligenceRetrieval()
    if not rag.rag_store:
        return {"enabled": False, "message": "RAG DB disabled"}

    paths: List[Path] = []
    if cve_file:
        paths.append(Path(cve_file))
    if cve_dir:
        root = Path(cve_dir)
        if root.exists():
            paths.extend(sorted(root.glob("*.json")))
            paths.extend(sorted(root.glob("**/*.json")))
    # De-duplicate and keep existing files only
    unique_paths = []
    seen = set()
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        if p.exists() and p.is_file():
            unique_paths.append(p)

    parsed: Dict[str, Dict[str, Any]] = {}
    failed = []
    for p in unique_paths:
        try:
            payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            row = _parse_single_cve_json(payload)
            if row:
                parsed[row["cve"]] = row
            else:
                failed.append({"file": str(p), "reason": "not_cve_record"})
        except Exception as exc:
            failed.append({"file": str(p), "reason": str(exc)})

    # Keep local rule files when rebuilding from CVE import
    external_rules = _load_rule_files_as_db(_default_rules_dir())
    external_iocs = _load_ioc_files_as_db(_default_ioc_dir())
    reindex_result = rag.reindex_database(
        external_cve_db=parsed,
        external_ioc_db=external_iocs,
        external_rule_db=external_rules,
    )
    return {
        "imported": len(parsed),
        "failed": len(failed),
        "failed_samples": failed[:10],
        "paths_scanned": len(unique_paths),
        "reindex": reindex_result,
    }


def generate_rules_from_cve_to_rag(
    cve_dir: str = "",
    cve_file: str = "",
    max_cves: int = 500,
) -> Dict[str, Any]:
    """Generate deterministic rule documents from CVE knowledge and rebuild RAG DB."""
    rag = ThreatIntelligenceRetrieval()
    if not rag.rag_store:
        return {"enabled": False, "message": "RAG DB disabled"}

    # Reuse existing CVE loader pipeline.
    paths: List[Path] = []
    if cve_file:
        paths.append(Path(cve_file))
    if cve_dir:
        root = Path(cve_dir)
        if root.exists():
            paths.extend(sorted(root.glob("*.json")))
            paths.extend(sorted(root.glob("**/*.json")))
    uniq: List[Path] = []
    seen = set()
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        if p.exists() and p.is_file():
            uniq.append(p)

    parsed_cves: Dict[str, Dict[str, Any]] = {}
    failed: List[Dict[str, str]] = []
    for p in uniq:
        if len(parsed_cves) >= max(1, max_cves):
            break
        try:
            payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            row = _parse_single_cve_json(payload)
            if row:
                parsed_cves[row["cve"]] = row
            else:
                failed.append({"file": str(p), "reason": "not_cve_record"})
        except Exception as exc:
            failed.append({"file": str(p), "reason": str(exc)})

    synthesized_rules = _synthesize_rules_from_cves(parsed_cves)
    local_rules = _load_rule_files_as_db(_default_rules_dir())
    local_iocs = _load_ioc_files_as_db(_default_ioc_dir())

    # Keep both local custom rules and synthesized CVE rules.
    merged_rules = {**local_rules, **synthesized_rules}
    reindex_result = rag.reindex_database(
        external_cve_db=parsed_cves,
        external_ioc_db=local_iocs,
        external_rule_db=merged_rules,
    )
    return {
        "imported_cves": len(parsed_cves),
        "generated_rules": len(synthesized_rules),
        "failed": len(failed),
        "failed_samples": failed[:10],
        "paths_scanned": len(uniq),
        "reindex": reindex_result,
    }


def import_rule_json_to_rag(rule_dir: str = "", rule_file: str = "") -> Dict[str, Any]:
    rag = ThreatIntelligenceRetrieval()
    if not rag.rag_store:
        return {"enabled": False, "message": "RAG DB disabled"}

    parsed_rules, failed, scanned = _load_rule_files(rule_dir=rule_dir, rule_file=rule_file)
    # Keep CVE files when rebuilding from rules import
    external_cve = _load_cve_files_as_db(_default_cve_dir())
    external_iocs = _load_ioc_files_as_db(_default_ioc_dir())
    reindex_result = rag.reindex_database(
        external_cve_db=external_cve,
        external_ioc_db=external_iocs,
        external_rule_db=parsed_rules,
    )
    return {
        "imported_rules": len(parsed_rules),
        "failed": len(failed),
        "failed_samples": failed[:10],
        "paths_scanned": scanned,
        "reindex": reindex_result,
    }


def import_ioc_json_to_rag(ioc_dir: str = "", ioc_file: str = "") -> Dict[str, Any]:
    rag = ThreatIntelligenceRetrieval()
    if not rag.rag_store:
        return {"enabled": False, "message": "RAG DB disabled"}

    parsed_iocs, failed, scanned = _load_ioc_files(ioc_dir=ioc_dir, ioc_file=ioc_file)
    external_cve = _load_cve_files_as_db(_default_cve_dir())
    external_rules = _load_rule_files_as_db(_default_rules_dir())
    reindex_result = rag.reindex_database(
        external_cve_db=external_cve,
        external_ioc_db=parsed_iocs,
        external_rule_db=external_rules,
    )
    return {
        "imported_iocs": len(parsed_iocs),
        "failed": len(failed),
        "failed_samples": failed[:10],
        "paths_scanned": scanned,
        "reindex": reindex_result,
    }


def _parse_single_cve_json(payload: Dict[str, Any]) -> Dict[str, Any] | None:
    cve_id = str(payload.get("cveMetadata", {}).get("cveId", "")).upper().strip()
    if not cve_id.startswith("CVE-"):
        return None

    cna = payload.get("containers", {}).get("cna", {}) or {}
    descriptions = cna.get("descriptions", []) or []
    description = ""
    for item in descriptions:
        if str(item.get("lang", "")).lower() == "en" and item.get("value"):
            description = str(item.get("value", "")).strip()
            break
    if not description and descriptions:
        description = str(descriptions[0].get("value", "")).strip()

    severity = 0.0
    metrics = cna.get("metrics", []) or []
    for item in metrics:
        cvss = item.get("cvssV3_1") or item.get("cvssV3_0")
        if isinstance(cvss, dict) and cvss.get("baseScore") is not None:
            try:
                severity = float(cvss.get("baseScore", 0.0))
                break
            except Exception:
                pass

    if severity <= 0:
        adp_entries = payload.get("containers", {}).get("adp", []) or []
        for adp in adp_entries:
            for item in adp.get("metrics", []) or []:
                cvss = item.get("cvssV3_1") or item.get("cvssV3_0")
                if isinstance(cvss, dict) and cvss.get("baseScore") is not None:
                    try:
                        severity = float(cvss.get("baseScore", 0.0))
                        break
                    except Exception:
                        pass
            if severity > 0:
                break

    ttp = ""
    for ptype in cna.get("problemTypes", []) or []:
        for desc in ptype.get("descriptions", []) or []:
            text = str(desc.get("description", "")).strip()
            if text:
                ttp = text
                break
        if ttp:
            break
    if not ttp:
        ttp = "Unknown"

    source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    refs = cna.get("references", []) or []
    for ref in refs:
        url = str(ref.get("url", "")).strip()
        if url.startswith("http"):
            source_url = url
            break

    cwe_values: List[str] = []
    for ptype in cna.get("problemTypes", []) or []:
        for desc in ptype.get("descriptions", []) or []:
            cwe_id = str(desc.get("cweId", "")).strip().upper()
            if cwe_id.startswith("CWE-"):
                cwe_values.append(cwe_id)
            text = str(desc.get("description", ""))
            for m in re.findall(r"\bCWE-\d+\b", text, flags=re.IGNORECASE):
                cwe_values.append(m.upper())
    cwe_values = list(dict.fromkeys([x for x in cwe_values if x]))

    software_versions: List[str] = []
    fixed_versions: List[str] = []
    for aff in cna.get("affected", []) or []:
        product = str(aff.get("product", "")).strip()
        vendor = str(aff.get("vendor", "")).strip()
        product_prefix = " / ".join([x for x in [vendor, product] if x])
        for ver in aff.get("versions", []) or []:
            version = str(ver.get("version", "")).strip()
            less_than = str(ver.get("lessThan", "")).strip()
            less_equal = str(ver.get("lessThanOrEqual", "")).strip()
            status = str(ver.get("status", "")).strip().lower()
            value = version or less_than or less_equal
            if not value:
                continue
            if product_prefix:
                value = f"{product_prefix}:{value}"
            if status in {"affected", "unknown"}:
                software_versions.append(value)
            if status in {"fixed", "unaffected"}:
                fixed_versions.append(value)

    software_versions = list(dict.fromkeys([x for x in software_versions if x]))[:10]
    fixed_versions = list(dict.fromkeys([x for x in fixed_versions if x]))[:10]

    vuln_alias = str(cna.get("title", "")).strip() or cve_id

    return {
        "cve": cve_id,
        "severity": severity,
        "description": description,
        "ttp": ttp,
        "source_url": source_url,
        "cwe": cwe_values,
        "vuln_alias": vuln_alias,
        "software_versions": software_versions,
        "fixed_versions": fixed_versions,
    }


def _load_cve_files_as_db(cve_dir: str) -> Dict[str, Dict[str, Any]]:
    root = Path(cve_dir)
    if not root.exists():
        return {}
    parsed: Dict[str, Dict[str, Any]] = {}
    for p in sorted(root.glob("**/*.json")):
        try:
            payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            row = _parse_single_cve_json(payload)
            if row:
                parsed[row["cve"]] = row
        except Exception:
            continue
    return parsed


def _synthesize_rules_from_cves(cve_db: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    rules: Dict[str, Dict[str, Any]] = {}
    for cve_id, payload in cve_db.items():
        cve = str(cve_id).upper()
        severity_raw = float(payload.get("severity", 0.0))
        severity = max(0.2, min(1.0, round(severity_raw / 10.0, 3))) if severity_raw > 0 else 0.55
        confidence = max(0.55, min(0.95, round(0.45 + severity * 0.45, 3)))
        desc = str(payload.get("description", ""))
        ttp = str(payload.get("ttp", "Unknown"))

        keywords = _extract_rule_keywords(desc)
        pattern = " | ".join([cve, *keywords[:4]]) if keywords else cve
        rule_id = f"RULE-CVE-{cve.replace('-', '_')}"
        rules[rule_id] = {
            "rule_id": rule_id,
            "rule_type": "behavior",
            "title": f"Auto mitigation signal for {cve}",
            "pattern": pattern,
            "ttp": ttp,
            "severity": severity,
            "confidence": confidence,
            "source": "cve_auto_generated",
            "version": "v1",
            "source_url": str(payload.get("source_url", f"https://nvd.nist.gov/vuln/detail/{cve}")),
        }
    return rules


def _extract_rule_keywords(text: str) -> List[str]:
    tokens = re.findall(r"[a-zA-Z0-9_\-./]+", (text or "").lower())
    stop = {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "allow",
        "allows",
        "via",
        "remote",
        "code",
        "execution",
    }
    out = []
    seen = set()
    for token in tokens:
        if len(token) < 4 or token in stop:
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= 8:
            break
    return out


def _load_ioc_files(ioc_dir: str = "", ioc_file: str = "") -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, str]], int]:
    paths: List[Path] = []
    if ioc_file:
        paths.append(Path(ioc_file))
    if ioc_dir:
        root = Path(ioc_dir)
        if root.exists():
            paths.extend(sorted(root.glob("*.json")))
            paths.extend(sorted(root.glob("**/*.json")))
    uniq: List[Path] = []
    seen = set()
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        if p.exists() and p.is_file():
            uniq.append(p)
    parsed: Dict[str, Dict[str, Any]] = {}
    failed: List[Dict[str, str]] = []
    for p in uniq:
        try:
            payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            rows = _parse_ioc_payload(payload)
            if not rows:
                failed.append({"file": str(p), "reason": "not_ioc_json"})
                continue
            for row in rows:
                parsed[str(row["ioc"]).lower()] = {
                    "threat": str(row.get("threat", "")),
                    "confidence": float(row.get("confidence", 0.6)),
                    "source_url": str(row.get("source_url", "")),
                }
        except Exception as exc:
            failed.append({"file": str(p), "reason": str(exc)})
    return parsed, failed, len(uniq)


def _load_ioc_files_as_db(ioc_dir: str) -> Dict[str, Dict[str, Any]]:
    parsed, _, _ = _load_ioc_files(ioc_dir=ioc_dir)
    return parsed


def _parse_ioc_payload(payload: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if isinstance(payload, dict):
        if isinstance(payload.get("iocs"), list):
            payload = payload["iocs"]
        else:
            # Compatibility shape: {"ip":[...], "domain":[...], "process":[...]}
            for key in ["ip", "domain", "process"]:
                for value in payload.get(key, []) or []:
                    rows.append(
                        {
                            "ioc": str(value),
                            "threat": f"{key}_indicator",
                            "confidence": 0.65,
                            "source_url": "",
                        }
                    )
            return rows
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            if item.get("ioc"):
                rows.append(
                    {
                        "ioc": str(item.get("ioc")),
                        "threat": str(item.get("threat", "external_ioc")),
                        "confidence": float(item.get("confidence", 0.6)),
                        "source_url": str(item.get("source_url", "")),
                    }
                )
                continue
            # Compatibility: {"ip":"1.2.3.4","threat":"..."}
            for key in ["ip", "domain", "process"]:
                if item.get(key):
                    rows.append(
                        {
                            "ioc": str(item.get(key)),
                            "threat": str(item.get("threat", f"{key}_indicator")),
                            "confidence": float(item.get("confidence", 0.6)),
                            "source_url": str(item.get("source_url", "")),
                        }
                    )
    return rows


def _load_rule_files(rule_dir: str = "", rule_file: str = "") -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, str]], int]:
    paths: List[Path] = []
    if rule_file:
        paths.append(Path(rule_file))
    if rule_dir:
        root = Path(rule_dir)
        if root.exists():
            paths.extend(sorted(root.glob("*.json")))
            paths.extend(sorted(root.glob("**/*.json")))
    uniq: List[Path] = []
    seen = set()
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        if p.exists() and p.is_file():
            uniq.append(p)
    parsed: Dict[str, Dict[str, Any]] = {}
    failed: List[Dict[str, str]] = []
    for p in uniq:
        try:
            payload = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            rows = _parse_rule_payload(payload)
            if not rows:
                failed.append({"file": str(p), "reason": "not_rule_json"})
                continue
            for row in rows:
                parsed[str(row["rule_id"])] = row
        except Exception as exc:
            failed.append({"file": str(p), "reason": str(exc)})
    return parsed, failed, len(uniq)


def _load_rule_files_as_db(rule_dir: str) -> Dict[str, Dict[str, Any]]:
    parsed, _, _ = _load_rule_files(rule_dir=rule_dir)
    return parsed


def _parse_rule_payload(payload: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if isinstance(payload, list):
        for item in payload:
            row = _parse_one_rule(item)
            if row:
                rows.append(row)
        return rows
    if isinstance(payload, dict):
        # Sigma-like one-rule object
        one = _parse_one_rule(payload)
        if one:
            return [one]
        # Custom wrapper {"rules":[...]}
        rule_list = payload.get("rules")
        if isinstance(rule_list, list):
            for item in rule_list:
                row = _parse_one_rule(item)
                if row:
                    rows.append(row)
    return rows


def _parse_one_rule(item: Any) -> Dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    # Custom schema
    if item.get("rule_id"):
        return {
            "rule_id": str(item.get("rule_id")),
            "rule_type": str(item.get("rule_type", "custom")),
            "title": str(item.get("title", item.get("rule_id"))),
            "pattern": str(item.get("pattern", "")),
            "ttp": str(item.get("ttp", "Unknown")),
            "severity": float(item.get("severity", 0.5)),
            "confidence": float(item.get("confidence", 0.6)),
            "source": str(item.get("source", "custom_rule_file")),
            "version": str(item.get("version", "v1")),
            "source_url": str(item.get("source_url", "")),
        }
    # Sigma-like
    if item.get("title") and item.get("detection") is not None:
        rule_id = str(item.get("id", item.get("title"))).strip()
        tags = item.get("tags", []) or []
        ttp = "Unknown"
        for tag in tags:
            t = str(tag)
            if t.startswith("attack."):
                ttp = t
                break
        detection = item.get("detection", {})
        pattern = json.dumps(detection, ensure_ascii=False)[:1200]
        level_map = {"critical": 0.95, "high": 0.85, "medium": 0.65, "low": 0.45}
        severity = level_map.get(str(item.get("level", "medium")).lower(), 0.65)
        return {
            "rule_id": rule_id,
            "rule_type": "sigma",
            "title": str(item.get("title", rule_id)),
            "pattern": pattern,
            "ttp": ttp,
            "severity": severity,
            "confidence": 0.75,
            "source": "sigma_rule_file",
            "version": str(item.get("status", "stable")),
            "source_url": "",
        }
    return None


def _default_rules_dir() -> str:
    return str(Path(__file__).resolve().parents[2] / "data" / "rules")


def _default_cve_dir() -> str:
    return str(Path(__file__).resolve().parents[2] / "data" / "cve")


def _default_ioc_dir() -> str:
    return str(Path(__file__).resolve().parents[2] / "data" / "ioc")


def evaluate_csv_with_rules_and_evidence(
    csv_dataset_file: str,
    max_rows: int = 10,
    start_index: int = 0,
) -> Dict[str, Any]:
    ingest = DataIngestion()
    total = ingest.count_csv_rows(csv_dataset_file)
    end_index = min(total, start_index + max(1, max_rows))
    rag = ThreatIntelligenceRetrieval()

    rows = []
    count_by_level = {"high_risk": 0, "suspicious": 0, "low_risk": 0}
    for idx in range(start_index, end_index):
        incident, meta = ingest.load_from_csv_row(csv_dataset_file, idx)
        intel = rag.retrieve(incident)
        verdict = _rule_evidence_verdict(incident, intel)
        level = verdict.get("level", "low_risk")
        count_by_level[level] = count_by_level.get(level, 0) + 1
        rows.append(
            {
                "row_index": idx,
                "event_summary": incident.event_summary,
                "level": level,
                "score": verdict.get("score", 0.0),
                "decision": verdict.get("decision", ""),
                "reasons": verdict.get("reasons", []),
                "evidence_ids": verdict.get("evidence_ids", []),
                "ttp": verdict.get("ttp", []),
                "validated_rule_count": verdict.get("validated_rule_count", 0),
                "evidence_count": {
                    "rule": len(intel.rule_findings),
                    "cve": len(intel.cve_findings),
                    "ioc": len(intel.ioc_findings),
                    "asset": len(intel.asset_findings),
                },
                "source": meta.get("source", "csv_dataset"),
                "risk_flags": verdict.get("risk_flags", []),
            }
        )

    attack_chain_report = _build_attack_chain_report(
        dataset_file=csv_dataset_file,
        rows=rows,
        start_index=start_index,
        end_index=end_index,
    )

    return {
        "dataset_file": csv_dataset_file,
        "start_index": start_index,
        "end_index": end_index,
        "processed_rows": len(rows),
        "verdict_distribution": count_by_level,
        "rows": rows,
        "attack_chain_report": attack_chain_report,
        "db_stats": rag.rag_store.stats() if rag.rag_store else {"enabled": False},
    }


def _rule_evidence_verdict(incident: Incident, intel: ThreatIntel) -> Dict[str, Any]:
    haystack = " ".join([incident.event_summary, *(incident.raw_logs or [])]).lower()
    validated_rules = [r for r in intel.rule_findings if _rule_pattern_hit(str(r.get("pattern", "")), haystack)]
    top_rules = sorted(
        validated_rules,
        key=lambda x: float(x.get("severity", 0.0)) * 0.7 + float(x.get("confidence", 0.0)) * 0.3,
        reverse=True,
    )[:3]
    top_cves = sorted(intel.cve_findings, key=lambda x: float(x.get("severity", 0.0)), reverse=True)[:3]
    top_iocs = sorted(intel.ioc_findings, key=lambda x: float(x.get("confidence", 0.0)), reverse=True)[:5]
    high_assets = [a for a in intel.asset_findings if str(a.get("criticality", "")).lower() == "high"]

    score = 0.0
    score += sum(float(r.get("severity", 0.0)) * float(r.get("confidence", 0.0)) for r in top_rules) * 1.3
    score += sum(float(c.get("severity", 0.0)) / 10.0 for c in top_cves)
    score += sum(float(i.get("confidence", 0.0)) for i in top_iocs) * 0.8
    score += len(high_assets) * 0.4

    risk_flags: List[str] = []
    if _matches_common_normal_traffic(haystack):
        score *= 0.55
        risk_flags.append("normal_traffic_template")
    if _matches_whitelist_url_or_ua(haystack):
        score *= 0.7
        risk_flags.append("whitelist_url_or_ua")
    historical_feedback = ((intel.rag_context or {}).get("historical_case_feedback", {}) or {})
    if historical_feedback.get("has_false_positive_pattern", False):
        score *= 0.65
        risk_flags.append("historical_false_positive_pattern")

    min_evidence = max(1, int(os.getenv("RAG_RULE_MIN_EVIDENCE_COUNT", "2")))
    strong_evidence_count = len(top_rules) + len(top_cves) + min(2, len(top_iocs)) + len(high_assets)
    if strong_evidence_count < min_evidence and score >= 1.8:
        score = min(score, 1.2)
        risk_flags.append("insufficient_evidence")

    score = round(score, 3)

    reasons: List[str] = []
    evidence_ids: List[str] = []
    ttp: List[str] = []
    if top_rules:
        reasons.append(f"命中规则 {top_rules[0].get('rule_id', '')}，可信度与严重度较高")
        ttp = list(dict.fromkeys([str(r.get("ttp", "Unknown")) for r in top_rules if str(r.get("ttp", "")).strip()]))[:3]
    if top_cves:
        reasons.append(f"命中高危CVE {top_cves[0].get('cve', '')}")
    if top_iocs:
        reasons.append(f"命中IOC数量={len(top_iocs)}")
    if high_assets:
        reasons.append(f"涉及高价值资产数量={len(high_assets)}")
    for item in top_rules + top_cves + top_iocs[:2]:
        eid = str(item.get("evidence_id", "")).strip()
        if eid:
            evidence_ids.append(eid)

    if "normal_traffic_template" in risk_flags:
        reasons.append("命中常见正常流量模板，已降低风险评分")
    if "whitelist_url_or_ua" in risk_flags:
        reasons.append("命中URL/UA白名单关键词，已降低风险评分")
    if "insufficient_evidence" in risk_flags:
        reasons.append(f"证据数量不足(min={min_evidence})，暂不升级为高等级")
    if "historical_false_positive_pattern" in risk_flags:
        reasons.append("命中历史误报样本模式，已根据案例库下调风险")

    base_payload = {
        "score": score,
        "reasons": reasons,
        "evidence_ids": evidence_ids,
        "ttp": ttp,
        "validated_rule_count": len(validated_rules),
        "risk_flags": risk_flags,
    }

    if score >= 1.8:
        return {"level": "high_risk", "decision": "建议立即处置并升级告警", **base_payload}
    if score >= 0.75:
        return {"level": "suspicious", "decision": "建议人工复核并持续监控", **base_payload}
    return {"level": "low_risk", "decision": "暂列低风险，保留证据追踪", **base_payload}


def _rule_pattern_hit(pattern: str, haystack: str) -> bool:
    pattern = (pattern or "").strip().lower()
    if not pattern:
        return False
    if pattern in haystack:
        return True

    cve_tokens = re.findall(r"cve-\d{4}-\d{4,7}", pattern, flags=re.IGNORECASE)
    if cve_tokens and not any(cve.lower() in haystack for cve in cve_tokens):
        return False

    tokens = [t for t in re.split(r"[^a-zA-Z0-9_\-./]+", pattern) if len(t) >= 4]
    if not tokens:
        return False
    hit_count = sum(1 for token in dict.fromkeys(tokens) if token in haystack)
    if len(tokens) == 1:
        return hit_count == 1
    return hit_count >= 2 and (hit_count / len(tokens)) >= 0.4


def _matches_whitelist_url_or_ua(haystack: str) -> bool:
    url_keywords = [
        "quantserve.com",
        "today.com",
        "weixin.qq.com",
        "wechat.com",
        "alicdn.com",
        "xa.gov.cn",
    ]
    ua_keywords = [
        "micromessenger client",
        "headlesschrome/76.0.3809.100",
    ]
    return any(k in haystack for k in url_keywords + ua_keywords)


def _matches_common_normal_traffic(haystack: str) -> bool:
    patterns = [
        r"/pixel;.*quantserve",
        r"post\s+/mmtls/",
        r"/daprobe/node_status",
        r"magellan probe",
    ]
    return any(re.search(p, haystack, flags=re.IGNORECASE) for p in patterns)


def _collect_risk_downgrade_reasons(incident: Incident) -> List[str]:
    haystack = " ".join([incident.event_summary, *(incident.raw_logs or [])]).lower()
    reasons: List[str] = []
    if _matches_common_normal_traffic(haystack):
        reasons.append("matched_common_normal_traffic_template")
    if _matches_whitelist_url_or_ua(haystack):
        reasons.append("matched_whitelist_url_or_ua")
    if len((incident.raw_logs or [])) <= 1 and not any(incident.ioc.__dict__.values()):
        reasons.append("low_evidence_volume")
    return reasons


def _explain_risk_downgrade_reasons(reason_codes: List[str]) -> List[Dict[str, str]]:
    mapping = {
        "matched_common_normal_traffic_template": {
            "title": "命中正常流量模板",
            "description": "事件文本与已知常见正常流量模式相似，系统主动降低风险评分。",
            "severity": "low",
        },
        "matched_whitelist_url_or_ua": {
            "title": "命中白名单URL或UA",
            "description": "日志中包含白名单域名、URL或User-Agent特征，可能是合法业务流量。",
            "severity": "low",
        },
        "historical_false_positive_pattern": {
            "title": "命中历史误报模式",
            "description": "本地案例库中存在相似且已被人工修正为误报/正常的历史事件，因此下调当前风险评分。",
            "severity": "medium",
        },
        "low_evidence_volume": {
            "title": "证据量偏低",
            "description": "原始日志和IOC支撑不足，系统避免过度升级判定。",
            "severity": "medium",
        },
    }
    explained: List[Dict[str, str]] = []
    for code in reason_codes:
        base = mapping.get(code, {})
        explained.append(
            {
                "code": code,
                "title": base.get("title", code),
                "description": base.get("description", "系统根据降级策略下调风险等级。"),
                "severity": base.get("severity", "low"),
            }
        )
    return explained


def _build_attack_chain_report(
    dataset_file: str,
    rows: List[Dict[str, Any]],
    start_index: int,
    end_index: int,
) -> Dict[str, Any]:
    chain_nodes: List[Dict[str, Any]] = []
    for row in rows:
        level = str(row.get("level", "low_risk"))
        if level not in {"suspicious", "high_risk"}:
            continue
        node_score = float(row.get("score", 0.0))
        ttp = row.get("ttp", []) or ["Unknown"]
        confidence = round(max(0.1, min(0.99, node_score / 2.5)), 3)
        stage = _infer_attack_stage(ttp, str(row.get("event_summary", "")))
        chain_nodes.append(
            {
                "node_id": f"row-{row.get('row_index', 0)}",
                "row_index": int(row.get("row_index", 0)),
                "stage": stage,
                "ttp": ttp,
                "confidence": confidence,
                "decision": row.get("decision", ""),
                "evidence_ids": row.get("evidence_ids", []),
                "summary": str(row.get("event_summary", ""))[:220],
                "risk_level": level,
            }
        )
    chain_nodes.sort(key=lambda x: x["row_index"])
    report = {
        "dataset_file": dataset_file,
        "start_index": start_index,
        "end_index": end_index,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "chain_node_count": len(chain_nodes),
        "chain": chain_nodes,
    }
    paths = _write_attack_chain_files(report)
    return {**report, "report_files": paths}


def _infer_attack_stage(ttp_list: List[str], event_summary: str) -> str:
    text = f"{' '.join(ttp_list)} {event_summary}".lower()
    if "t1059" in text or "shell_exec" in text or "cmd=" in text:
        return "execution"
    if "t1005" in text or "../" in text:
        return "collection"
    if "t1071" in text or "dns" in text:
        return "command-and-control"
    if "cve-" in text:
        return "initial-access"
    return "reconnaissance"


def _write_attack_chain_files(report: Dict[str, Any]) -> Dict[str, str]:
    logs_dir = Path(__file__).resolve().parents[2] / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    json_path = logs_dir / f"attack_chain_{ts}.json"
    md_path = logs_dir / f"attack_chain_{ts}.md"

    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(_render_attack_chain_markdown(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def _render_attack_chain_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Attack Chain Report",
        "",
        f"- Dataset: {report.get('dataset_file', '')}",
        f"- Range: {report.get('start_index', 0)}..{report.get('end_index', 0)}",
        f"- GeneratedAt: {report.get('generated_at', '')}",
        f"- NodeCount: {report.get('chain_node_count', 0)}",
        "",
        "| Row | Stage | Risk | TTP | Confidence | EvidenceIDs | Summary |",
        "|---|---|---|---|---:|---|---|",
    ]
    for node in report.get("chain", []) or []:
        lines.append(
            "| {row} | {stage} | {risk} | {ttp} | {conf} | {eids} | {summary} |".format(
                row=node.get("row_index", ""),
                stage=node.get("stage", ""),
                risk=node.get("risk_level", ""),
                ttp=", ".join(node.get("ttp", []) or []),
                conf=node.get("confidence", 0.0),
                eids=", ".join(node.get("evidence_ids", []) or []),
                summary=str(node.get("summary", "")).replace("|", " "),
            )
        )
    return "\n".join(lines) + "\n"


def rag_smoke_test(
    input_file: str = "",
    dataset_file: str = "",
    dataset_index: int = 0,
    csv_dataset_file: str = "",
    csv_row_index: int = 0,
) -> Dict[str, Any]:
    ingest = DataIngestion()
    if csv_dataset_file:
        incident, meta = ingest.load_from_csv_row(csv_dataset_file, csv_row_index)
    elif dataset_file:
        incident, meta = ingest.load_from_dataset_json(dataset_file, dataset_index)
    elif input_file:
        incident = ingest.load_from_json(input_file)
        meta = {"source": "json", "path": input_file}
    else:
        raise ValueError("rag_smoke_test requires one of input_file/dataset_file/csv_dataset_file")

    rag = ThreatIntelligenceRetrieval()
    out = rag.retrieve(incident)
    return {
        "input_meta": meta,
        "summary": out.summary,
        "cve_findings_count": len(out.cve_findings),
        "ioc_findings_count": len(out.ioc_findings),
        "asset_findings_count": len(out.asset_findings),
        "rule_findings_count": len(out.rule_findings),
        "compressed_context_preview": out.compressed_context[:500],
        "db_stats": rag.rag_store.stats() if rag.rag_store else {"enabled": False},
    }
