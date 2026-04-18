from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List

from ..domain.config import ModelConfig, RuleGenerationConfig
from ..domain.models import Incident, ThreatIntel
from .llm_client import LLMClient


_DOMESTIC_PROVIDERS = {"qwen", "glm", "deepseek"}


@dataclass
class RuleCandidate:
    candidate_id: str
    temperature: float
    iterations: int
    score: float
    rule: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "temperature": self.temperature,
            "iterations": self.iterations,
            "score": round(self.score, 4),
            "rule": self.rule,
        }


class RuleGenerationEngine:
    """5x5 CVE rule generation: 5 parallel candidates, each up to 5 optimization rounds."""

    def __init__(
        self,
        model_config: ModelConfig,
        config: RuleGenerationConfig,
        llm_client: LLMClient | None = None,
    ) -> None:
        self.model_config = model_config
        self.config = config
        self.llm_client = llm_client or LLMClient(model_config)

    def generate_for_incident(self, incident: Incident, intel: ThreatIntel) -> Dict[str, Any]:
        started = time.perf_counter()
        cve_list = list(incident.ioc.cve or [])
        if not cve_list:
            cve_list = [str(item.get("cve", "")) for item in (intel.cve_findings or []) if item.get("cve")]
        cve_list = [str(x).upper() for x in cve_list if str(x).strip()]

        if not self.config.enabled:
            return {
                "enabled": False,
                "reason": "disabled",
                "provider": self.model_config.provider,
                "results": [],
            }

        if self.config.enforce_domestic_model and self.model_config.provider not in _DOMESTIC_PROVIDERS:
            return {
                "enabled": False,
                "reason": "provider_not_domestic",
                "provider": self.model_config.provider,
                "results": [],
            }

        if not cve_list:
            return {
                "enabled": True,
                "reason": "no_cve",
                "provider": self.model_config.provider,
                "results": [],
            }

        if len(incident.raw_logs or []) < max(0, self.config.min_raw_logs):
            return {
                "enabled": True,
                "reason": "skip_low_log_volume",
                "provider": self.model_config.provider,
                "results": [],
            }

        if len(intel.rule_findings or []) >= max(0, self.config.skip_if_rule_hits_gte):
            top_conf = max([float(x.get("confidence", 0.0)) for x in (intel.rule_findings or [])] or [0.0])
            if top_conf >= self.config.skip_if_confidence_gte:
                return {
                    "enabled": True,
                    "reason": "skip_existing_high_confidence_rules",
                    "provider": self.model_config.provider,
                    "results": [],
                }

        results = []
        budget_ms = max(0, int(self.config.budget_ms))
        for cve_id in cve_list[: max(1, self.config.max_cves_per_incident)]:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            if budget_ms and elapsed_ms >= budget_ms:
                break
            results.append(self._generate_for_single_cve(cve_id=cve_id, incident=incident, intel=intel))

        return {
            "enabled": True,
            "reason": "ok" if results else "skip_budget_exhausted",
            "provider": self.model_config.provider,
            "results": results,
            "budget_ms": budget_ms,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }

    def _generate_for_single_cve(self, cve_id: str, incident: Incident, intel: ThreatIntel) -> Dict[str, Any]:
        temps = self._build_temperature_plan()
        candidates: List[RuleCandidate] = []
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=min(len(temps), self.config.candidate_parallel)) as pool:
            futures = [
                pool.submit(
                    self._build_candidate_chain,
                    cve_id,
                    incident,
                    intel,
                    idx,
                    temp,
                )
                for idx, temp in enumerate(temps)
            ]
            for future in as_completed(futures):
                if self.config.budget_ms and int((time.perf_counter() - started) * 1000) >= self.config.budget_ms:
                    break
                try:
                    candidate = future.result()
                    candidates.append(candidate)
                except Exception:
                    continue
            for future in futures:
                future.cancel()

        candidates.sort(key=lambda x: x.score, reverse=True)
        top_candidates = candidates[: self.config.top_k_keep]
        return {
            "cve_id": cve_id,
            "candidate_count": len(top_candidates),
            "max_iterations": self.config.max_iterations,
            "candidates": [c.to_dict() for c in top_candidates],
            "best_rule": top_candidates[0].rule if top_candidates else {},
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }

    def _build_candidate_chain(
        self,
        cve_id: str,
        incident: Incident,
        intel: ThreatIntel,
        idx: int,
        temperature: float,
    ) -> RuleCandidate:
        candidate_id = f"cand-{idx + 1}"
        rule = self._generate_initial_rule(cve_id, incident, intel, candidate_id, temperature)
        best_rule = dict(rule)
        best_score = self._score_rule(best_rule, incident.raw_logs)
        best_iterations = 1

        for iteration in range(2, self.config.max_iterations + 1):
            improved = self._optimize_rule(
                cve_id=cve_id,
                incident=incident,
                intel=intel,
                rule=best_rule,
                candidate_id=candidate_id,
                temperature=temperature,
                current_score=best_score,
                iteration=iteration,
            )
            score = self._score_rule(improved, incident.raw_logs)
            if score > best_score:
                best_rule = improved
                best_score = score
                best_iterations = iteration
            if best_score >= 0.95:
                break

        best_rule.setdefault("source", "rule_generation_engine")
        best_rule.setdefault("version", f"iter-{best_iterations}")
        best_rule.setdefault("rule_id", f"AUTO-{cve_id}-{candidate_id}")
        return RuleCandidate(
            candidate_id=candidate_id,
            temperature=temperature,
            iterations=best_iterations,
            score=best_score,
            rule=best_rule,
        )

    def _generate_initial_rule(
        self,
        cve_id: str,
        incident: Incident,
        intel: ThreatIntel,
        candidate_id: str,
        temperature: float,
    ) -> Dict[str, Any]:
        payload = {
            "cve_id": cve_id,
            "incident_summary": incident.event_summary,
            "raw_logs": list((incident.raw_logs or [])[:40]),
            "ioc": incident.ioc.__dict__,
            "rag": {
                "summary": intel.summary,
                "rule_findings": (intel.rule_findings or [])[:20],
                "cve_findings": (intel.cve_findings or [])[:10],
            },
            "candidate_id": candidate_id,
        }
        system_prompt = (
            "你是安全规则生成智能体。必须输出JSON对象，字段包括: "
            "rule_id, rule_type, title, pattern, logic, ttp, severity, confidence, rationale。"
            "severity/confidence范围0~1。"
        )
        data = self.llm_client.generate_json(
            system_prompt=system_prompt,
            user_prompt=json.dumps(payload, ensure_ascii=False),
            temperature=temperature,
        )
        return self._normalize_rule(data, cve_id, candidate_id)

    def _optimize_rule(
        self,
        cve_id: str,
        incident: Incident,
        intel: ThreatIntel,
        rule: Dict[str, Any],
        candidate_id: str,
        temperature: float,
        current_score: float,
        iteration: int,
    ) -> Dict[str, Any]:
        payload = {
            "task": "optimize_rule",
            "cve_id": cve_id,
            "candidate_id": candidate_id,
            "iteration": iteration,
            "current_score": round(current_score, 4),
            "current_rule": rule,
            "incident_summary": incident.event_summary,
            "raw_logs": list((incident.raw_logs or [])[:40]),
            "rag_summary": intel.compressed_context[:1800],
        }
        system_prompt = (
            "你是规则优化智能体。输出优化后的JSON对象，字段与输入规则一致。"
            "目标: 提升可检测性、减少误报、保持与CVE语义一致。"
        )
        data = self.llm_client.generate_json(
            system_prompt=system_prompt,
            user_prompt=json.dumps(payload, ensure_ascii=False),
            temperature=temperature,
        )
        if not data:
            return rule
        return self._normalize_rule(data, cve_id, candidate_id, fallback=rule)

    def _normalize_rule(
        self,
        data: Dict[str, Any] | None,
        cve_id: str,
        candidate_id: str,
        fallback: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        base = dict(fallback or {})
        if not isinstance(data, dict):
            data = {}

        normalized = {
            "rule_id": str(data.get("rule_id") or base.get("rule_id") or f"AUTO-{cve_id}-{candidate_id}"),
            "rule_type": str(data.get("rule_type") or base.get("rule_type") or "sigma"),
            "title": str(data.get("title") or base.get("title") or f"Auto rule for {cve_id}"),
            "pattern": str(data.get("pattern") or base.get("pattern") or cve_id),
            "logic": str(data.get("logic") or base.get("logic") or "keyword match"),
            "ttp": str(data.get("ttp") or base.get("ttp") or "attack.t1190"),
            "severity": self._to_unit_float(data.get("severity"), base.get("severity", 0.7)),
            "confidence": self._to_unit_float(data.get("confidence"), base.get("confidence", 0.7)),
            "rationale": str(data.get("rationale") or base.get("rationale") or "Generated from incident evidence."),
        }
        return normalized

    def _score_rule(self, rule: Dict[str, Any], logs: List[str]) -> float:
        severity = self._to_unit_float(rule.get("severity"), 0.5)
        confidence = self._to_unit_float(rule.get("confidence"), 0.5)

        text_blob = "\n".join(logs or [])[:12000].lower()
        tokens = [
            str(rule.get("pattern", "")).lower(),
            str(rule.get("title", "")).lower(),
            str(rule.get("logic", "")).lower(),
        ]
        hit_terms = 0
        for token in tokens:
            for piece in [x for x in re.split(r"[^a-zA-Z0-9_\-./]+", token) if len(x) >= 4]:
                if piece and piece in text_blob:
                    hit_terms += 1
        match_score = min(1.0, hit_terms / 4.0)
        return round(0.45 * confidence + 0.35 * severity + 0.2 * match_score, 4)

    def _build_temperature_plan(self) -> List[float]:
        temps = list(self.config.temperatures or [0.7, 0.75, 0.8, 0.85, 0.9])
        if not temps:
            temps = [0.7, 0.75, 0.8, 0.85, 0.9]
        plan = []
        for idx in range(self.config.candidate_parallel):
            plan.append(float(temps[idx % len(temps)]))
        return plan

    @staticmethod
    def _to_unit_float(value: Any, default: float) -> float:
        try:
            f = float(value)
        except Exception:
            f = float(default)
        return round(max(0.0, min(1.0, f)), 4)
