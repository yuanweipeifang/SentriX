from __future__ import annotations

import re
from typing import Any, Dict, List

from ..domain.models import Incident, ThreatIntel


class RuleJudgementEngine:
    """Rule-only incident judgement: generate/mount rules then match event evidence directly."""

    def evaluate(
        self,
        incident: Incident,
        intel: ThreatIntel,
        generated_rules: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        rules = self._collect_rules(intel=intel, generated_rules=generated_rules or {})
        haystack = self._build_haystack(incident)

        matched: List[Dict[str, Any]] = []
        for rule in rules:
            match_info = self._match_rule(rule, haystack)
            if not match_info["matched"]:
                continue
            matched.append(
                {
                    "rule_id": rule.get("rule_id", ""),
                    "rule_type": rule.get("rule_type", "custom"),
                    "pattern": rule.get("pattern", ""),
                    "source": rule.get("source", "rule_store"),
                    "severity": float(rule.get("severity", 0.5)),
                    "confidence": float(rule.get("confidence", 0.6)),
                    "match_score": match_info["match_score"],
                    "evidence_hits": match_info["hits"],
                    "ttp": rule.get("ttp", "Unknown"),
                }
            )

        matched.sort(
            key=lambda x: (
                float(x.get("match_score", 0.0)),
                float(x.get("severity", 0.0)) * float(x.get("confidence", 0.0)),
            ),
            reverse=True,
        )

        decision, audit_result, execution_allowed = self._decide(matched)

        return {
            "mode": "rule_only",
            "decision": decision,
            "audit_result": audit_result,
            "execution_allowed": execution_allowed,
            "matched_rule_count": len(matched),
            "total_rule_count": len(rules),
            "top_matches": matched[:5],
            "matched_rules": matched,
        }

    @staticmethod
    def _collect_rules(intel: ThreatIntel, generated_rules: Dict[str, Any]) -> List[Dict[str, Any]]:
        rules: List[Dict[str, Any]] = []
        seen = set()

        for row in intel.rule_findings or []:
            rule_id = str(row.get("rule_id", "")).strip()
            if not rule_id or rule_id in seen:
                continue
            seen.add(rule_id)
            rules.append(
                {
                    "rule_id": rule_id,
                    "rule_type": row.get("rule_type", "custom"),
                    "pattern": str(row.get("pattern", "")),
                    "severity": float(row.get("severity", 0.5)),
                    "confidence": float(row.get("confidence", 0.6)),
                    "ttp": row.get("ttp", "Unknown"),
                    "source": row.get("source", "rag_rule"),
                }
            )

        for item in generated_rules.get("results", []) or []:
            rule = item.get("best_rule", {}) or {}
            rule_id = str(rule.get("rule_id", "")).strip()
            if not rule_id or rule_id in seen:
                continue
            seen.add(rule_id)
            rules.append(
                {
                    "rule_id": rule_id,
                    "rule_type": rule.get("rule_type", "sigma"),
                    "pattern": str(rule.get("pattern", "")),
                    "severity": float(rule.get("severity", 0.6)),
                    "confidence": float(rule.get("confidence", 0.6)),
                    "ttp": rule.get("ttp", "Unknown"),
                    "source": rule.get("source", "generated_rule"),
                }
            )

        return rules

    @staticmethod
    def _build_haystack(incident: Incident) -> str:
        ioc = incident.ioc
        parts = [
            incident.event_summary,
            *incident.raw_logs,
            *(incident.affected_assets or []),
            *(ioc.ip or []),
            *(ioc.domain or []),
            *(ioc.cve or []),
            *(ioc.process or []),
        ]
        return "\n".join(str(x) for x in parts).lower()

    @staticmethod
    def _match_rule(rule: Dict[str, Any], haystack: str) -> Dict[str, Any]:
        pattern = str(rule.get("pattern", "")).strip().lower()
        if not pattern:
            return {"matched": False, "match_score": 0.0, "hits": []}

        hits: List[str] = []
        if pattern in haystack:
            hits.append(pattern)

        tokens = [x for x in re.split(r"[^a-zA-Z0-9_\-./]+", pattern) if len(x) >= 4]
        token_hits = [token for token in tokens if token in haystack]
        hits.extend(token_hits)

        unique_hits = list(dict.fromkeys(hits))
        if not unique_hits:
            return {"matched": False, "match_score": 0.0, "hits": []}

        density = len(unique_hits) / max(1, len(tokens) if tokens else 1)
        score = min(1.0, 0.4 + 0.6 * density)
        return {"matched": True, "match_score": round(score, 4), "hits": unique_hits[:8]}

    @staticmethod
    def _decide(matched_rules: List[Dict[str, Any]]) -> tuple[str, str, bool]:
        if not matched_rules:
            return "clean", "pass", True

        top = matched_rules[0]
        top_risk = float(top.get("severity", 0.0)) * float(top.get("confidence", 0.0))
        if top_risk >= 0.7:
            return "malicious", "fail", False
        if top_risk >= 0.35:
            return "suspicious", "warning", False
        return "low_risk", "pass", True
