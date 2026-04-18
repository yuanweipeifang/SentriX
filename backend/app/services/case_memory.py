from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List

from ..domain.models import IOC, Incident


class LocalCaseMemory:
    """Local JSONL-backed case memory for historical decisions and corrections."""

    def __init__(self, storage_file: str | None = None) -> None:
        default_file = Path(__file__).resolve().parents[2] / "data" / "case_memory" / "cases.jsonl"
        self.storage_file = Path(storage_file) if storage_file else default_file
        self.storage_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.storage_file.exists():
            self.storage_file.write_text("", encoding="utf-8")

    def stats(self) -> Dict[str, Any]:
        rows = self._load_all()
        by_label: Dict[str, int] = {}
        for row in rows:
            label = str(row.get("effective_label", row.get("label", "unknown")))
            by_label[label] = by_label.get(label, 0) + 1
        return {
            "storage_file": str(self.storage_file),
            "total_cases": len(rows),
            "labels": by_label,
        }

    def record_case(self, incident: Incident, result: Dict[str, Any], incident_meta: Dict[str, Any]) -> Dict[str, Any]:
        rows = self._load_all()
        fingerprint = self._fingerprint(incident)
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        rag = result.get("rag", {}) or {}
        response = result.get("response", {}) or {}
        audit = result.get("audit", {}) or {}
        confidence = result.get("confidence_model", {}) or {}
        existing = next((row for row in rows if row.get("fingerprint") == fingerprint), None)
        existing = existing or {}
        payload = {
            "case_id": existing.get("case_id") if existing else f"case-{fingerprint[:12]}",
            "fingerprint": fingerprint,
            "created_at": existing.get("created_at", now) if existing else now,
            "updated_at": now,
            "event_summary": incident.event_summary,
            "ioc": incident.ioc.__dict__,
            "affected_assets": list(incident.affected_assets or []),
            "raw_logs_preview": list((incident.raw_logs or [])[:3]),
            "source": incident_meta.get("source", "unknown"),
            "source_ref": incident_meta.get("path", incident_meta.get("dataset_file", "")),
            "row_index": incident_meta.get("row_index"),
            "dataset_index": incident_meta.get("dataset_index"),
            "label": self._derive_label(result),
            "effective_label": existing.get("effective_label", self._derive_label(result)) if existing else self._derive_label(result),
            "manual_correction": existing.get("manual_correction", {}) if existing else {},
            "top_threat": self._top_threat(result),
            "best_action": (response.get("best_action", {}) or {}).get("action_name", ""),
            "audit_result": audit.get("audit_result", "unknown"),
            "execution_allowed": bool(result.get("execution_allowed", False)),
            "confidence_model": confidence,
            "matched_rule_ids": [str(x.get("rule_id", "")) for x in (rag.get("rule_findings", []) or [])[:8] if str(x.get("rule_id", "")).strip()],
            "downgrade_reasons": list(((rag.get("rag_context", {}) or {}).get("downgrade_reasons", []) or [])),
            "notes": existing.get("notes", ""),
        }
        if existing:
            rows = [payload if row.get("case_id") == payload["case_id"] else row for row in rows]
        else:
            rows.append(payload)
        self._write_all(rows)
        return payload

    def apply_manual_correction(self, case_id: str, label: str, notes: str = "") -> Dict[str, Any]:
        rows = self._load_all()
        for row in rows:
            if row.get("case_id") != case_id:
                continue
            row["manual_correction"] = {
                "label": label,
                "notes": notes,
                "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
            row["effective_label"] = label
            row["notes"] = notes
            row["updated_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            self._write_all(rows)
            return row
        raise KeyError(f"case_id not found: {case_id}")

    def search_similar(self, incident: Incident, limit: int = 3) -> List[Dict[str, Any]]:
        rows = self._load_all()
        query_terms = self._query_terms(incident)
        out: List[Dict[str, Any]] = []
        for row in rows:
            row_terms = set(self._query_terms_from_case(row))
            overlap = len(query_terms.intersection(row_terms))
            if overlap <= 0:
                continue
            out.append(
                {
                    "case_id": row.get("case_id", ""),
                    "score": overlap,
                    "event_summary": row.get("event_summary", "")[:180],
                    "effective_label": row.get("effective_label", row.get("label", "unknown")),
                    "top_threat": row.get("top_threat", ""),
                    "best_action": row.get("best_action", ""),
                    "matched_rule_ids": row.get("matched_rule_ids", []),
                    "downgrade_reasons": row.get("downgrade_reasons", []),
                    "manual_correction": row.get("manual_correction", {}),
                }
            )
        out.sort(key=lambda x: (x.get("score", 0), len(x.get("matched_rule_ids", []))), reverse=True)
        return out[:limit]

    def historical_feedback(self, incident: Incident) -> Dict[str, Any]:
        similar = self.search_similar(incident, limit=5)
        labels = [str(x.get("effective_label", "unknown")) for x in similar]
        benign_like = sum(1 for x in labels if x in {"benign", "false_positive"})
        malicious_like = sum(1 for x in labels if x in {"malicious", "confirmed_attack"})
        return {
            "similar_cases": similar,
            "benign_like_count": benign_like,
            "malicious_like_count": malicious_like,
            "has_false_positive_pattern": benign_like > 0 and benign_like >= malicious_like,
        }

    def _load_all(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        if not self.storage_file.exists():
            return rows
        for line in self.storage_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
        return rows

    def _write_all(self, rows: List[Dict[str, Any]]) -> None:
        content = "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows)
        if content:
            content += "\n"
        self.storage_file.write_text(content, encoding="utf-8")

    @staticmethod
    def _fingerprint(incident: Incident) -> str:
        blob = json.dumps(
            {
                "summary": incident.event_summary,
                "ioc": incident.ioc.__dict__,
                "assets": incident.affected_assets,
                "logs": (incident.raw_logs or [])[:5],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha1(blob.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def _derive_label(result: Dict[str, Any]) -> str:
        audit_result = str((result.get("audit", {}) or {}).get("audit_result", "unknown")).lower()
        detection = float((result.get("confidence_model", {}) or {}).get("detection_confidence", 0.0))
        if audit_result == "pass" and detection >= 0.75:
            return "malicious"
        if audit_result == "fail" and detection < 0.5:
            return "benign"
        return "needs_review"

    @staticmethod
    def _top_threat(result: Dict[str, Any]) -> str:
        layers = result.get("agent_layers", {}) or {}
        prioritized = layers.get("prioritized_threats", []) or []
        if prioritized:
            return str(prioritized[0].get("threat", ""))
        return str((result.get("incident", {}) or {}).get("event_summary", ""))[:120]

    @staticmethod
    def _query_terms(incident: Incident) -> set[str]:
        parts = [
            incident.event_summary,
            *incident.affected_assets,
            *incident.ioc.ip,
            *incident.ioc.domain,
            *incident.ioc.cve,
            *incident.ioc.process,
        ]
        tokens = set()
        for part in parts:
            text = str(part).lower()
            for token in re.split(r"[^a-z0-9_.:-]+", text):
                if len(token) >= 4:
                    tokens.add(token)
        return tokens

    @staticmethod
    def _query_terms_from_case(case: Dict[str, Any]) -> List[str]:
        incident_like = Incident(
            event_summary=str(case.get("event_summary", "")),
            ioc=IOC(**(case.get("ioc", {}) or {})),
            affected_assets=list(case.get("affected_assets", []) or []),
            raw_logs=[],
            timestamp="",
        )
        return list(LocalCaseMemory._query_terms(incident_like))
