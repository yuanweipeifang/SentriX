from typing import Any, Dict, List

from ..domain.models import Incident, STATE_DIMENSIONS, StateVector


class StateEstimator:
    def estimate(self, incident: Incident, rag_context: Dict[str, Any] | None = None) -> StateVector:
        raw = " ".join(incident.raw_logs).lower()
        summary = incident.event_summary.lower()
        text = f"{summary} {raw}"
        rag_context = rag_context or {}

        containment = 0.2 if ("block" in text or "isolat" in text) else 0.05
        assessment = 0.2 if ("ioc" in text or "alert" in text or "anomal" in text) else 0.1
        preservation = 0.2 if ("snapshot" in text or "forensic" in text or "memory dump" in text) else 0.05
        eviction = 0.2 if ("kill process" in text or "quarantine" in text or "remove malware" in text) else 0.05
        hardening = 0.2 if ("patch" in text or "mfa" in text or "segmentation" in text) else 0.05
        restoration = 0.2 if ("service restored" in text or "recovered" in text or "restoration" in text) else 0.05

        if incident.ioc.cve:
            assessment += 0.15
            hardening += 0.1
        if rag_context.get("matched_cves"):
            assessment += 0.08
            hardening += 0.08
        if rag_context.get("matched_rules"):
            containment += 0.06
            eviction += 0.06
        if rag_context.get("similar_cases"):
            assessment += 0.05
        if incident.affected_assets:
            containment += 0.1

        state = StateVector(
            containment=containment,
            assessment=assessment,
            preservation=preservation,
            eviction=eviction,
            hardening=hardening,
            restoration=restoration,
        ).clamp()

        state.explanation = self._build_explanation(state, incident.raw_logs)
        return state

    @staticmethod
    def _build_explanation(state: StateVector, logs: List[str]) -> str:
        strongest = sorted(
            [
                ("containment", state.containment),
                ("assessment", state.assessment),
                ("preservation", state.preservation),
                ("eviction", state.eviction),
                ("hardening", state.hardening),
                ("restoration", state.restoration),
            ],
            key=lambda x: x[1],
            reverse=True,
        )[:2]
        weakest = sorted(
            [(dim, getattr(state, dim)) for dim in STATE_DIMENSIONS],
            key=lambda x: x[1],
        )[:2]
        return (
            f"状态评估基于日志关键词匹配与IOC上下文。当前较高维度为: "
            f"{strongest[0][0]}={strongest[0][1]:.2f}, {strongest[1][0]}={strongest[1][1]:.2f}。"
            f" 当前短板维度为: {weakest[0][0]}, {weakest[1][0]}。已分析日志条数: {len(logs)}。"
        )
