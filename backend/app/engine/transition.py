from __future__ import annotations

import json
from typing import Dict

from ..domain.models import Action, Incident, STATE_DIMENSIONS, ThreatIntel
from ..services.llm_client import LLMClient


_KEYWORD_RULES = {
    "containment": ["isolate", "block", "disable access", "quarantine", "segmentation"],
    "assessment": ["analyze", "inspect", "review logs", "triage", "investigate"],
    "preservation": ["memory dump", "forensic", "disk image", "snapshot"],
    "eviction": ["remove malware", "reset credential", "kill process", "terminate"],
    "hardening": ["patch", "upgrade", "harden", "close port", "mfa"],
    "restoration": ["restore", "restart", "recover", "rollback"],
}


def predict_state_delta(
    action: Action,
    incident: Incident,
    intel: ThreatIntel,
    llm_client: LLMClient | None = None,
) -> Dict[str, float]:
    """Predict action->state delta with optional LLM and deterministic rule correction."""
    delta = _rule_based_delta(action)
    if llm_client:
        llm_delta = _llm_delta(action, incident, intel, llm_client)
        if llm_delta:
            for dim in STATE_DIMENSIONS:
                delta[dim] = max(delta[dim], llm_delta.get(dim, 0.0))
    # Final safety clamp.
    return {dim: round(max(0.0, min(0.6, float(delta.get(dim, 0.0)))), 4) for dim in STATE_DIMENSIONS}


def _rule_based_delta(action: Action) -> Dict[str, float]:
    text = f"{action.action_name} {action.description} {action.reasoning}".lower()
    result = {dim: 0.0 for dim in STATE_DIMENSIONS}
    for dim, words in _KEYWORD_RULES.items():
        if any(word in text for word in words):
            result[dim] = max(result[dim], 0.2)
    # Preserve explicit effects if provided by upstream generator.
    for dim in STATE_DIMENSIONS:
        explicit = float(action.effects.get(dim, action.effects.get("recovery", 0.0))) if action.effects else 0.0
        result[dim] = max(result[dim], explicit)
    return result


def _llm_delta(action: Action, incident: Incident, intel: ThreatIntel, llm_client: LLMClient) -> Dict[str, float] | None:
    payload = {
        "action": action.to_dict(),
        "incident": {
            "event_summary": incident.event_summary,
            "ioc": incident.ioc.__dict__,
            "assets": incident.affected_assets,
        },
        "rag": {
            "summary": intel.summary,
            "matched_cves": intel.cve_findings[:5],
            "matched_rules": intel.rule_findings[:5],
        },
        "output_schema": {
            dim: "0~0.6" for dim in STATE_DIMENSIONS
        },
    }
    data = llm_client.generate_json(
        system_prompt=(
            "你是状态转移预测器。请只输出JSON对象，包含6个维度: "
            "containment,assessment,preservation,eviction,hardening,restoration。"
        ),
        user_prompt=json.dumps(payload, ensure_ascii=False),
        temperature=0.1,
    )
    if not isinstance(data, dict):
        return None
    out: Dict[str, float] = {}
    for dim in STATE_DIMENSIONS:
        try:
            out[dim] = float(data.get(dim, 0.0))
        except Exception:
            out[dim] = 0.0
    return out
