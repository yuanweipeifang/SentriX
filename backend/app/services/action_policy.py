from __future__ import annotations

from typing import Dict, List, Set, Tuple

from ..domain.config import ALLOWED_COMMAND_PREFIXES, RESPONSE_STAGES, SUPPORTED_CAPABILITIES
from ..domain.models import Action, Incident, STATE_DIMENSIONS


def sanitize_actions(
    actions: List[Action],
    incident: Incident,
    history_names: Set[str],
    limit: int,
) -> Tuple[List[Action], List[Dict[str, str]]]:
    """
    Apply planning-time legality/consistency checks:
    - context consistency
    - existing asset reference
    - history duplication
    - environment capability boundaries
    """
    output: List[Action] = []
    rejects: List[Dict[str, str]] = []
    seen: Set[str] = set()
    incident_terms = set(
        [
            *(incident.affected_assets or []),
            *(incident.ioc.ip or []),
            *(incident.ioc.domain or []),
            *(incident.ioc.cve or []),
            *(incident.ioc.process or []),
        ]
    )
    normalized_incident_terms = {x.lower() for x in incident_terms}

    for action in actions:
        normalized_name = action.action_name.strip()
        if not normalized_name or normalized_name in history_names or normalized_name in seen:
            rejects.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "reason": "重复动作或空动作，已过滤。",
                }
            )
            continue
        if action.target_stage not in RESPONSE_STAGES:
            rejects.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "reason": f"目标阶段不合法({action.target_stage})，已过滤。",
                }
            )
            continue
        if not action.command.strip() and not action.api_call:
            rejects.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "reason": "缺少命令或API调用，已过滤。",
                }
            )
            continue

        if action.target_assets and any(asset not in incident.affected_assets for asset in action.target_assets):
            rejects.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "reason": "动作引用了incident中不存在的资产，已过滤。",
                }
            )
            continue

        if action.capability_tags and any(tag not in SUPPORTED_CAPABILITIES for tag in action.capability_tags):
            rejects.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "reason": "动作超出环境能力边界，已过滤。",
                }
            )
            continue

        if action.command and not any(action.command.startswith(prefix) for prefix in ALLOWED_COMMAND_PREFIXES):
            rejects.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "reason": "命令不在允许的执行前缀白名单中，已过滤。",
                }
            )
            continue

        context_text = f"{action.action_name} {action.description} {action.reasoning}".lower()
        if normalized_incident_terms and not any(term in context_text for term in normalized_incident_terms):
            rejects.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "reason": "动作与incident上下文不一致，已过滤。",
                }
            )
            continue

        action.action_name = normalized_name
        action.risk_penalty = max(0.0, min(1.0, float(action.risk_penalty)))
        action.estimated_cost = max(0.1, float(action.estimated_cost))
        action.confidence = max(0.0, min(1.0, float(action.confidence)))

        sanitized_effects = {}
        for dim in STATE_DIMENSIONS:
            value = float(action.effects.get(dim, action.effects.get("recovery", 0.0)))
            sanitized_effects[dim] = max(0.0, min(0.6, value))
        action.effects = sanitized_effects

        if not action.has_positive_state_gain():
            rejects.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "reason": "动作不推进任何状态维度，已过滤。",
                }
            )
            continue

        seen.add(action.action_name)
        output.append(action)
        if len(output) >= limit:
            break
    return output, rejects
