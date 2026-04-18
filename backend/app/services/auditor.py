from __future__ import annotations

from typing import Any, Dict, List

from ..domain.models import ActionScore, Incident, ResponsePlan, StateVector, ThreatIntel


class DecisionAuditor:
    """Audit planning decisions with full traceability for planning/self-validation."""

    def audit(
        self,
        incident: Incident,
        state: StateVector,
        intel: ThreatIntel,
        response_plan: ResponsePlan,
        ranked_actions: List[ActionScore],
        action_filter_audit: List[Dict[str, str]] | None = None,
    ) -> Dict[str, Any]:
        findings: List[Dict[str, str]] = []
        action_filter_audit = action_filter_audit or []
        best = response_plan.best_action

        if not best.command.strip() and not (best.api_call or "").strip():
            findings.append(
                {
                    "severity": "high",
                    "category": "execution",
                    "detail": "best_action 缺少可执行命令或API。",
                    "fix_suggestion": "补充可执行信息后再下发。",
                }
            )

        best_score = ranked_actions[0] if ranked_actions else None
        if best_score and best_score.hallucination_flag:
            findings.append(
                {
                    "severity": "high",
                    "category": "risk",
                    "detail": "best_action 被判定为幻觉动作。",
                    "fix_suggestion": "切换到下一个 validation_passed 动作。",
                }
            )

        if best_score and not best_score.validation_passed:
            findings.append(
                {
                    "severity": "high",
                    "category": "validation",
                    "detail": "best_action 未通过状态推进验证。",
                    "fix_suggestion": "过滤无效动作后重新规划。",
                }
            )

        if action_filter_audit:
            findings.append(
                {
                    "severity": "low",
                    "category": "policy",
                    "detail": f"规划前已过滤动作数={len(action_filter_audit)}。",
                    "fix_suggestion": "可在策略层持续优化动作生成质量。",
                }
            )

        severity_rank = {"high": 3, "medium": 2, "low": 1}
        findings.sort(key=lambda f: severity_rank.get(f["severity"], 0), reverse=True)
        has_high = any(f["severity"] == "high" for f in findings)
        has_medium = any(f["severity"] == "medium" for f in findings)
        audit_result = "fail" if has_high else ("warning" if has_medium else "pass")

        planning_trace = []
        for score in ranked_actions:
            planning_trace.append(
                {
                    "action": score.action.to_dict(),
                    "projected_state": score.projected_state,
                    "rollout_results": [r.to_dict() for r in score.rollout_results],
                    "score": score.score,
                    "hallucination_flag": score.hallucination_flag,
                    "validation_passed": score.validation_passed,
                    "selection_reason": score.reason,
                }
            )

        return {
            "audit_result": audit_result,
            "findings": findings,
            "candidate_actions": [s.action.to_dict() for s in ranked_actions],
            "state_predictions": [
                {"action_id": s.action.action_id, "projected_state": s.projected_state} for s in ranked_actions
            ],
            "rollout_results": [
                {"action_id": s.action.action_id, "rollouts": [r.to_dict() for r in s.rollout_results]}
                for s in ranked_actions
            ],
            "scores": [
                {"action_id": s.action.action_id, "score": s.score, "validation_passed": s.validation_passed}
                for s in ranked_actions
            ],
            "best_action_selection_reason": (
                ranked_actions[0].reason if ranked_actions else "无可用动作"
            ),
            "filtered_actions": action_filter_audit,
            "execution_guardrails": [
                "若 audit_result=fail，禁止自动执行",
                "优先执行 validation_passed 且 hallucination_flag=false 的动作",
                "高风险动作需人工审批",
            ],
            "final_note": (
                f"state_progress={state.average_progress():.3f}; "
                f"incident_assets={len(incident.affected_assets)}; "
                f"rag_context_len={len(intel.compressed_context)}"
            ),
            "planning_trace": planning_trace,
        }
