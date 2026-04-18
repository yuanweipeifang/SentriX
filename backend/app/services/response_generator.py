from typing import Dict, List

from ..domain.models import ActionScore, Incident, ResponsePlan, StateVector, ThreatIntel
from .execution_adapter import ExecutionAdapter


class ResponseGenerator:
    def __init__(self) -> None:
        self.execution_adapter = ExecutionAdapter()

    def generate(
        self,
        incident: Incident,
        state: StateVector,
        intel: ThreatIntel,
        ranked_actions: List[ActionScore],
    ) -> ResponsePlan:
        best = ranked_actions[0]
        reasons: Dict[str, str] = {}
        for idx, score in enumerate(ranked_actions, start=1):
            reasons[score.action.action_name] = (
                f"Rank {idx}: score={score.score:.3f}, "
                f"progress_gain={score.progress_gain:.3f}, "
                f"cost={score.cumulative_cost:.1f}m, "
                f"hallucination={score.hallucination_flag}, "
                f"validated={score.validation_passed}."
            )

        risk_alerts = [
            f"{r.action.action_name}: 风险={r.action.risk_penalty:.2f}"
            for r in ranked_actions
            if r.action.risk_penalty >= 0.3
        ]
        execution_bundle = self.execution_adapter.build(incident, best.action)

        return ResponsePlan(
            best_action=best.action,
            ranked_actions=ranked_actions,
            reasons=reasons,
            expected_recovery_effect={
                "current_state_progress": round(state.average_progress(), 3),
                "projected_gain_best_action": round(best.progress_gain, 3),
                "projected_recovery_time_minutes": round(best.projected_recovery_time, 2),
                "projected_state_best_action": best.projected_state,
            },
            risk_alerts=risk_alerts,
            executable=execution_bundle,
            explainability={
                "state_explanation": state.explanation,
                "rag_compressed_context": intel.compressed_context,
                "decision_policy": "Score = progress_gain * 100 - cumulative_cost - risk_penalty * 5",
                "incident_summary": incident.event_summary,
                "execution_mode": execution_bundle.get("mode", ""),
                "soar_task_count": len(execution_bundle.get("tasks", [])),
            },
        )
