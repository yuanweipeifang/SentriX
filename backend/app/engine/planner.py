from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Dict, List

if TYPE_CHECKING:
    from ..services.action_generator import ActionGenerator

from ..domain.config import PlannerConfig
from ..domain.models import Action, ActionScore, Incident, PlanningResult, RolloutResult, STATE_DIMENSIONS, StateVector, ThreatIntel
from .rollout import rollout_once
from .scoring import score_action


class StateDrivenPlanner:
    def __init__(self, config: PlannerConfig, action_generator: "ActionGenerator", llm_client=None) -> None:
        self.config = config
        self.action_generator = action_generator
        self.llm_client = llm_client

    def plan(
        self,
        incident: Incident,
        state: StateVector,
        history: List[Action],
        intel: ThreatIntel,
        candidates: List[Action],
        progress_callback: Callable[[str], None] | None = None,
    ) -> PlanningResult:
        scores: List[ActionScore] = []
        best_completed_score: float | None = None
        total_actions = len(candidates)
        for action_idx, action in enumerate(candidates, start=1):
            if progress_callback:
                progress_callback(
                    f"planning_action_start action={action.action_name}; "
                    f"stage={action.target_stage}; index={action_idx}/{total_actions}"
                )
            rollout_samples: List[RolloutResult] = []
            early_stopped = False
            early_stop_reason = ""
            for rollout_idx in range(self.config.rollout_count):
                sample = rollout_once(
                    config=self.config,
                    action_generator=self.action_generator,
                    incident=incident,
                    initial_state=state,
                    history=history,
                    intel=intel,
                    first_action=action,
                    llm_client=self.llm_client,
                )
                rollout_samples.append(sample)
                if progress_callback:
                    progress_callback(
                        f"planning_rollout_done action={action.action_name}; "
                        f"rollout={rollout_idx + 1}/{self.config.rollout_count}; "
                        f"gain={round(sample.progress_gain, 4)}; "
                        f"cost={round(sample.cumulative_cost, 2)}"
                    )
                if (
                    self.config.early_stop_enabled
                    and best_completed_score is not None
                    and len(rollout_samples) >= max(1, self.config.early_stop_min_rollouts)
                ):
                    partial_avg_cost = sum(s.cumulative_cost for s in rollout_samples) / len(rollout_samples)
                    partial_avg_gain = sum(s.progress_gain for s in rollout_samples) / len(rollout_samples)
                    partial_hallucination = all(s.hallucination_flag for s in rollout_samples)
                    partial_score = score_action(partial_avg_gain, partial_avg_cost, action.risk_penalty, partial_hallucination)
                    if partial_score + self.config.early_stop_margin < best_completed_score:
                        early_stopped = True
                        early_stop_reason = (
                            f"partial_score={partial_score:.3f} trails best_completed_score={best_completed_score:.3f}"
                        )
                        if progress_callback:
                            progress_callback(
                                f"planning_action_early_stop action={action.action_name}; "
                                f"after_rollouts={len(rollout_samples)}; "
                                f"reason={early_stop_reason}"
                            )
                        break

            avg_cost = sum(s.cumulative_cost for s in rollout_samples) / len(rollout_samples)
            avg_gain = sum(s.progress_gain for s in rollout_samples) / len(rollout_samples)
            avg_time = sum(s.projected_recovery_time for s in rollout_samples) / len(rollout_samples)
            hallucination = all(s.hallucination_flag for s in rollout_samples)
            projected_state = self._average_projected_state(rollout_samples)
            rollout_path = rollout_samples[0].rollout_path if rollout_samples else []
            final_score = score_action(avg_gain, avg_cost, action.risk_penalty, hallucination)
            validation_passed = not hallucination and avg_gain > 0
            reason = (
                f"score={final_score:.3f}; progress_gain={avg_gain:.3f}; "
                f"cumulative_cost={avg_cost:.2f}; risk_penalty={action.risk_penalty:.2f}."
            )
            scores.append(
                ActionScore(
                    action=action,
                    score=final_score,
                    projected_state=projected_state,
                    cumulative_cost=avg_cost,
                    progress_gain=avg_gain,
                    projected_recovery_time=avg_time,
                    hallucination_flag=hallucination,
                    rollout_path=rollout_path,
                    reason=reason,
                    rollout_results=rollout_samples,
                    validation_passed=validation_passed,
                    execution_meta={
                        "rollouts_executed": len(rollout_samples),
                        "rollouts_planned": self.config.rollout_count,
                        "early_stopped": early_stopped,
                        "early_stop_reason": early_stop_reason,
                    },
                )
            )
            best_completed_score = final_score if best_completed_score is None else max(best_completed_score, final_score)
            if progress_callback:
                progress_callback(
                    f"planning_action_done action={action.action_name}; "
                    f"score={round(final_score, 3)}; "
                    f"avg_gain={round(avg_gain, 4)}; "
                    f"avg_cost={round(avg_cost, 2)}; "
                    f"valid={validation_passed}; "
                    f"early_stopped={early_stopped}"
                )
        ranked = sorted(scores, key=lambda x: x.score, reverse=True)
        return PlanningResult(
            ranked_actions=ranked,
            best_action=ranked[0].action if ranked else None,
            planning_explanation=(
                "State-driven rollout planning: ranked by progress_gain, cumulative_cost, risk_penalty and hallucination checks."
            ),
        )

    @staticmethod
    def _average_projected_state(rollout_results: List[RolloutResult]) -> Dict[str, float]:
        if not rollout_results:
            return {dim: 0.0 for dim in STATE_DIMENSIONS}
        out: Dict[str, float] = {}
        for dim in STATE_DIMENSIONS:
            out[dim] = round(
                sum(item.projected_state.get(dim, 0.0) for item in rollout_results) / len(rollout_results),
                4,
            )
        return out
