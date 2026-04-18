from __future__ import annotations

import copy
import random
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from ..services.action_generator import ActionGenerator

from ..domain.config import PlannerConfig
from ..domain.models import Action, Incident, RolloutResult, STATE_DIMENSIONS, StateVector, ThreatIntel
from .transition import predict_state_delta


def compute_parallel_cost(action: Action) -> float:
    if not action.sub_steps:
        return max(0.0, float(action.estimated_cost))
    parallel_groups: Dict[str, List[float]] = {}
    serial_cost = 0.0
    for step in action.sub_steps:
        mode = str(step.get("mode", "serial")).lower()
        cost = max(0.0, float(step.get("cost_minutes", 0.0)))
        if mode == "parallel":
            group = str(step.get("group", "default"))
            parallel_groups.setdefault(group, []).append(cost)
        else:
            serial_cost += cost
    parallel_cost = sum(max(values) for values in parallel_groups.values()) if parallel_groups else 0.0
    return serial_cost + parallel_cost


def rollout_once(
    config: PlannerConfig,
    action_generator: "ActionGenerator",
    incident: Incident,
    initial_state: StateVector,
    history: List[Action],
    intel: ThreatIntel,
    first_action: Action,
    llm_client=None,
) -> RolloutResult:
    state = copy.deepcopy(initial_state)
    local_history = history[:]
    path = [first_action.action_id]

    delta = predict_state_delta(first_action, incident, intel, llm_client=llm_client)
    state, progress_gain = state.apply_delta(delta)
    invalid = progress_gain <= 0
    cumulative_cost = compute_parallel_cost(first_action)
    local_history.append(first_action)

    if config.planning_depth > 1 and not state.is_terminal(config.terminal_threshold):
        for _ in range(config.planning_depth - 1):
            followups = action_generator.generate(incident, state, local_history, intel, use_llm=False)
            if not followups:
                break
            next_action = random.choice(followups[: min(config.candidate_count, len(followups))])
            next_delta = predict_state_delta(next_action, incident, intel, llm_client=llm_client)
            state, _ = state.apply_delta(next_delta)
            local_history.append(next_action)
            path.append(next_action.action_id)
            cumulative_cost += compute_parallel_cost(next_action)
            if state.is_terminal(config.terminal_threshold):
                break

    progress = state.progress_gain_from(initial_state)
    return RolloutResult(
        projected_state={dim: round(getattr(state, dim), 4) for dim in STATE_DIMENSIONS},
        cumulative_cost=round(max(0.0, cumulative_cost), 4),
        progress_gain=round(max(0.0, progress), 4),
        projected_recovery_time=round(max(0.0, cumulative_cost), 4),
        hallucination_flag=bool(invalid),
        rollout_path=path,
    )
