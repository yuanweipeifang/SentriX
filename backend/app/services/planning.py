from __future__ import annotations

from typing import List

from ..domain.config import PlannerConfig
from ..domain.models import Action, ActionScore, Incident, StateVector, ThreatIntel
from ..engine.planner import StateDrivenPlanner
from ..engine.rollout import compute_parallel_cost
from .action_generator import ActionGenerator


class PlanningEngine:
    """Compatibility facade for legacy imports; delegates to engine StateDrivenPlanner."""

    def __init__(self, config: PlannerConfig, action_generator: ActionGenerator, llm_client=None) -> None:
        self._planner = StateDrivenPlanner(config=config, action_generator=action_generator, llm_client=llm_client)

    def plan(
        self,
        incident: Incident,
        state: StateVector,
        history: List[Action],
        intel: ThreatIntel,
        candidates: List[Action],
    ) -> List[ActionScore]:
        return self._planner.plan(incident, state, history, intel, candidates).ranked_actions

    @staticmethod
    def compute_action_cost(action: Action) -> float:
        return compute_parallel_cost(action)
