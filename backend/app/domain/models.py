from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


STATE_DIMENSIONS = [
    "containment",
    "assessment",
    "preservation",
    "eviction",
    "hardening",
    "restoration",
]


@dataclass
class IOC:
    ip: List[str] = field(default_factory=list)
    domain: List[str] = field(default_factory=list)
    cve: List[str] = field(default_factory=list)
    process: List[str] = field(default_factory=list)


@dataclass
class Incident:
    event_summary: str
    ioc: IOC
    affected_assets: List[str]
    raw_logs: List[str]
    timestamp: str

    @staticmethod
    def from_dict(payload: Dict[str, Any]) -> "Incident":
        return Incident(
            event_summary=payload.get("event_summary", ""),
            ioc=IOC(**payload.get("ioc", {})),
            affected_assets=payload.get("affected_assets", []),
            raw_logs=payload.get("raw_logs", []),
            timestamp=payload.get("timestamp", datetime.utcnow().isoformat()),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StateVector:
    containment: float = 0.0
    assessment: float = 0.0
    preservation: float = 0.0
    eviction: float = 0.0
    hardening: float = 0.0
    restoration: float = 0.0
    explanation: str = ""

    def clamp(self) -> "StateVector":
        for key in STATE_DIMENSIONS:
            value = max(0.0, min(1.0, float(getattr(self, key))))
            setattr(self, key, value)
        return self

    def to_dict(self, include_legacy: bool = True) -> Dict[str, Any]:
        payload = asdict(self)
        if include_legacy:
            payload["recovery"] = self.restoration
        return payload

    def average_progress(self) -> float:
        return sum(getattr(self, dim) for dim in STATE_DIMENSIONS) / len(STATE_DIMENSIONS)

    def total_progress(self) -> float:
        return self.average_progress()

    def is_terminal(self, threshold: float = 0.95) -> bool:
        return all(getattr(self, dim) >= threshold for dim in STATE_DIMENSIONS)

    def apply_delta(self, delta: Dict[str, float]) -> tuple["StateVector", float]:
        before = self.average_progress()
        for dim in STATE_DIMENSIONS:
            legacy_key = "recovery" if dim == "restoration" else dim
            value = float(delta.get(dim, delta.get(legacy_key, 0.0)))
            setattr(self, dim, getattr(self, dim) + value)
        self.clamp()
        gain = self.average_progress() - before
        return self, max(0.0, gain)

    def progress_gain_from(self, previous: "StateVector") -> float:
        return max(0.0, self.average_progress() - previous.average_progress())


@dataclass
class ThreatIntel:
    summary: str
    cve_findings: List[Dict[str, Any]] = field(default_factory=list)
    ioc_findings: List[Dict[str, Any]] = field(default_factory=list)
    asset_findings: List[Dict[str, Any]] = field(default_factory=list)
    rule_findings: List[Dict[str, Any]] = field(default_factory=list)
    compressed_context: str = ""
    rag_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Action:
    action_id: str
    action_name: str
    description: str
    target_stage: str
    estimated_cost: float
    risk_penalty: float
    confidence: float
    reasoning: str
    command: str = ""
    api_call: Optional[str] = None
    effects: Dict[str, float] = field(default_factory=dict)
    target_assets: List[str] = field(default_factory=list)
    capability_tags: List[str] = field(default_factory=list)
    sub_steps: List[Dict[str, Any]] = field(default_factory=list)
    parallel_group: Optional[str] = None

    @property
    def id(self) -> str:
        return self.action_id

    @property
    def name(self) -> str:
        return self.action_name

    @property
    def stage(self) -> str:
        return self.target_stage

    @property
    def risk(self) -> float:
        return self.risk_penalty

    @property
    def cost_minutes(self) -> float:
        return self.estimated_cost

    @property
    def reason(self) -> str:
        return self.reasoning

    def has_positive_state_gain(self) -> bool:
        for dim in STATE_DIMENSIONS:
            if float(self.effects.get(dim, self.effects.get("recovery", 0.0))) > 0:
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload.update(
            {
                "id": self.action_id,
                "name": self.action_name,
                "stage": self.target_stage,
                "risk": self.risk_penalty,
                "cost_minutes": self.estimated_cost,
                "reason": self.reasoning,
            }
        )
        return payload


@dataclass
class RolloutResult:
    projected_state: Dict[str, float]
    cumulative_cost: float
    progress_gain: float
    projected_recovery_time: float
    hallucination_flag: bool
    rollout_path: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActionScore:
    action: Action
    score: float
    projected_state: Dict[str, float]
    cumulative_cost: float
    progress_gain: float
    projected_recovery_time: float
    hallucination_flag: bool
    rollout_path: List[str]
    reason: str
    rollout_results: List[RolloutResult] = field(default_factory=list)
    validation_passed: bool = True
    execution_meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "score": self.score,
            "projected_state": self.projected_state,
            "cumulative_cost": self.cumulative_cost,
            "progress_gain": self.progress_gain,
            "projected_recovery_time": self.projected_recovery_time,
            "hallucination_flag": self.hallucination_flag,
            "rollout_path": self.rollout_path,
            "reason": self.reason,
            "validation_passed": self.validation_passed,
            "rollout_results": [r.to_dict() for r in self.rollout_results],
            "execution_meta": self.execution_meta,
        }


@dataclass
class ResponsePlan:
    best_action: Action
    ranked_actions: List[ActionScore]
    reasons: Dict[str, str]
    expected_recovery_effect: Dict[str, Any]
    risk_alerts: List[str]
    executable: Dict[str, Any]
    explainability: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "best_action": self.best_action.to_dict(),
            "recommended_action": self.best_action.to_dict(),
            "ranked_actions": [x.to_dict() for x in self.ranked_actions],
            "reasons": self.reasons,
            "expected_recovery_effect": self.expected_recovery_effect,
            "risk_alerts": self.risk_alerts,
            "executable": self.executable,
            "explainability": self.explainability,
        }


@dataclass
class RolloutStep:
    action_id: str
    state_before: Dict[str, float]
    state_after: Dict[str, float]
    progress_gain: float
    cumulative_cost: float


@dataclass
class PlanningResult:
    ranked_actions: List[ActionScore]
    best_action: Optional[Action]
    planning_explanation: str


@dataclass
class FinalResponse:
    incident: Dict[str, Any]
    state: Dict[str, Any]
    rag: Dict[str, Any]
    response: Dict[str, Any]
    audit: Dict[str, Any]


@dataclass
class AuditRecord:
    incident_meta: Dict[str, Any]
    rag_summary: Dict[str, Any]
    state_snapshot: Dict[str, Any]
    candidates_raw: List[Dict[str, Any]]
    filter_audit: List[Dict[str, Any]]
    planning_trace: List[Dict[str, Any]]
    scores: List[Dict[str, Any]]
    best_action_reason: str
    final_output: Dict[str, Any]


# Domain aliases for clearer semantics in state-driven planning.
RecoveryState = StateVector
CandidateAction = Action
