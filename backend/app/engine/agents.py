from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Protocol

from ..domain.config import ModelConfig
from ..services.llm_client import LLMClient


class Agent(Protocol):
    name: str

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


@dataclass
class BaseAgent:
    name: str

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"agent": self.name, "payload": payload}


def _score_by_triage(payload: Dict[str, Any]) -> Dict[str, float]:
    scores: Dict[str, float] = {}
    for action in payload.get("candidates", []):
        action_id = str(action.get("action_id", ""))
        target_stage = str(action.get("target_stage", ""))
        risk = float(action.get("risk_penalty", 0.0))
        progress_gain = float(action.get("progress_gain", 0.0))
        stage_bonus = 0.1 if target_stage in {"containment", "assessment"} else 0.0
        scores[action_id] = progress_gain + stage_bonus - risk * 0.3
    return scores


def _score_by_intel(payload: Dict[str, Any]) -> Dict[str, float]:
    ioc_terms = payload.get("ioc_terms", [])
    scores: Dict[str, float] = {}
    for action in payload.get("candidates", []):
        action_id = str(action.get("action_id", ""))
        text = (
            f"{action.get('action_name', '')} "
            f"{action.get('description', '')} "
            f"{action.get('reasoning', '')}"
        ).lower()
        hit_count = sum(1 for term in ioc_terms if term and term in text)
        scores[action_id] = min(1.0, hit_count / max(1, len(ioc_terms)))
    return scores


def _score_by_response(payload: Dict[str, Any]) -> Dict[str, float]:
    scores: Dict[str, float] = {}
    for action in payload.get("candidates", []):
        action_id = str(action.get("action_id", ""))
        progress_gain = float(action.get("progress_gain", 0.0))
        cost = float(action.get("projected_recovery_time", action.get("estimated_cost", 0.0)))
        risk = float(action.get("risk_penalty", 0.0))
        velocity = progress_gain / max(1.0, cost)
        scores[action_id] = velocity * 100.0 - risk * 2.0
    return scores


def _load_prompt(file_name: str) -> str:
    prompt_file = Path(__file__).resolve().parents[1] / "prompts" / file_name
    return prompt_file.read_text(encoding="utf-8") if prompt_file.exists() else ""


def _resolve_agent_model_config(base_model: ModelConfig, role: str) -> ModelConfig:
    role_prefix = f"AGENT_{role.upper()}_"
    default_endpoint = os.getenv("AGENT_ENDPOINT", base_model.endpoint)
    default_api_key = os.getenv("AGENT_API_KEY", base_model.api_key)
    default_model = os.getenv("AGENT_MODEL", base_model.model_name)
    default_provider = os.getenv("AGENT_PROVIDER", base_model.provider)
    default_timeout = int(os.getenv("AGENT_TIMEOUT_SECONDS", str(base_model.timeout_seconds)))
    return ModelConfig(
        provider=os.getenv(f"{role_prefix}PROVIDER", default_provider),
        endpoint=os.getenv(f"{role_prefix}ENDPOINT", default_endpoint),
        api_key=os.getenv(f"{role_prefix}API_KEY", default_api_key),
        model_name=os.getenv(f"{role_prefix}MODEL", default_model),
        timeout_seconds=int(os.getenv(f"{role_prefix}TIMEOUT_SECONDS", str(default_timeout))),
        enable_online_rag=base_model.enable_online_rag,
        web_search_provider=base_model.web_search_provider,
        web_search_endpoint=base_model.web_search_endpoint,
        web_search_api_key=base_model.web_search_api_key,
        web_search_top_k=base_model.web_search_top_k,
    )


@dataclass
class LLMScoringAgent(BaseAgent):
    role: str
    system_prompt: str
    llm_client: LLMClient
    fallback_scorer: Any
    use_online_search: bool = False

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        candidates = payload.get("candidates", [])
        action_ids = [str(x.get("action_id", "")) for x in candidates]
        if not action_ids:
            return {"agent": self.name, "scores": {}, "note": "no_candidates"}

        if not self.system_prompt.strip():
            return {
                "agent": self.name,
                "scores": self.fallback_scorer(payload),
                "note": "fallback:no_prompt",
            }

        llm_resp = self.llm_client.generate_json(
            system_prompt=self.system_prompt,
            user_prompt=json.dumps(payload, ensure_ascii=False),
            use_online_search=self.use_online_search,
        )
        parsed = self._parse_llm_scores(llm_resp, action_ids)
        if parsed is not None:
            return {"agent": self.name, "scores": parsed, "note": "llm"}
        return {
            "agent": self.name,
            "scores": self.fallback_scorer(payload),
            "note": "fallback:llm_unavailable_or_invalid",
        }

    @staticmethod
    def _parse_llm_scores(response: Dict[str, Any] | None, action_ids: List[str]) -> Dict[str, float] | None:
        if not response:
            return None
        # Preferred schema: {"scores":[{"action_id":"a1","score":0.12}, ...]}
        if isinstance(response.get("scores"), list):
            scores = {action_id: 0.0 for action_id in action_ids}
            found = 0
            for item in response.get("scores", []):
                if not isinstance(item, dict):
                    continue
                action_id = str(item.get("action_id", ""))
                if action_id in scores:
                    scores[action_id] = float(item.get("score", 0.0))
                    found += 1
            if found > 0:
                return scores
        # Compatibility schema: {"action_scores":{"a1":0.1}}
        if isinstance(response.get("action_scores"), dict):
            scores = {action_id: 0.0 for action_id in action_ids}
            found = 0
            for action_id, raw_score in response.get("action_scores", {}).items():
                action_id = str(action_id)
                if action_id in scores:
                    scores[action_id] = float(raw_score)
                    found += 1
            if found > 0:
                return scores
        return None


def build_default_multi_agents(base_model_config: ModelConfig, use_llm_agents: bool) -> List[Agent]:
    triage_prompt = _load_prompt("agent_triage.prompt.txt")
    intel_prompt = _load_prompt("agent_intel.prompt.txt")
    response_prompt = _load_prompt("agent_response.prompt.txt")

    triage_client = LLMClient(_resolve_agent_model_config(base_model_config, "triage"))
    intel_client = LLMClient(_resolve_agent_model_config(base_model_config, "intel"))
    response_client = LLMClient(_resolve_agent_model_config(base_model_config, "response"))

    if not use_llm_agents:
        triage_prompt = ""
        intel_prompt = ""
        response_prompt = ""

    return [
        LLMScoringAgent(
            name="triage_agent",
            role="triage",
            system_prompt=triage_prompt,
            llm_client=triage_client,
            fallback_scorer=_score_by_triage,
            use_online_search=False,
        ),
        LLMScoringAgent(
            name="intel_agent",
            role="intel",
            system_prompt=intel_prompt,
            llm_client=intel_client,
            fallback_scorer=_score_by_intel,
            use_online_search=os.getenv("AGENT_INTEL_ENABLE_SEARCH", "false").lower() == "true",
        ),
        LLMScoringAgent(
            name="response_agent",
            role="response",
            system_prompt=response_prompt,
            llm_client=response_client,
            fallback_scorer=_score_by_response,
            use_online_search=False,
        ),
    ]


class MultiAgentCoordinator:
    """
    Current implementation is backend-only orchestration.
    New agents can be plugged in without changing main workflow.
    """

    def __init__(self) -> None:
        self.registry: Dict[str, Agent] = {}

    def register(self, agent: Agent) -> None:
        self.registry[agent.name] = agent

    def dispatch(self, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if name not in self.registry:
            raise KeyError(f"Agent {name} is not registered")
        return self.registry[name].run(payload)

    def run_parallel(self, payload: Dict[str, Any], per_agent_timeout_ms: int) -> List[Dict[str, Any]]:
        if not self.registry:
            return []
        timeout_s = max(0.01, per_agent_timeout_ms / 1000.0)
        outputs: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=len(self.registry)) as executor:
            futures = {executor.submit(agent.run, dict(payload)): name for name, agent in self.registry.items()}
            done, pending = wait(set(futures.keys()), timeout=timeout_s)
            for future in done:
                name = futures[future]
                try:
                    result = future.result()
                    outputs.append(result if isinstance(result, dict) else {"agent": name, "scores": {}})
                except Exception as exc:
                    outputs.append({"agent": name, "scores": {}, "error": str(exc)})
            for future in pending:
                name = futures[future]
                future.cancel()
                outputs.append({"agent": name, "scores": {}, "timeout": True})
        return outputs

    def deliberate(
        self,
        payload: Dict[str, Any],
        max_rounds: int,
        convergence_streak: int,
        min_consensus_margin: float,
        per_agent_timeout_ms: int,
        max_elapsed_ms: int,
    ) -> Dict[str, Any]:
        start = time.perf_counter()
        score_board: Dict[str, float] = {}
        winners: List[str] = []
        rounds: List[Dict[str, Any]] = []
        action_ids = [str(x.get("action_id", "")) for x in payload.get("candidates", [])]

        if not action_ids:
            return {
                "enabled": True,
                "converged": True,
                "selected_action_id": "",
                "rounds": [],
                "reason": "no_candidates",
                "elapsed_ms": 0,
            }

        for idx in range(max(1, max_rounds)):
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            if elapsed_ms >= max_elapsed_ms:
                break
            outputs = self.run_parallel(payload=payload, per_agent_timeout_ms=per_agent_timeout_ms)
            round_scores = {action_id: score_board.get(action_id, 0.0) * 0.4 for action_id in action_ids}
            for item in outputs:
                for action_id, score in (item.get("scores", {}) or {}).items():
                    if action_id in round_scores:
                        round_scores[action_id] += float(score)
            ranked = sorted(round_scores.items(), key=lambda x: x[1], reverse=True)
            winner = ranked[0][0]
            margin = ranked[0][1] - ranked[1][1] if len(ranked) > 1 else ranked[0][1]
            score_board = dict(round_scores)
            winners.append(winner)
            rounds.append(
                {
                    "round": idx + 1,
                    "winner_action_id": winner,
                    "winner_margin": round(margin, 4),
                    "outputs": outputs,
                }
            )

            if len(winners) >= convergence_streak:
                recent = winners[-convergence_streak:]
                if len(set(recent)) == 1 and margin >= min_consensus_margin:
                    return {
                        "enabled": True,
                        "converged": True,
                        "selected_action_id": winner,
                        "rounds": rounds,
                        "reason": "stable_winner",
                        "elapsed_ms": int((time.perf_counter() - start) * 1000),
                    }

        final_ranked = sorted(score_board.items(), key=lambda x: x[1], reverse=True)
        selected = final_ranked[0][0] if final_ranked else action_ids[0]
        return {
            "enabled": True,
            "converged": False,
            "selected_action_id": selected,
            "rounds": rounds,
            "reason": "round_or_time_budget_reached",
            "elapsed_ms": int((time.perf_counter() - start) * 1000),
        }
