import tempfile
import unittest
from unittest.mock import patch

from backend.app.domain.config import ModelConfig, PlannerConfig, RuleGenerationConfig
from backend.app.domain.models import Action, Incident, IOC, RolloutResult, StateVector, ThreatIntel
from backend.app.engine.layered_agents import ProfessionalLayeredAgents
from backend.app.engine.planner import StateDrivenPlanner
from backend.app.engine.workflow import (
    _build_confidence_model,
    _build_evidence_trace_tree,
    _build_frontend_explainability,
    _build_frontend_payload,
)
from backend.app.services.case_memory import LocalCaseMemory
from backend.app.services.rag import ThreatIntelligenceRetrieval
from backend.app.services.response_generator import ResponseGenerator
from backend.app.services.rule_generation import RuleGenerationEngine


def _incident(summary: str = "normal incident") -> Incident:
    return Incident(
        event_summary=summary,
        ioc=IOC(ip=["198.51.100.23"], domain=[], cve=["CVE-2024-3400"], process=[]),
        affected_assets=["db-prod-01"],
        raw_logs=["GET /pixel;foo HTTP/1.1 Host: pixel.quantserve.com"],
        timestamp="2026-04-18T00:00:00Z",
    )


def _threat_intel() -> ThreatIntel:
    return ThreatIntel(
        summary="test",
        cve_findings=[],
        ioc_findings=[],
        asset_findings=[],
        rule_findings=[
            {
                "rule_id": "RULE-1",
                "title": "test rule",
                "threat": "test threat",
                "pattern": "test",
                "severity": 0.9,
                "confidence": 0.95,
                "evidence_id": "ev-1",
            }
        ],
        compressed_context="ctx",
        rag_context={},
    )


class DummyActionGenerator:
    pass


def _action(action_id: str, name: str, risk: float) -> Action:
    return Action(
        action_id=action_id,
        action_name=name,
        description=name,
        target_stage="containment",
        estimated_cost=10.0,
        risk_penalty=risk,
        confidence=0.8,
        reasoning="test",
    )


class PerformanceExplainabilityTests(unittest.TestCase):
    def test_rag_cache_hit_and_downgrade_reason(self) -> None:
        model_config = ModelConfig(rag_use_db=False, analysis_cache_ttl_seconds=60)
        rag = ThreatIntelligenceRetrieval(model_config=model_config)
        incident = _incident()

        first = rag.retrieve(incident)
        second = rag.retrieve(incident)

        self.assertFalse(first.rag_context.get("cache_hit", False))
        self.assertTrue(second.rag_context.get("cache_hit", False))
        self.assertIn("matched_common_normal_traffic_template", first.rag_context.get("downgrade_reasons", []))

    def test_layered_agents_cache_hit(self) -> None:
        agents = ProfessionalLayeredAgents()
        incident = _incident("suspicious execution incident")
        intel = _threat_intel()

        first = agents.run(incident, intel)
        second = agents.run(incident, intel)

        self.assertFalse(first.get("cache_hit", False))
        self.assertTrue(second.get("cache_hit", False))
        self.assertGreaterEqual(len(first.get("hunt_queries", [])), 1)
        templates = first["hunt_queries"][0].get("templates", {})
        self.assertIn("sql", templates)
        self.assertIn("elasticsearch_dsl", templates)
        self.assertIn("splunk_spl", templates)
        self.assertIn("SELECT", templates.get("sql", ""))

    def test_rule_generation_skip_on_existing_high_confidence_rules(self) -> None:
        model_config = ModelConfig()
        config = RuleGenerationConfig(
            enabled=True,
            candidate_parallel=2,
            max_iterations=2,
            temperatures=[0.7, 0.8],
            top_k_keep=2,
            enforce_domestic_model=False,
            max_cves_per_incident=1,
            budget_ms=1000,
            skip_if_rule_hits_gte=1,
            skip_if_confidence_gte=0.9,
            min_raw_logs=1,
        )
        engine = RuleGenerationEngine(model_config=model_config, config=config)
        result = engine.generate_for_incident(_incident("CVE incident"), _threat_intel())
        self.assertEqual(result.get("reason"), "skip_existing_high_confidence_rules")

    def test_planner_early_stop_marks_metadata(self) -> None:
        config = PlannerConfig(
            candidate_count=3,
            rollout_count=3,
            planning_depth=3,
            early_stop_enabled=True,
            early_stop_min_rollouts=2,
            early_stop_margin=0.1,
        )
        planner = StateDrivenPlanner(config=config, action_generator=DummyActionGenerator())
        incident = _incident("planner incident")
        state = StateVector()
        intel = _threat_intel()
        actions = [
            _action("a1", "best", 0.1),
            _action("a2", "worst", 0.9),
        ]

        def fake_rollout_once(config, action_generator, incident, initial_state, history, intel, first_action, llm_client):
            if first_action.action_id == "a1":
                return RolloutResult(
                    projected_state={"containment": 0.8},
                    cumulative_cost=10.0,
                    progress_gain=0.7,
                    projected_recovery_time=10.0,
                    hallucination_flag=False,
                    rollout_path=["a1"],
                )
            return RolloutResult(
                projected_state={"containment": 0.1},
                cumulative_cost=30.0,
                progress_gain=0.05,
                projected_recovery_time=30.0,
                hallucination_flag=False,
                rollout_path=["a2"],
            )

        with patch("backend.app.engine.planner.rollout_once", side_effect=fake_rollout_once):
            result = planner.plan(incident, state, [], intel, actions)

        self.assertEqual(result.ranked_actions[0].action.action_id, "a1")
        loser_meta = result.ranked_actions[1].execution_meta
        self.assertTrue(loser_meta.get("early_stopped", False))
        self.assertLess(loser_meta.get("rollouts_executed", 0), config.rollout_count)

    def test_response_generator_builds_execution_bundle(self) -> None:
        incident = _incident("execution bundle incident")
        state = StateVector()
        intel = _threat_intel()
        action = _action("a1", "best", 0.2)
        action.command = "echo test"
        action.api_call = "POST /ops/test"
        action.sub_steps = [
            {"name": "step-1", "cost_minutes": 3, "mode": "serial"},
            {"name": "step-2", "cost_minutes": 5, "mode": "parallel", "group": "g1"},
        ]
        ranked = [
            type(
                "Ranked",
                (),
                {
                    "action": action,
                    "score": 1.0,
                    "progress_gain": 0.2,
                    "projected_recovery_time": 8.0,
                    "projected_state": {"containment": 0.5},
                    "cumulative_cost": 8.0,
                    "hallucination_flag": False,
                    "validation_passed": True,
                    "reason": "ok",
                    "to_dict": lambda self=None: {},
                },
            )()
        ]

        response = ResponseGenerator().generate(incident, state, intel, ranked)
        executable = response.executable

        self.assertEqual(executable.get("mode"), "hybrid")
        self.assertGreaterEqual(len(executable.get("tasks", [])), 2)
        self.assertIn("playbook_id", executable.get("playbook", {}))
        self.assertTrue(executable.get("summary", {}).get("has_shell"))
        self.assertTrue(executable.get("summary", {}).get("has_api"))
        orchestration = executable.get("orchestration", {})
        self.assertIn("graph_id", orchestration)
        self.assertGreaterEqual(len(orchestration.get("nodes", [])), 2)
        self.assertIn("rollback_plan", orchestration)

    def test_response_generator_orchestration_adds_approval_node_for_high_risk(self) -> None:
        incident = _incident("approval test incident")
        state = StateVector()
        intel = _threat_intel()
        action = _action("a9", "high-risk action", 0.5)
        action.command = "echo risky"
        action.sub_steps = [{"name": "risky-step", "cost_minutes": 2, "mode": "serial"}]
        ranked = [
            type(
                "Ranked",
                (),
                {
                    "action": action,
                    "score": 0.9,
                    "progress_gain": 0.2,
                    "projected_recovery_time": 2.0,
                    "projected_state": {"containment": 0.5},
                    "cumulative_cost": 2.0,
                    "hallucination_flag": False,
                    "validation_passed": True,
                    "reason": "ok",
                    "to_dict": lambda self=None: {},
                },
            )()
        ]
        executable = ResponseGenerator().generate(incident, state, intel, ranked).executable
        orchestration = executable.get("orchestration", {})
        self.assertGreaterEqual(len(orchestration.get("approval_nodes", [])), 1)

    def test_frontend_explainability_is_ui_friendly(self) -> None:
        incident = _incident("frontend explainability incident")
        rag = ThreatIntelligenceRetrieval(model_config=ModelConfig(rag_use_db=False, analysis_cache_ttl_seconds=60)).retrieve(incident)
        agent_layers = ProfessionalLayeredAgents().run(incident, rag)
        response = ResponseGenerator().generate(
            incident,
            StateVector(),
            rag,
            [
                type(
                    "Ranked",
                    (),
                    {
                        "action": _action("a1", "best", 0.1),
                        "score": 1.0,
                        "progress_gain": 0.2,
                        "projected_recovery_time": 5.0,
                        "projected_state": {"containment": 0.5},
                        "cumulative_cost": 5.0,
                        "hallucination_flag": False,
                        "validation_passed": True,
                        "reason": "ok",
                        "to_dict": lambda self=None: {},
                    },
                )()
            ],
        ).to_dict()
        result = {
            "incident": incident.to_dict(),
            "rag": rag.to_dict(),
            "response": response,
            "audit": {"audit_result": "pass"},
            "execution_allowed": True,
            "agent_layers": agent_layers,
            "skill_runtime": {"execution_trace": []},
        }
        result["confidence_model"] = _build_confidence_model(result)
        result["evidence_trace_tree"] = _build_evidence_trace_tree(result)
        result["observability"] = {"cache_hit": {"rag": False, "layered_agents": False}, "planner": {}, "stage_elapsed_ms": {}}

        frontend = _build_frontend_explainability(result)
        self.assertIn("summary_cards", frontend)
        self.assertIn("confidence_panel", frontend)
        self.assertIn("evidence_graph", frontend)
        self.assertIn("downgrade_explanations", frontend)
        self.assertIn("hunt_query_tabs", frontend)
        self.assertGreaterEqual(len(frontend["summary_cards"]), 1)
        self.assertEqual(frontend["evidence_graph"]["root_id"], "event-root")
        result["case_memory"] = {"stored": True, "case_id": "case-1", "effective_label": "malicious", "storage_file": "tmp"}
        payload = _build_frontend_payload(result)
        self.assertEqual(payload["schema_version"], "frontend-payload/v1")
        self.assertIn("incident_overview", payload)
        self.assertIn("case_memory", payload)
        self.assertIn("orchestration", payload)

    def test_case_memory_record_search_and_manual_correction(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = LocalCaseMemory(storage_file=f"{tmpdir}/cases.jsonl")
            incident = _incident("historical benign case")
            result = {
                "incident": incident.to_dict(),
                "audit": {"audit_result": "fail"},
                "execution_allowed": False,
                "confidence_model": {"detection_confidence": 0.2},
                "agent_layers": {"prioritized_threats": [{"threat": "normal traffic"}]},
                "response": {"best_action": {"action_name": "monitor"}},
                "rag": {"rule_findings": [], "rag_context": {"downgrade_reasons": ["matched_common_normal_traffic_template"]}},
            }
            stored = memory.record_case(incident, result, {"source": "test", "path": "sample"})
            self.assertEqual(stored["effective_label"], "benign")
            found = memory.search_similar(incident, limit=3)
            self.assertGreaterEqual(len(found), 1)

            corrected = memory.apply_manual_correction(stored["case_id"], "false_positive", "confirmed by analyst")
            self.assertEqual(corrected["effective_label"], "false_positive")
            feedback = memory.historical_feedback(incident)
            self.assertTrue(feedback["has_false_positive_pattern"])


if __name__ == "__main__":
    unittest.main()
