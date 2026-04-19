from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List

try:
    from colorama import Fore, Style
except Exception:  # pragma: no cover - graceful fallback when colorama unavailable
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""

    class _NoStyle:
        RESET_ALL = ""

    Fore = _NoColor()
    Style = _NoStyle()

from ..auditory import RuntimeAuditory
from ..domain.config import ModelConfig, MultiAgentConfig, PlannerConfig, RuleGenerationConfig
from ..engine.planner import StateDrivenPlanner
from ..services.action_generator import ActionGenerator
from ..services.auditor import DecisionAuditor
from ..services.case_memory import LocalCaseMemory
from ..services.ingestion import DataIngestion
from ..services.llm_client import LLMClient
from ..services.rag import ThreatIntelligenceRetrieval
from ..services.response_generator import ResponseGenerator
from ..services.rule_generation import RuleGenerationEngine
from ..services.state_estimator import StateEstimator
from .layered_agents import ProfessionalLayeredAgents
from .skill_engine import BackendSkillEngine


def _tokenize(text: str) -> List[str]:
    return [t.strip(".,:;()[]{}\"'").lower() for t in text.split() if t.strip()]


def _action_log_match(action_text: str, logs: List[str]) -> float:
    action_tokens = set(_tokenize(action_text))
    if not action_tokens:
        return 0.0
    log_tokens = set()
    for line in logs:
        log_tokens.update(_tokenize(line))
    overlap = action_tokens.intersection(log_tokens)
    return round(len(overlap) / max(1, len(action_tokens)), 3)


def _format_runtime_line(agent: str, status: str, details: str = "") -> str:
    label = f"{agent:<11}"
    tail = f" | {details}" if details else ""
    return f"{label} {status}{tail}"


def _format_progress_event(message: str) -> str:
    if message.startswith("sample_load_start"):
        return _format_runtime_line("INGEST", "START", "loading incident sample")
    if message.startswith("sample_load_done"):
        details = message.replace("sample_load_done ", "", 1)
        return _format_runtime_line("INGEST", "DONE ", details)
    if message == "rag_start":
        return _format_runtime_line("RAG", "START", "retrieving evidence")
    if message.startswith("rag_done"):
        details = message.replace("rag_done ", "", 1)
        return _format_runtime_line("RAG", "DONE ", details)
    if message == "layered_agents_start":
        return _format_runtime_line("IDENTIFIER", "START", "building layered threat view")
    if message.startswith("layered_agents_done"):
        details = message.replace("layered_agents_done ", "", 1)
        return _format_runtime_line("ANALYST", "DONE ", details)
    if message == "state_estimation_start":
        return _format_runtime_line("STATE", "START", "estimating 6D posture")
    if message.startswith("state_estimation_done"):
        details = message.replace("state_estimation_done ", "", 1)
        return _format_runtime_line("STATE", "DONE ", details)
    if message == "rule_generation_start":
        return _format_runtime_line("RULEGEN", "START", "generating adaptive rules")
    if message.startswith("rule_generation_done"):
        details = message.replace("rule_generation_done ", "", 1)
        return _format_runtime_line("RULEGEN", "DONE ", details)
    if message == "candidate_generation_start":
        return _format_runtime_line("RESPONDER", "START", "building candidate actions")
    if message.startswith("candidate_generation_done"):
        details = message.replace("candidate_generation_done ", "", 1)
        return _format_runtime_line("RESPONDER", "DONE ", details)
    if message == "planning_start":
        return _format_runtime_line("PLANNER", "START", "state-driven rollout")
    if message.startswith("planning_action_start"):
        details = message.replace("planning_action_start ", "", 1)
        return _format_runtime_line("PLANNER", "ACTION", details)
    if message.startswith("planning_rollout_done"):
        details = message.replace("planning_rollout_done ", "", 1)
        return _format_runtime_line("PLANNER", "ROLLOUT", details)
    if message.startswith("planning_action_done"):
        details = message.replace("planning_action_done ", "", 1)
        return _format_runtime_line("PLANNER", "SCORE ", details)
    if message.startswith("planning_action_early_stop"):
        details = message.replace("planning_action_early_stop ", "", 1)
        return _format_runtime_line("PLANNER", "STOP  ", details)
    if message.startswith("planning_done"):
        details = message.replace("planning_done ", "", 1)
        return _format_runtime_line("PLANNER", "DONE ", details)
    if message == "response_generation_start":
        return _format_runtime_line("RESPONDER", "START", "assembling response plan")
    if message.startswith("response_generation_done"):
        details = message.replace("response_generation_done ", "", 1)
        return _format_runtime_line("RESPONDER", "DONE ", details)
    if message == "audit_start":
        return _format_runtime_line("AUDITOR", "START", "verifying decision")
    if message.startswith("audit_done"):
        details = message.replace("audit_done ", "", 1)
        return _format_runtime_line("AUDITOR", "DONE ", details)
    if message.startswith("audit_log_written"):
        details = message.replace("audit_log_written ", "", 1)
        return _format_runtime_line("AUDIT-LOG", "WRITE", details)
    if message.startswith("case_memory_stored"):
        details = message.replace("case_memory_stored ", "", 1)
        return _format_runtime_line("CASE-MEM", "WRITE", details)
    return _format_runtime_line("FLOW", "INFO ", message)


def _clamp01(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 4)


def _build_confidence_model(result: Dict) -> Dict:
    rag = result.get("rag", {}) or {}
    response = result.get("response", {}) or {}
    audit = result.get("audit", {}) or {}
    agent_layers = result.get("agent_layers", {}) or {}
    ranked = response.get("ranked_actions", []) or []
    top_ranked = ranked[0] if ranked else {}
    top_priority = ((agent_layers.get("prioritized_threats", []) or [{}])[0] if isinstance(agent_layers, dict) else {})

    top_rule_conf = max([float(x.get("confidence", 0.0)) for x in rag.get("rule_findings", [])] or [0.0])
    top_cve_sev = max([float(x.get("severity", 0.0)) / 10.0 for x in rag.get("cve_findings", [])] or [0.0])
    top_priority_score = float(top_priority.get("priority_score", 0.0))
    detection_confidence = _clamp01(max(top_rule_conf, top_cve_sev, min(1.0, top_priority_score)))

    best_score = float(top_ranked.get("score", 0.0))
    validation_bonus = 0.15 if top_ranked.get("validation_passed", False) else 0.0
    hallucination_penalty = 0.2 if top_ranked.get("hallucination_flag", False) else 0.0
    response_confidence = _clamp01(0.55 + min(0.3, max(0.0, best_score + 25.0) / 100.0) + validation_bonus - hallucination_penalty)

    audit_result = str(audit.get("audit_result", "unknown")).lower()
    audit_factor = {"pass": 1.0, "review": 0.65, "warn": 0.55, "fail": 0.25}.get(audit_result, 0.45)
    execution_confidence = _clamp01(response_confidence * audit_factor)

    return {
        "detection_confidence": detection_confidence,
        "response_confidence": response_confidence,
        "execution_confidence": execution_confidence,
        "audit_factor": audit_factor,
    }


def _build_evidence_trace_tree(result: Dict) -> Dict:
    incident = result.get("incident", {}) or {}
    rag = result.get("rag", {}) or {}
    agent_layers = result.get("agent_layers", {}) or {}
    confidence_model = result.get("confidence_model", {}) or {}

    nodes: List[Dict] = []
    for item in (rag.get("rule_findings", []) or [])[:3]:
        nodes.append(
            {
                "type": "rule",
                "label": item.get("rule_id", ""),
                "confidence": item.get("confidence", 0.0),
                "severity": item.get("severity", 0.0),
                "evidence_id": item.get("evidence_id", ""),
                "support": item.get("title", "") or item.get("pattern", ""),
            }
        )
    for item in (rag.get("cve_findings", []) or [])[:2]:
        nodes.append(
            {
                "type": "cve",
                "label": item.get("cve", ""),
                "confidence": item.get("severity", 0.0),
                "severity": item.get("severity", 0.0),
                "evidence_id": item.get("evidence_id", ""),
                "support": item.get("description", "") or item.get("threat", ""),
            }
        )
    for item in (rag.get("ioc_findings", []) or [])[:3]:
        nodes.append(
            {
                "type": "ioc",
                "label": item.get("ioc", item.get("source_url", "")),
                "confidence": item.get("confidence", 0.0),
                "severity": item.get("severity", 0.0),
                "evidence_id": item.get("evidence_id", ""),
                "support": item.get("threat", "") or item.get("snippet", ""),
            }
        )
    log_nodes = [
        {"type": "raw_log", "label": f"log#{idx+1}", "support": line[:180]}
        for idx, line in enumerate((incident.get("raw_logs", []) or [])[:3])
    ]
    top_threat = ((agent_layers.get("prioritized_threats", []) or [{}])[0] if isinstance(agent_layers, dict) else {})
    return {
        "root": {
            "event_summary": incident.get("event_summary", ""),
            "top_threat": top_threat.get("threat", ""),
            "detection_confidence": confidence_model.get("detection_confidence", 0.0),
        },
        "supporting_nodes": nodes,
        "log_nodes": log_nodes,
        "downgrade_reasons": ((rag.get("rag_context", {}) or {}).get("downgrade_reasons", []) or []),
    }


def _build_observability_snapshot(result: Dict) -> Dict:
    trace = (result.get("skill_runtime", {}) or {}).get("execution_trace", []) or []
    response = result.get("response", {}) or {}
    ranked = response.get("ranked_actions", []) or []
    early_stop_count = sum(
        1 for item in ranked if ((item.get("execution_meta", {}) or {}).get("early_stopped", False))
    )
    return {
        "stage_elapsed_ms": {item.get("stage", f"stage_{idx}"): int(item.get("elapsed_ms", "0") or 0) for idx, item in enumerate(trace)},
        "cache_hit": {
            "rag": bool(((result.get("rag", {}) or {}).get("rag_context", {}) or {}).get("cache_hit", False)),
            "layered_agents": bool((result.get("agent_layers", {}) or {}).get("cache_hit", False)),
        },
        "planner": {
            "early_stop_count": early_stop_count,
            "ranked_action_count": len(ranked),
        },
    }


def _confidence_level(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def _confidence_label(score: float) -> str:
    return {"high": "高", "medium": "中", "low": "低"}[_confidence_level(score)]


def _build_frontend_explainability(result: Dict) -> Dict:
    incident = result.get("incident", {}) or {}
    rag = result.get("rag", {}) or {}
    response = result.get("response", {}) or {}
    audit = result.get("audit", {}) or {}
    confidence = result.get("confidence_model", {}) or {}
    evidence_tree = result.get("evidence_trace_tree", {}) or {}
    observability = result.get("observability", {}) or {}
    agent_layers = result.get("agent_layers", {}) or {}

    detection = float(confidence.get("detection_confidence", 0.0))
    response_conf = float(confidence.get("response_confidence", 0.0))
    execution = float(confidence.get("execution_confidence", 0.0))

    top_rule = max([float(x.get("confidence", 0.0)) for x in rag.get("rule_findings", [])] or [0.0])
    top_cve = max([float(x.get("severity", 0.0)) / 10.0 for x in rag.get("cve_findings", [])] or [0.0])
    top_ioc = max([float(x.get("confidence", 0.0)) for x in rag.get("ioc_findings", [])] or [0.0])
    audit_factor = float(confidence.get("audit_factor", 0.0))

    graph_nodes: List[Dict[str, Any]] = []
    graph_edges: List[Dict[str, Any]] = []
    root = evidence_tree.get("root", {}) or {}
    root_id = "event-root"
    graph_nodes.append(
        {
            "id": root_id,
            "type": "incident",
            "label": root.get("event_summary", "")[:96],
            "title": "事件根节点",
            "subtitle": root.get("top_threat", ""),
            "severity": _confidence_level(detection),
            "meta": {
                "detection_confidence": root.get("detection_confidence", 0.0),
                "asset_count": len(incident.get("affected_assets", []) or []),
            },
        }
    )
    for idx, node in enumerate((evidence_tree.get("supporting_nodes", []) or []), start=1):
        node_id = f"support-{idx}"
        graph_nodes.append(
            {
                "id": node_id,
                "type": node.get("type", "evidence"),
                "label": node.get("label", ""),
                "title": node.get("support", ""),
                "subtitle": f"confidence={node.get('confidence', 0.0)}",
                "severity": _confidence_level(float(node.get("confidence", 0.0))),
                "meta": {
                    "evidence_id": node.get("evidence_id", ""),
                    "severity": node.get("severity", 0.0),
                },
            }
        )
        graph_edges.append({"from": root_id, "to": node_id, "relation": "supports"})
    for idx, node in enumerate((evidence_tree.get("log_nodes", []) or []), start=1):
        node_id = f"log-{idx}"
        graph_nodes.append(
            {
                "id": node_id,
                "type": "log",
                "label": node.get("label", ""),
                "title": node.get("support", ""),
                "subtitle": "raw_log",
                "severity": "low",
                "meta": {},
            }
        )
        graph_edges.append({"from": root_id, "to": node_id, "relation": "observed_in"})

    downgrade_details = ((rag.get("rag_context", {}) or {}).get("downgrade_reason_details", []) or [])
    history_feedback = ((rag.get("rag_context", {}) or {}).get("historical_case_feedback", {}) or {})
    hunt_queries = (agent_layers.get("hunt_queries", []) or [])[:3] if isinstance(agent_layers, dict) else []
    best_action = response.get("best_action", {}) or {}
    return {
        "schema_version": "v1",
        "summary_cards": [
            {"key": "top_threat", "label": "首要威胁", "value": root.get("top_threat", ""), "tone": "danger"},
            {"key": "recommended_action", "label": "推荐动作", "value": best_action.get("action_name", ""), "tone": "primary"},
            {"key": "audit_result", "label": "审计结果", "value": audit.get("audit_result", "unknown"), "tone": "info"},
            {"key": "execution_allowed", "label": "是否可执行", "value": "是" if result.get("execution_allowed", False) else "否", "tone": "success" if result.get("execution_allowed", False) else "warning"},
        ],
        "confidence_panel": {
            "scores": {
                "detection_confidence": detection,
                "response_confidence": response_conf,
                "execution_confidence": execution,
            },
            "levels": {
                "detection_confidence": _confidence_label(detection),
                "response_confidence": _confidence_label(response_conf),
                "execution_confidence": _confidence_label(execution),
            },
            "breakdown": [
                {"key": "rule_confidence", "label": "规则证据强度", "value": round(top_rule, 4), "weight": "high"},
                {"key": "cve_severity", "label": "CVE严重度归一化", "value": round(top_cve, 4), "weight": "medium"},
                {"key": "ioc_confidence", "label": "IOC置信度", "value": round(top_ioc, 4), "weight": "medium"},
                {"key": "audit_factor", "label": "审计系数", "value": round(audit_factor, 4), "weight": "high"},
            ],
        },
        "evidence_graph": {
            "root_id": root_id,
            "nodes": graph_nodes,
            "edges": graph_edges,
            "legend": {
                "incident": "事件",
                "rule": "规则",
                "cve": "漏洞",
                "ioc": "IOC",
                "log": "日志片段",
            },
        },
        "downgrade_explanations": [
            {
                "code": item.get("code", ""),
                "title": item.get("title", ""),
                "description": item.get("description", ""),
                "severity": item.get("severity", "low"),
                "display": item.get("title", ""),
            }
            for item in downgrade_details
        ],
        "review_checklist": [
            {"key": "check_top_threat", "label": "确认首要威胁是否符合人工研判", "status": "todo"},
            {"key": "check_action", "label": "确认推荐动作与资产影响范围", "status": "todo"},
            {"key": "check_evidence", "label": "复核关键证据节点与原始日志", "status": "todo"},
        ],
        "timeline": [
            {"id": "tl-1", "stage": "detection", "label": "威胁检测", "value": f"规则={len(rag.get('rule_findings', []) or [])} / CVE={len(rag.get('cve_findings', []) or [])}"},
            {"id": "tl-2", "stage": "analysis", "label": "威胁分析", "value": f"优先威胁={len((agent_layers.get('prioritized_threats', []) or []) if isinstance(agent_layers, dict) else [])}"},
            {"id": "tl-3", "stage": "response", "label": "响应规划", "value": best_action.get("action_name", "")},
            {"id": "tl-4", "stage": "audit", "label": "执行审计", "value": audit.get("audit_result", "unknown")},
        ],
        "hunt_query_tabs": [
            {
                "id": f"hunt-{idx+1}",
                "title": item.get("threat", ""),
                "stage": item.get("stage", ""),
                "sql": ((item.get("templates", {}) or {}).get("sql", "")),
                "elasticsearch_dsl": ((item.get("templates", {}) or {}).get("elasticsearch_dsl", {})),
                "splunk_spl": ((item.get("templates", {}) or {}).get("splunk_spl", "")),
            }
            for idx, item in enumerate(hunt_queries)
        ],
        "observability_panel": {
            "cache_hit": observability.get("cache_hit", {}),
            "planner": observability.get("planner", {}),
            "stage_elapsed_ms": observability.get("stage_elapsed_ms", {}),
        },
        "historical_case_panel": {
            "has_false_positive_pattern": bool(history_feedback.get("has_false_positive_pattern", False)),
            "benign_like_count": int(history_feedback.get("benign_like_count", 0)),
            "malicious_like_count": int(history_feedback.get("malicious_like_count", 0)),
            "cases": [
                {
                    "case_id": item.get("case_id", ""),
                    "score": item.get("score", 0),
                    "effective_label": item.get("effective_label", ""),
                    "top_threat": item.get("top_threat", ""),
                    "best_action": item.get("best_action", ""),
                }
                for item in (history_feedback.get("similar_cases", []) or [])[:5]
            ],
        },
    }


def _build_frontend_payload(result: Dict) -> Dict:
    incident = result.get("incident", {}) or {}
    response = result.get("response", {}) or {}
    frontend_explainability = result.get("frontend_explainability", {}) or {}
    case_memory = result.get("case_memory", {}) or {}
    executable = response.get("executable", {}) or {}
    orchestration = executable.get("orchestration", {}) or {}

    return {
        "schema_version": "frontend-payload/v1",
        "page_title": "安全事件研判面板",
        "incident_overview": {
            "event_summary": incident.get("event_summary", ""),
            "affected_assets": incident.get("affected_assets", []),
            "ioc": incident.get("ioc", {}),
            "timestamp": incident.get("timestamp", ""),
            "source": (result.get("input_meta", {}) or {}).get("source", "unknown"),
        },
        "cards": frontend_explainability.get("summary_cards", []),
        "confidence": frontend_explainability.get("confidence_panel", {}),
        "evidence": frontend_explainability.get("evidence_graph", {}),
        "downgrade": frontend_explainability.get("downgrade_explanations", []),
        "timeline": frontend_explainability.get("timeline", []),
        "checklist": frontend_explainability.get("review_checklist", []),
        "hunt": {
            "tabs": frontend_explainability.get("hunt_query_tabs", []),
            "count": len(frontend_explainability.get("hunt_query_tabs", []) or []),
        },
        "execution": {
            "mode": executable.get("mode", ""),
            "guardrails": executable.get("guardrails", []),
            "playbook": executable.get("playbook", {}),
            "tasks": executable.get("tasks", []),
            "countermeasures": executable.get("countermeasures", []),
            "summary": executable.get("summary", {}),
        },
        "orchestration": {
            "graph_id": orchestration.get("graph_id", ""),
            "strategy": orchestration.get("strategy", ""),
            "nodes": orchestration.get("nodes", []),
            "edges": orchestration.get("edges", []),
            "approval_nodes": orchestration.get("approval_nodes", []),
            "rollback_plan": orchestration.get("rollback_plan", {}),
            "execution_order": orchestration.get("execution_order", []),
        },
        "case_memory": {
            "stored": bool(case_memory.get("stored", False)),
            "case_id": case_memory.get("case_id", ""),
            "effective_label": case_memory.get("effective_label", ""),
            "storage_file": case_memory.get("storage_file", ""),
            "historical_panel": frontend_explainability.get("historical_case_panel", {}),
        },
        "observability": frontend_explainability.get("observability_panel", {}),
    }


def build_concise_view(result: Dict) -> Dict:
    incident = result["incident"]
    state = result["state"]
    rag = result["rag"]
    response = result["response"]
    audit = result["audit"]
    confidence_model = result.get("confidence_model", {}) or {}
    evidence_tree = result.get("evidence_trace_tree", {}) or {}

    ranked = response.get("ranked_actions", [])
    top_actions = []
    for item in ranked[:3]:
        action = item["action"]
        match_score = _action_log_match(
            f"{action.get('action_name', '')} {action.get('description', '')} {action.get('reasoning', '')}",
            incident.get("raw_logs", []),
        )
        top_actions.append(
            {
                "action_id": action.get("action_id"),
                "action_name": action.get("action_name"),
                "target_stage": action.get("target_stage"),
                "score": round(item.get("score", 0.0), 3),
                "progress_gain": item.get("progress_gain", 0.0),
                "projected_recovery_time": item.get("projected_recovery_time", 0.0),
                "log_match_score": match_score,
                "hallucination_flag": item.get("hallucination_flag", False),
                "validation_passed": item.get("validation_passed", False),
            }
        )

    best = response.get("best_action", {})
    projected = response.get("expected_recovery_effect", {})
    trace = result.get("skill_runtime", {}).get("execution_trace", [])
    rule_gen = result.get("rule_generation", {})
    agent_layers = result.get("agent_layers", {})
    prioritized = agent_layers.get("prioritized_threats", []) if isinstance(agent_layers, dict) else []
    top_threat = prioritized[0] if prioritized else {}
    hunt_queries = agent_layers.get("hunt_queries", []) if isinstance(agent_layers, dict) else []
    case_memory = result.get("case_memory", {}) or {}
    hunt_preview = []
    for item in hunt_queries[:2]:
        templates = item.get("templates", {}) or {}
        hunt_preview.append(
            {
                "stage": item.get("stage", ""),
                "threat": item.get("threat", ""),
                "sql": str(templates.get("sql", ""))[:180],
                "splunk_spl": str(templates.get("splunk_spl", ""))[:180],
            }
        )
    execution_pkg = response.get("executable", {}) or {}
    frontend_explainability = result.get("frontend_explainability", {}) or {}

    return {
        "结论": {
            "可执行": result.get("execution_allowed", False),
            "审计结果": audit.get("audit_result", "unknown"),
            "推荐动作": best.get("action_name", ""),
            "推荐阶段": best.get("target_stage", ""),
            "预计恢复增益": projected.get("projected_gain_best_action", 0.0),
            "预计恢复时间(分钟)": projected.get("projected_recovery_time_minutes", 0.0),
        },
        "数据来源": result.get("input_meta", {"source": "json"}),
        "研判摘要": {
            "事件": incident.get("event_summary", ""),
            "资产": ", ".join(incident.get("affected_assets", [])),
            "情报模式": rag.get("summary", ""),
            "IOC数量": {
                "ip": len(incident.get("ioc", {}).get("ip", [])),
                "domain": len(incident.get("ioc", {}).get("domain", [])),
                "cve": len(incident.get("ioc", {}).get("cve", [])),
                "process": len(incident.get("ioc", {}).get("process", [])),
            },
            "规则命中数": len(rag.get("rule_findings", [])),
            "相似案例数": len((rag.get("rag_context", {}) or {}).get("similar_cases", [])),
            "状态短板": sorted(
                [
                    ("containment", state.get("containment", 0.0)),
                    ("assessment", state.get("assessment", 0.0)),
                    ("preservation", state.get("preservation", 0.0)),
                    ("eviction", state.get("eviction", 0.0)),
                    ("hardening", state.get("hardening", 0.0)),
                    ("restoration", state.get("restoration", 0.0)),
                ],
                key=lambda x: x[1],
            )[:2],
        },
        "动作对比Top3": top_actions,
        "执行适配": {
            "mode": execution_pkg.get("mode", ""),
            "task_count": len(execution_pkg.get("tasks", []) or []),
            "guardrails": execution_pkg.get("guardrails", [])[:3],
            "rollback_hint": ((execution_pkg.get("playbook", {}) or {}).get("rollback_hint", "")),
            "orchestration": {
                "graph_id": ((execution_pkg.get("orchestration", {}) or {}).get("graph_id", "")),
                "node_count": len(((execution_pkg.get("orchestration", {}) or {}).get("nodes", []) or [])),
                "approval_count": len(((execution_pkg.get("orchestration", {}) or {}).get("approval_nodes", []) or [])),
                "rollback_task_count": len((((execution_pkg.get("orchestration", {}) or {}).get("rollback_plan", {}) or {}).get("tasks", []) or [])),
            },
        },
        "运行状态": {
            "已加载技能数": len(result.get("skill_runtime", {}).get("loaded_skills", [])),
            "执行阶段数": len(trace),
            "阶段链路": [f"{x.get('stage')}:{x.get('status')}" for x in trace],
            "规则生成": {
                "启用": rule_gen.get("enabled", False),
                "原因": rule_gen.get("reason", ""),
                "provider": rule_gen.get("provider", ""),
                "CVE任务数": len(rule_gen.get("results", [])),
            },
            "专业分层代理": {
                "启用": bool(agent_layers.get("enabled", False)),
                "识别威胁数": len(agent_layers.get("identified_threats", [])) if isinstance(agent_layers, dict) else 0,
                "优先威胁数": len(prioritized),
                "猎捕查询数": len(agent_layers.get("hunt_queries", [])) if isinstance(agent_layers, dict) else 0,
                "首要威胁": top_threat.get("threat", ""),
            },
            "可观测性": result.get("observability", {}),
            "审计日志文件": result.get("audit_log_file", ""),
        },
        "置信度模型": confidence_model,
        "证据溯源": {
            "根事件": evidence_tree.get("root", {}),
            "支撑节点数": len(evidence_tree.get("supporting_nodes", []) or []),
            "降级原因": evidence_tree.get("downgrade_reasons", []),
        },
        "前端解释": {
            "摘要卡片数": len(frontend_explainability.get("summary_cards", []) or []),
            "证据图节点数": len(((frontend_explainability.get("evidence_graph", {}) or {}).get("nodes", []) or [])),
            "降级说明数": len(frontend_explainability.get("downgrade_explanations", []) or []),
            "查询标签页数": len(frontend_explainability.get("hunt_query_tabs", []) or []),
        },
        "前端载荷": {
            "schema_version": ((result.get("frontend_payload", {}) or {}).get("schema_version", "")),
            "sections": list((result.get("frontend_payload", {}) or {}).keys()),
        },
        "案例记忆库": {
            "stored": bool(case_memory.get("stored", False)),
            "case_id": case_memory.get("case_id", ""),
            "effective_label": case_memory.get("effective_label", ""),
            "memory_similar_cases": len((((result.get("rag", {}) or {}).get("rag_context", {}) or {}).get("historical_case_feedback", {}) or {}).get("similar_cases", [])),
        },
        "猎捕模板": {
            "查询数": len(hunt_queries),
            "预览": hunt_preview,
        },
    }


@dataclass
class BackendWorkflow:
    project_root: str
    model_config: ModelConfig
    planner_config: PlannerConfig
    multi_agent_config: MultiAgentConfig
    rule_generation_config: RuleGenerationConfig

    @classmethod
    def from_runtime(cls, project_root: str) -> "BackendWorkflow":
        return cls(
            project_root=project_root,
            model_config=ModelConfig.from_env(),
            planner_config=PlannerConfig.from_env(),
            multi_agent_config=MultiAgentConfig.from_env(),
            rule_generation_config=RuleGenerationConfig.from_env(),
        )

    def run(
        self,
        input_file: str,
        incident_meta: Dict,
        preloaded_incident=None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> dict:
        def emit(message: str, color: str = "cyan") -> None:
            if not progress_callback:
                return
            palette = {
                "blue": Fore.BLUE,
                "cyan": Fore.CYAN,
                "green": Fore.GREEN,
                "yellow": Fore.YELLOW,
                "red": Fore.RED,
                "magenta": Fore.MAGENTA,
            }
            prefix = palette.get(color, Fore.CYAN)
            progress_callback(f"{prefix}{_format_progress_event(message)}{Style.RESET_ALL}")

        skill_engine = BackendSkillEngine(project_root=self.project_root)
        skill_engine.verify_required()

        if not hasattr(self, "_runtime_components"):
            llm_client = LLMClient(self.model_config)
            action_generator = ActionGenerator(planner_config=self.planner_config, llm_client=llm_client)
            self._runtime_components = {
                "ingest": DataIngestion(),
                "estimator": StateEstimator(),
                "llm_client": llm_client,
                "rag": ThreatIntelligenceRetrieval(model_config=self.model_config, llm_client=llm_client),
                "action_generator": action_generator,
                "planner": StateDrivenPlanner(
                    config=self.planner_config,
                    action_generator=action_generator,
                    llm_client=llm_client,
                ),
                "rule_generator": RuleGenerationEngine(
                    model_config=self.model_config,
                    config=self.rule_generation_config,
                    llm_client=llm_client,
                ),
                "responder": ResponseGenerator(),
                "auditor": DecisionAuditor(),
                "runtime_auditory": RuntimeAuditory(project_root=self.project_root),
                "layered_agents": ProfessionalLayeredAgents(),
                "case_memory": LocalCaseMemory(),
            }
        components = self._runtime_components
        ingest = components["ingest"]
        estimator = components["estimator"]
        rag = components["rag"]
        action_generator = components["action_generator"]
        planner = components["planner"]
        rule_generator = components["rule_generator"]
        responder = components["responder"]
        auditor = components["auditor"]
        runtime_auditory = components["runtime_auditory"]
        layered_agents = components["layered_agents"]
        case_memory = components["case_memory"]

        emit(f"sample_load_start source={incident_meta.get('source', 'json')}", "blue")
        incident = preloaded_incident or skill_engine.run_stage("triage", ingest.load_from_json, input_file)
        if preloaded_incident:
            skill_engine.trace.append({"stage": "triage", "skill": "soc-incident-triage", "status": "executed"})
        emit(
            f"sample_load_done assets={len(incident.affected_assets)}; raw_logs={len(incident.raw_logs)}; "
            f"summary={incident.event_summary[:72]}",
            "green",
        )
        emit("rag_start", "blue")
        intel = skill_engine.run_stage("rag", rag.retrieve, incident)
        emit(
            f"rag_done rules={len(intel.rule_findings)}; cves={len(intel.cve_findings)}; "
            f"iocs={len(intel.ioc_findings)}; assets={len(intel.asset_findings)}; "
            f"cache_hit={bool((intel.rag_context or {}).get('cache_hit', False))}",
            "green",
        )
        emit("layered_agents_start", "blue")
        agent_layers = layered_agents.run(incident, intel)
        emit(
            f"layered_agents_done identified={len(agent_layers.get('identified_threats', []))}; "
            f"prioritized={len(agent_layers.get('prioritized_threats', []))}; "
            f"hunt_queries={len(agent_layers.get('hunt_queries', []))}; "
            f"cache_hit={bool(agent_layers.get('cache_hit', False))}",
            "green",
        )
        emit("state_estimation_start", "blue")
        state = skill_engine.run_stage("triage", estimator.estimate, incident, intel.rag_context)
        emit(
            f"state_estimation_done containment={state.containment:.2f}; assessment={state.assessment:.2f}; "
            f"preservation={state.preservation:.2f}",
            "green",
        )
        rule_gen_begin = time.perf_counter()
        emit("rule_generation_start", "blue")
        generated_rules = rule_generator.generate_for_incident(incident=incident, intel=intel)
        generated_rules["elapsed_ms"] = int((time.perf_counter() - rule_gen_begin) * 1000)
        emit(
            f"rule_generation_done reason={generated_rules.get('reason', '')}; "
            f"tasks={len(generated_rules.get('results', []))}; "
            f"elapsed_ms={generated_rules.get('elapsed_ms', 0)}",
            "green",
        )

        history_actions = []
        emit("candidate_generation_start", "blue")
        candidates = action_generator.generate(incident, state, history_actions, intel, use_llm=False)
        if not candidates:
            raise RuntimeError("No valid candidate actions after policy filtering.")
        emit(f"candidate_generation_done count={len(candidates)}", "green")

        emit("planning_start", "blue")
        planning_result = skill_engine.run_stage(
            "planning",
            planner.plan,
            incident,
            state,
            history_actions,
            intel,
            candidates,
            progress_callback=lambda msg: emit(msg, "yellow"),
        )
        ranked = planning_result.ranked_actions
        if not ranked:
            raise RuntimeError("No ranked actions from planning engine.")
        emit(
            f"planning_done ranked={len(ranked)}; best_action={ranked[0].action.action_name}; "
            f"best_score={ranked[0].score:.3f}",
            "green",
        )

        emit("response_generation_start", "blue")
        response_plan = responder.generate(incident, state, intel, ranked)
        emit(
            f"response_generation_done best_action={response_plan.best_action.action_name}; "
            f"stage={response_plan.best_action.target_stage}",
            "green",
        )
        emit("audit_start", "blue")
        audit = skill_engine.run_stage(
            "audit",
            auditor.audit,
            incident,
            state,
            intel,
            response_plan,
            ranked,
            action_generator.last_filter_audit,
        )

        execution_allowed = audit["audit_result"] != "fail"
        response_plan_dict = response_plan.to_dict()
        executable = response_plan_dict["executable"] if execution_allowed else {
            "mode": "blocked",
            "shell": "",
            "api": "",
            "playbook": {},
            "tasks": [],
            "guardrails": ["audit_result=fail，禁止自动执行"],
            "target_assets": [],
            "capability_tags": [],
            "summary": {"action_name": response_plan.best_action.action_name, "stage": response_plan.best_action.target_stage},
        }
        draft_result = {
            "incident": incident.to_dict(),
            "rag": intel.to_dict(),
            "response": {**response_plan_dict, "executable": executable},
            "audit": audit,
            "agent_layers": agent_layers,
            "skill_runtime": skill_engine.runtime_info(),
        }
        confidence_model = _build_confidence_model(draft_result)
        emit(
            f"audit_done result={audit.get('audit_result', 'unknown')}; "
            f"execution_allowed={execution_allowed}; "
            f"execution_confidence={confidence_model.get('execution_confidence', 0.0)}",
            "green" if execution_allowed else "red",
        )

        result = {
            "incident": incident.to_dict(),
            "state": state.to_dict(),
            "rag": intel.to_dict(),
            "response": {
                **response_plan_dict,
                "executable": executable,
                "planning_explanation": planning_result.planning_explanation,
            },
            "audit": audit,
            "execution_allowed": execution_allowed,
            "model_runtime": {
                "provider": self.model_config.provider,
                "model_name": self.model_config.model_name,
                "endpoint": self.model_config.endpoint,
            },
            "skill_runtime": skill_engine.runtime_info(),
            "multi_agent": {
                "enabled": False,
                "converged": False,
                "selected_action_id": ranked[0].action.action_id if ranked else "",
                "rounds": [],
                "reason": "state_driven_planning",
                "elapsed_ms": 0,
            },
            "agent_layers": agent_layers,
            "confidence_model": confidence_model,
            "rule_generation": generated_rules,
            "input_meta": incident_meta,
        }
        result["evidence_trace_tree"] = _build_evidence_trace_tree(result)
        result["observability"] = _build_observability_snapshot(result)
        result["frontend_explainability"] = _build_frontend_explainability(result)
        stored_case = case_memory.record_case(incident=incident, result=result, incident_meta=incident_meta)
        result["case_memory"] = {
            "stored": True,
            "case_id": stored_case.get("case_id", ""),
            "effective_label": stored_case.get("effective_label", ""),
            "storage_file": case_memory.stats().get("storage_file", ""),
        }
        result["frontend_payload"] = _build_frontend_payload(result)
        emit(
            f"case_memory_stored case_id={result['case_memory']['case_id']}; "
            f"label={result['case_memory']['effective_label']}",
            "magenta",
        )

        audit_payload = {
            "incident_meta": incident_meta,
            "rag_summary": {
                "summary": intel.summary,
                "matched_iocs": len(intel.ioc_findings),
                "matched_cves": len(intel.cve_findings),
                "matched_rules": len(intel.rule_findings),
                "similar_cases": len((intel.rag_context or {}).get("similar_cases", [])),
            },
            "state_snapshot": state.to_dict(),
            "candidates_raw": [x.to_dict() for x in candidates],
            "filter_audit": action_generator.last_filter_audit,
            "planning_trace": audit.get("planning_trace", []),
            "scores": audit.get("scores", []),
            "best_action_reason": audit.get("best_action_selection_reason", ""),
            "final_output": {
                "audit_result": audit.get("audit_result", "unknown"),
                "execution_allowed": execution_allowed,
                "best_action": response_plan.best_action.to_dict(),
                "confidence_model": confidence_model,
            },
            "agent_layers": agent_layers,
            "evidence_trace_tree": result["evidence_trace_tree"],
            "observability": result["observability"],
            "frontend_explainability": result["frontend_explainability"],
            "frontend_payload": result["frontend_payload"],
            "case_memory": result["case_memory"],
            "result": result,
        }
        result["audit_log_file"] = runtime_auditory.write_full_run(audit_payload)
        emit(f"audit_log_written path={result['audit_log_file']}", "magenta")
        return result


def run_pipeline(input_file: str) -> dict:
    incident_meta = {"source": "json", "path": input_file}
    project_root = str(Path(__file__).resolve().parents[3])
    workflow = BackendWorkflow.from_runtime(project_root=project_root)
    return workflow.run(input_file=input_file, incident_meta=incident_meta)


def run_pipeline_dataset(dataset_file: str, sample_index: int) -> dict:
    project_root = str(Path(__file__).resolve().parents[3])
    ingest = DataIngestion()
    incident, meta = ingest.load_from_dataset_json(dataset_file, sample_index)
    meta = {**meta, "path": dataset_file}
    workflow = BackendWorkflow.from_runtime(project_root=project_root)
    return workflow.run(input_file=dataset_file, incident_meta=meta, preloaded_incident=incident)


def run_pipeline_csv_dataset(csv_file: str, row_index: int) -> dict:
    project_root = str(Path(__file__).resolve().parents[3])
    ingest = DataIngestion()
    incident, meta = ingest.load_from_csv_row(csv_file, row_index)
    meta = {**meta, "path": csv_file}
    workflow = BackendWorkflow.from_runtime(project_root=project_root)
    return workflow.run(input_file=csv_file, incident_meta=meta, preloaded_incident=incident)


def run_stress_test(
    dataset_file: str,
    mode: str,
    max_samples: int,
    start_index: int = 0,
) -> Dict:
    project_root = str(Path(__file__).resolve().parents[3])
    workflow = BackendWorkflow.from_runtime(project_root=project_root)
    ingest = DataIngestion()

    if mode == "csv":
        total = ingest.count_csv_rows(dataset_file)
    else:
        total = ingest.count_dataset_samples(dataset_file)

    end_index = min(total, start_index + max(1, max_samples))
    success = 0
    failed = 0
    elapsed_list = []
    samples = []

    for idx in range(start_index, end_index):
        begin = time.perf_counter()
        try:
            if mode == "csv":
                incident, meta = ingest.load_from_csv_row(dataset_file, idx)
            else:
                incident, meta = ingest.load_from_dataset_json(dataset_file, idx)
            result = workflow.run(
                input_file=dataset_file,
                incident_meta={**meta, "path": dataset_file},
                preloaded_incident=incident,
                progress_callback=lambda msg, sample_idx=idx: print(
                    f"{Fore.CYAN}[SAMPLE {sample_idx:02d}]{Style.RESET_ALL} {msg}",
                    flush=True,
                ),
            )
            elapsed_ms = int((time.perf_counter() - begin) * 1000)
            elapsed_list.append(elapsed_ms)
            success += 1
            samples.append(
                {
                    "index": idx,
                    "ok": True,
                    "elapsed_ms": elapsed_ms,
                    "audit_result": result.get("audit", {}).get("audit_result", "unknown"),
                    "best_action": result.get("response", {}).get("best_action", {}).get("action_name", ""),
                    "top_threat": (
                        (result.get("agent_layers", {}).get("prioritized_threats", []) or [{}])[0].get("threat", "")
                        if isinstance(result.get("agent_layers", {}), dict)
                        else ""
                    ),
                    "hunt_query_count": len((result.get("agent_layers", {}) or {}).get("hunt_queries", []))
                    if isinstance(result.get("agent_layers", {}), dict)
                    else 0,
                    "execution_confidence": (result.get("confidence_model", {}) or {}).get("execution_confidence", 0.0),
                    "cache_hit": (result.get("observability", {}) or {}).get("cache_hit", {}),
                    "early_stop_count": ((result.get("observability", {}) or {}).get("planner", {}) or {}).get(
                        "early_stop_count", 0
                    ),
                    "model": result.get("model_runtime", {}),
                }
            )
            print(
                f"{Fore.GREEN}[SAMPLE]{Style.RESET_ALL} index={idx}; ok=true; "
                f"elapsed_ms={elapsed_ms}; audit_result={samples[-1]['audit_result']}; "
                f"best_action={samples[-1]['best_action']}; "
                f"top_threat={samples[-1]['top_threat'][:64]}; "
                f"hunt_queries={samples[-1]['hunt_query_count']}; "
                f"exec_conf={samples[-1]['execution_confidence']}; "
                f"cache={samples[-1]['cache_hit']}; "
                f"early_stop={samples[-1]['early_stop_count']}",
                flush=True,
            )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - begin) * 1000)
            elapsed_list.append(elapsed_ms)
            failed += 1
            samples.append({"index": idx, "ok": False, "elapsed_ms": elapsed_ms, "error": str(exc)})
            print(
                f"{Fore.RED}[SAMPLE]{Style.RESET_ALL} index={idx}; ok=false; "
                f"elapsed_ms={elapsed_ms}; error={str(exc)}",
                flush=True,
            )

    avg_elapsed = round(sum(elapsed_list) / len(elapsed_list), 2) if elapsed_list else 0.0
    p95 = 0.0
    if elapsed_list:
        sorted_elapsed = sorted(elapsed_list)
        p95 = float(sorted_elapsed[min(len(sorted_elapsed) - 1, int(len(sorted_elapsed) * 0.95))])

    return {
        "mode": mode,
        "dataset_file": dataset_file,
        "requested_samples": max_samples,
        "processed_samples": len(samples),
        "start_index": start_index,
        "end_index": end_index,
        "success": success,
        "failed": failed,
        "success_rate": round(success / max(1, len(samples)), 4),
        "latency_ms": {
            "avg": avg_elapsed,
            "p95": p95,
            "max": max(elapsed_list) if elapsed_list else 0,
            "min": min(elapsed_list) if elapsed_list else 0,
        },
        "samples": samples[:20],
    }
