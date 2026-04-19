from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any

from flask import Flask, jsonify, request

from .domain.config import ModelConfig
from .engine.workflow import run_pipeline, run_pipeline_csv_dataset, run_pipeline_dataset
from .services.countermeasure_service import CountermeasureService
from .services.countermeasure_state_store import CountermeasureStateStore
from .services.llm_client import LLMClient
from .services.rag_store import SQLiteRAGStore


DEFAULT_DATASET = str(Path(__file__).resolve().parents[1] / "dataset" / "incident_examples_min.json")
DEFAULT_INPUT = str(Path(__file__).resolve().parents[1] / "data" / "sample_incident.json")
AVAILABLE_COPILOT_MODELS = (
    "qwen3-max",
    "qwen3-max-preview",
    "qwen3-max-2025-09-23",
    "qwen-max",
    "qwen-max-latest",
    "qwen-max-2025-01-25",
    "qwen-max-2024-09-19",
    "qwen3.6-plus",
    "qwen3.6-plus-2026-04-02",
    "qwen3.5-plus",
    "qwen3.5-plus-2026-02-15",
    "qwen-plus",
    "qwen-plus-latest",
    "qwen-plus-2024-12-20",
    "qwen-plus-2025-01-25",
    "qwen-plus-us",
    "qwen-plus-2025-12-01",
    "qwen-plus-2025-12-01-us",
    "qwen3.6-flash",
    "qwen3.6-flash-2026-04-16",
    "qwen3.5-flash",
    "qwen3.5-flash-2026-02-23",
    "qwen-flash",
    "qwen-flash-2025-07-28",
    "qwen-flash-us",
    "qwen-flash-2025-07-28-us",
    "qwen-turbo",
    "qwen-turbo-latest",
    "qwen-turbo-2024-11-01",
    "qwen-turbo-2025-04-28",
    "qwen3-coder-plus",
    "qwen3-coder-plus-2025-07-22",
    "qwen3-coder-flash",
    "qwen3-coder-flash-2025-07-28",
    "qwen-coder-plus",
    "qwen-coder-plus-latest",
    "qwen-coder-plus-2024-11-06",
    "qwen-coder-turbo",
    "qwen-coder-turbo-latest",
    "qwen-coder-turbo-2024-09-19",
    "qwq-plus",
    "qwq-plus-latest",
    "qwq-plus-2025-03-05",
    "qwen-math-plus",
    "qwen-math-plus-latest",
    "qwen-math-plus-2024-08-16",
    "qwen-math-turbo",
    "qwen-math-turbo-latest",
    "qwen-vl-plus",
    "qwen-vl-plus-latest",
    "qwen-vl-plus-0815",
    "qwen-vl-plus-2025-01-25",
    "qwen-vl-plus-2025-07-10",
    "qwen-vl-plus-2025-08-15",
    "qwen-vl-max",
    "qwen-vl-max-latest",
    "qwen-vl-max-0813",
    "qwen3.6-35b-a3b",
    "qwen3.5-397b-a17b",
    "qwen3.5-120b-a10b",
    "qwen3.5-35b-a3b",
    "qwen3.5-27b",
    "qwen3-next-80b-a3b-thinking",
    "qwen3-next-80b-a3b-instruct",
    "qwen3-235b-a22b-thinking-2507",
    "qwen3-235b-a22b-instruct-2507",
    "qwen3-30b-a3b-thinking-2507",
    "qwen3-30b-a3b-instruct-2507",
    "qwen3-235b-a22b",
    "qwen3-32b",
    "qwen3-30b-a3b",
    "qwen3-14b",
    "qwen3-8b",
    "qwen3-4b",
    "qwen3-1.7b",
    "qwen3-0.6b",
    "qwen2.5-72b-instruct",
    "qwen2.5-32b-instruct",
    "qwen2.5-14b-instruct",
    "qwen2.5-14b-instruct-1m",
    "qwen2.5-7b-instruct",
    "qwen2.5-7b-instruct-1m",
    "qwen2.5-3b-instruct",
    "qwen2.5-1.5b-instruct",
    "qwen2.5-0.5b-instruct",
)

COUNTERMEASURE_STATE_STORE = CountermeasureStateStore()

SYSTEM_SETTINGS_SCHEMA: dict[str, dict[str, Any]] = {
    "rules_default_page_size": {"type": "int", "default": 100, "min": 5, "max": 200},
    "model_timeout_seconds": {"type": "int", "default": 30, "min": 5, "max": 180},
    "online_rag_enabled": {"type": "bool", "default": False},
    "multi_agent_enabled": {"type": "bool", "default": True},
}


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on"}


def _serialize_system_setting(key: str, value: Any) -> str:
    schema = SYSTEM_SETTINGS_SCHEMA.get(key, {})
    if schema.get("type") == "bool":
        return "true" if _parse_bool(value) else "false"
    return str(int(value))


def _coerce_system_setting_value(key: str, raw_value: Any) -> Any:
    if key not in SYSTEM_SETTINGS_SCHEMA:
        raise ValueError(f"unsupported setting: {key}")

    schema = SYSTEM_SETTINGS_SCHEMA[key]
    if schema["type"] == "bool":
        return _parse_bool(raw_value)

    value = int(raw_value)
    min_value = schema.get("min")
    max_value = schema.get("max")
    if min_value is not None and value < min_value:
        raise ValueError(f"{key} must be >= {min_value}")
    if max_value is not None and value > max_value:
        raise ValueError(f"{key} must be <= {max_value}")
    return value


def _system_settings_defaults() -> dict[str, Any]:
    defaults = {k: v["default"] for k, v in SYSTEM_SETTINGS_SCHEMA.items()}
    defaults["model_timeout_seconds"] = int(os.getenv("MODEL_TIMEOUT_SECONDS", str(defaults["model_timeout_seconds"])))
    defaults["online_rag_enabled"] = os.getenv("ONLINE_RAG_ENABLED", "false").lower() == "true"
    defaults["multi_agent_enabled"] = os.getenv("MULTI_AGENT_ENABLED", "true").lower() == "true"
    return defaults


def _ensure_settings_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def _load_system_settings(db_path: str) -> tuple[dict[str, Any], str]:
    defaults = _system_settings_defaults()
    settings = dict(defaults)
    latest_updated_at = ""

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        _ensure_settings_table(conn)
        rows = conn.execute(
            "SELECT key, value, updated_at FROM app_settings WHERE key IN ({})".format(
                ",".join("?" for _ in SYSTEM_SETTINGS_SCHEMA)
            ),
            tuple(SYSTEM_SETTINGS_SCHEMA.keys()),
        ).fetchall()
        for row in rows:
            key = str(row["key"])
            try:
                settings[key] = _coerce_system_setting_value(key, row["value"])
            except (TypeError, ValueError):
                settings[key] = defaults[key]
            latest_updated_at = max(latest_updated_at, str(row["updated_at"] or ""))
    finally:
        conn.close()

    return settings, latest_updated_at


def _save_system_settings(db_path: str, updates: dict[str, Any]) -> tuple[dict[str, Any], str]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        _ensure_settings_table(conn)
        for key, value in updates.items():
            conn.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, _serialize_system_setting(key, value)),
            )
        conn.commit()
    finally:
        conn.close()

    return _load_system_settings(db_path)


def _apply_runtime_settings(settings: dict[str, Any]) -> None:
    os.environ["MODEL_TIMEOUT_SECONDS"] = str(int(settings["model_timeout_seconds"]))
    os.environ["ONLINE_RAG_ENABLED"] = "true" if settings["online_rag_enabled"] else "false"
    os.environ["MULTI_AGENT_ENABLED"] = "true" if settings["multi_agent_enabled"] else "false"


def _parse_system_settings_patch(payload: dict[str, Any]) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    for key in SYSTEM_SETTINGS_SCHEMA:
        if key not in payload:
            continue
        updates[key] = _coerce_system_setting_value(key, payload.get(key))
    return updates


def _sync_countermeasure_runtime(result: dict[str, Any]) -> dict[str, Any]:
    frontend_payload = result.get("frontend_payload", {}) or {}
    case_memory = result.get("case_memory", {}) or {}
    case_id = str(case_memory.get("case_id", "") or (frontend_payload.get("case_memory", {}) or {}).get("case_id", "")).strip()
    execution = frontend_payload.get("execution", {}) or {}
    countermeasures = execution.get("countermeasures", []) or []
    if not case_id or not isinstance(countermeasures, list):
        return result

    merged = COUNTERMEASURE_STATE_STORE.merge(case_id=case_id, countermeasures=countermeasures)
    execution["countermeasures"] = merged
    summary = execution.get("summary", {}) or {}
    summary["countermeasure_count"] = len(merged)
    summary["applied_countermeasure_count"] = sum(1 for item in merged if item.get("applied"))
    execution["summary"] = summary
    frontend_payload["execution"] = execution
    result["frontend_payload"] = frontend_payload

    response = result.get("response", {}) or {}
    executable = response.get("executable", {}) or {}
    if executable:
        executable["countermeasures"] = merged
        executable["summary"] = summary
        response["executable"] = executable
        result["response"] = response
    return result


def _list_attack_rules(query: str = "", limit: int = 100, offset: int = 0) -> dict[str, Any]:
    model_config = ModelConfig.from_env()
    rag_store = SQLiteRAGStore(model_config.rag_db_path)
    rag_store.initialize()
    safe_limit = max(1, min(int(limit), 200))
    safe_offset = max(0, int(offset))
    q = str(query or "").strip().lower()

    where_clause = "WHERE doc_type = 'rule'"
    params: list[Any] = []
    if q:
        where_clause += " AND (LOWER(text_key) LIKE ? OR LOWER(title) LIKE ? OR LOWER(metadata_json) LIKE ?)"
        like_value = f"%{q}%"
        params.extend([like_value, like_value, like_value])

    with rag_store._managed_connect() as conn:  # type: ignore[attr-defined]
        total_row = conn.execute(
            f"""
            SELECT COUNT(1) AS total
            FROM rag_documents
            {where_clause}
            """,
            tuple(params),
        ).fetchone()
        total = int(total_row["total"] or 0) if total_row else 0

        raw_rows = conn.execute(
            f"""
            SELECT text_key, title, metadata_json, updated_at
            FROM rag_documents
            {where_clause}
            ORDER BY updated_at DESC, text_key ASC
            LIMIT ? OFFSET ?
            """,
            tuple([*params, safe_limit, safe_offset]),
        ).fetchall()

    items = []
    for row in raw_rows:
        metadata = {}
        try:
            metadata = json.loads(row["metadata_json"] or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            metadata = {}
        items.append(
            {
                "rule_id": str(metadata.get("rule_id", row["text_key"])),
                "title": str(row["title"]),
                "rule_type": str(metadata.get("rule_type", "")),
                "pattern": str(metadata.get("pattern", "")),
                "ttp": str(metadata.get("ttp", "")),
                "severity": float(metadata.get("severity", 0.0) or 0.0),
                "confidence": float(metadata.get("confidence", 0.0) or 0.0),
                "source": str(metadata.get("source", "")),
                "version": str(metadata.get("version", "")),
                "source_url": str(metadata.get("source_url", "")),
                "updated_at": str(row["updated_at"] or metadata.get("updated_at", "")),
            }
        )

    return {
        "total": total,
        "page": safe_offset // safe_limit + 1,
        "page_size": safe_limit,
        "db_path": model_config.rag_db_path,
        "items": items,
    }


def _tokenize_terms(text: str) -> list[str]:
    return [
        token.strip().lower()
        for token in re.findall(r"[a-zA-Z0-9_.:/\-]+", text or "")
        if token and len(token.strip()) >= 2
    ]


def _extract_template_tokens(template: str) -> list[str]:
    tokens = set(re.findall(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}", template or ""))
    tokens.update(re.findall(r"\$([a-zA-Z_][a-zA-Z0-9_]*)", template or ""))
    return list(tokens)


def _collect_hunt_query_terms(
    query_template: str,
    param_keys: list[str],
    context: dict[str, Any],
) -> list[str]:
    terms: list[str] = []
    terms.extend(_tokenize_terms(query_template)[:60])
    terms.extend([str(x).strip().lower() for x in param_keys if str(x).strip()])

    event_summary = str(context.get("eventSummary", "") or "")
    terms.extend(_tokenize_terms(event_summary)[:30])

    top_threat = str(context.get("topThreat", "") or "")
    terms.extend(_tokenize_terms(top_threat)[:20])

    for field in ("affectedAssets", "additionalTerms"):
        values = context.get(field, []) or []
        if isinstance(values, list):
            for item in values[:30]:
                terms.extend(_tokenize_terms(str(item)))

    ioc = context.get("ioc", {}) or {}
    if isinstance(ioc, dict):
        for key in ("ip", "domain", "cve", "process"):
            values = ioc.get(key, []) or []
            if isinstance(values, list):
                for item in values[:30]:
                    terms.extend(_tokenize_terms(str(item)))

    seen = set()
    dedup: list[str] = []
    for term in terms:
        if not term or term in seen:
            continue
        seen.add(term)
        dedup.append(term)
    return dedup[:80]


def _is_ip(text: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text or ""))


def _suggest_param_value(param_key: str, rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any]] | None:
    key = param_key.lower()

    def pick(predicate) -> tuple[str, dict[str, Any]] | None:
        for row in rows:
            text_key = str(row.get("text_key", "") or "")
            metadata = row.get("metadata", {}) or {}
            if predicate(row, text_key, metadata):
                return text_key, row
        return None

    if any(word in key for word in ("ip", "src_ip", "dst_ip")):
        return pick(lambda row, text_key, _meta: row.get("doc_type") == "ioc" and _is_ip(text_key))

    if any(word in key for word in ("domain", "host", "fqdn")):
        return pick(
            lambda row, text_key, _meta: row.get("doc_type") in {"ioc", "asset"}
            and ("." in text_key and not _is_ip(text_key))
        )

    if "asset" in key:
        return pick(lambda row, _text_key, _meta: row.get("doc_type") == "asset")

    if "cve" in key:
        return pick(lambda row, text_key, _meta: row.get("doc_type") == "cve" and text_key.upper().startswith("CVE-"))

    if "rule" in key:
        return pick(lambda row, _text_key, _meta: row.get("doc_type") == "rule")

    if "ttp" in key:
        for row in rows:
            metadata = row.get("metadata", {}) or {}
            ttp = str(metadata.get("ttp", "") or "")
            if ttp:
                return ttp, row

    if "severity" in key:
        for row in rows:
            metadata = row.get("metadata", {}) or {}
            severity = metadata.get("severity")
            if severity is not None:
                return str(severity), row

    if rows:
        fallback = rows[0]
        return str(fallback.get("text_key", "")), fallback
    return None


def _build_param_suggestions(param_keys: list[str], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    suggestions: list[dict[str, Any]] = []
    for key in param_keys:
        if not str(key).strip():
            continue
        matched = _suggest_param_value(str(key), rows)
        if not matched:
            continue
        value, row = matched
        score = float(row.get("score", 0.0) or 0.0)
        confidence = max(0.45, min(0.99, 0.5 + score / 6.0))
        metadata = row.get("metadata", {}) or {}
        suggestions.append(
            {
                "param_key": str(key),
                "param_value": value,
                "confidence": round(confidence, 3),
                "evidence_ref": {
                    "doc_type": row.get("doc_type", ""),
                    "text_key": row.get("text_key", ""),
                    "title": row.get("title", ""),
                    "source_type": metadata.get("source_type", ""),
                    "score": round(score, 4),
                },
            }
        )
    return suggestions


def _build_copilot_system_prompt(context: dict[str, Any] | None) -> str:
    context = context or {}
    page_title = str(context.get("pageTitle", "") or "当前页面")
    event_summary = str(context.get("eventSummary", "") or "无事件摘要")
    top_threat = str(context.get("topThreat", "") or "无首要威胁")
    recommended_action = str(context.get("recommendedAction", "") or "无推荐动作")
    return (
        "你是 SentriX 的右侧副驾驶 AI 助手。"
        "你的回答必须简洁、直接、偏执行建议，优先解释当前页面信息与后端运行状态。"
        "如果用户询问风险、动作、日志或研判，请结合给定上下文作答，不要编造未提供的数据。\n"
        f"页面: {page_title}\n"
        f"事件摘要: {event_summary}\n"
        f"首要威胁: {top_threat}\n"
        f"推荐动作: {recommended_action}"
    )


def create_frontend_api_app() -> Flask:
    app = Flask(__name__)

    @app.after_request
    def _apply_cors_headers(response):  # type: ignore[no-untyped-def]
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"ok": True, "service": "frontend-payload-api", "framework": "flask"})

    @app.route("/api/frontend-payload", methods=["GET"])
    def frontend_payload():
        dataset_file = request.args.get("dataset_file", DEFAULT_DATASET)
        dataset_index = request.args.get("dataset_index", default=0, type=int)
        input_file = request.args.get("input_file", "")
        csv_file = request.args.get("csv_file", "")
        csv_row_index = request.args.get("csv_row_index", default=0, type=int)

        try:
            if csv_file:
                result = run_pipeline_csv_dataset(csv_file=csv_file, row_index=csv_row_index)
            elif input_file:
                result = run_pipeline(input_file=input_file)
            else:
                result = run_pipeline_dataset(dataset_file=dataset_file, sample_index=dataset_index)
            result = _sync_countermeasure_runtime(result)
            frontend_payload = result.get("frontend_payload", {}) or {}
            frontend_payload["rules"] = _list_attack_rules(limit=120)
            result["frontend_payload"] = frontend_payload
            return jsonify(result)
        except Exception as exc:  # pragma: no cover - defensive API boundary
            return (
                jsonify(
                {
                    "error": "frontend_payload_failed",
                    "message": str(exc),
                    "frontend_payload": {},
                }
                ),
                500,
            )

    @app.route("/api/copilot/chat", methods=["POST"])
    def copilot_chat():
        payload = request.get_json(silent=True) or {}
        user_message = str(payload.get("message", "")).strip()
        history = payload.get("history", []) or []
        context = payload.get("context", {}) or {}
        api_key_override = str(payload.get("apiKey", "")).strip()
        model_override = str(payload.get("model", "")).strip()

        if not user_message:
            return jsonify({"error": "invalid_request", "message": "message is required"}), 400

        model_config = ModelConfig.from_env()
        if api_key_override:
            model_config.api_key = api_key_override
        if model_override:
            if model_override not in AVAILABLE_COPILOT_MODELS:
                return (
                    jsonify(
                        {
                            "error": "invalid_model",
                            "message": f"model must be one of: {', '.join(AVAILABLE_COPILOT_MODELS)}",
                        }
                    ),
                    400,
                )
            model_config.model_name = model_override

        client = LLMClient(model_config)
        messages = [{"role": "system", "content": _build_copilot_system_prompt(context)}]

        for item in history[-10:]:
            role = str(item.get("role", "")).strip().lower()
            content = str(item.get("content", "")).strip()
            if role in {"user", "assistant"} and content:
                messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": user_message})

        answer = client.generate_text(messages=messages, temperature=0.2)
        if not answer:
            return (
                jsonify(
                    {
                        "error": "copilot_unavailable",
                        "message": "Qwen copilot request failed or API key is missing.",
                    }
                ),
                502,
            )

        return jsonify(
            {
                "reply": answer,
                "provider": model_config.provider,
                "model": model_config.model_name,
                "used_override_key": bool(api_key_override),
                "available_models": list(AVAILABLE_COPILOT_MODELS),
            }
        )

    @app.route("/api/hunt/rag-suggest", methods=["POST"])
    def hunt_rag_suggest():
        payload = request.get_json(silent=True) or {}
        query_template = str(payload.get("query_template", "") or "")
        context = payload.get("context", {}) or {}
        param_keys_input = payload.get("param_keys", []) or []
        top_k = int(payload.get("top_k", 12) or 12)
        param_keys = [str(item).strip() for item in param_keys_input if str(item).strip()]

        if not query_template.strip():
            return jsonify({"error": "invalid_request", "message": "query_template is required"}), 400

        if not param_keys:
            param_keys = _extract_template_tokens(query_template)

        query_terms = _collect_hunt_query_terms(query_template=query_template, param_keys=param_keys, context=context)

        model_config = ModelConfig.from_env()
        rag_store = SQLiteRAGStore(model_config.rag_db_path)
        rag_store.initialize()

        rows = rag_store.query(query_terms=query_terms, top_k=max(1, min(top_k, 30))) if query_terms else []
        suggestions = _build_param_suggestions(param_keys=param_keys, rows=rows)

        evidence = []
        for row in rows[:12]:
            metadata = row.get("metadata", {}) or {}
            evidence.append(
                {
                    "doc_type": row.get("doc_type", ""),
                    "text_key": row.get("text_key", ""),
                    "title": row.get("title", ""),
                    "score": round(float(row.get("score", 0.0) or 0.0), 4),
                    "source_type": metadata.get("source_type", ""),
                }
            )

        return jsonify(
            {
                "query_terms": query_terms,
                "filled_params": {item["param_key"]: item["param_value"] for item in suggestions},
                "suggestions": suggestions,
                "evidence": evidence,
                "db_path": model_config.rag_db_path,
            }
        )

    @app.route("/api/execution/countermeasure", methods=["POST"])
    def execution_countermeasure():
        payload = request.get_json(silent=True) or {}
        active_response_enabled = os.getenv("SENTRIX_ENABLE_ACTIVE_RESPONSE", "false").lower() == "true"
        service = CountermeasureService()

        try:
            result = service.dispatch(payload, active_response_enabled=active_response_enabled)
        except ValueError as exc:
            return jsonify({"error": "invalid_request", "message": str(exc)}), 400
        except Exception as exc:  # pragma: no cover - defensive API boundary
            return jsonify({"error": "countermeasure_failed", "message": str(exc)}), 500

        COUNTERMEASURE_STATE_STORE.upsert(case_id=str(payload.get("case_id", "")).strip(), state=result)

        if payload.get("apply") and result.get("status") == "blocked":
            return jsonify(result), 403
        if payload.get("apply") and result.get("status") == "queued":
            return jsonify(result), 202
        return jsonify(result)

    @app.route("/api/rules/search", methods=["GET"])
    def rules_search():
        query = str(request.args.get("q", "") or "")
        page = request.args.get("page", default=1, type=int)
        page_size = request.args.get("page_size", type=int)
        limit = request.args.get("limit", type=int)
        model_config = ModelConfig.from_env()
        settings, _ = _load_system_settings(model_config.rag_db_path)
        default_limit = int(settings.get("rules_default_page_size", 100) or 100)
        effective_limit = page_size if page_size is not None else (limit if limit is not None else default_limit)
        safe_page = max(1, int(page or 1))
        offset = (safe_page - 1) * max(1, int(effective_limit or 100))
        try:
            return jsonify(_list_attack_rules(query=query, limit=effective_limit, offset=offset))
        except Exception as exc:  # pragma: no cover - defensive API boundary
            return jsonify({"error": "rules_search_failed", "message": str(exc), "items": [], "total": 0, "page": 1, "page_size": 100}), 500

    @app.route("/api/system/settings", methods=["GET", "PATCH"])
    def system_settings():
        model_config = ModelConfig.from_env()
        db_path = model_config.rag_db_path

        if request.method == "GET":
            settings, updated_at = _load_system_settings(db_path)
            return jsonify(
                {
                    "settings": settings,
                    "db_path": db_path,
                    "updated_at": updated_at,
                }
            )

        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "invalid_request", "message": "request body must be a JSON object"}), 400

        try:
            updates = _parse_system_settings_patch(payload)
        except (TypeError, ValueError) as exc:
            return jsonify({"error": "invalid_request", "message": str(exc)}), 400

        if not updates:
            return (
                jsonify(
                    {
                        "error": "invalid_request",
                        "message": "no supported setting fields found",
                        "allowed_fields": list(SYSTEM_SETTINGS_SCHEMA.keys()),
                    }
                ),
                400,
            )

        settings, updated_at = _save_system_settings(db_path, updates)
        _apply_runtime_settings(settings)
        return jsonify(
            {
                "settings": settings,
                "db_path": db_path,
                "updated_at": updated_at,
                "applied": list(updates.keys()),
            }
        )

    return app


def run_frontend_api_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    app = create_frontend_api_app()
    print(f"[FrontendAPI] serving at http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
