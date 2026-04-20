from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Set, Tuple

from colorama import Fore, Style

from ..engine.workflow import run_pipeline_dataset


def run_eval_harness(
    dataset_file: str,
    max_samples: int = 20,
    start_index: int = 0,
    incident_threshold: float = 0.6,
) -> Dict[str, Any]:
    payload = json.loads(Path(dataset_file).read_text(encoding="utf-8"))
    instructions = payload.get("instructions", []) or []
    answers = payload.get("answers", []) or []

    total = len(instructions)
    end_index = min(total, start_index + max(1, int(max_samples)))

    sample_rows: List[Dict[str, Any]] = []
    latencies: List[int] = []
    token_totals: List[int] = []

    incident_eval_count = 0
    incident_correct = 0

    mitre_tp = 0
    mitre_fp = 0
    mitre_fn = 0
    mitre_eval_count = 0

    high_risk_pred_count = 0
    high_risk_blocked_count = 0

    hallucination_count = 0

    cache_hit_rag_count = 0
    cache_hit_layered_count = 0
    early_stop_positive_count = 0
    audit_fail_count = 0
    rule_hit_sum = 0

    stage_elapsed_agg: Dict[str, List[int]] = {}

    for idx in range(start_index, end_index):
        begin = time.perf_counter()
        result = run_pipeline_dataset(
            dataset_file=dataset_file,
            sample_index=idx,
            progress_callback=lambda msg, sample_idx=idx: print(
                f"{Fore.CYAN}[EVAL {sample_idx:02d}]{Style.RESET_ALL} {msg}",
                flush=True,
            ),
        )
        elapsed_ms = int((time.perf_counter() - begin) * 1000)
        latencies.append(elapsed_ms)

        gt = _parse_ground_truth(str(answers[idx]) if idx < len(answers) else "")
        pred = _extract_prediction(result, incident_threshold=incident_threshold)

        if gt["incident"] is not None:
            incident_eval_count += 1
            incident_correct += 1 if pred["incident"] == gt["incident"] else 0

        if gt["mitre"]:
            mitre_eval_count += 1
            tp, fp, fn = _set_confusion(gt["mitre"], pred["mitre"])
            mitre_tp += tp
            mitre_fp += fp
            mitre_fn += fn

        if pred["high_risk"]:
            high_risk_pred_count += 1
            if pred["blocked"]:
                high_risk_blocked_count += 1

        if pred["hallucination"]:
            hallucination_count += 1

        if pred["cache_hit_rag"]:
            cache_hit_rag_count += 1
        if pred["cache_hit_layered"]:
            cache_hit_layered_count += 1
        if pred["early_stop_count"] > 0:
            early_stop_positive_count += 1
        if pred["audit_result"] == "fail":
            audit_fail_count += 1

        token_totals.append(pred["total_tokens"])
        rule_hit_sum += pred["rule_hit_count"]

        for stage, ms in pred["stage_elapsed_ms"].items():
            stage_elapsed_agg.setdefault(stage, []).append(int(ms or 0))

        sample_rows.append(
            {
                "index": idx,
                "elapsed_ms": elapsed_ms,
                "total_tokens": pred["total_tokens"],
                "pred_incident": pred["incident"],
                "gt_incident": gt["incident"],
                "incident_match": None if gt["incident"] is None else pred["incident"] == gt["incident"],
                "pred_mitre": sorted(list(pred["mitre"])),
                "gt_mitre": sorted(list(gt["mitre"])),
                "audit_result": pred["audit_result"],
                "execution_allowed": not pred["blocked"],
                "high_risk_pred": pred["high_risk"],
                "hallucination": pred["hallucination"],
                "rule_hit_count": pred["rule_hit_count"],
                "cache_hit": {
                    "rag": pred["cache_hit_rag"],
                    "layered_agents": pred["cache_hit_layered"],
                },
                "early_stop_count": pred["early_stop_count"],
                "stage_elapsed_ms": pred["stage_elapsed_ms"],
                "top_threat": pred["top_threat"],
                "best_action": pred["best_action"],
                "risk_score": pred["risk_score"],
                "downgrade_reasons": pred["downgrade_reasons"],
                "incident_basis": pred["incident_basis"],
            }
        )
        _print_eval_sample_line(
            idx=idx,
            elapsed_ms=elapsed_ms,
            pred_incident=pred["incident"],
            gt_incident=gt["incident"],
            audit_result=pred["audit_result"],
            risk_score=pred["risk_score"],
            tokens=pred["total_tokens"],
        )
        _print_eval_analysis_matrix(idx=idx, result=result)

    processed = len(sample_rows)
    incident_accuracy = _safe_div(incident_correct, incident_eval_count)
    mitre_precision = _safe_div(mitre_tp, (mitre_tp + mitre_fp))
    mitre_recall = _safe_div(mitre_tp, (mitre_tp + mitre_fn))
    mitre_f1 = _f1(mitre_precision, mitre_recall)

    summary = {
        "dataset_file": dataset_file,
        "start_index": start_index,
        "end_index": end_index,
        "processed_samples": processed,
        "metrics": {
            "incident_yes_no_accuracy": {
                "value": incident_accuracy,
                "eval_samples": incident_eval_count,
            },
            "mitre_match_f1": {
                "precision": mitre_precision,
                "recall": mitre_recall,
                "f1": mitre_f1,
                "eval_samples": mitre_eval_count,
            },
            "audit_block_effectiveness": {
                "blocked_when_high_risk_pred": _safe_div(high_risk_blocked_count, high_risk_pred_count),
                "high_risk_pred_samples": high_risk_pred_count,
            },
            "hallucination_rate": _safe_div(hallucination_count, processed),
            "latency_ms": {
                "avg": _avg(latencies),
                "p95": _percentile(latencies, 95),
                "min": min(latencies) if latencies else 0,
                "max": max(latencies) if latencies else 0,
            },
            "tokens": {
                "avg_total_tokens": _avg(token_totals),
                "p95_total_tokens": _percentile(token_totals, 95),
                "with_usage_count": sum(1 for x in token_totals if x > 0),
            },
        },
        "technical_effects": {
            "cache_hit_rate": {
                "rag": _safe_div(cache_hit_rag_count, processed),
                "layered_agents": _safe_div(cache_hit_layered_count, processed),
            },
            "planner_early_stop_rate": _safe_div(early_stop_positive_count, processed),
            "avg_rule_hit_count": _avg([row.get("rule_hit_count", 0) for row in sample_rows]),
            "audit_fail_rate": _safe_div(audit_fail_count, processed),
            "avg_stage_elapsed_ms": {k: _avg(v) for k, v in stage_elapsed_agg.items()},
        },
        "mapping_diagnostics": _build_mapping_diagnostics(sample_rows),
        "samples": sample_rows,
    }

    report_files = _write_eval_reports(summary)
    summary["report_files"] = report_files
    return summary


def _extract_prediction(result: Dict[str, Any], incident_threshold: float) -> Dict[str, Any]:
    confidence = result.get("confidence_model", {}) or {}
    detection_conf = float(confidence.get("detection_confidence", 0.0) or 0.0)
    execution_conf = float(confidence.get("execution_confidence", 0.0) or 0.0)

    audit = result.get("audit", {}) or {}
    audit_result = str(audit.get("audit_result", "unknown")).lower()
    blocked = not bool(result.get("execution_allowed", False))

    ranked = (result.get("response", {}) or {}).get("ranked_actions", []) or []
    top_ranked = ranked[0] if ranked else {}

    observability = result.get("observability", {}) or {}
    cache_hit = observability.get("cache_hit", {}) or {}
    planner = observability.get("planner", {}) or {}
    stage_elapsed = observability.get("stage_elapsed_ms", {}) or {}

    model_runtime = result.get("model_runtime", {}) or {}
    token_usage = model_runtime.get("token_usage", {}) or {}

    rag = result.get("rag", {}) or {}
    rule_findings = rag.get("rule_findings", []) or []
    cve_findings = rag.get("cve_findings", []) or []
    downgrade_reasons = ((rag.get("rag_context", {}) or {}).get("downgrade_reasons", []) or [])

    pred_mitre = _normalize_mitre(_extract_predicted_mitre_terms(rule_findings, cve_findings))

    risk_score = 0
    if detection_conf >= incident_threshold:
        risk_score += 1
    if execution_conf >= 0.65:
        risk_score += 1
    if len(rule_findings) >= 3:
        risk_score += 1
    if audit_result in {"warning", "fail"}:
        risk_score += 1

    if downgrade_reasons:
        risk_score -= 1
    if "matched_common_normal_traffic_template" in downgrade_reasons:
        risk_score -= 1
    if "matched_whitelist_url_or_ua" in downgrade_reasons:
        risk_score -= 1

    # Align prediction with the system's final operational decision path.
    pred_incident = blocked or (audit_result in {"warning", "fail"})
    high_risk_pred = blocked and (audit_result in {"warning", "fail"})
    incident_basis = {
        "blocked": blocked,
        "audit_result": audit_result,
        "risk_score": risk_score,
        "detection_confidence": round(detection_conf, 4),
        "execution_confidence": round(execution_conf, 4),
        "rule_hit_count": len(rule_findings),
        "downgrade_reasons": [str(x) for x in downgrade_reasons],
    }
    if not pred_incident:
        pred_mitre = set()

    prioritized = ((result.get("agent_layers", {}) or {}).get("prioritized_threats", []) or [{}])
    top_threat = str(prioritized[0].get("threat", "")) if prioritized else ""
    best_action = str(((result.get("response", {}) or {}).get("best_action", {}) or {}).get("action_name", ""))

    return {
        "incident": pred_incident,
        "mitre": pred_mitre,
        "high_risk": high_risk_pred,
        "blocked": blocked,
        "audit_result": audit_result,
        "hallucination": bool(top_ranked.get("hallucination_flag", False)),
        "cache_hit_rag": bool(cache_hit.get("rag", False)),
        "cache_hit_layered": bool(cache_hit.get("layered_agents", False)),
        "early_stop_count": int(planner.get("early_stop_count", 0) or 0),
        "stage_elapsed_ms": {str(k): int(v or 0) for k, v in stage_elapsed.items()},
        "total_tokens": int(token_usage.get("total_tokens", 0) or 0),
        "rule_hit_count": len(rule_findings),
        "top_threat": top_threat,
        "best_action": best_action,
        "risk_score": risk_score,
        "downgrade_reasons": [str(x) for x in downgrade_reasons],
        "incident_basis": incident_basis,
    }


def _print_eval_sample_line(
    idx: int,
    elapsed_ms: int,
    pred_incident: bool,
    gt_incident: bool | None,
    audit_result: str,
    risk_score: int,
    tokens: int,
) -> None:
    match = (gt_incident is None) or (pred_incident == gt_incident)
    color = Fore.GREEN if match else Fore.RED
    print(
        f"{color}[EVAL-SAMPLE]{Style.RESET_ALL} "
        f"#{idx:02d} | {elapsed_ms}ms | tok={tokens} | pred={pred_incident} | gt={gt_incident} | "
        f"audit={audit_result} | risk={risk_score} | match={match}",
        flush=True,
    )


def _print_eval_analysis_matrix(idx: int, result: Dict[str, Any]) -> None:
    deep = result.get("deep_analysis", {}) or {}
    attack_rows = deep.get("攻击链ATT&CK映射", []) or []
    exposure = deep.get("暴露面分析", {}) or {}
    ioc_rows = deep.get("IOC指标", []) or []

    print(f"{Fore.MAGENTA}[EVAL-MATRIX]{Style.RESET_ALL} sample=#{idx:02d}", flush=True)

    # 1) 攻击链 ATT&CK 映射矩阵
    print("  [1] 攻击链ATT&CK映射", flush=True)
    print("  | 攻击阶段 | ATT&CK战术 | 技术ID | 技术描述 |", flush=True)
    print("  |---|---|---|---|", flush=True)
    if attack_rows:
        for row in attack_rows:
            print(
                "  | {stage} | {tactic} | {tid} | {desc} |".format(
                    stage=str(row.get("攻击阶段", "Unknown")),
                    tactic=str(row.get("ATT&CK战术", "Unknown")),
                    tid=str(row.get("技术ID", "Unknown")),
                    desc=str(row.get("技术描述", "Unknown"))[:140],
                ),
                flush=True,
            )
    else:
        print("  | Unknown | Unknown | Unknown | Unknown |", flush=True)

    # 2) 暴露面分析矩阵
    print("  [2] 暴露面分析", flush=True)
    print("  | 场景风险等级说明 |", flush=True)
    print("  |---|", flush=True)
    print(
        "  | {desc} |".format(
            desc=str(exposure.get("场景风险等级说明", "Unknown")),
        ),
        flush=True,
    )

    # 3) IOC 指标矩阵
    print("  [3] IOC指标", flush=True)
    print("  | CVE | CWE | 漏洞代号 | 软件版本 | 修复版本 |", flush=True)
    print("  |---|---|---|---|---|", flush=True)
    if ioc_rows:
        for item in ioc_rows:
            metric_map = _metric_row_to_map(item)
            print(
                "  | {cve} | {cwe} | {alias} | {sv} | {fv} |".format(
                    cve=metric_map.get("CVE", "Unknown"),
                    cwe=metric_map.get("CWE", "Unknown"),
                    alias=metric_map.get("漏洞代号", "Unknown"),
                    sv=metric_map.get("软件版本", "Unknown"),
                    fv=metric_map.get("修复版本", "Unknown"),
                ),
                flush=True,
            )
    else:
        print("  | Unknown | Unknown | Unknown | Unknown | Unknown |", flush=True)


def _metric_row_to_map(item: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for metric in item.get("指标", []) or []:
        name = str(metric.get("名称", "")).strip()
        value = str(metric.get("值", "")).strip() or "Unknown"
        if not name:
            continue
        # 若同名字段重复，保留首个非Unknown值，避免覆盖成Unknown。
        if name not in out:
            out[name] = value
            continue
        if out[name] == "Unknown" and value != "Unknown":
            out[name] = value
    return out


def _build_mapping_diagnostics(sample_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    mismatch_rows = [row for row in sample_rows if row.get("incident_match") is False]
    reason_stats: Dict[str, int] = {
        "audit_pass_but_pred_incident": 0,
        "blocked_but_gt_no_incident": 0,
        "gt_missing": 0,
    }
    mismatch_details: List[Dict[str, Any]] = []

    for row in sample_rows:
        if row.get("gt_incident") is None:
            reason_stats["gt_missing"] += 1

    for row in mismatch_rows:
        basis = row.get("incident_basis", {}) or {}
        pred = bool(row.get("pred_incident", False))
        gt = row.get("gt_incident")
        blocked = bool(not row.get("execution_allowed", True))
        audit_result = str(row.get("audit_result", "unknown"))

        if pred and gt is False and audit_result == "pass":
            reason_stats["audit_pass_but_pred_incident"] += 1
        if blocked and gt is False:
            reason_stats["blocked_but_gt_no_incident"] += 1

        mismatch_details.append(
            {
                "index": row.get("index", -1),
                "pred_incident": pred,
                "gt_incident": gt,
                "audit_result": audit_result,
                "execution_allowed": row.get("execution_allowed", True),
                "risk_score": row.get("risk_score", 0),
                "rule_hit_count": row.get("rule_hit_count", 0),
                "downgrade_reasons": row.get("downgrade_reasons", []),
                "incident_basis": basis,
            }
        )

    return {
        "incident_mismatch_count": len(mismatch_rows),
        "incident_mismatch_rate": _safe_div(len(mismatch_rows), len(sample_rows)),
        "reason_stats": reason_stats,
        "mismatch_samples": mismatch_details[:20],
    }


def _extract_predicted_mitre_terms(rule_findings: List[Dict[str, Any]], cve_findings: List[Dict[str, Any]]) -> Set[str]:
    out: Set[str] = set()
    for item in rule_findings[:12]:
        ttp = str(item.get("ttp", "")).strip()
        if ttp:
            out.add(ttp)
    for item in cve_findings[:6]:
        ttp = str(item.get("ttp", "")).strip()
        if ttp:
            out.add(ttp)
    return out


def _parse_ground_truth(answer_text: str) -> Dict[str, Any]:
    parsed = _extract_answer_json(answer_text)
    if not parsed:
        fallback_incident = _extract_incident_fallback(answer_text)
        fallback_mitre = _extract_mitre_fallback(answer_text)
        return {"incident": fallback_incident, "mitre": fallback_mitre}

    incident_raw = str(parsed.get("Incident", "")).strip().lower()
    incident_value = None
    if incident_raw in {"yes", "no"}:
        incident_value = incident_raw == "yes"

    tactics = parsed.get("MITRE ATT&CK Tactics", []) or []
    techniques = parsed.get("MITRE ATT&CK Techniques", []) or []

    mitre_terms = set([str(x) for x in tactics if str(x).strip()])
    mitre_terms.update([str(x) for x in techniques if str(x).strip()])

    return {
        "incident": incident_value,
        "mitre": _normalize_mitre(mitre_terms),
    }


def _extract_incident_fallback(answer_text: str) -> bool | None:
    match = re.search(r"['\"]Incident['\"]\s*:\s*['\"](Yes|No)['\"]", answer_text, flags=re.IGNORECASE)
    if not match:
        return None
    return str(match.group(1)).strip().lower() == "yes"


def _extract_mitre_fallback(answer_text: str) -> Set[str]:
    tactics = _extract_list_field(answer_text, "MITRE ATT&CK Tactics")
    techniques = _extract_list_field(answer_text, "MITRE ATT&CK Techniques")
    merged = set(tactics)
    merged.update(techniques)
    return _normalize_mitre(merged)


def _extract_list_field(text: str, field_name: str) -> List[str]:
    pattern = rf"['\"]{re.escape(field_name)}['\"]\s*:\s*\[(.*?)\]"
    match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return []
    body = match.group(1)
    return [x.strip() for x in re.findall(r"['\"]([^'\"]+)['\"]", body) if x.strip()]


def _extract_answer_json(answer_text: str) -> Dict[str, Any]:
    if not answer_text.strip():
        return {}

    start = answer_text.find("{")
    end = answer_text.rfind("}")
    if start < 0 or end <= start:
        return {}

    candidate = answer_text[start : end + 1]
    candidate = re.sub(r"<\|.*?\|>", "", candidate)
    try:
        obj = json.loads(candidate)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _normalize_mitre(items: Set[str]) -> Set[str]:
    out: Set[str] = set()
    for item in items:
        text = str(item).strip().lower()
        text = re.sub(r"\s+", " ", text)
        if not text or text in {"n/a", "unknown", "none"}:
            continue
        out.add(text)
    return out


def _set_confusion(gt: Set[str], pred: Set[str]) -> Tuple[int, int, int]:
    tp = len(gt.intersection(pred))
    fp = len(pred.difference(gt))
    fn = len(gt.difference(pred))
    return tp, fp, fn


def _safe_div(a: float, b: float) -> float:
    if b <= 0:
        return 0.0
    return round(float(a) / float(b), 4)


def _f1(precision: float, recall: float) -> float:
    if precision + recall <= 0:
        return 0.0
    return round((2.0 * precision * recall) / (precision + recall), 4)


def _avg(values: List[int]) -> float:
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)


def _percentile(values: List[int], pct: int) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = int((len(sorted_vals) - 1) * (pct / 100.0))
    idx = max(0, min(idx, len(sorted_vals) - 1))
    return float(sorted_vals[idx])


def _write_eval_reports(summary: Dict[str, Any]) -> Dict[str, str]:
    logs_dir = Path(__file__).resolve().parents[2] / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    json_path = logs_dir / f"eval_harness_{ts}.json"
    md_path = logs_dir / f"eval_harness_{ts}.md"

    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(summary), encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
    }


def _render_markdown(summary: Dict[str, Any]) -> str:
    metrics = summary.get("metrics", {}) or {}
    effects = summary.get("technical_effects", {}) or {}
    latency = metrics.get("latency_ms", {}) or {}
    tokens = metrics.get("tokens", {}) or {}
    block = metrics.get("audit_block_effectiveness", {}) or {}
    cache = effects.get("cache_hit_rate", {}) or {}
    mapping_diag = summary.get("mapping_diagnostics", {}) or {}
    reason_stats = mapping_diag.get("reason_stats", {}) or {}

    lines = [
        "# Eval Harness Report",
        "",
        f"- Dataset: {summary.get('dataset_file', '')}",
        f"- Range: {summary.get('start_index', 0)}..{summary.get('end_index', 0)}",
        f"- Processed: {summary.get('processed_samples', 0)}",
        "",
        "## Key Metrics",
        "",
        f"- Incident Yes/No Accuracy: {((metrics.get('incident_yes_no_accuracy', {}) or {}).get('value', 0.0))}",
        f"- MITRE F1: {((metrics.get('mitre_match_f1', {}) or {}).get('f1', 0.0))}",
        f"- Audit Block Effectiveness: {block.get('blocked_when_high_risk_pred', 0.0)}",
        f"- Hallucination Rate: {metrics.get('hallucination_rate', 0.0)}",
        f"- Latency(ms): avg={latency.get('avg', 0.0)}, p95={latency.get('p95', 0.0)}",
        f"- Tokens: avg={tokens.get('avg_total_tokens', 0.0)}, p95={tokens.get('p95_total_tokens', 0.0)}",
        "",
        "## Technical Effects",
        "",
        f"- Cache Hit: rag={cache.get('rag', 0.0)}, layered_agents={cache.get('layered_agents', 0.0)}",
        f"- Planner Early Stop Rate: {effects.get('planner_early_stop_rate', 0.0)}",
        f"- Avg Rule Hit Count: {effects.get('avg_rule_hit_count', 0.0)}",
        f"- Audit Fail Rate: {effects.get('audit_fail_rate', 0.0)}",
        "",
        "## Mapping Diagnostics",
        "",
        f"- Incident Mismatch Count: {mapping_diag.get('incident_mismatch_count', 0)}",
        f"- Incident Mismatch Rate: {mapping_diag.get('incident_mismatch_rate', 0.0)}",
        f"- Reason(audit_pass_but_pred_incident): {reason_stats.get('audit_pass_but_pred_incident', 0)}",
        f"- Reason(blocked_but_gt_no_incident): {reason_stats.get('blocked_but_gt_no_incident', 0)}",
        f"- GT Missing Count: {reason_stats.get('gt_missing', 0)}",
        "",
        "## Sample Snapshot (Top 10)",
        "",
        "| idx | elapsed_ms | tokens | pred_incident | gt_incident | audit_result | hallucination | rule_hits |",
        "|---:|---:|---:|---|---|---|---|---:|",
    ]

    for row in (summary.get("samples", []) or [])[:10]:
        lines.append(
            "| {idx} | {elapsed} | {tokens} | {pred_incident} | {gt_incident} | {audit} | {hall} | {hits} |".format(
                idx=row.get("index", ""),
                elapsed=row.get("elapsed_ms", 0),
                tokens=row.get("total_tokens", 0),
                pred_incident=row.get("pred_incident", ""),
                gt_incident=row.get("gt_incident", ""),
                audit=row.get("audit_result", ""),
                hall=row.get("hallucination", False),
                hits=row.get("rule_hit_count", 0),
            )
        )

    lines.append("")
    return "\n".join(lines)
