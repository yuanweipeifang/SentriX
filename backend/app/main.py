from __future__ import annotations

import argparse
import json
from pathlib import Path
import threading
import time
from typing import Any, Dict
from colorama import Fore, Style, init as colorama_init

from .api_server import run_frontend_api_server
from .engine.workflow import (
    build_concise_view,
    run_pipeline,
    run_pipeline_csv_dataset,
    run_pipeline_dataset,
    run_stress_test,
)
from .services.rag import (
    evaluate_csv_with_rules_and_evidence,
    generate_rules_from_cve_to_rag,
    import_cve_json_to_rag,
    import_ioc_json_to_rag,
    import_rule_json_to_rag,
    rag_smoke_test,
    rebuild_rag_database,
)
from .services.case_memory import LocalCaseMemory


def _print_processing_logs(result: Dict[str, Any]) -> None:
    runtime = result.get("skill_runtime", {}) or {}
    trace = runtime.get("execution_trace", []) or []
    model_runtime = result.get("model_runtime", {}) or {}
    rule_gen = result.get("rule_generation", {}) or {}
    response = result.get("response", {}) or {}
    audit = result.get("audit", {}) or {}
    layers = result.get("agent_layers", {}) or {}

    print(f"\n{Fore.CYAN}[PROCESS]{Style.RESET_ALL} 模型运行信息")
    print(
        f"  provider={model_runtime.get('provider', '')}; "
        f"model={model_runtime.get('model_name', '')}; "
        f"endpoint={model_runtime.get('endpoint', '')}"
    )

    print(f"{Fore.CYAN}[PROCESS]{Style.RESET_ALL} 阶段执行轨迹")
    if not trace:
        print("  - no stage trace")
    for idx, item in enumerate(trace, start=1):
        print(
            f"  {idx}. stage={item.get('stage', '')}; "
            f"skill={item.get('skill', '')}; "
            f"status={item.get('status', '')}; "
            f"elapsed_ms={item.get('elapsed_ms', 'n/a')}"
        )

    print(f"{Fore.CYAN}[PROCESS]{Style.RESET_ALL} 规则生成引擎")
    print(
        f"  enabled={rule_gen.get('enabled', False)}; "
        f"reason={rule_gen.get('reason', '')}; "
        f"provider={rule_gen.get('provider', '')}; "
        f"elapsed_ms={rule_gen.get('elapsed_ms', 0)}"
    )
    for cve_task in rule_gen.get("results", []) or []:
        cve_id = cve_task.get("cve_id", "")
        candidates = cve_task.get("candidates", []) or []
        print(f"  CVE={cve_id}; candidates={len(candidates)}")
        for cand in candidates:
            print(
                f"    - id={cand.get('candidate_id', '')}; "
                f"temp={cand.get('temperature', '')}; "
                f"iter={cand.get('iterations', '')}; "
                f"score={cand.get('score', '')}"
            )

    ranked = response.get("ranked_actions", []) or []
    print(f"{Fore.CYAN}[PROCESS]{Style.RESET_ALL} 动作排序 Top3")
    for idx, item in enumerate(ranked[:3], start=1):
        action = item.get("action", {}) or {}
        print(
            f"  {idx}. action={action.get('action_name', '')}; "
            f"stage={action.get('target_stage', '')}; "
            f"score={round(float(item.get('score', 0.0)), 3)}; "
            f"valid={item.get('validation_passed', False)}"
        )

    print(f"{Fore.CYAN}[PROCESS]{Style.RESET_ALL} 审计结果")
    print(
        f"  audit_result={audit.get('audit_result', '')}; "
        f"execution_allowed={result.get('execution_allowed', False)}"
    )

    print(f"{Fore.CYAN}[PROCESS]{Style.RESET_ALL} 专业分层代理")
    prioritized = layers.get("prioritized_threats", []) or []
    print(
        f"  enabled={layers.get('enabled', False)}; "
        f"identified={len(layers.get('identified_threats', []) or [])}; "
        f"prioritized={len(prioritized)}; "
        f"hunt_queries={len(layers.get('hunt_queries', []) or [])}; "
        f"elapsed_ms={layers.get('elapsed_ms', 0)}"
    )
    if prioritized:
        print(
            f"  top_threat={prioritized[0].get('threat', '')}; "
            f"score={prioritized[0].get('priority_score', 0.0)}"
        )


def _run_with_heartbeat(task_name: str, interval_seconds: int, fn, *args, **kwargs):
    if interval_seconds <= 0:
        return fn(*args, **kwargs)

    stop_event = threading.Event()
    started_at = time.perf_counter()

    def _heartbeat_loop() -> None:
        pulse = 0
        while not stop_event.wait(interval_seconds):
            pulse += 1
            elapsed = int(time.perf_counter() - started_at)
            print(
                f"{Fore.YELLOW}[HEARTBEAT]{Style.RESET_ALL} task={task_name}; "
                f"pulse={pulse}; elapsed={elapsed}s; status=running"
            )

    worker = threading.Thread(target=_heartbeat_loop, daemon=True)
    print(f"{Fore.BLUE}[HEARTBEAT]{Style.RESET_ALL} task={task_name}; status=start; interval={interval_seconds}s")
    worker.start()
    try:
        result = fn(*args, **kwargs)
    finally:
        stop_event.set()
        worker.join(timeout=0.2)
        elapsed = int(time.perf_counter() - started_at)
        print(f"{Fore.GREEN}[HEARTBEAT]{Style.RESET_ALL} task={task_name}; status=stop; elapsed={elapsed}s")
    return result


def main() -> None:
    colorama_init(autoreset=True)
    parser = argparse.ArgumentParser(description="Automated Threat Analysis & Incident Response Backend")
    parser.add_argument(
        "--input",
        default=str(Path(__file__).resolve().parents[1] / "data" / "sample_incident.json"),
        help="Path to incident JSON file",
    )
    parser.add_argument(
        "--dataset-file",
        "--dataset",
        dest="dataset_file",
        default="",
        help="Path to dataset json (supports keys: instructions/answers).",
    )
    parser.add_argument(
        "--dataset-index",
        "--index",
        dest="dataset_index",
        type=int,
        default=0,
        help="Sample index when using --dataset-file.",
    )
    parser.add_argument(
        "--full-output",
        action="store_true",
        help="Print full raw output (default prints concise runtime effect view).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Disable detailed processing logs and print only final result payload.",
    )
    parser.add_argument(
        "--heartbeat-seconds",
        type=int,
        default=5,
        help="Heartbeat interval in seconds for long-running tasks; set 0 to disable.",
    )
    parser.add_argument(
        "--csv-dataset-file",
        "--csv",
        dest="csv_dataset_file",
        default="",
        help="Path to CSV traffic dataset file (one row -> one incident sample).",
    )
    parser.add_argument(
        "--csv-row-index",
        "--row",
        dest="csv_row_index",
        type=int,
        default=0,
        help="Row index when using --csv-dataset-file.",
    )
    parser.add_argument(
        "--stress-test",
        action="store_true",
        help="Run stress test over dataset_json or csv dataset and print performance summary.",
    )
    parser.add_argument(
        "--stress-mode",
        choices=["dataset_json", "csv"],
        default="dataset_json",
        help="Stress test mode: dataset_json or csv.",
    )
    parser.add_argument(
        "--stress-max-samples",
        type=int,
        default=10,
        help="Maximum samples to run in stress test.",
    )
    parser.add_argument(
        "--stress-start-index",
        type=int,
        default=0,
        help="Start index for stress test.",
    )
    parser.add_argument(
        "--rag-reindex",
        action="store_true",
        help="Rebuild local SQLite RAG database from built-in intel data.",
    )
    parser.add_argument(
        "--rag-smoke-test",
        action="store_true",
        help="Run a real retrieval smoke test against current RAG database.",
    )
    parser.add_argument(
        "--rag-import-cve-dir",
        default="",
        help="Import CVE JSON files from a directory and rebuild RAG database.",
    )
    parser.add_argument(
        "--rag-import-cve-file",
        default="",
        help="Import one CVE JSON file and rebuild RAG database.",
    )
    parser.add_argument(
        "--rag-generate-rules-from-cve-dir",
        default="",
        help="Generate rules from CVE JSON files in a directory and rebuild RAG database.",
    )
    parser.add_argument(
        "--rag-generate-rules-from-cve-file",
        default="",
        help="Generate rules from one CVE JSON file and rebuild RAG database.",
    )
    parser.add_argument(
        "--rag-generate-rules-max-cves",
        type=int,
        default=500,
        help="Maximum CVE records used when generating rules from CVE data.",
    )
    parser.add_argument(
        "--rag-import-rule-dir",
        default="",
        help="Import attack rule JSON files from a directory and rebuild RAG database.",
    )
    parser.add_argument(
        "--rag-import-rule-file",
        default="",
        help="Import one rule JSON file and rebuild RAG database.",
    )
    parser.add_argument(
        "--rag-import-ioc-dir",
        default="",
        help="Import IOC JSON files from a directory and rebuild RAG database.",
    )
    parser.add_argument(
        "--rag-import-ioc-file",
        default="",
        help="Import one IOC JSON file and rebuild RAG database.",
    )
    parser.add_argument(
        "--rag-eval-csv",
        action="store_true",
        help="Evaluate csv dataset rows using rule+evidence judgement logic.",
    )
    parser.add_argument(
        "--rag-eval-max-rows",
        type=int,
        default=10,
        help="Maximum csv rows to evaluate when --rag-eval-csv is enabled.",
    )
    parser.add_argument(
        "--rag-eval-start-index",
        type=int,
        default=0,
        help="Start row index when --rag-eval-csv is enabled.",
    )
    parser.add_argument(
        "--case-memory-stats",
        action="store_true",
        help="Show local historical case memory stats.",
    )
    parser.add_argument(
        "--case-memory-correct-id",
        default="",
        help="Apply manual correction to a stored case_id.",
    )
    parser.add_argument(
        "--case-memory-label",
        default="",
        help="Manual correction label, e.g. benign/false_positive/malicious/confirmed_attack.",
    )
    parser.add_argument(
        "--case-memory-notes",
        default="",
        help="Notes for manual correction.",
    )
    parser.add_argument(
        "--serve-api",
        action="store_true",
        help="Start Flask API service for frontend frontend_payload requests.",
    )
    parser.add_argument(
        "--api-host",
        default="127.0.0.1",
        help="Host for --serve-api.",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=8000,
        help="Port for --serve-api.",
    )
    args = parser.parse_args()

    if args.serve_api:
        run_frontend_api_server(host=args.api_host, port=args.api_port)
        return
    if args.case_memory_stats:
        print(json.dumps(LocalCaseMemory().stats(), ensure_ascii=False, indent=2))
        return
    if args.case_memory_correct_id:
        if not args.case_memory_label:
            raise ValueError("--case-memory-correct-id requires --case-memory-label")
        print(
            json.dumps(
                LocalCaseMemory().apply_manual_correction(
                    case_id=args.case_memory_correct_id,
                    label=args.case_memory_label,
                    notes=args.case_memory_notes,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if args.rag_reindex:
        print(
            json.dumps(
                _run_with_heartbeat("rag_reindex", args.heartbeat_seconds, rebuild_rag_database),
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if args.rag_import_cve_dir or args.rag_import_cve_file:
        print(
            json.dumps(
                _run_with_heartbeat(
                    "rag_import_cve",
                    args.heartbeat_seconds,
                    import_cve_json_to_rag,
                    cve_dir=args.rag_import_cve_dir,
                    cve_file=args.rag_import_cve_file,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if args.rag_generate_rules_from_cve_dir or args.rag_generate_rules_from_cve_file:
        print(
            json.dumps(
                _run_with_heartbeat(
                    "rag_generate_rules_from_cve",
                    args.heartbeat_seconds,
                    generate_rules_from_cve_to_rag,
                    cve_dir=args.rag_generate_rules_from_cve_dir,
                    cve_file=args.rag_generate_rules_from_cve_file,
                    max_cves=args.rag_generate_rules_max_cves,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if args.rag_import_rule_dir or args.rag_import_rule_file:
        print(
            json.dumps(
                _run_with_heartbeat(
                    "rag_import_rule",
                    args.heartbeat_seconds,
                    import_rule_json_to_rag,
                    rule_dir=args.rag_import_rule_dir,
                    rule_file=args.rag_import_rule_file,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if args.rag_import_ioc_dir or args.rag_import_ioc_file:
        print(
            json.dumps(
                _run_with_heartbeat(
                    "rag_import_ioc",
                    args.heartbeat_seconds,
                    import_ioc_json_to_rag,
                    ioc_dir=args.rag_import_ioc_dir,
                    ioc_file=args.rag_import_ioc_file,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if args.rag_eval_csv:
        eval_file = args.csv_dataset_file or str(Path(__file__).resolve().parents[1] / "dataset" / "test_10_no_label.csv")
        print(
            json.dumps(
                _run_with_heartbeat(
                    "rag_eval_csv",
                    args.heartbeat_seconds,
                    evaluate_csv_with_rules_and_evidence,
                    csv_dataset_file=eval_file,
                    max_rows=args.rag_eval_max_rows,
                    start_index=args.rag_eval_start_index,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if args.rag_smoke_test:
        result = _run_with_heartbeat(
            "rag_smoke_test",
            args.heartbeat_seconds,
            rag_smoke_test,
            input_file=args.input,
            dataset_file=args.dataset_file,
            dataset_index=args.dataset_index,
            csv_dataset_file=args.csv_dataset_file,
            csv_row_index=args.csv_row_index,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.stress_test:
        if args.stress_mode == "csv":
            if not args.csv_dataset_file:
                raise ValueError("Stress mode csv requires --csv-dataset-file")
            result = _run_with_heartbeat(
                "stress_test_csv",
                args.heartbeat_seconds,
                run_stress_test,
                dataset_file=args.csv_dataset_file,
                mode="csv",
                max_samples=args.stress_max_samples,
                start_index=args.stress_start_index,
            )
        else:
            if not args.dataset_file:
                raise ValueError("Stress mode dataset_json requires --dataset-file")
            result = _run_with_heartbeat(
                "stress_test_dataset",
                args.heartbeat_seconds,
                run_stress_test,
                dataset_file=args.dataset_file,
                mode="dataset_json",
                max_samples=args.stress_max_samples,
                start_index=args.stress_start_index,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.csv_dataset_file:
        result = _run_with_heartbeat(
            "pipeline_csv",
            args.heartbeat_seconds,
            run_pipeline_csv_dataset,
            args.csv_dataset_file,
            args.csv_row_index,
        )
    elif args.dataset_file:
        result = _run_with_heartbeat(
            "pipeline_dataset",
            args.heartbeat_seconds,
            run_pipeline_dataset,
            args.dataset_file,
            args.dataset_index,
        )
    else:
        result = _run_with_heartbeat("pipeline", args.heartbeat_seconds, run_pipeline, args.input)

    if not args.quiet:
        _print_processing_logs(result)

    if args.full_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(json.dumps(build_concise_view(result), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
