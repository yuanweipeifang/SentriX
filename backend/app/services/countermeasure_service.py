from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def _as_record(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_bool(value: Any, fallback: bool = False) -> bool:
    return value if isinstance(value, bool) else fallback


def _as_string(value: Any, fallback: str = "") -> str:
    return value.strip() if isinstance(value, str) else fallback


def _as_string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


class CountermeasureService:
    """Prepare safe-by-default active response plans."""

    def plan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        task = _as_record(payload.get("task"))
        countermeasure = _as_record(payload.get("countermeasure"))
        incident = _as_record(payload.get("incident"))
        playbook = _as_record(payload.get("playbook"))
        guardrails = _as_string_list(payload.get("guardrails"))

        if not task and not countermeasure:
            raise ValueError("task or countermeasure is required")

        task_id = _as_string(countermeasure.get("task_id")) or _as_string(task.get("task_id")) or "task-unknown"
        title = (
            _as_string(countermeasure.get("title"))
            or _as_string(task.get("name"))
            or _as_string(countermeasure.get("description"))
            or "未命名反制动作"
        )
        description = (
            _as_string(countermeasure.get("description"))
            or _as_string(task.get("description"))
            or "对当前高风险动作生成后端反制计划。"
        )
        stage = _as_string(countermeasure.get("stage")) or _as_string(task.get("stage")) or "containment"
        mode = _as_string(countermeasure.get("mode")) or _as_string(task.get("execution_type")) or "playbook"
        command_preview = _as_string(countermeasure.get("command_preview")) or _as_string(task.get("shell"))
        api_preview = _as_string(countermeasure.get("api_preview")) or _as_string(task.get("api"))
        target_assets = _as_string_list(countermeasure.get("target_assets")) or _as_string_list(task.get("target_assets"))
        capability_tags = _as_string_list(countermeasure.get("capability_tags")) or _as_string_list(task.get("capability_tags"))
        requires_approval = _as_bool(countermeasure.get("requires_approval"), _as_bool(task.get("requires_approval")))
        rollback_hint = _as_string(playbook.get("rollback_hint"), "按变更流程执行标准回滚")
        kind = _as_string(countermeasure.get("kind")) or self._infer_kind(
            title=title,
            description=description,
            stage=stage,
            capability_tags=capability_tags,
            command_preview=command_preview,
            api_preview=api_preview,
        )

        first_asset = target_assets[0] if target_assets else "当前受影响资产"
        event_summary = _as_string(incident.get("event_summary"), "当前安全事件")
        primary_indicator = self._pick_primary_indicator(_as_record(incident.get("ioc")))

        safeguards = self._merge_safeguards(kind=kind, guardrails=guardrails, requires_approval=requires_approval)
        steps = self._build_steps(
            kind=kind,
            first_asset=first_asset,
            title=title,
            primary_indicator=primary_indicator,
        )
        status = "approval_required" if requires_approval else "ready"

        return {
            "countermeasure_id": _as_string(countermeasure.get("countermeasure_id")) or f"cm-{task_id}",
            "task_id": task_id,
            "title": title,
            "description": description,
            "kind": kind,
            "stage": stage,
            "mode": mode,
            "status": status,
            "requires_approval": requires_approval,
            "target_assets": target_assets,
            "capability_tags": capability_tags,
            "command_preview": command_preview,
            "api_preview": api_preview,
            "rollback_hint": rollback_hint,
            "incident_summary": event_summary,
            "primary_indicator": primary_indicator,
            "safeguards": safeguards,
            "steps": steps,
        }

    def dispatch(self, payload: Dict[str, Any], active_response_enabled: bool) -> Dict[str, Any]:
        plan = self.plan(payload)
        apply_countermeasure = _as_bool(payload.get("apply"), False)

        if not apply_countermeasure:
            return {
                **plan,
                "status": "preview_ready",
                "message": "已生成后端反制预演，可用于人工审核或后续下发。",
                "applied": False,
                "provider": "sentrix-countermeasure-planner",
                "operation_id": "",
                "executed_at": "",
            }

        if plan["requires_approval"]:
            return {
                **plan,
                "status": "approval_required",
                "message": "当前动作需要审批，后端未执行实际反制。",
                "applied": False,
                "provider": "sentrix-countermeasure-planner",
                "operation_id": "",
                "executed_at": "",
            }

        if not active_response_enabled:
            return {
                **plan,
                "status": "blocked",
                "message": "后端主动反制开关未开启，当前仅允许预演。",
                "applied": False,
                "provider": "sentrix-countermeasure-planner",
                "operation_id": "",
                "executed_at": "",
            }

        executed_at = datetime.now(timezone.utc).isoformat()
        return {
            **plan,
            "status": "queued",
            "message": "反制任务已进入后端执行队列，可继续接入真实 EDR / SOAR 执行器。",
            "applied": True,
            "provider": "sentrix-countermeasure-planner",
            "operation_id": f"op-{plan['countermeasure_id']}",
            "executed_at": executed_at,
        }

    @staticmethod
    def _pick_primary_indicator(ioc: Dict[str, Any]) -> str:
        for key in ("ip", "domain", "cve", "process"):
            values = ioc.get(key)
            if isinstance(values, list):
                for item in values:
                    if str(item).strip():
                        return str(item).strip()
        return ""

    @staticmethod
    def _merge_safeguards(kind: str, guardrails: List[str], requires_approval: bool) -> List[str]:
        baseline = [
            "仅允许对当前事件关联资产下发反制",
            "执行前记录审计日志与回滚提示",
        ]
        if kind in {"network_isolation", "process_termination"}:
            baseline.append("优先在隔离环境或受控终端执行高影响动作")
        if requires_approval:
            baseline.append("当前动作命中审批门槛，需人工确认后执行")

        merged: List[str] = []
        for item in [*guardrails, *baseline]:
            text = str(item).strip()
            if text and text not in merged:
                merged.append(text)
        return merged[:6]

    @staticmethod
    def _infer_kind(
        title: str,
        description: str,
        stage: str,
        capability_tags: List[str],
        command_preview: str,
        api_preview: str,
    ) -> str:
        haystack = " ".join([title, description, stage, command_preview, api_preview, " ".join(capability_tags)]).lower()
        if "network_isolation" in capability_tags or any(token in haystack for token in ("隔离", "isolate", "iptables", "drop")):
            return "network_isolation"
        if "process_control" in capability_tags or any(token in haystack for token in ("kill", "pkill", "terminate", "终止进程")):
            return "process_termination"
        if "forensics_collection" in capability_tags or any(token in haystack for token in ("forensics", "内存", "磁盘镜像", "采集")):
            return "evidence_preservation"
        if "patch_management" in capability_tags or any(token in haystack for token in ("patch", "补丁", "cve", "基线加固")):
            return "patch_management"
        if "service_recovery" in capability_tags or any(token in haystack for token in ("恢复", "restart", "recover", "health check")):
            return "service_recovery"
        return "generic_response"

    @staticmethod
    def _build_steps(kind: str, first_asset: str, title: str, primary_indicator: str) -> List[str]:
        indicator_text = primary_indicator or "当前威胁指标"
        if kind == "network_isolation":
            return [
                f"校验资产 {first_asset} 与威胁指标 {indicator_text} 的关联性",
                f"通过网络或 EDR 通道对 {first_asset} 执行隔离",
                "验证外联流量是否被成功阻断",
            ]
        if kind == "process_termination":
            return [
                f"确认 {first_asset} 上恶意进程与事件证据一致",
                f"终止可疑进程并保留样本或哈希用于追溯",
                "复核进程是否再次拉起并同步告警结果",
            ]
        if kind == "evidence_preservation":
            return [
                f"冻结 {first_asset} 当前现场状态",
                "执行内存、磁盘或日志采集任务",
                "核验证据完整性并入库供后续溯源",
            ]
        if kind == "patch_management":
            return [
                f"确认 {first_asset} 对应漏洞或基线缺口",
                "执行补丁、配置修复或基线加固",
                "完成修复后进行健康检查和回归验证",
            ]
        if kind == "service_recovery":
            return [
                f"在 {first_asset} 上执行服务恢复或重启",
                "运行健康检查确认业务可用",
                "观察恢复后是否仍有异常行为或告警回流",
            ]
        return [
            f"准备动作 {title} 的执行上下文",
            "校验命令/API 与目标资产映射关系",
            "将反制任务发送到后端执行器或人工审批流",
        ]
