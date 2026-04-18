from __future__ import annotations

from typing import Any, Dict, List

from ..domain.models import Action, Incident


class ExecutionAdapter:
    """Build a normalized execution package for shell/api/playbook/SOAR handoff."""

    def build(self, incident: Incident, action: Action) -> Dict[str, Any]:
        mode = self._resolve_mode(action)
        shell = action.command.strip()
        api = (action.api_call or "").strip()
        playbook = self._build_playbook(action, mode)
        tasks = self._build_soar_tasks(action, mode)
        guardrails = self._build_guardrails(incident, action, mode)
        orchestration = self._build_orchestration(action, tasks, playbook, guardrails)

        return {
            "mode": mode,
            "shell": shell,
            "api": api,
            "playbook": playbook,
            "tasks": tasks,
            "orchestration": orchestration,
            "guardrails": guardrails,
            "target_assets": list(action.target_assets or []),
            "capability_tags": list(action.capability_tags or []),
            "summary": {
                "action_name": action.action_name,
                "stage": action.target_stage,
                "task_count": len(tasks),
                "has_shell": bool(shell),
                "has_api": bool(api),
                "parallel_groups": sorted({t.get("parallel_group", "") for t in tasks if t.get("parallel_group", "")}),
                "approval_count": len(orchestration.get("approval_nodes", [])),
            },
        }

    @staticmethod
    def _resolve_mode(action: Action) -> str:
        if action.command.strip() and (action.api_call or "").strip():
            return "hybrid"
        if (action.api_call or "").strip():
            return "api"
        if action.command.strip():
            return "shell"
        return "playbook"

    def _build_playbook(self, action: Action, mode: str) -> Dict[str, Any]:
        steps: List[Dict[str, Any]] = []
        if action.sub_steps:
            for idx, step in enumerate(action.sub_steps, start=1):
                steps.append(
                    {
                        "id": f"{action.action_id}-step-{idx}",
                        "name": step.get("name", f"step-{idx}"),
                        "mode": step.get("mode", "serial"),
                        "parallel_group": step.get("group", action.parallel_group or ""),
                        "estimated_cost_minutes": step.get("cost_minutes", action.estimated_cost),
                    }
                )
        else:
            steps.append(
                {
                    "id": f"{action.action_id}-step-1",
                    "name": action.action_name,
                    "mode": "serial",
                    "parallel_group": action.parallel_group or "",
                    "estimated_cost_minutes": action.estimated_cost,
                }
            )

        return {
            "playbook_id": f"playbook-{action.action_id}",
            "title": action.action_name,
            "mode": mode,
            "stage": action.target_stage,
            "steps": steps,
            "rollback_hint": self._rollback_hint(action),
        }

    def _build_soar_tasks(self, action: Action, mode: str) -> List[Dict[str, Any]]:
        tasks: List[Dict[str, Any]] = []
        playbook = self._build_playbook(action, mode)
        for idx, step in enumerate(playbook.get("steps", []), start=1):
            tasks.append(
                {
                    "task_id": f"task-{action.action_id}-{idx}",
                    "name": step.get("name", ""),
                    "execution_type": mode,
                    "parallel_group": step.get("parallel_group", ""),
                    "mode": step.get("mode", "serial"),
                    "stage": action.target_stage,
                    "shell": action.command.strip() if mode in {"shell", "hybrid"} and idx == 1 else "",
                    "api": (action.api_call or "").strip() if mode in {"api", "hybrid"} and idx == 1 else "",
                    "estimated_cost_minutes": step.get("estimated_cost_minutes", action.estimated_cost),
                    "target_assets": list(action.target_assets or []),
                    "requires_approval": action.risk_penalty >= 0.3,
                }
            )
        return tasks

    def _build_orchestration(
        self,
        action: Action,
        tasks: List[Dict[str, Any]],
        playbook: Dict[str, Any],
        guardrails: List[str],
    ) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, str]] = []
        approval_nodes: List[Dict[str, Any]] = []
        rollback_tasks: List[Dict[str, Any]] = []

        previous_serial_node = ""
        for idx, task in enumerate(tasks, start=1):
            task_id = str(task.get("task_id", f"task-{idx}"))
            parallel_group = str(task.get("parallel_group", ""))
            node_type = "parallel_task" if parallel_group else "task"
            nodes.append(
                {
                    "id": task_id,
                    "type": node_type,
                    "name": task.get("name", ""),
                    "stage": task.get("stage", ""),
                    "execution_type": task.get("execution_type", ""),
                    "mode": task.get("mode", "serial"),
                    "parallel_group": parallel_group,
                    "requires_approval": bool(task.get("requires_approval", False)),
                }
            )

            if task.get("requires_approval", False):
                approval_id = f"approve-{task_id}"
                approval_node = {
                    "id": approval_id,
                    "type": "approval",
                    "name": f"审批 {task.get('name', '')}",
                    "reason": "risk_penalty_high",
                }
                approval_nodes.append(approval_node)
                nodes.append(approval_node)
                if previous_serial_node:
                    edges.append({"from": previous_serial_node, "to": approval_id, "condition": "serial"})
                edges.append({"from": approval_id, "to": task_id, "condition": "approved"})
                previous_serial_node = task_id
            else:
                if previous_serial_node and not parallel_group:
                    edges.append({"from": previous_serial_node, "to": task_id, "condition": "serial"})
                elif previous_serial_node and parallel_group and nodes:
                    edges.append({"from": previous_serial_node, "to": task_id, "condition": "fan_out"})
                if not parallel_group:
                    previous_serial_node = task_id

            rollback_tasks.append(
                {
                    "task_id": f"rollback-{task_id}",
                    "for_task": task_id,
                    "name": f"回滚 {task.get('name', '')}",
                    "instruction": playbook.get("rollback_hint", ""),
                }
            )

        execution_order = [node["id"] for node in nodes if node.get("type") in {"task", "parallel_task", "approval"}]
        return {
            "graph_id": f"orchestrate-{action.action_id}",
            "strategy": "serial_with_parallel_groups",
            "nodes": nodes,
            "edges": edges,
            "approval_nodes": approval_nodes,
            "rollback_plan": {
                "strategy": "reverse_order_on_failure",
                "tasks": rollback_tasks,
            },
            "execution_order": execution_order,
            "guardrails": guardrails,
        }

    @staticmethod
    def _build_guardrails(incident: Incident, action: Action, mode: str) -> List[str]:
        guardrails = [
            "仅在audit_result=pass且execution_allowed=true时允许下发",
            "执行前确认目标资产列表与当前事件一致",
        ]
        if action.risk_penalty >= 0.3:
            guardrails.append("高风险动作需人工审批后执行")
        if mode in {"shell", "hybrid"}:
            guardrails.append("Shell命令需在隔离或受控终端中执行")
        if mode in {"api", "hybrid"}:
            guardrails.append("API调用需校验鉴权与变更窗口")
        if incident.affected_assets:
            guardrails.append(f"优先针对资产 {incident.affected_assets[0]} 执行")
        return guardrails

    @staticmethod
    def _rollback_hint(action: Action) -> str:
        stage = action.target_stage.lower()
        if stage == "containment":
            return "撤销隔离策略并恢复网络连通性"
        if stage == "preservation":
            return "停止取证任务并校验采集结果完整性"
        if stage == "eviction":
            return "恢复被终止进程前先确认恶意性"
        if stage == "hardening":
            return "如补丁异常，回滚到上一稳定版本"
        if stage == "restoration":
            return "恢复前一稳定快照或服务版本"
        return "按变更流程执行标准回滚"
