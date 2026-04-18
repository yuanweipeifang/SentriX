from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Set

from .action_policy import sanitize_actions
from ..domain.config import PlannerConfig
from .llm_client import LLMClient
from ..domain.models import Action, Incident, StateVector, ThreatIntel


class ActionGenerator:
    def __init__(self, planner_config: PlannerConfig, llm_client: LLMClient | None = None) -> None:
        self.planner_config = planner_config
        self.llm_client = llm_client or LLMClient()
        self.prompt_template = self._load_prompt("action_generation.prompt.txt")
        self.last_filter_audit: List[Dict[str, str]] = []

    def generate(
        self,
        incident: Incident,
        state: StateVector,
        history: List[Action],
        intel: ThreatIntel,
        use_llm: bool = True,
    ) -> List[Action]:
        history_names: Set[str] = {h.action_name for h in history}
        model_actions = self._generate_with_llm(incident, state, history, intel) if use_llm else []
        if model_actions:
            valid, rejects = sanitize_actions(model_actions, incident, history_names, self.planner_config.candidate_count)
            self.last_filter_audit = rejects
            if valid:
                return valid
        valid, rejects = sanitize_actions(
            self._rule_based_actions(incident, state, history, intel),
            incident,
            history_names,
            self.planner_config.candidate_count,
        )
        self.last_filter_audit = rejects
        return valid

    def _generate_with_llm(
        self,
        incident: Incident,
        state: StateVector,
        history: List[Action],
        intel: ThreatIntel,
    ) -> List[Action]:
        payload = {
            "logs": incident.raw_logs,
            "state": state.to_dict(),
            "history_actions": [h.action_name for h in history],
            "rag": intel.to_dict(),
            "rag_context": intel.rag_context,
        }
        data = self.llm_client.generate_json(
            system_prompt="你是SOC动作生成智能体，请返回JSON数组，每个元素包含动作字段。",
            user_prompt=self.prompt_template + "\n\n" + json.dumps(payload, ensure_ascii=False),
        )
        if not data or "actions" not in data:
            return []

        output: List[Action] = []
        history_names: Set[str] = {h.action_name for h in history}
        for idx, raw in enumerate(data.get("actions", [])):
            name = raw.get("action_name", raw.get("name", "")).strip()
            if not name or name in history_names:
                continue
            output.append(
                Action(
                    action_id=raw.get("action_id", f"llm-{idx}"),
                    action_name=name,
                    description=raw.get("description", raw.get("reason", "LLM动作建议")),
                    target_stage=raw.get("target_stage", raw.get("stage", "containment")),
                    estimated_cost=float(raw.get("estimated_cost", raw.get("cost_minutes", 10))),
                    risk_penalty=float(raw.get("risk_penalty", raw.get("risk", 0.3))),
                    confidence=float(raw.get("confidence", 0.6)),
                    reasoning=raw.get("reasoning", raw.get("reason", "LLM建议动作")),
                    command=raw.get("command", ""),
                    api_call=raw.get("api_call"),
                    effects=raw.get("effects", {}),
                    target_assets=raw.get("target_assets", []),
                    capability_tags=raw.get("capability_tags", []),
                    sub_steps=raw.get("sub_steps", []),
                    parallel_group=raw.get("parallel_group"),
                )
            )
        return output

    @staticmethod
    def _rule_based_actions(
        incident: Incident,
        state: StateVector,
        history: List[Action],
        intel: ThreatIntel,
    ) -> List[Action]:
        history_names = {h.action_name for h in history}
        has_assets = bool(incident.affected_assets)
        primary_asset = incident.affected_assets[0] if has_assets else "host-A"
        target_assets = [primary_asset] if has_assets else []
        primary_ip = incident.ioc.ip[0] if incident.ioc.ip else "198.51.100.23"
        primary_proc = incident.ioc.process[0] if incident.ioc.process else "unknown.exe"
        top_cve = intel.cve_findings[0]["cve"] if intel.cve_findings else "CVE-unknown"

        candidate_bank = [
            Action(
                action_id="a1",
                action_name=f"隔离 {primary_asset} 的对外连接",
                description="阻断可疑外联，优先遏制攻击扩散。",
                target_stage="containment",
                estimated_cost=8,
                risk_penalty=0.25,
                confidence=0.84,
                reasoning="IOC显示存在C2外联，优先执行网络遏制。",
                command=f"iptables -A OUTPUT -d {primary_ip} -j DROP",
                api_call=f"POST /edr/isolate?asset={primary_asset}",
                target_assets=target_assets,
                capability_tags=["network_isolation"],
                effects={"containment": 0.35, "assessment": 0.1},
                sub_steps=[
                    {"name": "封禁C2出口", "cost_minutes": 5, "mode": "serial"},
                    {"name": "应用EDR隔离", "cost_minutes": 8, "mode": "parallel", "group": "contain"},
                ],
                parallel_group="contain",
            ),
            Action(
                action_id="a2",
                action_name=f"采集 {primary_asset} 内存与磁盘镜像",
                description="在清除前先进行证据保全，支持溯源和合规。",
                target_stage="preservation",
                estimated_cost=20,
                risk_penalty=0.15,
                confidence=0.79,
                reasoning="当前取证保全维度较低，优先补齐证据链。",
                command=f"velociraptor collect --target {primary_asset} --profile memory,disk",
                api_call=f"POST /forensics/acquire?asset={primary_asset}",
                target_assets=target_assets,
                capability_tags=["forensics_collection"],
                effects={"preservation": 0.45, "assessment": 0.1},
                sub_steps=[
                    {"name": "内存采集", "cost_minutes": 18, "mode": "parallel", "group": "forensics"},
                    {"name": "磁盘采集", "cost_minutes": 20, "mode": "parallel", "group": "forensics"},
                ],
                parallel_group="forensics",
            ),
            Action(
                action_id="a3",
                action_name=f"终止进程 {primary_proc} 并隔离样本",
                description="清除正在运行的恶意进程并隔离可疑样本。",
                target_stage="eviction",
                estimated_cost=6,
                risk_penalty=0.35,
                confidence=0.81,
                reasoning="进程IOC直接命中，执行清除动作可快速减少威胁。",
                command=f"pkill -f {primary_proc}",
                api_call=f"POST /edr/kill_process?name={primary_proc}",
                target_assets=target_assets,
                capability_tags=["process_control"],
                effects={"eviction": 0.4, "containment": 0.1},
                sub_steps=[{"name": "终止恶意进程", "cost_minutes": 6, "mode": "serial"}],
                parallel_group="evict",
            ),
            Action(
                action_id="a4",
                action_name=f"修复漏洞 {top_cve} 并更新基线",
                description="完成补丁与安全基线更新，降低复发风险。",
                target_stage="hardening",
                estimated_cost=30,
                risk_penalty=0.2,
                confidence=0.75,
                reasoning="CVE高危且资产关键，需补丁和基线强化。",
                command=f"ansible-playbook patch.yml --limit {primary_asset}",
                api_call=f"POST /patch/apply?asset={primary_asset}&cve={top_cve}",
                target_assets=target_assets,
                capability_tags=["patch_management"],
                effects={"hardening": 0.5, "restoration": 0.1},
                sub_steps=[
                    {"name": "漏洞修复", "cost_minutes": 30, "mode": "serial"},
                    {"name": "基线加固", "cost_minutes": 12, "mode": "serial"},
                ],
                parallel_group="hardening",
            ),
            Action(
                action_id="a5",
                action_name=f"恢复 {primary_asset} 关键服务并验证",
                description="恢复业务服务并执行验证，推进恢复完成。",
                target_stage="restoration",
                estimated_cost=12,
                risk_penalty=0.3,
                confidence=0.72,
                reasoning="在遏制与清除后执行业务恢复与验证。",
                command=f"systemctl restart critical-service && systemctl status critical-service",
                api_call=f"POST /ops/recover?asset={primary_asset}",
                target_assets=target_assets,
                capability_tags=["service_recovery"],
                effects={"restoration": 0.45, "assessment": 0.1},
                sub_steps=[
                    {"name": "服务重启", "cost_minutes": 8, "mode": "serial"},
                    {"name": "健康检查", "cost_minutes": 4, "mode": "serial"},
                ],
                parallel_group="recovery",
            ),
        ]

        actions = [a for a in candidate_bank if a.action_name not in history_names]
        # 优先补齐短板状态维度
        deficits = sorted(
            [
                ("containment", state.containment),
                ("assessment", state.assessment),
                ("preservation", state.preservation),
                ("eviction", state.eviction),
                ("hardening", state.hardening),
                ("restoration", state.restoration),
            ],
            key=lambda item: item[1],
        )
        priority = [k for k, _ in deficits[:2]]
        actions.sort(key=lambda a: 0 if a.target_stage in priority else 1)
        return actions

    @staticmethod
    def _load_prompt(file_name: str) -> str:
        prompt_file = Path(__file__).resolve().parents[1] / "prompts" / file_name
        return prompt_file.read_text(encoding="utf-8") if prompt_file.exists() else ""
