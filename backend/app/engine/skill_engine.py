from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Dict, List


class BackendSkillEngine:
    """
    Make .trae skills effective in backend runtime:
    - verify required skills exist
    - route each pipeline stage through a skill gate
    - emit execution trace for auditability
    """

    STAGE_SKILL = {
        "triage": "soc-incident-triage",
        "rag": "soc-rag-intel-analyst",
        "planning": "soc-response-planner",
        "audit": "soc-decision-auditor",
    }

    def __init__(self, project_root: str) -> None:
        self.project_root = Path(project_root)
        self.skills_dir = self.project_root / ".trae" / "skills"
        self.trace: List[Dict[str, str]] = []
        self.loaded_skills = self._discover_skills()

    def _discover_skills(self) -> List[str]:
        if not self.skills_dir.exists():
            return []
        result = []
        for skill_dir in self.skills_dir.iterdir():
            if skill_dir.is_dir() and (skill_dir / "SKILL.md").exists():
                result.append(skill_dir.name)
        return sorted(result)

    def verify_required(self) -> None:
        missing = [name for name in self.STAGE_SKILL.values() if name not in self.loaded_skills]
        if missing:
            raise RuntimeError(f"Missing required backend skills: {missing}")

    def run_stage(self, stage: str, handler: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if stage not in self.STAGE_SKILL:
            raise KeyError(f"Unknown stage: {stage}")
        skill_name = self.STAGE_SKILL[stage]
        if skill_name not in self.loaded_skills:
            raise RuntimeError(f"Skill {skill_name} is not loaded")
        begin = time.perf_counter()
        try:
            result = handler(*args, **kwargs)
            elapsed_ms = int((time.perf_counter() - begin) * 1000)
            self.trace.append(
                {
                    "stage": stage,
                    "skill": skill_name,
                    "status": "executed",
                    "elapsed_ms": str(elapsed_ms),
                }
            )
            return result
        except Exception:
            elapsed_ms = int((time.perf_counter() - begin) * 1000)
            self.trace.append(
                {
                    "stage": stage,
                    "skill": skill_name,
                    "status": "failed",
                    "elapsed_ms": str(elapsed_ms),
                }
            )
            raise

    def runtime_info(self) -> Dict[str, Any]:
        return {"loaded_skills": self.loaded_skills, "execution_trace": self.trace}
