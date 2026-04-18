from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from .services.auditor import DecisionAuditor


class RuntimeAuditory:
	"""Persist full pipeline audit trail into backend/logs/full_run_*.json."""

	def __init__(self, project_root: str) -> None:
		self.project_root = Path(project_root)
		self.logs_dir = self.project_root / "backend" / "logs"
		self.logs_dir.mkdir(parents=True, exist_ok=True)

	def write_full_run(self, payload: Dict[str, Any]) -> str:
		ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
		file_path = self.logs_dir / f"full_run_{ts}.json"
		file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
		return str(file_path)


__all__ = ["DecisionAuditor", "RuntimeAuditory"]
