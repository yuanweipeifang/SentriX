from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List


def _as_string(value: Any, fallback: str = "") -> str:
    return value.strip() if isinstance(value, str) else fallback


class CountermeasureStateStore:
    """In-memory runtime store for active-response feedback."""

    def __init__(self) -> None:
        self._rows: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._lock = Lock()

    def upsert(self, case_id: str, state: Dict[str, Any]) -> None:
        normalized_case_id = _as_string(case_id)
        if not normalized_case_id:
            return

        countermeasure_id = _as_string(state.get("countermeasure_id"))
        task_id = _as_string(state.get("task_id"))
        key = countermeasure_id or task_id
        if not key:
            return

        with self._lock:
            bucket = self._rows.setdefault(normalized_case_id, {})
            bucket[key] = {
                "countermeasure_id": countermeasure_id,
                "task_id": task_id,
                "status": _as_string(state.get("status")),
                "message": _as_string(state.get("message")),
                "operation_id": _as_string(state.get("operation_id")),
                "executed_at": _as_string(state.get("executed_at")),
                "provider": _as_string(state.get("provider")),
                "applied": bool(state.get("applied", False)),
            }

    def merge(self, case_id: str, countermeasures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized_case_id = _as_string(case_id)
        if not normalized_case_id:
            return countermeasures

        with self._lock:
            bucket = dict(self._rows.get(normalized_case_id, {}))

        merged: List[Dict[str, Any]] = []
        for item in countermeasures:
            countermeasure_id = _as_string(item.get("countermeasure_id"))
            task_id = _as_string(item.get("task_id"))
            runtime = bucket.get(countermeasure_id) or bucket.get(task_id) or {}
            merged.append(
                {
                    **item,
                    "status": _as_string(runtime.get("status"), _as_string(item.get("status"), "ready")),
                    "status_message": _as_string(runtime.get("message")),
                    "operation_id": _as_string(runtime.get("operation_id")),
                    "executed_at": _as_string(runtime.get("executed_at")),
                    "provider": _as_string(runtime.get("provider")),
                    "applied": bool(runtime.get("applied", False)),
                }
            )
        return merged

    def clear(self, case_id: str = "") -> None:
        normalized_case_id = _as_string(case_id)
        with self._lock:
            if normalized_case_id:
                self._rows.pop(normalized_case_id, None)
            else:
                self._rows.clear()
