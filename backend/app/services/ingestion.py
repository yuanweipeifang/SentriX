import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Tuple

from ..domain.models import Incident


class DataIngestion:
    """Normalize raw log payload into the unified incident object."""

    @staticmethod
    def load_from_json(file_path: str) -> Incident:
        payload = json.loads(Path(file_path).read_text(encoding="utf-8"))
        if DataIngestion._is_dataset_payload(payload):
            normalized = DataIngestion.normalize_dataset_sample(payload, sample_index=0)[0]
            return Incident.from_dict(normalized)
        return Incident.from_dict(DataIngestion.normalize(payload))

    @staticmethod
    def load_from_dataset_json(file_path: str, sample_index: int) -> Tuple[Incident, Dict[str, Any]]:
        payload = json.loads(Path(file_path).read_text(encoding="utf-8"))
        normalized, meta = DataIngestion.normalize_dataset_sample(payload, sample_index=sample_index)
        return Incident.from_dict(normalized), meta

    @staticmethod
    def load_from_csv_row(file_path: str, row_index: int) -> Tuple[Incident, Dict[str, Any]]:
        file = Path(file_path)
        has_header = DataIngestion._csv_has_header(file)
        with file.open("r", encoding="utf-8", errors="ignore", newline="") as f:
            if has_header:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    if idx != row_index:
                        continue
                    values = [str(v).strip() for v in row.values() if str(v).strip()]
                    text = " | ".join(values[:40])
                    extracted = DataIngestion._extract_ioc_assets(text)
                    event_summary = f"CSV row #{row_index}: {text[:180]}" if text else f"CSV row #{row_index}"
                    normalized = {
                        "event_summary": event_summary,
                        "ioc": extracted["ioc"],
                        "affected_assets": extracted["affected_assets"],
                        "raw_logs": [text] if text else [],
                        "timestamp": None,
                    }
                    meta = {
                        "source": "csv_dataset",
                        "row_index": row_index,
                        "dataset_file": str(file),
                        "columns": list(row.keys())[:30],
                        "has_header": True,
                    }
                    return Incident.from_dict(normalized), meta
            else:
                reader = csv.reader(f)
                for idx, row in enumerate(reader):
                    if idx != row_index:
                        continue
                    values = [str(v).strip() for v in row if str(v).strip()]
                    text = " | ".join(values[:40])
                    extracted = DataIngestion._extract_ioc_assets(text)
                    event_summary = f"CSV row #{row_index}: {text[:180]}" if text else f"CSV row #{row_index}"
                    normalized = {
                        "event_summary": event_summary,
                        "ioc": extracted["ioc"],
                        "affected_assets": extracted["affected_assets"],
                        "raw_logs": [text] if text else [],
                        "timestamp": None,
                    }
                    meta = {
                        "source": "csv_dataset",
                        "row_index": row_index,
                        "dataset_file": str(file),
                        "columns": [f"col_{i}" for i in range(min(len(row), 30))],
                        "has_header": False,
                    }
                    return Incident.from_dict(normalized), meta
        raise IndexError(f"row_index out of range: {row_index}")

    @staticmethod
    def count_csv_rows(file_path: str) -> int:
        file = Path(file_path)
        has_header = DataIngestion._csv_has_header(file)
        with file.open("r", encoding="utf-8", errors="ignore", newline="") as f:
            if has_header:
                reader = csv.DictReader(f)
                return sum(1 for _ in reader)
            reader = csv.reader(f)
            return sum(1 for _ in reader)

    @staticmethod
    def count_dataset_samples(file_path: str) -> int:
        payload = json.loads(Path(file_path).read_text(encoding="utf-8"))
        instructions = payload.get("instructions", [])
        return len(instructions) if isinstance(instructions, list) else 0

    @staticmethod
    def normalize(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_summary": payload.get("event_summary", payload.get("summary", "")),
            "ioc": payload.get("ioc", payload.get("iocs", {})),
            "affected_assets": payload.get("affected_assets", payload.get("assets", [])),
            "raw_logs": payload.get("raw_logs", payload.get("logs", [])),
            "timestamp": payload.get("timestamp"),
        }

    @staticmethod
    def normalize_dataset_sample(payload: Dict[str, Any], sample_index: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        instructions = payload.get("instructions", [])
        answers = payload.get("answers", [])
        if not instructions:
            raise ValueError("Dataset JSON does not contain 'instructions'.")
        if sample_index < 0 or sample_index >= len(instructions):
            raise IndexError(f"sample_index out of range: {sample_index}, total={len(instructions)}")

        instruction_text = str(instructions[sample_index])
        answer_text = str(answers[sample_index]) if sample_index < len(answers) else ""

        system_text = DataIngestion._extract_section(instruction_text, "System")
        logs_text = DataIngestion._extract_section(instruction_text, "Logs")
        task_text = DataIngestion._extract_section(instruction_text, "Instruction")

        raw_logs = [line.strip() for line in logs_text.splitlines() if line.strip()]
        if not raw_logs:
            raw_logs = [logs_text.strip()] if logs_text.strip() else []

        extracted = DataIngestion._extract_ioc_assets(f"{system_text}\n{logs_text}\n{task_text}")
        event_summary = raw_logs[0][:180] if raw_logs else (task_text[:180] or "Dataset incident sample")

        normalized = {
            "event_summary": event_summary,
            "ioc": extracted["ioc"],
            "affected_assets": extracted["affected_assets"],
            "raw_logs": raw_logs[:80],
            "timestamp": None,
        }
        meta = {
            "source": "dataset",
            "sample_index": sample_index,
            "dataset_size": len(instructions),
            "answer_preview": answer_text[:200],
        }
        return normalized, meta

    @staticmethod
    def _extract_section(text: str, section_name: str) -> str:
        # Matches blocks like "### Logs:\n ... \n### Instruction:"
        pattern = rf"###\s*{re.escape(section_name)}:\s*\n([\s\S]*?)(?:\n###\s*[A-Za-z]+:|\Z)"
        match = re.search(pattern, text)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _extract_ioc_assets(text: str) -> Dict[str, Any]:
        ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
        cves = sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)))
        domains = sorted(
            set(
                d.lower()
                for d in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
                if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", d)
            )
        )
        processes = sorted(set(re.findall(r"\b[a-zA-Z0-9._-]+\.(?:exe|dll|sh|py|ps1)\b", text, flags=re.IGNORECASE)))
        # Prefer explicit identifiers wrapped by backticks, then fallback host-like tokens.
        asset_candidates = set(re.findall(r"`([a-zA-Z0-9._-]{3,})`", text))
        asset_candidates.update(re.findall(r"\b[a-zA-Z][a-zA-Z0-9-]*(?:-[a-zA-Z0-9]+)+\b", text))
        stopwords = {
            "self-signed",
            "non-functional",
            "four-node",
            "unit-test",
            "base64-encoded",
            "let-s-encrypt",
        }
        assets = sorted(a for a in asset_candidates if a.lower() not in stopwords)
        return {
            "ioc": {
                "ip": ips[:20],
                "domain": domains[:20],
                "cve": [c.upper() for c in cves[:20]],
                "process": processes[:20],
            },
            "affected_assets": assets[:20],
        }

    @staticmethod
    def _is_dataset_payload(payload: Any) -> bool:
        return isinstance(payload, dict) and isinstance(payload.get("instructions"), list)

    @staticmethod
    def _csv_has_header(file_path: Path) -> bool:
        request_like = re.compile(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b\s+/|HTTP/\d\.\d|Host:", re.IGNORECASE)
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.reader(f)
                rows = []
                for row in reader:
                    if any(str(cell).strip() for cell in row):
                        rows.append(row)
                    if len(rows) >= 2:
                        break
            if rows:
                first_cell = str(rows[0][0]).strip() if rows[0] else ""
                if request_like.search(first_cell):
                    return False
                if len(rows) >= 2 and len(rows[0]) == 1 and len(rows[1]) == 1:
                    second_cell = str(rows[1][0]).strip() if rows[1] else ""
                    if request_like.search(second_cell):
                        return False
        except Exception:
            pass
        try:
            sample = file_path.read_text(encoding="utf-8", errors="ignore")[:8192]
            if not sample.strip():
                return False
            return bool(csv.Sniffer().has_header(sample))
        except Exception:
            return False
