import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


_DOTENV_LOADED = False


def _load_env_file() -> None:
    """Load key=value pairs from workspace .env once, without overriding existing env vars."""
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return

    candidate_files = [
        Path(__file__).resolve().parents[3] / ".env",  # workspace root .env
        Path(__file__).resolve().parents[2] / ".env",  # backend/.env fallback
    ]

    for env_file in candidate_files:
        if not env_file.exists():
            continue
        try:
            for raw_line in env_file.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("\"'")
                if key and key not in os.environ:
                    os.environ[key] = value
        except Exception:
            continue
        break

    _DOTENV_LOADED = True


@dataclass
class PlannerConfig:
    candidate_count: int = 3
    rollout_count: int = 3
    planning_depth: int = 3
    risk_penalty_weight: float = 0.7
    time_penalty_weight: float = 0.15
    terminal_threshold: float = 0.95
    early_stop_enabled: bool = True
    early_stop_min_rollouts: int = 2
    early_stop_margin: float = 0.15

    @staticmethod
    def from_env() -> "PlannerConfig":
        return PlannerConfig(
            candidate_count=int(os.getenv("PLANNER_CANDIDATE_COUNT", "3")),
            rollout_count=int(os.getenv("PLANNER_ROLLOUT_COUNT", "3")),
            planning_depth=int(os.getenv("PLANNER_DEPTH", "3")),
            risk_penalty_weight=float(os.getenv("PLANNER_RISK_PENALTY_WEIGHT", "0.7")),
            time_penalty_weight=float(os.getenv("PLANNER_TIME_PENALTY_WEIGHT", "0.15")),
            terminal_threshold=float(os.getenv("PLANNER_TERMINAL_THRESHOLD", "0.95")),
            early_stop_enabled=os.getenv("PLANNER_EARLY_STOP_ENABLED", "true").lower() == "true",
            early_stop_min_rollouts=int(os.getenv("PLANNER_EARLY_STOP_MIN_ROLLOUTS", "2")),
            early_stop_margin=float(os.getenv("PLANNER_EARLY_STOP_MARGIN", "0.15")),
        )


@dataclass
class MultiAgentConfig:
    enabled: bool = True
    use_llm_agents: bool = True
    max_rounds: int = 3
    convergence_streak: int = 2
    top_k_actions: int = 3
    per_agent_timeout_ms: int = 1800
    max_elapsed_ms: int = 6000
    min_consensus_margin: float = 0.05

    @staticmethod
    def from_env() -> "MultiAgentConfig":
        return MultiAgentConfig(
            enabled=os.getenv("MULTI_AGENT_ENABLED", "true").lower() == "true",
            use_llm_agents=os.getenv("MULTI_AGENT_USE_LLM_AGENTS", "true").lower() == "true",
            max_rounds=int(os.getenv("MULTI_AGENT_MAX_ROUNDS", "3")),
            convergence_streak=int(os.getenv("MULTI_AGENT_CONVERGENCE_STREAK", "2")),
            top_k_actions=int(os.getenv("MULTI_AGENT_TOP_K_ACTIONS", "3")),
            per_agent_timeout_ms=int(os.getenv("MULTI_AGENT_PER_AGENT_TIMEOUT_MS", "1800")),
            max_elapsed_ms=int(os.getenv("MULTI_AGENT_MAX_ELAPSED_MS", "6000")),
            min_consensus_margin=float(os.getenv("MULTI_AGENT_MIN_MARGIN", "0.05")),
        )


@dataclass
class ModelConfig:
    provider: str = "qwen"
    endpoint: str = ""
    api_key: str = ""
    model_name: str = "qwen-plus"
    timeout_seconds: int = 30
    enable_online_rag: bool = False
    web_search_provider: str = "serper"
    web_search_endpoint: str = "https://google.serper.dev/search"
    web_search_api_key: str = ""
    web_search_top_k: int = 5
    rag_use_db: bool = True
    rag_db_path: str = ""
    rag_top_k: int = 12
    rag_auto_reindex: bool = True
    rag_use_llm_compression: bool = False
    online_rag_min_rule_hits: int = 1
    analysis_cache_ttl_seconds: int = 300
    embedding_endpoint: str = ""
    embedding_model_name: str = ""
    embedding_timeout_seconds: int = 6

    @staticmethod
    def from_env() -> "ModelConfig":
        # Hardcoded runtime defaults: always use a domestic provider stack.
        apikey_payload = _load_apikey_payload()
        provider = "qwen"
        defaults = _provider_defaults(provider, apikey_payload)
        default_rag_db_path = str(Path(__file__).resolve().parents[2] / "data" / "rag_intel.db")
        enable_online_rag = os.getenv("ONLINE_RAG_ENABLED", "false").lower() == "true"
        web_search_provider = os.getenv("WEB_SEARCH_PROVIDER", "serper").strip().lower() or "serper"
        web_search_endpoint = os.getenv("WEB_SEARCH_ENDPOINT", "https://google.serper.dev/search").strip()
        web_search_api_key = os.getenv("WEB_SEARCH_API_KEY", "").strip()
        web_search_top_k = int(os.getenv("WEB_SEARCH_TOP_K", "5"))
        online_rag_min_rule_hits = int(os.getenv("ONLINE_RAG_MIN_RULE_HITS", "1"))
        timeout_seconds = int(os.getenv("MODEL_TIMEOUT_SECONDS", "30"))
        analysis_cache_ttl_seconds = int(os.getenv("ANALYSIS_CACHE_TTL_SECONDS", "300"))
        return ModelConfig(
            provider=provider,
            endpoint=defaults["endpoint"],
            api_key=defaults["api_key"],
            model_name=defaults["model_name"],
            timeout_seconds=timeout_seconds,
            enable_online_rag=enable_online_rag,
            web_search_provider=web_search_provider,
            web_search_endpoint=web_search_endpoint,
            web_search_api_key=web_search_api_key,
            web_search_top_k=web_search_top_k,
            rag_use_db=True,
            rag_db_path=default_rag_db_path,
            rag_top_k=12,
            rag_auto_reindex=True,
            rag_use_llm_compression=False,
            online_rag_min_rule_hits=online_rag_min_rule_hits,
            analysis_cache_ttl_seconds=analysis_cache_ttl_seconds,
            embedding_endpoint=defaults["embedding_endpoint"],
            embedding_model_name=defaults["embedding_model_name"],
            embedding_timeout_seconds=6,
        )


@dataclass
class RuleGenerationConfig:
    enabled: bool = False
    candidate_parallel: int = 5
    max_iterations: int = 5
    temperatures: List[float] | None = None
    top_k_keep: int = 5
    enforce_domestic_model: bool = True
    max_cves_per_incident: int = 1
    budget_ms: int = 5000
    skip_if_rule_hits_gte: int = 4
    skip_if_confidence_gte: float = 0.9
    min_raw_logs: int = 1

    @staticmethod
    def from_env() -> "RuleGenerationConfig":
        parsed_temps = [0.7, 0.75, 0.8, 0.85, 0.9]
        return RuleGenerationConfig(
            enabled=os.getenv("RULEGEN_ENABLED", "true").lower() == "true",
            candidate_parallel=int(os.getenv("RULEGEN_CANDIDATE_PARALLEL", "5")),
            max_iterations=int(os.getenv("RULEGEN_MAX_ITERATIONS", "5")),
            temperatures=parsed_temps,
            top_k_keep=int(os.getenv("RULEGEN_TOP_K_KEEP", "5")),
            enforce_domestic_model=os.getenv("RULEGEN_ENFORCE_DOMESTIC_MODEL", "true").lower() == "true",
            max_cves_per_incident=int(os.getenv("RULEGEN_MAX_CVES_PER_INCIDENT", "1")),
            budget_ms=int(os.getenv("RULEGEN_BUDGET_MS", "5000")),
            skip_if_rule_hits_gte=int(os.getenv("RULEGEN_SKIP_IF_RULE_HITS_GTE", "4")),
            skip_if_confidence_gte=float(os.getenv("RULEGEN_SKIP_IF_CONFIDENCE_GTE", "0.9")),
            min_raw_logs=int(os.getenv("RULEGEN_MIN_RAW_LOGS", "1")),
        )


def _load_apikey_payload() -> Dict[str, str]:
    file_candidates = []
    env_path = os.getenv("API_KEY_FILE", "").strip()
    if env_path:
        file_candidates.append(Path(env_path))
    # Default location: backend/apikey.txt
    file_candidates.append(Path(__file__).resolve().parents[2] / "apikey.txt")

    payload: Dict[str, str] = {}
    for file_path in file_candidates:
        if not file_path.exists():
            continue
        try:
            for raw_line in file_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    payload[key] = value
        except Exception:
            continue
    return payload


def _provider_defaults(provider: str, apikey_payload: Dict[str, str]) -> Dict[str, str]:
    provider = provider.strip().lower()
    if provider == "glm":
        return {
            "api_key": apikey_payload.get("GLM_API_KEY", ""),
            "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            "model_name": "glm-4-flash",
            "embedding_endpoint": "https://open.bigmodel.cn/api/paas/v4/embeddings",
            "embedding_model_name": "embedding-3",
        }
    if provider == "deepseek":
        return {
            "api_key": apikey_payload.get("DEEPSEEK_API_KEY", ""),
            "endpoint": "https://api.deepseek.com/v1/chat/completions",
            "model_name": "deepseek-chat",
            "embedding_endpoint": "",
            "embedding_model_name": "",
        }
    if provider == "openai":
        return {
            "api_key": apikey_payload.get("OPENAI_API_KEY", ""),
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "model_name": "gpt-4o-mini",
        }
    # Default provider: qwen / dashscope compatible endpoint
    return {
        "api_key": apikey_payload.get("DASHSCOPE_API_KEY", ""),
        "endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "model_name": "qwen-plus",
        "embedding_endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1/embeddings",
        "embedding_model_name": "text-embedding-v3",
    }


DEFAULT_CVE_DB = {
    "CVE-2021-44228": {"severity": 9.8, "description": "Log4Shell RCE", "ttp": "Initial Access"},
    "CVE-2023-23397": {"severity": 9.8, "description": "Outlook privilege escalation", "ttp": "Execution"},
    "CVE-2024-3400": {"severity": 10.0, "description": "Palo Alto PAN-OS command injection", "ttp": "Persistence"},
}

DEFAULT_IOC_INTEL = {
    "198.51.100.23": {"threat": "C2 IP", "confidence": 0.91},
    "malicious-updates.example": {"threat": "Phishing domain", "confidence": 0.87},
    "rclone.exe": {"threat": "Potential exfiltration tooling", "confidence": 0.73},
}

DEFAULT_ASSET_DB = {
    "db-prod-01": {"criticality": "high", "owner": "data-platform"},
    "web-prod-02": {"criticality": "medium", "owner": "web-team"},
    "edr-gateway-01": {"criticality": "high", "owner": "soc"},
}

DEFAULT_RULE_DB = {
    "RULE-SIGMA-001": {
        "rule_type": "sigma",
        "title": "Suspicious PowerShell Encoded Command",
        "pattern": "powershell -enc",
        "ttp": "attack.t1059.001",
        "severity": 0.86,
        "confidence": 0.8,
        "source": "builtin_sigma",
        "version": "v1",
        "source_url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "RULE-SURICATA-001": {
        "rule_type": "suricata",
        "title": "Possible C2 Beacon Pattern",
        "pattern": "beaconing interval",
        "ttp": "attack.t1071",
        "severity": 0.8,
        "confidence": 0.74,
        "source": "builtin_suricata",
        "version": "v1",
        "source_url": "https://attack.mitre.org/techniques/T1071/",
    },
    "RULE-BEHAVIOR-001": {
        "rule_type": "behavior",
        "title": "Lateral Movement via Remote Service",
        "pattern": "psexec",
        "ttp": "attack.t1021",
        "severity": 0.82,
        "confidence": 0.72,
        "source": "builtin_behavior",
        "version": "v1",
        "source_url": "https://attack.mitre.org/techniques/T1021/",
    },
    "RULE-WEB-ATTACK-001": {
        "rule_type": "sigma",
        "title": "Command Injection Web Pattern",
        "pattern": "shell_exec",
        "ttp": "attack.t1059",
        "severity": 0.9,
        "confidence": 0.82,
        "source": "builtin_web_rules",
        "version": "v1",
        "source_url": "https://attack.mitre.org/techniques/T1059/",
    },
    "RULE-WEB-ATTACK-002": {
        "rule_type": "sigma",
        "title": "Path Traversal Pattern",
        "pattern": "../",
        "ttp": "attack.t1005",
        "severity": 0.78,
        "confidence": 0.76,
        "source": "builtin_web_rules",
        "version": "v1",
        "source_url": "https://attack.mitre.org/techniques/T1005/",
    },
}

RESPONSE_STAGES: List[str] = [
    "containment",
    "assessment",
    "preservation",
    "eviction",
    "hardening",
    "restoration",
]

SUPPORTED_CAPABILITIES: List[str] = [
    "network_isolation",
    "forensics_collection",
    "process_control",
    "patch_management",
    "service_recovery",
]

ALLOWED_COMMAND_PREFIXES: List[str] = [
    "iptables",
    "velociraptor",
    "pkill",
    "ansible-playbook",
    "systemctl",
]
