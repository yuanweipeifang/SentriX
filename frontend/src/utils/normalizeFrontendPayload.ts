import { DEFAULT_NAV, createEmptyFrontendPayload } from '../constants/defaultUi'
import type {
  AiPanelMessage,
  DashboardNavItem,
  FrontendPayload,
  UiShellData,
} from '../types/frontendPayload'

const defaultPayload = createEmptyFrontendPayload()

function asRecord(input: unknown): Record<string, unknown> {
  return input && typeof input === 'object' ? (input as Record<string, unknown>) : {}
}

function asArray<T>(input: unknown, fallback: T[] = []): T[] {
  return Array.isArray(input) ? (input as T[]) : fallback
}

function asString(input: unknown, fallback = ''): string {
  return typeof input === 'string' ? input : fallback
}

function asBoolean(input: unknown, fallback = false): boolean {
  return typeof input === 'boolean' ? input : fallback
}

function asNumber(input: unknown, fallback = 0): number {
  return typeof input === 'number' && Number.isFinite(input) ? input : fallback
}

function buildAiMessages(raw: Record<string, unknown>, frontendPayload: FrontendPayload): AiPanelMessage[] {
  const modelRuntime = asRecord(raw.model_runtime)
  const agentLayers = asRecord(raw.agent_layers)
  const audit = asRecord(raw.audit)
  const confidence = asRecord(raw.confidence_model)

  const prioritizedThreats = asArray<Record<string, unknown>>(agentLayers.prioritized_threats)
  const topThreat = asString(asRecord(prioritizedThreats[0]).threat, frontendPayload.cards[0]?.value ?? 'N/A')

  return [
    {
      id: 'runtime',
      role: 'system',
      title: '模型运行',
      content: `provider=${asString(modelRuntime.provider, 'unknown')}, model=${asString(modelRuntime.model_name, 'unknown')}`,
      meta: 'LLM Runtime',
    },
    {
      id: 'agents',
      role: 'assistant',
      title: 'AI 代理状态',
      content: `top_threat=${topThreat}; hunt_queries=${frontendPayload.hunt.count}`,
      meta: 'Agents',
    },
    {
      id: 'audit',
      role: 'insight',
      title: '审计与执行',
      content: `audit=${asString(audit.audit_result, 'unknown')}; execution_confidence=${asNumber(confidence.execution_confidence, 0)}`,
      meta: 'Audit',
    },
  ]
}

export function normalizeFrontendPayload(rawInput: unknown): UiShellData {
  const raw = asRecord(rawInput)
  const payloadCandidate = asRecord(raw.frontend_payload)
  const source = Object.keys(payloadCandidate).length > 0 ? payloadCandidate : raw

  const frontendPayload: FrontendPayload = {
    schema_version: asString(source.schema_version, defaultPayload.schema_version),
    page_title: asString(source.page_title, defaultPayload.page_title),
    incident_overview: {
      event_summary: asString(asRecord(source.incident_overview).event_summary, defaultPayload.incident_overview.event_summary),
      affected_assets: asArray<string>(asRecord(source.incident_overview).affected_assets, defaultPayload.incident_overview.affected_assets),
      ioc: {
        ip: asArray<string>(asRecord(asRecord(source.incident_overview).ioc).ip, defaultPayload.incident_overview.ioc.ip),
        domain: asArray<string>(asRecord(asRecord(source.incident_overview).ioc).domain, defaultPayload.incident_overview.ioc.domain),
        cve: asArray<string>(asRecord(asRecord(source.incident_overview).ioc).cve, defaultPayload.incident_overview.ioc.cve),
        process: asArray<string>(asRecord(asRecord(source.incident_overview).ioc).process, defaultPayload.incident_overview.ioc.process),
      },
      timestamp: asString(asRecord(source.incident_overview).timestamp, defaultPayload.incident_overview.timestamp),
      source: asString(asRecord(source.incident_overview).source, defaultPayload.incident_overview.source),
    },
    cards: asArray(source.cards, defaultPayload.cards),
    confidence: {
      scores: {
        detection_confidence: asNumber(asRecord(asRecord(source.confidence).scores).detection_confidence, defaultPayload.confidence.scores.detection_confidence),
        response_confidence: asNumber(asRecord(asRecord(source.confidence).scores).response_confidence, defaultPayload.confidence.scores.response_confidence),
        execution_confidence: asNumber(asRecord(asRecord(source.confidence).scores).execution_confidence, defaultPayload.confidence.scores.execution_confidence),
      },
      levels: {
        detection_confidence: asString(asRecord(asRecord(source.confidence).levels).detection_confidence, defaultPayload.confidence.levels.detection_confidence),
        response_confidence: asString(asRecord(asRecord(source.confidence).levels).response_confidence, defaultPayload.confidence.levels.response_confidence),
        execution_confidence: asString(asRecord(asRecord(source.confidence).levels).execution_confidence, defaultPayload.confidence.levels.execution_confidence),
      },
      breakdown: asArray(asRecord(source.confidence).breakdown, defaultPayload.confidence.breakdown),
    },
    evidence: {
      root_id: asString(asRecord(source.evidence).root_id, defaultPayload.evidence.root_id),
      nodes: asArray(asRecord(source.evidence).nodes, defaultPayload.evidence.nodes),
      edges: asArray(asRecord(source.evidence).edges, defaultPayload.evidence.edges),
      legend: asRecord(asRecord(source.evidence).legend) as Record<string, string>,
    },
    downgrade: asArray(source.downgrade, defaultPayload.downgrade),
    timeline: asArray(source.timeline, defaultPayload.timeline),
    checklist: asArray(source.checklist, defaultPayload.checklist),
    hunt: {
      tabs: asArray(asRecord(source.hunt).tabs, defaultPayload.hunt.tabs),
      count: asNumber(asRecord(source.hunt).count, defaultPayload.hunt.count),
    },
    execution: {
      mode: asString(asRecord(source.execution).mode, defaultPayload.execution.mode),
      guardrails: asArray(asRecord(source.execution).guardrails, defaultPayload.execution.guardrails),
      playbook: asRecord(asRecord(source.execution).playbook),
      tasks: asArray(asRecord(source.execution).tasks, defaultPayload.execution.tasks),
      summary: asRecord(asRecord(source.execution).summary),
    },
    orchestration: {
      graph_id: asString(asRecord(source.orchestration).graph_id, defaultPayload.orchestration.graph_id),
      strategy: asString(asRecord(source.orchestration).strategy, defaultPayload.orchestration.strategy),
      nodes: asArray(asRecord(source.orchestration).nodes, defaultPayload.orchestration.nodes),
      edges: asArray(asRecord(source.orchestration).edges, defaultPayload.orchestration.edges),
      approval_nodes: asArray(asRecord(source.orchestration).approval_nodes, defaultPayload.orchestration.approval_nodes),
      rollback_plan: asRecord(asRecord(source.orchestration).rollback_plan),
      execution_order: asArray(asRecord(source.orchestration).execution_order, defaultPayload.orchestration.execution_order),
    },
    case_memory: {
      stored: asBoolean(asRecord(source.case_memory).stored, defaultPayload.case_memory.stored),
      case_id: asString(asRecord(source.case_memory).case_id, defaultPayload.case_memory.case_id),
      effective_label: asString(asRecord(source.case_memory).effective_label, defaultPayload.case_memory.effective_label),
      storage_file: asString(asRecord(source.case_memory).storage_file, defaultPayload.case_memory.storage_file),
      historical_panel: {
        has_false_positive_pattern: asBoolean(asRecord(asRecord(source.case_memory).historical_panel).has_false_positive_pattern, defaultPayload.case_memory.historical_panel.has_false_positive_pattern),
        benign_like_count: asNumber(asRecord(asRecord(source.case_memory).historical_panel).benign_like_count, defaultPayload.case_memory.historical_panel.benign_like_count),
        malicious_like_count: asNumber(asRecord(asRecord(source.case_memory).historical_panel).malicious_like_count, defaultPayload.case_memory.historical_panel.malicious_like_count),
        cases: asArray(asRecord(asRecord(source.case_memory).historical_panel).cases, defaultPayload.case_memory.historical_panel.cases),
      },
    },
    observability: {
      cache_hit: asRecord(asRecord(source.observability).cache_hit) as Record<string, boolean>,
      planner: asRecord(asRecord(source.observability).planner),
      stage_elapsed_ms: asRecord(asRecord(source.observability).stage_elapsed_ms) as Record<string, number>,
    },
  }

  const nav: DashboardNavItem[] = DEFAULT_NAV
  const aiPanel = {
    title: 'AI 协同窗口',
    subtitle: '大模型、RAG、规划与审计信息',
    messages: buildAiMessages(raw, frontendPayload),
  }

  return {
    nav,
    selectedNavId: 'analysis',
    frontendPayload,
    aiPanel,
  }
}
