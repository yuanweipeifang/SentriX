import { DEFAULT_NAV, createEmptyFrontendPayload } from '../constants/defaultUi'
import type {
  AttackChainMappingItem,
  AiPanelMessage,
  CountermeasurePreview,
  DashboardNavItem,
  ExecutionTask,
  FrontendPayload,
  IocIndicatorRecord,
  OrchestrationNode,
  SkillExecutionTraceItem,
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

function asStringArray(input: unknown, fallback: string[] = []): string[] {
  if (!Array.isArray(input)) {
    return fallback
  }
  return input.map((item) => String(item ?? '').trim()).filter(Boolean)
}

function normalizeExecutionTask(input: unknown): ExecutionTask {
  const item = asRecord(input)
  return {
    task_id: asString(item.task_id),
    name: asString(item.name),
    description: asString(item.description),
    execution_type: asString(item.execution_type),
    parallel_group: asString(item.parallel_group),
    mode: asString(item.mode),
    stage: asString(item.stage),
    shell: asString(item.shell),
    api: asString(item.api),
    estimated_cost_minutes: asNumber(item.estimated_cost_minutes),
    target_assets: asStringArray(item.target_assets),
    capability_tags: asStringArray(item.capability_tags),
    countermeasure_kind: asString(item.countermeasure_kind),
    requires_approval: asBoolean(item.requires_approval),
  }
}

function normalizeCountermeasure(input: unknown): CountermeasurePreview {
  const item = asRecord(input)
  return {
    countermeasure_id: asString(item.countermeasure_id),
    task_id: asString(item.task_id),
    title: asString(item.title),
    description: asString(item.description),
    kind: asString(item.kind),
    stage: asString(item.stage),
    mode: asString(item.mode),
    status: asString(item.status),
    command_preview: asString(item.command_preview),
    api_preview: asString(item.api_preview),
    target_assets: asStringArray(item.target_assets),
    capability_tags: asStringArray(item.capability_tags),
    requires_approval: asBoolean(item.requires_approval),
    status_message: asString(item.status_message),
    operation_id: asString(item.operation_id),
    executed_at: asString(item.executed_at),
    provider: asString(item.provider),
    applied: asBoolean(item.applied),
  }
}

function normalizeOrchestrationNode(input: unknown): OrchestrationNode {
  const item = asRecord(input)
  return {
    id: asString(item.id),
    type: asString(item.type, 'node'),
    name: asString(item.name),
    stage: asString(item.stage),
    execution_type: asString(item.execution_type),
    mode: asString(item.mode),
    parallel_group: asString(item.parallel_group),
    requires_approval: asBoolean(item.requires_approval),
  }
}

function normalizeSkillExecutionTrace(input: unknown): SkillExecutionTraceItem[] {
  return asArray(input).map((item) => {
    const row = asRecord(item)
    return {
      stage: asString(row.stage),
      skill: asString(row.skill),
      status: asString(row.status),
      elapsed_ms: asNumber(row.elapsed_ms),
    }
  })
}

function normalizeAttackChainMapping(input: unknown): AttackChainMappingItem[] {
  return asArray(input).map((item) => {
    const row = asRecord(item)
    return {
      stage: asString(row.stage, asString(row['攻击阶段'])),
      tactic: asString(row.tactic, asString(row['ATT&CK战术'])),
      technique_id: asString(row.technique_id, asString(row['技术ID'])),
      description: asString(row.description, asString(row['技术描述'])),
    }
  })
}

function normalizeIocIndicators(input: unknown): IocIndicatorRecord[] {
  return asArray(input).map((item) => {
    const row = asRecord(item)
    const metrics = asArray(row.metrics, asArray(row['指标'])).map((metric) => {
      const m = asRecord(metric)
      return {
        name: asString(m.name, asString(m['名称'])),
        value: asString(m.value, asString(m['值'])),
      }
    })
    return {
      index: asNumber(row.index, asNumber(row['记录'], 0)),
      metrics,
    }
  })
}

function buildAiMessages(frontendPayload: FrontendPayload): AiPanelMessage[] {
  const runtime = frontendPayload.runtime
  const topThreat =
    frontendPayload.cards.find((item) => item.key === 'top_threat')?.value ||
    frontendPayload.incident_overview.event_summary ||
    '暂无'
  const huntCount = frontendPayload.hunt.tabs.length

  return [
    {
      id: 'runtime',
      role: 'system',
      title: '模型运行',
      content: `服务商=${runtime.model_provider || '未知'}；模型=${runtime.model_name || '未知'}`,
      meta: '运行时',
    },
    {
      id: 'agents',
      role: 'assistant',
      title: '分析摘要',
      content: `首要威胁=${topThreat}；猎捕查询=${huntCount} 条`,
      meta: '研判',
    },
    {
      id: 'audit',
      role: 'insight',
      title: '审计与执行',
      content: `审计结果=${runtime.audit_result || '未知'}；允许执行=${runtime.execution_allowed ? '是' : '否'}`,
      meta: '审计',
    },
  ]
}

export function normalizeFrontendPayload(rawInput: unknown): UiShellData {
  const raw = asRecord(rawInput)
  const payloadCandidate = asRecord(raw.frontend_payload)
  const source = Object.keys(payloadCandidate).length > 0 ? payloadCandidate : raw
  const sourceRuntime = asRecord(source.runtime)
  const modelRuntime = asRecord(raw.model_runtime)
  const skillRuntime = asRecord(raw.skill_runtime)
  const audit = asRecord(raw.audit)

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
      count: asNumber(asRecord(source.hunt).count, asArray(asRecord(source.hunt).tabs, defaultPayload.hunt.tabs).length),
    },
    execution: {
      mode: asString(asRecord(source.execution).mode, defaultPayload.execution.mode),
      guardrails: asArray(asRecord(source.execution).guardrails, defaultPayload.execution.guardrails),
      playbook: asRecord(asRecord(source.execution).playbook),
      tasks: asArray(asRecord(source.execution).tasks).map((item) => normalizeExecutionTask(item)),
      countermeasures: asArray(asRecord(source.execution).countermeasures).map((item) => normalizeCountermeasure(item)),
      summary: asRecord(asRecord(source.execution).summary),
    },
    orchestration: {
      graph_id: asString(asRecord(source.orchestration).graph_id, defaultPayload.orchestration.graph_id),
      strategy: asString(asRecord(source.orchestration).strategy, defaultPayload.orchestration.strategy),
      nodes: asArray(asRecord(source.orchestration).nodes).map((item) => normalizeOrchestrationNode(item)),
      edges: asArray(asRecord(source.orchestration).edges, defaultPayload.orchestration.edges),
      approval_nodes: asArray<Record<string, unknown>>(
        asRecord(source.orchestration).approval_nodes,
        asArray<Record<string, unknown>>(asRecord(source.orchestration).nodes).filter((item) =>
          asBoolean(asRecord(item).requires_approval),
        ),
      ),
      rollback_plan: asRecord(asRecord(source.orchestration).rollback_plan),
      execution_order: asArray(asRecord(source.orchestration).execution_order, defaultPayload.orchestration.execution_order),
    },
    rules: {
      total: asNumber(asRecord(source.rules).total, defaultPayload.rules.total),
      page: asNumber(asRecord(source.rules).page, defaultPayload.rules.page),
      page_size: asNumber(asRecord(source.rules).page_size, defaultPayload.rules.page_size),
      db_path: asString(asRecord(source.rules).db_path, defaultPayload.rules.db_path),
      items: asArray(asRecord(source.rules).items, defaultPayload.rules.items),
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
      planner: {
        early_stop_count: asNumber(
          asRecord(asRecord(source.observability).planner).early_stop_count,
          defaultPayload.observability.planner.early_stop_count,
        ),
        ranked_action_count: asNumber(
          asRecord(asRecord(source.observability).planner).ranked_action_count,
          defaultPayload.observability.planner.ranked_action_count,
        ),
      },
      stage_elapsed_ms: asRecord(asRecord(source.observability).stage_elapsed_ms) as Record<string, number>,
      rag_enrichment: {
        online_findings_count: asNumber(
          asRecord(asRecord(source.observability).rag_enrichment).online_findings_count,
          defaultPayload.observability.rag_enrichment.online_findings_count,
        ),
        online_cve_enriched_count: asNumber(
          asRecord(asRecord(source.observability).rag_enrichment).online_cve_enriched_count,
          defaultPayload.observability.rag_enrichment.online_cve_enriched_count,
        ),
        online_cve_field_enriched_count: asNumber(
          asRecord(asRecord(source.observability).rag_enrichment).online_cve_field_enriched_count,
          defaultPayload.observability.rag_enrichment.online_cve_field_enriched_count,
        ),
        online_db_upserted: asNumber(
          asRecord(asRecord(source.observability).rag_enrichment).online_db_upserted,
          defaultPayload.observability.rag_enrichment.online_db_upserted,
        ),
      },
      async_cross_validate: {
        enabled: asBoolean(
          asRecord(asRecord(source.observability).async_cross_validate).enabled,
          defaultPayload.observability.async_cross_validate.enabled,
        ),
        scheduled: asNumber(
          asRecord(asRecord(source.observability).async_cross_validate).scheduled,
          defaultPayload.observability.async_cross_validate.scheduled,
        ),
        queued: asNumber(
          asRecord(asRecord(source.observability).async_cross_validate).queued,
          defaultPayload.observability.async_cross_validate.queued,
        ),
        running: asNumber(
          asRecord(asRecord(source.observability).async_cross_validate).running,
          defaultPayload.observability.async_cross_validate.running,
        ),
        done: asNumber(
          asRecord(asRecord(source.observability).async_cross_validate).done,
          defaultPayload.observability.async_cross_validate.done,
        ),
        failed: asNumber(
          asRecord(asRecord(source.observability).async_cross_validate).failed,
          defaultPayload.observability.async_cross_validate.failed,
        ),
      },
    },
    runtime: {
      model_provider: asString(sourceRuntime.model_provider, asString(modelRuntime.provider)),
      model_name: asString(sourceRuntime.model_name, asString(modelRuntime.model_name)),
      model_endpoint: asString(sourceRuntime.model_endpoint, asString(modelRuntime.endpoint)),
      token_usage: Object.keys(asRecord(sourceRuntime.token_usage)).length > 0
        ? asRecord(sourceRuntime.token_usage)
        : asRecord(modelRuntime.token_usage),
      audit_result: asString(sourceRuntime.audit_result, asString(audit.audit_result)),
      execution_allowed: asBoolean(sourceRuntime.execution_allowed, asBoolean(raw.execution_allowed, false)),
      audit_log_file: asString(sourceRuntime.audit_log_file, asString(raw.audit_log_file)),
      skill_trace: normalizeSkillExecutionTrace(sourceRuntime.skill_trace ?? skillRuntime.execution_trace),
    },
    attack_chain_mapping: normalizeAttackChainMapping(
      asRecord(source).attack_chain_mapping ?? asRecord(raw.deep_analysis)['攻击链ATT&CK映射'],
    ),
    exposure_surface_analysis: {
      risk_level: asString(
        asRecord(source).exposure_surface_analysis && asRecord(asRecord(source).exposure_surface_analysis).risk_level,
        asString(asRecord(asRecord(raw.deep_analysis)['暴露面分析'])['场景风险等级']),
      ),
      risk_reason: asString(
        asRecord(source).exposure_surface_analysis && asRecord(asRecord(source).exposure_surface_analysis).risk_reason,
        asString(asRecord(asRecord(raw.deep_analysis)['暴露面分析'])['场景风险等级说明']),
      ),
      asset_count: asNumber(
        asRecord(source).exposure_surface_analysis && asRecord(asRecord(source).exposure_surface_analysis).asset_count,
        asNumber(asRecord(asRecord(raw.deep_analysis)['暴露面分析'])['暴露资产数'], 0),
      ),
      critical_asset_count: asNumber(
        asRecord(source).exposure_surface_analysis && asRecord(asRecord(source).exposure_surface_analysis).critical_asset_count,
        asNumber(asRecord(asRecord(raw.deep_analysis)['暴露面分析'])['关键资产数'], 0),
      ),
      max_cve_severity: asNumber(
        asRecord(source).exposure_surface_analysis && asRecord(asRecord(source).exposure_surface_analysis).max_cve_severity,
        asNumber(asRecord(asRecord(raw.deep_analysis)['暴露面分析'])['最高CVE严重度'], 0),
      ),
    },
    ioc_indicators: normalizeIocIndicators(
      asRecord(source).ioc_indicators ?? asRecord(raw.deep_analysis)['IOC指标'],
    ),
    runtime_logs: asArray<string>(asRecord(source).runtime_logs, []),
  }

  const nav: DashboardNavItem[] = DEFAULT_NAV
  const aiPanel = {
    title: 'AI 协同窗口',
    subtitle: '大模型、RAG、规划与审计信息',
    messages: buildAiMessages(frontendPayload),
  }

  return {
    nav,
    selectedNavId: 'home',
    frontendPayload,
    aiPanel,
  }
}
