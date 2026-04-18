import type { DashboardNavItem, FrontendPayload, UiShellData } from '../types/frontendPayload'

export const DEFAULT_NAV: DashboardNavItem[] = [
  { id: 'dashboard', label: '仪表盘' },
  { id: 'analysis', label: '事件研判', badge: 'LIVE' },
  { id: 'evidence', label: '证据图谱' },
  { id: 'hunt', label: '猎捕查询' },
  { id: 'execution', label: '执行编排' },
  { id: 'history', label: '历史案例' },
  { id: 'settings', label: '系统设置' },
]

export function createEmptyFrontendPayload(): FrontendPayload {
  return {
    schema_version: '',
    page_title: '',
    incident_overview: {
      event_summary: '',
      affected_assets: [],
      ioc: {
        ip: [],
        domain: [],
        cve: [],
        process: [],
      },
      timestamp: '',
      source: '',
    },
    cards: [],
    confidence: {
      scores: {
        detection_confidence: 0,
        response_confidence: 0,
        execution_confidence: 0,
      },
      levels: {
        detection_confidence: '',
        response_confidence: '',
        execution_confidence: '',
      },
      breakdown: [],
    },
    evidence: {
      root_id: '',
      nodes: [],
      edges: [],
      legend: {
        incident: '事件',
        rule: '规则',
        cve: '漏洞',
        ioc: 'IOC',
        log: '日志片段',
      },
    },
    downgrade: [],
    timeline: [],
    checklist: [],
    hunt: {
      tabs: [],
      count: 0,
    },
    execution: {
      mode: '',
      guardrails: [],
      playbook: {},
      tasks: [],
      summary: {},
    },
    orchestration: {
      graph_id: '',
      strategy: '',
      nodes: [],
      edges: [],
      approval_nodes: [],
      rollback_plan: {},
      execution_order: [],
    },
    case_memory: {
      stored: false,
      case_id: '',
      effective_label: '',
      storage_file: '',
      historical_panel: {
        has_false_positive_pattern: false,
        benign_like_count: 0,
        malicious_like_count: 0,
        cases: [],
      },
    },
    observability: {
      cache_hit: {},
      planner: {},
      stage_elapsed_ms: {},
    },
  }
}

export function createEmptyUiShellData(): UiShellData {
  return {
    nav: DEFAULT_NAV,
    selectedNavId: 'analysis',
    frontendPayload: createEmptyFrontendPayload(),
    aiPanel: {
      title: 'AI 协同窗口',
      subtitle: '展示后端模型、RAG、规划与审计信息',
      messages: [],
    },
  }
}
