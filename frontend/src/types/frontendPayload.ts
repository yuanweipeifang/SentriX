export type Tone = 'danger' | 'primary' | 'info' | 'success' | 'warning' | 'default'
export type Severity = 'high' | 'medium' | 'low'

export interface SummaryCard {
  key: string
  label: string
  value: string
  tone: Tone
}

export interface ConfidenceBreakdownItem {
  key: string
  label: string
  value: number
  weight: string
}

export interface ConfidencePanel {
  scores: {
    detection_confidence: number
    response_confidence: number
    execution_confidence: number
  }
  levels: {
    detection_confidence: string
    response_confidence: string
    execution_confidence: string
  }
  breakdown: ConfidenceBreakdownItem[]
}

export interface EvidenceNode {
  id: string
  type: string
  label: string
  title: string
  subtitle: string
  severity: Severity
  meta: Record<string, unknown>
}

export interface EvidenceEdge {
  from: string
  to: string
  relation: string
}

export interface EvidenceGraph {
  root_id: string
  nodes: EvidenceNode[]
  edges: EvidenceEdge[]
  legend: Record<string, string>
}

export interface DowngradeExplanation {
  code: string
  title: string
  description: string
  severity: Severity
  display: string
}

export interface TimelineItem {
  id: string
  stage: string
  label: string
  value: string
}

export interface ChecklistItem {
  key: string
  label: string
  status: string
}

export interface HuntTab {
  id: string
  title: string
  stage: string
  sql: string
  elasticsearch_dsl: Record<string, unknown>
  splunk_spl: string
}

export interface HuntPanel {
  tabs: HuntTab[]
  count: number
}

export interface ExecutionTask {
  task_id: string
  name: string
  description: string
  execution_type: string
  parallel_group: string
  mode: string
  stage: string
  shell: string
  api: string
  estimated_cost_minutes: number
  target_assets: string[]
  capability_tags: string[]
  countermeasure_kind: string
  requires_approval: boolean
}

export interface CountermeasurePreview {
  countermeasure_id: string
  task_id: string
  title: string
  description: string
  kind: string
  stage: string
  mode: string
  status: string
  command_preview: string
  api_preview: string
  target_assets: string[]
  capability_tags: string[]
  requires_approval: boolean
  status_message: string
  operation_id: string
  executed_at: string
  provider: string
  applied: boolean
}

export interface ExecutionPanel {
  mode: string
  guardrails: string[]
  playbook: Record<string, unknown>
  tasks: ExecutionTask[]
  countermeasures: CountermeasurePreview[]
  summary: Record<string, unknown>
}

export interface OrchestrationNode {
  id: string
  type: string
  name: string
  stage: string
  execution_type: string
  mode: string
  parallel_group: string
  requires_approval: boolean
}

export interface OrchestrationGraph {
  graph_id: string
  strategy: string
  nodes: OrchestrationNode[]
  edges: Record<string, unknown>[]
  approval_nodes: Record<string, unknown>[]
  rollback_plan: Record<string, unknown>
  execution_order: string[]
}

export interface HistoricalCaseItem {
  case_id: string
  score: number
  effective_label: string
  top_threat: string
  best_action: string
}

export interface HistoricalCasePanel {
  has_false_positive_pattern: boolean
  benign_like_count: number
  malicious_like_count: number
  cases: HistoricalCaseItem[]
}

export interface RuleRecord {
  rule_id: string
  title: string
  rule_type: string
  pattern: string
  ttp: string
  severity: number
  confidence: number
  source: string
  version: string
  source_url: string
  updated_at: string
}

export interface RulesPanel {
  total: number
  page: number
  page_size: number
  db_path: string
  items: RuleRecord[]
}

export interface CaseMemoryPanel {
  stored: boolean
  case_id: string
  effective_label: string
  storage_file: string
  historical_panel: HistoricalCasePanel
}

export interface ObservabilityPanel {
  cache_hit: Record<string, boolean>
  planner: Record<string, unknown>
  stage_elapsed_ms: Record<string, number>
}

export interface IncidentOverview {
  event_summary: string
  affected_assets: string[]
  ioc: {
    ip: string[]
    domain: string[]
    cve: string[]
    process: string[]
  }
  timestamp: string
  source: string
}

export interface FrontendPayload {
  schema_version: string
  page_title: string
  incident_overview: IncidentOverview
  cards: SummaryCard[]
  confidence: ConfidencePanel
  evidence: EvidenceGraph
  downgrade: DowngradeExplanation[]
  timeline: TimelineItem[]
  checklist: ChecklistItem[]
  hunt: HuntPanel
  execution: ExecutionPanel
  orchestration: OrchestrationGraph
  rules: RulesPanel
  case_memory: CaseMemoryPanel
  observability: ObservabilityPanel
}

export interface AiPanelMessage {
  id: string
  role: 'system' | 'assistant' | 'insight' | 'user'
  title: string
  content: string
  meta?: string
}

export interface DashboardNavItem {
  id: string
  label: string
  badge?: string
}

export interface UiShellData {
  nav: DashboardNavItem[]
  selectedNavId: string
  frontendPayload: FrontendPayload
  aiPanel: {
    title: string
    subtitle: string
    messages: AiPanelMessage[]
  }
}
