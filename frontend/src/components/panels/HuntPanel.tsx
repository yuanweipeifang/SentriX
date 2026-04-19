import { useEffect, useMemo, useState } from 'react'
import { SectionTitle } from '../common/SectionTitle'
import { fetchHuntRagSuggest, type HuntRagEvidenceItem } from '../../services/huntRagApi'
import type { HuntPanel as HuntPanelType } from '../../types/frontendPayload'
import type { HuntBridgePayload } from '../../types/huntBridge'

interface HuntPanelProps {
  hunt: HuntPanelType
  selectedHuntId: string
  onSelect: (id: string) => void
  ragContext: {
    eventSummary?: string
    topThreat?: string
    affectedAssets?: string[]
    ioc?: {
      ip?: string[]
      domain?: string[]
      cve?: string[]
      process?: string[]
    }
  }
  graphBridge?: HuntBridgePayload | null
  fullHeight?: boolean
}

type QueryLanguage = 'sql' | 'dsl' | 'spl'
type QueryRiskLevel = 'high' | 'medium' | 'low'

interface QueryRiskItem {
  level: QueryRiskLevel
  code: string
  message: string
}

interface QuerySnapshot {
  id: string
  createdAt: number
  huntId: string
  huntTitle: string
  language: QueryLanguage
  params: Record<string, string>
  query: string
  sourceNodeLabel?: string
}

interface TerminalRecord {
  id: string
  type: 'input' | 'output'
  text: string
  at: number
}

const languageLabelMap: Record<QueryLanguage, string> = {
  sql: 'SQL',
  dsl: 'Elasticsearch DSL',
  spl: 'Splunk SPL',
}

const FAVORITES_KEY = 'sentrix.hunt.favorites.v1'
const RECENT_KEY = 'sentrix.hunt.recent.v1'
const HISTORY_KEY = 'sentrix.hunt.history.v1'

const TERMINAL_COMMANDS = [
  '展示当前查询',
  '展示当前参数',
  '展示语句风险',
  '模拟执行当前查询',
  '展示参数差异',
  '列出收藏查询',
  '列出最近查询',
  '列出历史版本',
]

function readSnapshotStorage(key: string): QuerySnapshot[] {
  try {
    const raw = window.localStorage.getItem(key)
    if (!raw) return []
    const parsed = JSON.parse(raw) as QuerySnapshot[]
    if (!Array.isArray(parsed)) return []
    return parsed.filter((item) => item && typeof item.id === 'string')
  } catch {
    return []
  }
}

function writeSnapshotStorage(key: string, data: QuerySnapshot[]) {
  window.localStorage.setItem(key, JSON.stringify(data))
}

function uniqueById(items: QuerySnapshot[]): QuerySnapshot[] {
  const map = new Map<string, QuerySnapshot>()
  items.forEach((item) => {
    map.set(item.id, item)
  })
  return Array.from(map.values())
}

function buildSnapshotKey(snapshot: QuerySnapshot): string {
  return `${snapshot.huntId}:${snapshot.language}:${snapshot.query}`
}

function extractTemplateTokens(input: string): string[] {
  const tokens = new Set<string>()
  const bracePattern = /\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g
  const dollarPattern = /\$([a-zA-Z_][a-zA-Z0-9_]*)/g

  let match: RegExpExecArray | null = bracePattern.exec(input)
  while (match) {
    tokens.add(match[1])
    match = bracePattern.exec(input)
  }

  match = dollarPattern.exec(input)
  while (match) {
    tokens.add(match[1])
    match = dollarPattern.exec(input)
  }

  return Array.from(tokens)
}

function applyTemplateParams(template: string, params: Record<string, string>): string {
  return Object.entries(params).reduce((current, [key, value]) => {
    if (!value.trim()) return current
    const braceRegex = new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, 'g')
    const dollarRegex = new RegExp(`\\$${key}\\b`, 'g')
    return current.replace(braceRegex, value).replace(dollarRegex, value)
  }, template)
}

function buildParamFillFromBridge(tokens: string[], bridge: HuntBridgePayload): Record<string, string> {
  const fill: Record<string, string> = {}

  tokens.forEach((token) => {
    const key = token.toLowerCase()
    if (/(^|_)(cve|vuln)/.test(key) && bridge.indicators.cve[0]) {
      fill[token] = bridge.indicators.cve[0]
      return
    }
    if (/(^|_)(domain|fqdn)/.test(key) && bridge.indicators.domain[0]) {
      fill[token] = bridge.indicators.domain[0]
      return
    }
    if (/(^|_)(src_ip|source_ip)/.test(key) && bridge.indicators.ip[0]) {
      fill[token] = bridge.indicators.ip[0]
      return
    }
    if (/(^|_)(dst_ip|dest_ip|destination_ip)/.test(key) && (bridge.indicators.ip[1] || bridge.indicators.ip[0])) {
      fill[token] = bridge.indicators.ip[1] || bridge.indicators.ip[0]
      return
    }
    if (/(^|_)(ip|ipv4|ipv6)/.test(key) && bridge.indicators.ip[0]) {
      fill[token] = bridge.indicators.ip[0]
      return
    }
    if (/(^|_)(host|hostname|asset|endpoint|device|computer)/.test(key) && bridge.indicators.host[0]) {
      fill[token] = bridge.indicators.host[0]
      return
    }
    if (/(^|_)(process|proc|image|exe|command)/.test(key) && bridge.indicators.process[0]) {
      fill[token] = bridge.indicators.process[0]
      return
    }
    if (/(^|_)(ioc|indicator|threat)/.test(key) && bridge.indicators.ioc[0]) {
      fill[token] = bridge.indicators.ioc[0]
    }
  })

  return fill
}

function sqlEscape(value: string): string {
  return value.replace(/'/g, "''")
}

function buildNodeClause(language: QueryLanguage, bridge: HuntBridgePayload): string {
  if (language === 'sql') {
    const clauses: string[] = []
    if (bridge.indicators.ip[0]) {
      const ip = sqlEscape(bridge.indicators.ip[0])
      clauses.push(`(src_ip = '${ip}' OR dst_ip = '${ip}' OR ip = '${ip}')`)
    }
    if (bridge.indicators.domain[0]) clauses.push(`domain = '${sqlEscape(bridge.indicators.domain[0])}'`)
    if (bridge.indicators.cve[0]) clauses.push(`cve_id = '${sqlEscape(bridge.indicators.cve[0])}'`)
    if (bridge.indicators.host[0]) clauses.push(`host = '${sqlEscape(bridge.indicators.host[0])}'`)
    return clauses.join(' AND ')
  }

  if (language === 'spl') {
    const clauses: string[] = []
    if (bridge.indicators.ip[0]) clauses.push(`(src_ip="${bridge.indicators.ip[0]}" OR dest_ip="${bridge.indicators.ip[0]}")`)
    if (bridge.indicators.domain[0]) clauses.push(`domain="${bridge.indicators.domain[0]}"`)
    if (bridge.indicators.cve[0]) clauses.push(`cve="${bridge.indicators.cve[0]}"`)
    if (bridge.indicators.host[0]) clauses.push(`host="${bridge.indicators.host[0]}"`)
    return clauses.join(' OR ')
  }

  const dslParts: string[] = []
  if (bridge.indicators.ip[0]) dslParts.push(`ip:${bridge.indicators.ip[0]}`)
  if (bridge.indicators.domain[0]) dslParts.push(`domain:${bridge.indicators.domain[0]}`)
  if (bridge.indicators.cve[0]) dslParts.push(`cve:${bridge.indicators.cve[0]}`)
  if (bridge.indicators.host[0]) dslParts.push(`host:${bridge.indicators.host[0]}`)
  return dslParts.join(' OR ')
}

function injectClause(language: QueryLanguage, template: string, clause: string): string {
  if (!template.trim() || !clause.trim()) return template

  if (language === 'sql') {
    if (/\bwhere\b/i.test(template)) return `${template}\n  AND (${clause})`
    return `${template}\nWHERE ${clause}`
  }

  if (language === 'spl') {
    return `${template}\n| search ${clause}`
  }

  try {
    const parsed = JSON.parse(template) as Record<string, unknown>
    const query = ((parsed.query as Record<string, unknown> | undefined) ??= {})
    const boolQuery = ((query.bool as Record<string, unknown> | undefined) ??= {})
    const currentFilter = boolQuery.filter
    const nextFilter = Array.isArray(currentFilter) ? [...currentFilter] : []
    nextFilter.push({ query_string: { query: clause } })
    boolQuery.filter = nextFilter
    return JSON.stringify(parsed, null, 2)
  } catch {
    return template
  }
}

function computeParamDiff(previous: Record<string, string>, current: Record<string, string>) {
  const added: string[] = []
  const changed: string[] = []
  const removed: string[] = []
  const keys = new Set([...Object.keys(previous), ...Object.keys(current)])

  keys.forEach((key) => {
    const prev = (previous[key] ?? '').trim()
    const next = (current[key] ?? '').trim()
    if (!prev && next) {
      added.push(`${key}: ${next}`)
      return
    }
    if (prev && !next) {
      removed.push(`${key}: ${prev}`)
      return
    }
    if (prev && next && prev !== next) {
      changed.push(`${key}: ${prev} -> ${next}`)
    }
  })

  return { added, changed, removed }
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function analyzeQueryRisk(query: string, language: QueryLanguage): QueryRiskItem[] {
  const q = query.trim()
  if (!q) return []
  const items: QueryRiskItem[] = []

  if (language === 'sql') {
    if (/^\s*select\s+\*/i.test(q)) {
      items.push({ level: 'medium', code: 'SQL_SELECT_ALL', message: '检测到 SELECT *，可能返回过多字段并放大扫描成本。' })
    }
    if (/^\s*select\b/i.test(q) && !/\bwhere\b/i.test(q)) {
      items.push({ level: 'high', code: 'SQL_FULL_SCAN', message: '未检测到 WHERE 条件，可能触发全表扫描。' })
    }
    if (/\bor\s+1\s*=\s*1\b/i.test(q)) {
      items.push({ level: 'high', code: 'SQL_TAUTOLOGY', message: '存在 OR 1=1 高危条件，可能绕过过滤。' })
    }
    if (/\b(delete|update)\b/i.test(q) && !/\bwhere\b/i.test(q)) {
      items.push({ level: 'high', code: 'SQL_WRITE_NO_WHERE', message: '写操作未带 WHERE，存在大范围数据修改风险。' })
    }
  }

  if (language === 'spl') {
    if (/\|\s*search\s+\*/i.test(q) || /^\s*search\s+\*/i.test(q)) {
      items.push({ level: 'high', code: 'SPL_BROAD_SEARCH', message: 'SPL 为宽泛检索（search *），可能扫描大体量日志。' })
    }
    if (!/\b(index|sourcetype|host|source)\s*=\s*/i.test(q)) {
      items.push({ level: 'medium', code: 'SPL_NO_SCOPE', message: '未检测到 index/sourcetype 等边界条件，建议先收敛范围。' })
    }
  }

  if (language === 'dsl') {
    if (/"match_all"\s*:\s*\{\s*\}/i.test(q)) {
      items.push({ level: 'high', code: 'DSL_MATCH_ALL', message: 'DSL 使用 match_all，可能触发全量扫描。' })
    }
    if (!/"filter"\s*:/i.test(q) && !/"term"\s*:/i.test(q) && !/"range"\s*:/i.test(q)) {
      items.push({ level: 'medium', code: 'DSL_WEAK_FILTER', message: 'DSL 未检测到强过滤条件，查询范围可能过宽。' })
    }
  }

  return items
}

function levelRank(level: QueryRiskLevel): number {
  if (level === 'high') return 3
  if (level === 'medium') return 2
  return 1
}

function buildTerminalOutput(
  command: string,
  args: {
    renderedQuery: string
    paramValues: Record<string, string>
    riskItems: QueryRiskItem[]
    favorites: QuerySnapshot[]
    recent: QuerySnapshot[]
    history: QuerySnapshot[]
    paramDiff: ReturnType<typeof computeParamDiff>
    selectedLanguage: QueryLanguage
  },
): string {
  const normalized = command.trim().toLowerCase()
  if (!normalized) return '未输入指令。'

  if (/当前查询|show\s+query|query/.test(normalized)) return args.renderedQuery.trim() || '当前查询为空。'
  if (/参数|params|parameter/.test(normalized)) return JSON.stringify(args.paramValues, null, 2)

  if (/风险|risk/.test(normalized)) {
    if (args.riskItems.length === 0) return '风险评估：未发现明显高风险特征。'
    return args.riskItems.map((item) => `[${item.level.toUpperCase()}] ${item.code} - ${item.message}`).join('\n')
  }

  if (/收藏|favorite/.test(normalized)) {
    if (args.favorites.length === 0) return '暂无收藏记录。'
    return args.favorites.slice(0, 8).map((item, idx) => `${idx + 1}. ${item.huntTitle} (${item.language})`).join('\n')
  }

  if (/最近|recent/.test(normalized)) {
    if (args.recent.length === 0) return '暂无最近记录。'
    return args.recent.slice(0, 8).map((item, idx) => `${idx + 1}. ${item.huntTitle} (${item.language})`).join('\n')
  }

  if (/历史|history/.test(normalized)) {
    if (args.history.length === 0) return '暂无历史版本。'
    return args.history.slice(0, 8).map((item, idx) => `${idx + 1}. ${item.huntTitle} @ ${formatTime(item.createdAt)}`).join('\n')
  }

  if (/差异|diff|compare/.test(normalized)) {
    const lines: string[] = []
    if (args.paramDiff.added.length > 0) lines.push(`新增: ${args.paramDiff.added.join(' | ')}`)
    if (args.paramDiff.changed.length > 0) lines.push(`变更: ${args.paramDiff.changed.join(' | ')}`)
    if (args.paramDiff.removed.length > 0) lines.push(`移除: ${args.paramDiff.removed.join(' | ')}`)
    return lines.length > 0 ? lines.join('\n') : '参数差异为空。'
  }

  if (/执行|run|simulate/.test(normalized)) {
    const maxLevel = args.riskItems.reduce<QueryRiskLevel>(
      (acc, item) => (levelRank(item.level) > levelRank(acc) ? item.level : acc),
      'low',
    )
    const riskSummary = args.riskItems.length === 0 ? 'none' : `${maxLevel} (${args.riskItems.length} 条)`
    const paramCount = Object.values(args.paramValues).filter((value) => value.trim()).length
    return ['执行模拟完成', `语言: ${args.selectedLanguage}`, `参数已填: ${paramCount}`, `风险等级: ${riskSummary}`].join('\n')
  }

  return '未识别该自然语言指令。可尝试：展示当前查询 / 展示风险 / 模拟执行当前查询 / 展示参数差异。'
}

export function HuntPanel({
  hunt,
  selectedHuntId,
  onSelect,
  ragContext,
  graphBridge,
  fullHeight = false,
}: HuntPanelProps) {
  const selectedHunt = hunt.tabs.find((item) => item.id === selectedHuntId) ?? hunt.tabs[0]

  const [selectedLanguage, setSelectedLanguage] = useState<QueryLanguage>('sql')
  const [paramValues, setParamValues] = useState<Record<string, string>>({})
  const [copied, setCopied] = useState(false)
  const [ragLoading, setRagLoading] = useState(false)
  const [ragError, setRagError] = useState('')
  const [ragEvidence, setRagEvidence] = useState<HuntRagEvidenceItem[]>([])
  const [generatedQuery, setGeneratedQuery] = useState('')
  const [generatedFromNode, setGeneratedFromNode] = useState('')
  const [lastBridgeRequestId, setLastBridgeRequestId] = useState(0)

  const [favorites, setFavorites] = useState<QuerySnapshot[]>([])
  const [recent, setRecent] = useState<QuerySnapshot[]>([])
  const [history, setHistory] = useState<QuerySnapshot[]>([])

  const [terminalPreset, setTerminalPreset] = useState<string>(TERMINAL_COMMANDS[0])
  const [terminalInput, setTerminalInput] = useState('')
  const [terminalRecords, setTerminalRecords] = useState<TerminalRecord[]>([])

  useEffect(() => {
    setFavorites(readSnapshotStorage(FAVORITES_KEY))
    setRecent(readSnapshotStorage(RECENT_KEY))
    setHistory(readSnapshotStorage(HISTORY_KEY))
  }, [])

  useEffect(() => {
    writeSnapshotStorage(FAVORITES_KEY, favorites)
  }, [favorites])

  useEffect(() => {
    writeSnapshotStorage(RECENT_KEY, recent)
  }, [recent])

  useEffect(() => {
    writeSnapshotStorage(HISTORY_KEY, history)
  }, [history])

  const queryTemplates = useMemo(() => {
    if (!selectedHunt) return { sql: '', dsl: '', spl: '' }
    const dslText = Object.keys(selectedHunt.elasticsearch_dsl || {}).length
      ? JSON.stringify(selectedHunt.elasticsearch_dsl, null, 2)
      : ''
    return {
      sql: selectedHunt.sql || '',
      dsl: dslText,
      spl: selectedHunt.splunk_spl || '',
    }
  }, [selectedHunt])

  const availableLanguages = useMemo(
    () => (['sql', 'dsl', 'spl'] as QueryLanguage[]).filter((key) => queryTemplates[key].trim().length > 0),
    [queryTemplates],
  )

  useEffect(() => {
    setCopied(false)
    setRagError('')
    setRagEvidence([])
    setParamValues({})
    setGeneratedQuery('')
    setGeneratedFromNode('')
    setSelectedLanguage((current) => (availableLanguages.includes(current) ? current : (availableLanguages[0] ?? 'sql')))
  }, [availableLanguages, selectedHunt?.id])

  const templateTokens = useMemo(() => {
    const allText = [queryTemplates.sql, queryTemplates.dsl, queryTemplates.spl].filter(Boolean).join('\n')
    return extractTemplateTokens(allText)
  }, [queryTemplates.dsl, queryTemplates.spl, queryTemplates.sql])

  const renderedTemplateQuery = useMemo(() => {
    const template = queryTemplates[selectedLanguage] || ''
    return applyTemplateParams(template, paramValues)
  }, [paramValues, queryTemplates, selectedLanguage])

  const renderedQuery = generatedQuery || renderedTemplateQuery

  function buildSnapshot(query: string, params: Record<string, string>, sourceNodeLabel?: string): QuerySnapshot | null {
    if (!selectedHunt || !query.trim()) return null
    return {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      createdAt: Date.now(),
      huntId: selectedHunt.id,
      huntTitle: selectedHunt.title,
      language: selectedLanguage,
      params,
      query,
      sourceNodeLabel,
    }
  }

  function saveToRecent(snapshot: QuerySnapshot) {
    setRecent((current) => {
      const currentKey = buildSnapshotKey(snapshot)
      const filtered = current.filter((item) => buildSnapshotKey(item) !== currentKey)
      return uniqueById([snapshot, ...filtered]).slice(0, 10)
    })
  }

  function saveToHistory(snapshot: QuerySnapshot) {
    setHistory((current) => uniqueById([snapshot, ...current]).slice(0, 30))
  }

  function saveToFavorites(snapshot: QuerySnapshot) {
    setFavorites((current) => {
      const currentKey = buildSnapshotKey(snapshot)
      const filtered = current.filter((item) => buildSnapshotKey(item) !== currentKey)
      return uniqueById([snapshot, ...filtered]).slice(0, 20)
    })
  }

  function generateQueryFromBridge(bridge: HuntBridgePayload, overrideFill?: Record<string, string>) {
    const currentTemplate = queryTemplates[selectedLanguage] || ''
    if (!currentTemplate.trim()) return

    const mergedParams = { ...paramValues, ...(overrideFill ?? {}) }
    const withParams = applyTemplateParams(currentTemplate, mergedParams)
    const clause = buildNodeClause(selectedLanguage, bridge)
    const nextQuery = injectClause(selectedLanguage, withParams, clause)
    setGeneratedQuery(nextQuery)
    setGeneratedFromNode(bridge.sourceNodeLabel)

    const snapshot = buildSnapshot(nextQuery, mergedParams, bridge.sourceNodeLabel)
    if (snapshot) saveToRecent(snapshot)
  }

  useEffect(() => {
    if (!graphBridge) return
    if (graphBridge.requestId === lastBridgeRequestId) return

    const autoFill = buildParamFillFromBridge(templateTokens, graphBridge)
    setLastBridgeRequestId(graphBridge.requestId)
    setParamValues((current) => {
      const next = { ...current }
      Object.entries(autoFill).forEach(([key, value]) => {
        if (!next[key]?.trim()) next[key] = value
      })

      if (graphBridge.action === 'generate') {
        const merged = { ...next }
        const withParams = applyTemplateParams(queryTemplates[selectedLanguage] || '', merged)
        const clause = buildNodeClause(selectedLanguage, graphBridge)
        const nextQuery = injectClause(selectedLanguage, withParams, clause)
        setGeneratedQuery(nextQuery)
        setGeneratedFromNode(graphBridge.sourceNodeLabel)
        const snapshot = buildSnapshot(nextQuery, merged, graphBridge.sourceNodeLabel)
        if (snapshot) saveToRecent(snapshot)
      }
      return next
    })
  }, [graphBridge, lastBridgeRequestId, queryTemplates, selectedLanguage, templateTokens])

  async function handleCopyQuery() {
    if (!renderedQuery.trim()) return
    try {
      await navigator.clipboard.writeText(renderedQuery)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      setCopied(false)
      return
    }

    const snapshot = buildSnapshot(renderedQuery, paramValues, generatedFromNode || undefined)
    if (snapshot) saveToRecent(snapshot)
  }

  async function handleRagSuggest() {
    const currentTemplate = queryTemplates[selectedLanguage] || ''
    if (!currentTemplate.trim() || ragLoading) return

    setRagLoading(true)
    setRagError('')

    try {
      const response = await fetchHuntRagSuggest({
        query_template: currentTemplate,
        param_keys: templateTokens,
        context: {
          eventSummary: ragContext.eventSummary,
          topThreat: ragContext.topThreat,
          affectedAssets: ragContext.affectedAssets,
          ioc: ragContext.ioc,
          additionalTerms: [selectedHunt?.title ?? '', selectedHunt?.stage ?? ''].filter(Boolean),
        },
        top_k: 12,
      })

      setParamValues((current) => {
        const next = { ...current }
        for (const [key, value] of Object.entries(response.filled_params || {})) {
          if (!next[key]?.trim()) next[key] = value
        }
        return next
      })
      setGeneratedQuery('')
      setRagEvidence(response.evidence || [])

      const snapshot = buildSnapshot(renderedTemplateQuery, { ...paramValues }, undefined)
      if (snapshot) saveToRecent(snapshot)
    } catch (error) {
      setRagError(error instanceof Error ? error.message : 'RAG 建议失败')
    } finally {
      setRagLoading(false)
    }
  }

  function updateParam(key: string, value: string) {
    setGeneratedQuery('')
    setGeneratedFromNode('')
    setParamValues((current) => ({ ...current, [key]: value }))
  }

  function handleSaveVersion() {
    const snapshot = buildSnapshot(renderedQuery, paramValues, generatedFromNode || undefined)
    if (!snapshot) return
    saveToHistory(snapshot)
  }

  function handleFavoriteCurrent() {
    const snapshot = buildSnapshot(renderedQuery, paramValues, generatedFromNode || undefined)
    if (!snapshot) return
    saveToFavorites(snapshot)
    saveToRecent(snapshot)
  }

  const filledParamCount = Object.values(paramValues).filter((value) => value.trim().length > 0).length
  const historyForSelected = useMemo(() => history.filter((item) => item.huntId === selectedHunt?.id), [
    history,
    selectedHunt?.id,
  ])
  const previousVersion = historyForSelected.find((item) => item.language === selectedLanguage)
  const paramDiff = computeParamDiff(previousVersion?.params ?? {}, paramValues)

  const bridgeIndicatorCount = graphBridge
    ? graphBridge.indicators.ioc.length + graphBridge.indicators.host.length + graphBridge.indicators.process.length
    : 0

  const riskItems = useMemo(() => analyzeQueryRisk(renderedQuery, selectedLanguage), [renderedQuery, selectedLanguage])
  const highestRisk = useMemo<QueryRiskLevel | null>(() => {
    if (riskItems.length === 0) return null
    return riskItems.reduce<QueryRiskLevel>(
      (acc, item) => (levelRank(item.level) > levelRank(acc) ? item.level : acc),
      'low',
    )
  }, [riskItems])

  function appendTerminalRecord(type: TerminalRecord['type'], text: string) {
    setTerminalRecords((current) => [
      ...current,
      {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        type,
        text,
        at: Date.now(),
      },
    ])
  }

  function handleUsePresetCommand() {
    setTerminalInput(terminalPreset)
  }

  function handleRunTerminalCommand() {
    const input = terminalInput.trim()
    if (!input) return
    appendTerminalRecord('input', input)
    const output = buildTerminalOutput(input, {
      renderedQuery,
      paramValues,
      riskItems,
      favorites,
      recent,
      history: historyForSelected,
      paramDiff,
      selectedLanguage,
    })
    appendTerminalRecord('output', output)
  }

  function handleClearTerminal() {
    setTerminalRecords([])
  }

  return (
    <section className="panel hunt-page-panel">
      <SectionTitle eyebrow="Hunt" title="猎捕查询" tone="eyebrow-orange" badge={`${hunt.count} tabs`} />
      <div className={`hunt-layout ${fullHeight ? 'hunt-layout-wide' : ''}`}>
        <div className="hunt-tab-list">
          {hunt.tabs.map((tab) => (
            <button
              key={tab.id}
              className={`hunt-tab-button ${selectedHunt?.id === tab.id ? 'hunt-tab-button-active' : ''}`}
              type="button"
              onClick={() => onSelect(tab.id)}
            >
              <span className="hunt-tab-stage">{tab.stage}</span>
              <span className="hunt-tab-title">{tab.title}</span>
            </button>
          ))}
        </div>

        {selectedHunt ? (
          <>
            <div className="hunt-workbench">
              <div className="hunt-workbench-scroll">
              <section className="hunt-card hunt-card-overview">
                <div className="hunt-overview-kicker">Threat Hunting Workbench</div>
                <div className="hunt-overview-head">
                  <div className="query-title">{selectedHunt.title}</div>
                  <span className="hunt-stage-chip">{selectedHunt.stage}</span>
                </div>
                <div className="hunt-overview-meta">
                  <span className="hunt-meta-pill">模板变量 {templateTokens.length}</span>
                  <span className="hunt-meta-pill">已填参数 {filledParamCount}</span>
                  <span className="hunt-meta-pill">语句源 {availableLanguages.length}</span>
                  <span className="hunt-meta-pill">节点联动 {graphBridge ? `已连接 (${bridgeIndicatorCount})` : '未连接'}</span>
                  <span className="hunt-meta-pill">当前语种 {languageLabelMap[selectedLanguage]}</span>
                </div>
              </section>

              <section className="hunt-card hunt-card-query">
                <div className="hunt-query-head">
                  <div className="hunt-language-tabs">
                    {availableLanguages.map((lang) => (
                      <button
                        key={lang}
                        type="button"
                        className={`hunt-language-tab ${selectedLanguage === lang ? 'hunt-language-tab-active' : ''}`}
                        onClick={() => setSelectedLanguage(lang)}
                      >
                        {languageLabelMap[lang]}
                      </button>
                    ))}
                  </div>
                  <div className="hunt-query-actions">
                    <button type="button" className="hunt-ghost-button" onClick={handleSaveVersion}>
                      保存版本
                    </button>
                    <button type="button" className="hunt-ghost-button" onClick={handleFavoriteCurrent}>
                      收藏当前
                    </button>
                    <button
                      type="button"
                      className="hunt-ghost-button"
                      onClick={() => graphBridge && generateQueryFromBridge(graphBridge)}
                      disabled={!graphBridge}
                    >
                      基于当前节点生成查询
                    </button>
                    <button type="button" className="hunt-rag-button" onClick={() => void handleRagSuggest()} disabled={ragLoading}>
                      {ragLoading ? 'RAG 解析中...' : 'RAG增强建议'}
                    </button>
                    <button type="button" className="hunt-copy-button" onClick={() => void handleCopyQuery()}>
                      {copied ? '已复制' : '复制查询'}
                    </button>
                  </div>
                </div>

                <div className={`hunt-risk-banner ${highestRisk ? `hunt-risk-banner-${highestRisk}` : 'hunt-risk-banner-safe'}`}>
                  <div className="hunt-risk-title">语句执行风险提示</div>
                  {riskItems.length > 0 ? (
                    <div className="hunt-risk-items">
                      {riskItems.map((item) => (
                        <span key={`${item.code}-${item.message}`} className={`hunt-risk-pill hunt-risk-pill-${item.level}`}>
                          {item.level.toUpperCase()} · {item.message}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="hunt-risk-safe">当前未检测到明显高风险条件。</div>
                  )}
                </div>

                {ragError ? <div className="hunt-rag-error">{ragError}</div> : null}
                {ragEvidence.length > 0 ? (
                  <div className="hunt-rag-evidence-row">
                    {ragEvidence.slice(0, 6).map((item) => (
                      <span key={`${item.doc_type}-${item.text_key}-${item.score}`} className="hunt-rag-evidence-pill">
                        {item.doc_type}:{item.text_key}
                      </span>
                    ))}
                  </div>
                ) : null}

                {generatedFromNode ? <div className="hunt-node-generated-tag">节点上下文: {generatedFromNode}</div> : null}

                <div className="hunt-query-shell">
                  <div className="hunt-query-caption">Executable Query</div>
                  <pre className="query-code">{renderedQuery || '当前语句为空'}</pre>
                </div>
              </section>

              <section className="hunt-card hunt-card-params">
                <div className="hunt-params-title">参数化输入</div>
                {templateTokens.length > 0 ? (
                  <div className="hunt-params-grid">
                    {templateTokens.map((token) => (
                      <label key={token} className="hunt-param-field">
                        <span>{token}</span>
                        <input
                          type="text"
                          value={paramValues[token] ?? ''}
                          onChange={(event) => updateParam(token, event.target.value)}
                          placeholder={`输入 ${token}`}
                        />
                      </label>
                    ))}
                  </div>
                ) : (
                  <div className="hunt-param-empty">当前查询模板未声明变量，可直接复制执行。</div>
                )}
              </section>
            </div>
          </div>

          <section className="hunt-card hunt-card-terminal hunt-card-terminal-wide">
            <div className="hunt-terminal-hero">
              <div className="hunt-terminal-accent" />
              <div className="hunt-terminal-copy">
                <div className="hunt-terminal-title-row">
                  <h3>模拟终端</h3>
                  <span className="hunt-meta-pill">自然语言指令入口</span>
                </div>
              </div>
              <button type="button" className="hunt-terminal-action" onClick={handleClearTerminal}>
                清空
              </button>
            </div>

            <div className="hunt-terminal-controls">
              <select value={terminalPreset} onChange={(event) => setTerminalPreset(event.target.value)}>
                {TERMINAL_COMMANDS.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
              <button type="button" className="hunt-ghost-button" onClick={handleUsePresetCommand}>
                选择指令填入
              </button>
              <input
                type="text"
                value={terminalInput}
                onChange={(event) => setTerminalInput(event.target.value)}
                placeholder="输入自然语言指令，例如：模拟执行当前查询"
              />
              <button type="button" className="hunt-rag-button" onClick={handleRunTerminalCommand}>
                执行指令
              </button>
            </div>

            <div className="hunt-terminal-screen">
              {terminalRecords.length === 0 ? (
                <div className="hunt-terminal-empty">终端空闲中。请选择或输入自然语言指令后执行。</div>
              ) : (
                [...terminalRecords].slice(-20).reverse().map((line) => (
                  <div key={line.id} className={`hunt-terminal-line hunt-terminal-line-${line.type}`}>
                    <span className="hunt-terminal-prefix">{line.type === 'input' ? 'user@hunt>' : 'sentrix>'}</span>
                    <pre>{line.text}</pre>
                  </div>
                ))
              )}
            </div>
          </section>
          </>
        ) : (
          <div className="empty-state">暂无猎捕查询</div>
        )}
      </div>
    </section>
  )
}
