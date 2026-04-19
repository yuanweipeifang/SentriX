import { useEffect, useMemo, useState } from 'react'
import { MetricRow } from '../common/MetricRow'
import { SectionTitle } from '../common/SectionTitle'
import { searchRules } from '../../services/rulesApi'
import type { RulesPanel } from '../../types/frontendPayload'

interface HistoryPanelProps {
  rules: RulesPanel
}

export function HistoryPanel({ rules }: HistoryPanelProps) {
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(100)
  const [typeFilter, setTypeFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [sortBy, setSortBy] = useState<'severity' | 'confidence' | 'updated' | 'rule_id'>('severity')
  const [expandedRuleId, setExpandedRuleId] = useState('')
  const [remoteRules, setRemoteRules] = useState<RulesPanel | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedQuery(query), 260)
    return () => window.clearTimeout(timer)
  }, [query])

  useEffect(() => {
    setPage(1)
  }, [debouncedQuery, pageSize])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError('')

    searchRules({ query: debouncedQuery, page, pageSize }, controller.signal)
      .then((payload) => setRemoteRules(payload))
      .catch((reason) => {
        if (controller.signal.aborted) return
        setError(reason instanceof Error ? reason.message : '攻击规则查询失败')
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      })

    return () => controller.abort()
  }, [debouncedQuery, page, pageSize])

  const activeRules = useMemo(() => remoteRules ?? rules, [remoteRules, rules])
  const currentPage = Math.max(1, activeRules.page || page)
  const activePageSize = Math.max(1, activeRules.page_size || pageSize)
  const totalPages = Math.max(1, Math.ceil((activeRules.total || 0) / activePageSize))

  const ruleTypeOptions = useMemo(() => {
    const uniqueTypes = Array.from(
      new Set(
        activeRules.items
          .map((item) => item.rule_type?.trim())
          .filter((item): item is string => Boolean(item)),
      ),
    )
    return uniqueTypes.sort((left, right) => left.localeCompare(right))
  }, [activeRules.items])

  const visibleRules = useMemo(() => {
    const severityThreshold = severityFilter === 'all' ? Number.NEGATIVE_INFINITY : Number(severityFilter)
    const filtered = activeRules.items.filter((item) => {
      const typeMatched = typeFilter === 'all' || item.rule_type === typeFilter
      const severityValue = Number.isFinite(item.severity) ? item.severity : 0
      const severityMatched = severityValue >= severityThreshold
      return typeMatched && severityMatched
    })

    const sorted = [...filtered].sort((left, right) => {
      if (sortBy === 'rule_id') {
        return left.rule_id.localeCompare(right.rule_id)
      }
      if (sortBy === 'updated') {
        const leftTime = Date.parse(left.updated_at || '') || 0
        const rightTime = Date.parse(right.updated_at || '') || 0
        return rightTime - leftTime
      }
      if (sortBy === 'confidence') {
        return right.confidence - left.confidence
      }
      return right.severity - left.severity
    })

    return sorted
  }, [activeRules.items, severityFilter, sortBy, typeFilter])

  function formatScore(value: number): string {
    return (Number.isFinite(value) ? value : 0).toFixed(2)
  }

  function formatUpdatedAt(value: string): string {
    if (!value) return ''
    const parsed = Date.parse(value)
    if (Number.isNaN(parsed)) return value
    return new Date(parsed).toLocaleString('zh-CN', { hour12: false })
  }

  useEffect(() => {
    setExpandedRuleId('')
  }, [currentPage, debouncedQuery])

  return (
    <section className="panel">
      <SectionTitle eyebrow="Rules" title="攻击规则" tone="eyebrow-violet" />
      <div className="case-memory-header">
        <span className="chip chip-outline">DB {activeRules.db_path || 'N/A'}</span>
        <span className="chip chip-primary">规则 {activeRules.total}</span>
        <span className="chip chip-outline">第 {currentPage}/{totalPages} 页</span>
      </div>
      <div className="rules-toolbar">
        <input
          className="rules-search-input"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="搜索 rule_id / title / pattern / ttp"
        />
        <div className="rules-toolbar-group">
          <select className="rules-select" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
            <option value="all">全部类型</option>
            {ruleTypeOptions.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
          <select
            className="rules-select"
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
          >
            <option value="all">全部严重度</option>
            <option value="0.3">severity ≥ 0.30</option>
            <option value="0.6">severity ≥ 0.60</option>
            <option value="0.8">severity ≥ 0.80</option>
          </select>
          <select className="rules-select" value={sortBy} onChange={(event) => setSortBy(event.target.value as typeof sortBy)}>
            <option value="severity">按严重度</option>
            <option value="confidence">按置信度</option>
            <option value="updated">按更新时间</option>
            <option value="rule_id">按规则 ID</option>
          </select>
          <select className="rules-select" value={String(pageSize)} onChange={(event) => setPageSize(Number(event.target.value))}>
            <option value="50">每页 50</option>
            <option value="100">每页 100</option>
            <option value="200">每页 200</option>
          </select>
        </div>
        <div className="muted">展示后端数据库中的攻击规则与关键信息</div>
      </div>
      <div className="metric-grid">
        <MetricRow label="规则总数" value={String(activeRules.total)} tone="text-orange" />
        <MetricRow
          label="搜索模式"
          value={debouncedQuery.trim() ? '数据库检索' : '数据库总览'}
          tone="text-blue"
        />
        <MetricRow label="来源" value={activeRules.db_path ? 'SQLite RAG' : '未连接'} tone="text-violet" />
      </div>
      {error ? <div className="hunt-rag-error">{error}</div> : null}
      <div className="case-list">
        {visibleRules.length > 0 ? (
          visibleRules.map((item) => {
            const expanded = expandedRuleId === item.rule_id
            const metaParts = [item.rule_id, item.rule_type, item.ttp].filter((part) => part && part.trim())
            const hasPattern = Boolean(item.pattern && item.pattern.trim())
            const hasUpdatedAt = Boolean(formatUpdatedAt(item.updated_at))
            return (
            <article key={item.rule_id} className="case-item">
              <div className="rules-card-header">
                <div>
                  <div className="case-title">{item.title || item.rule_id}</div>
                  {metaParts.length > 0 ? <div className="muted">{metaParts.join(' · ')}</div> : null}
                </div>
                <button
                  type="button"
                  className="rules-expand-btn"
                  onClick={() => setExpandedRuleId(expanded ? '' : item.rule_id)}
                >
                  {expanded ? '收起' : '详情'}
                </button>
              </div>
              {hasPattern ? <div className="case-action rules-pattern">{item.pattern}</div> : null}
              <div className="rules-rule-meta">
                <span className="mini-chip text-orange">severity {formatScore(item.severity)}</span>
                <span className="mini-chip text-blue">confidence {formatScore(item.confidence)}</span>
                {item.source ? <span className="mini-chip text-violet">{item.source}</span> : null}
              </div>
              {expanded ? (
                <div className="rules-detail-grid">
                  {item.version ? (
                    <div className="rules-detail-item">
                      <span className="muted">Version</span>
                      <span>{item.version}</span>
                    </div>
                  ) : null}
                  {hasUpdatedAt ? (
                    <div className="rules-detail-item">
                      <span className="muted">Updated</span>
                      <span>{formatUpdatedAt(item.updated_at)}</span>
                    </div>
                  ) : null}
                  {item.source_url ? (
                    <div className="rules-detail-item">
                      <span className="muted">Source URL</span>
                      <a className="rules-source-link" href={item.source_url} target="_blank" rel="noreferrer">
                        打开链接
                      </a>
                    </div>
                  ) : null}
                </div>
              ) : null}
            </article>
            )
          })
        ) : (
          <div className="empty-state">{loading ? '正在查询攻击规则...' : '暂无攻击规则结果'}</div>
        )}
      </div>
      <div className="rules-pagination">
        <button
          type="button"
          className="rules-page-btn"
          disabled={currentPage <= 1 || loading}
          onClick={() => setPage((current) => Math.max(1, current - 1))}
        >
          上一页
        </button>
        <div className="muted">第 {currentPage} 页，共 {totalPages} 页</div>
        <button
          type="button"
          className="rules-page-btn"
          disabled={currentPage >= totalPages || loading}
          onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
        >
          下一页
        </button>
      </div>
    </section>
  )
}
