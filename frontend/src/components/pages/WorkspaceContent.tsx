import { useEffect, useState } from 'react'
import { MetricRow } from '../common/MetricRow'
import { SectionTitle } from '../common/SectionTitle'
import { ConfidencePanel } from '../panels/ConfidencePanel'
import { EvidenceGraphPanel } from '../panels/EvidenceGraphPanel'
import { HistoryPanel } from '../panels/HistoryPanel'
import { HuntPanel } from '../panels/HuntPanel'
import { OrchestrationPanel } from '../panels/OrchestrationPanel'
import { TimelinePanel } from '../panels/TimelinePanel'
import type { DashboardNavItem, FrontendPayload } from '../../types/frontendPayload'

interface WorkspaceContentProps {
  payload: FrontendPayload
  selectedNavId: string
  nav: DashboardNavItem[]
  stageToneMap: Record<string, string>
}

export function WorkspaceContent({
  payload,
  selectedNavId,
  nav,
  stageToneMap,
}: WorkspaceContentProps) {
  const [selectedHuntId, setSelectedHuntId] = useState<string>(payload.hunt.tabs[0]?.id ?? '')

  useEffect(() => {
    setSelectedHuntId(payload.hunt.tabs[0]?.id ?? '')
  }, [payload.hunt.tabs])

  const renderDashboardPage = () => (
    <section className="content-grid dashboard-grid">
      <div className="main-column">
        <EvidenceGraphPanel evidence={payload.evidence} />
        <OrchestrationPanel execution={payload.execution} orchestration={payload.orchestration} />
      </div>
      <div className="side-column">
        <ConfidencePanel confidence={payload.confidence} />
        <TimelinePanel timeline={payload.timeline} stageToneMap={stageToneMap} />
        <HistoryPanel caseMemory={payload.case_memory} />
      </div>
    </section>
  )

  const renderAnalysisPage = () => (
    <section className="content-grid">
      <div className="main-column">
        <EvidenceGraphPanel evidence={payload.evidence} />
      </div>
      <div className="side-column">
        <ConfidencePanel confidence={payload.confidence} />
        <TimelinePanel timeline={payload.timeline} stageToneMap={stageToneMap} />
      </div>
    </section>
  )

  const renderEvidencePage = () => (
    <section className="single-column-layout">
      <EvidenceGraphPanel evidence={payload.evidence} />
      <section className="panel">
        <SectionTitle eyebrow="Evidence Details" title="证据节点详情" tone="eyebrow-blue" />
        <div className="detail-grid">
          {payload.evidence.nodes.map((node) => (
            <article key={node.id} className="detail-card">
              <div className="mini-title text-blue">{node.type}</div>
              <div className="detail-title">{node.label}</div>
              <div className="muted">{node.title}</div>
            </article>
          ))}
        </div>
      </section>
    </section>
  )

  const renderExecutionPage = () => (
    <section className="single-column-layout">
      <OrchestrationPanel execution={payload.execution} orchestration={payload.orchestration} />
      <section className="panel">
        <SectionTitle eyebrow="Orchestration" title="编排图摘要" tone="eyebrow-violet" />
        <div className="detail-grid">
          {payload.orchestration.nodes.map((node, index) => (
            <article key={`${String(node.id ?? index)}`} className="detail-card">
              <div className="mini-title text-violet">{String(node.type ?? 'node')}</div>
              <div className="detail-title">{String(node.name ?? node.id ?? 'unnamed')}</div>
              <div className="muted">{String(node.stage ?? payload.execution.mode)}</div>
            </article>
          ))}
        </div>
      </section>
    </section>
  )

  const renderHistoryPage = () => (
    <section className="single-column-layout">
      <HistoryPanel caseMemory={payload.case_memory} />
      <section className="panel">
        <SectionTitle eyebrow="Review" title="人工复核清单" tone="eyebrow-orange" />
        <div className="checklist-list">
          {payload.checklist.map((item) => (
            <div key={item.key} className="checklist-item">
              <span className="checklist-marker" />
              <div>
                <div className="detail-title">{item.label}</div>
                <div className="muted">状态：{item.status}</div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </section>
  )

  const renderSettingsPage = () => (
    <section className="single-column-layout">
      <section className="panel">
        <SectionTitle eyebrow="Settings" title="系统与数据契约" tone="eyebrow-orange" />
        <div className="metric-grid">
          <MetricRow label="Schema Version" value={payload.schema_version} tone="text-blue" />
          <MetricRow label="Source" value={payload.incident_overview.source} tone="text-violet" />
          <MetricRow label="Case Storage" value={payload.case_memory.storage_file || 'N/A'} tone="text-orange" />
        </div>
      </section>
      <section className="panel">
        <SectionTitle eyebrow="Safe Integration" title="真实数据接入说明" tone="eyebrow-blue" />
        <div className="notes-list">
          <div className="note-item">页面通过 `normalizeFrontendPayload()` 消费数据，字段缺失时会回退默认值。</div>
          <div className="note-item">模块支持 empty / partial / full 三态，不会因为单个 section 缺失直接白屏。</div>
          <div className="note-item">左侧导航已是真实页面切换入口，第二轮可直接接路由。</div>
        </div>
      </section>
    </section>
  )

  const selectedNav = nav.find((item) => item.id === selectedNavId) ?? nav[1] ?? nav[0]

  return (
    <div key={selectedNavId} className="page-transition-wrap">
      {selectedNav?.id === 'dashboard' ? renderDashboardPage() : null}
      {selectedNav?.id === 'analysis' ? renderAnalysisPage() : null}
      {selectedNav?.id === 'evidence' ? renderEvidencePage() : null}
      {selectedNav?.id === 'hunt' ? (
        <section className="single-column-layout">
          <HuntPanel
            hunt={payload.hunt}
            selectedHuntId={selectedHuntId}
            onSelect={setSelectedHuntId}
            fullHeight
          />
        </section>
      ) : null}
      {selectedNav?.id === 'execution' ? renderExecutionPage() : null}
      {selectedNav?.id === 'history' ? renderHistoryPage() : null}
      {selectedNav?.id === 'settings' ? renderSettingsPage() : null}
      {!selectedNav ? renderAnalysisPage() : null}
    </div>
  )
}
