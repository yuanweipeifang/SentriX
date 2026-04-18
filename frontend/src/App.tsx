import { useState } from 'react'
import './App.css'
import { DataStatusBanner } from './components/common/DataStatusBanner'
import { AIPanel } from './components/layout/AIPanel'
import { SidebarNav } from './components/layout/SidebarNav'
import { TopBar } from './components/layout/TopBar'
import { WorkspaceContent } from './components/pages/WorkspaceContent'
import { SummaryCards } from './components/panels/SummaryCards'
import { useDashboardData } from './hooks/useDashboardData'

const stageToneMap: Record<string, string> = {
  detection: 'tone-danger',
  analysis: 'tone-info',
  response: 'tone-primary',
  audit: 'tone-success',
}

const cardToneMap: Record<string, string> = {
  danger: 'tone-danger',
  primary: 'tone-primary',
  info: 'tone-info',
  success: 'tone-success',
  warning: 'tone-warning',
  default: 'tone-default',
}

const navAccentMap: Record<string, string> = {
  dashboard: 'nav-accent-blue',
  analysis: 'nav-accent-cyan',
  evidence: 'nav-accent-violet',
  hunt: 'nav-accent-orange',
  execution: 'nav-accent-blue',
  history: 'nav-accent-violet',
  settings: 'nav-accent-orange',
}

const pageMetaMap: Record<string, { title: string; subtitle: string; tone: string }> = {
  dashboard: {
    title: '总览仪表盘',
    subtitle: '汇总关键卡片、执行状态、案例库与系统可观测性。',
    tone: 'tone-primary',
  },
  analysis: {
    title: '事件研判',
    subtitle: '聚焦威胁分析、置信度、证据与响应决策。',
    tone: 'tone-violet',
  },
  evidence: {
    title: '证据图谱',
    subtitle: '查看事件根节点、证据节点与原始日志关系。',
    tone: 'tone-info',
  },
  hunt: {
    title: '猎捕查询',
    subtitle: '浏览 SQL / Elasticsearch DSL / Splunk SPL 模板。',
    tone: 'tone-warning',
  },
  execution: {
    title: '执行编排',
    subtitle: '查看 playbook、tasks、编排图与 guardrails。',
    tone: 'tone-primary',
  },
  history: {
    title: '历史案例',
    subtitle: '对照历史样本、人工修正标签与案例记忆库反馈。',
    tone: 'tone-violet',
  },
  settings: {
    title: '系统设置',
    subtitle: '查看 schema、数据源约束以及真实数据接入说明。',
    tone: 'tone-warning',
  },
}

function App() {
  const [selectedNavId, setSelectedNavId] = useState('analysis')
  const { ui, loadState, errorMessage } = useDashboardData()
  const payload = ui.frontendPayload
  const currentPage = pageMetaMap[selectedNavId] ?? pageMetaMap.analysis

  return (
    <div className="app-shell">
      <SidebarNav
        nav={ui.nav}
        selectedNavId={selectedNavId}
        schemaVersion={payload.schema_version}
        caseId={payload.case_memory.case_id}
        navAccentMap={navAccentMap}
        onSelect={setSelectedNavId}
      />

      <main className="workspace">
        <TopBar
          title={currentPage.title}
          subtitle={currentPage.subtitle}
          tone={currentPage.tone}
          source={payload.incident_overview.source}
          assetCount={payload.incident_overview.affected_assets.length}
        />
        <DataStatusBanner loadState={loadState} errorMessage={errorMessage} />
        <SummaryCards cards={payload.cards} cardToneMap={cardToneMap} />
        <WorkspaceContent
          payload={payload}
          selectedNavId={selectedNavId}
          nav={ui.nav}
          stageToneMap={stageToneMap}
        />
      </main>

      <AIPanel title={ui.aiPanel.title} subtitle={ui.aiPanel.subtitle} messages={ui.aiPanel.messages} />
    </div>
  )
}

export default App
