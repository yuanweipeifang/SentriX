import { useState } from 'react'
import './App.css'
import { AIPanel } from './components/layout/AIPanel'
import { SidebarNav } from './components/layout/SidebarNav'
import { TopBar } from './components/layout/TopBar'
import { WorkspaceContent } from './components/pages/WorkspaceContent'
import { useDashboardData } from './hooks/useDashboardData'

const navAccentMap: Record<string, string> = {
  home: 'nav-accent-cyan',
  dashboard: 'nav-accent-blue',
  analysis: 'nav-accent-cyan',
  evidence: 'nav-accent-violet',
  hunt: 'nav-accent-orange',
  execution: 'nav-accent-blue',
  history: 'nav-accent-violet',
  settings: 'nav-accent-orange',
}

const pageMetaMap: Record<string, { title: string; subtitle: string; tone: string }> = {
  home: {
    title: '系统首页',
    subtitle: '实时展示后端运行日志、关键阶段状态与核心结论摘要。',
    tone: 'tone-info',
  },
  dashboard: {
    title: '总览仪表盘',
    subtitle: '实时展示系统运行状态、关键阶段日志与核心风险结果，帮助用户快速理解当前后端工作情况。',
    tone: 'tone-primary',
  },
  analysis: {
    title: '事件研判',
    subtitle: '聚焦证据图谱，展示事件根节点、证据节点与关联关系。',
    tone: 'tone-violet',
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
    title: '攻击规则',
    subtitle: '浏览规则库、按字段检索并查看规则置信度与来源信息。',
    tone: 'tone-violet',
  },
  settings: {
    title: '系统设置',
    subtitle: '查看 schema、数据源约束以及真实数据接入说明。',
    tone: 'tone-warning',
  },
}

function App() {
  const [selectedNavId, setSelectedNavId] = useState('home')
  const { ui, refreshUi } = useDashboardData()
  const payload = ui.frontendPayload
  const currentPage = pageMetaMap[selectedNavId] ?? pageMetaMap.analysis

  return (
    <div className="app-scene">
      <div className="app-shell">
        <SidebarNav
          nav={ui.nav}
          selectedNavId={selectedNavId}
          assetCount={payload.incident_overview.affected_assets.length}
          ruleCount={payload.rules.total}
          navAccentMap={navAccentMap}
          onSelect={setSelectedNavId}
        />

        <main className="workspace">
          <TopBar
            title={currentPage.title}
            subtitle={currentPage.subtitle}
            source={payload.incident_overview.source}
            assetCount={payload.incident_overview.affected_assets.length}
            tone={currentPage.tone}
          />
          <div className="workspace-scroll">
            <WorkspaceContent
              payload={payload}
              aiMessages={ui.aiPanel.messages}
              selectedNavId={selectedNavId}
              nav={ui.nav}
              onNavigate={setSelectedNavId}
              onRefreshData={refreshUi}
            />
          </div>
        </main>

        <AIPanel
          title={ui.aiPanel.title}
          subtitle={ui.aiPanel.subtitle}
          messages={ui.aiPanel.messages}
          context={{
            pageTitle: currentPage.title,
            eventSummary: payload.incident_overview.event_summary,
            topThreat: payload.cards[0]?.value,
            recommendedAction: payload.cards[1]?.value,
          }}
        />
      </div>
    </div>
  )
}

export default App
