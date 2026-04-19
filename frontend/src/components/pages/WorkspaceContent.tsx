import type { AiPanelMessage, DashboardNavItem, FrontendPayload } from '../../types/frontendPayload'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { MetricRow } from '../common/MetricRow'
import { SectionTitle } from '../common/SectionTitle'
import { DashboardMonitor } from '../panels/DashboardMonitor'
import { EvidenceGraphPanel } from '../panels/EvidenceGraphPanel'
import { HistoryPanel } from '../panels/HistoryPanel'
import { HomeRuntimePanel } from '../panels/HomeRuntimePanel'
import { HuntPanel } from '../panels/HuntPanel'
import { OrchestrationPanel } from '../panels/OrchestrationPanel'
import type { HuntBridgePayload } from '../../types/huntBridge'
import {
  getSystemSettings,
  updateSystemSettings,
  type SystemSettings,
  type SystemSettingsResponse,
} from '../../services/systemSettingsApi'

interface WorkspaceContentProps {
  payload: FrontendPayload
  aiMessages: AiPanelMessage[]
  selectedNavId: string
  nav: DashboardNavItem[]
  onNavigate?: (navId: string) => void
  onRefreshData?: () => Promise<void>
}

export function WorkspaceContent({
  payload,
  aiMessages,
  selectedNavId,
  nav,
  onNavigate,
  onRefreshData,
}: WorkspaceContentProps) {
  const [selectedHuntId, setSelectedHuntId] = useState<string>(payload.hunt.tabs[0]?.id ?? '')
  const [huntBridgePayload, setHuntBridgePayload] = useState<HuntBridgePayload | null>(null)
  const [settingsData, setSettingsData] = useState<SystemSettingsResponse | null>(null)
  const [settingsDraft, setSettingsDraft] = useState<SystemSettings | null>(null)
  const [settingsLoading, setSettingsLoading] = useState(false)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [settingsMessage, setSettingsMessage] = useState('')

  useEffect(() => {
    setSelectedHuntId(payload.hunt.tabs[0]?.id ?? '')
  }, [payload.hunt.tabs])

  const loadSystemSettings = useCallback(async () => {
    setSettingsLoading(true)
    setSettingsMessage('')
    try {
      const data = await getSystemSettings()
      setSettingsData(data)
      setSettingsDraft(data.settings)
    } catch (error) {
      const message = error instanceof Error ? error.message : '加载系统设置失败'
      setSettingsMessage(message)
    } finally {
      setSettingsLoading(false)
    }
  }, [])

  useEffect(() => {
    if (selectedNavId !== 'settings') {
      return
    }
    void loadSystemSettings()
  }, [selectedNavId, loadSystemSettings])

  const hasSettingsChanges = useMemo(() => {
    if (!settingsData || !settingsDraft) {
      return false
    }
    return (
      settingsData.settings.rules_default_page_size !== settingsDraft.rules_default_page_size ||
      settingsData.settings.model_timeout_seconds !== settingsDraft.model_timeout_seconds ||
      settingsData.settings.online_rag_enabled !== settingsDraft.online_rag_enabled ||
      settingsData.settings.multi_agent_enabled !== settingsDraft.multi_agent_enabled
    )
  }, [settingsData, settingsDraft])

  async function handleSaveSystemSettings() {
    if (!settingsDraft) {
      return
    }
    setSettingsSaving(true)
    setSettingsMessage('')
    try {
      const data = await updateSystemSettings(settingsDraft)
      setSettingsData(data)
      setSettingsDraft(data.settings)
      setSettingsMessage('系统设置已保存并应用。')
    } catch (error) {
      const message = error instanceof Error ? error.message : '保存系统设置失败'
      setSettingsMessage(message)
    } finally {
      setSettingsSaving(false)
    }
  }

  function handleSendNodeToHunt(bridge: HuntBridgePayload) {
    setHuntBridgePayload(bridge)
    onNavigate?.('hunt')
  }

  const renderHomePage = () => (
    <section className="single-column-layout">
      <HomeRuntimePanel payload={payload} aiMessages={aiMessages} />
    </section>
  )

  const renderDashboardPage = () => (
    <section className="dashboard-page-shell">
      <DashboardMonitor payload={payload} />
    </section>
  )

  const renderAnalysisPage = () => (
    <section className="single-column-layout">
      <EvidenceGraphPanel evidence={payload.evidence} onSendToHunt={handleSendNodeToHunt} />
    </section>
  )

  const renderExecutionPage = () => (
    <section className="single-column-layout">
      <OrchestrationPanel
        execution={payload.execution}
        orchestration={payload.orchestration}
        incident={payload.incident_overview}
        caseId={payload.case_memory.case_id}
        onRefreshData={onRefreshData}
      />
    </section>
  )

  const renderHistoryPage = () => (
    <section className="single-column-layout">
      <HistoryPanel rules={payload.rules} />
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
        <SectionTitle eyebrow="Runtime Settings" title="运行时系统设置" tone="eyebrow-blue" />
        {settingsLoading ? <div className="note-item">正在加载系统设置...</div> : null}
        {settingsDraft ? (
          <div className="system-settings-grid">
            <label className="system-settings-field">
              <span>规则分页默认条数 (5-200)</span>
              <input
                type="number"
                min={5}
                max={200}
                value={settingsDraft.rules_default_page_size}
                onChange={(event) =>
                  setSettingsDraft((prev) =>
                    prev
                      ? {
                          ...prev,
                          rules_default_page_size: Math.max(5, Math.min(200, Number(event.target.value) || 5)),
                        }
                      : prev
                  )
                }
              />
            </label>
            <label className="system-settings-field">
              <span>模型超时秒数 (5-180)</span>
              <input
                type="number"
                min={5}
                max={180}
                value={settingsDraft.model_timeout_seconds}
                onChange={(event) =>
                  setSettingsDraft((prev) =>
                    prev
                      ? {
                          ...prev,
                          model_timeout_seconds: Math.max(5, Math.min(180, Number(event.target.value) || 5)),
                        }
                      : prev
                  )
                }
              />
            </label>
            <label className="system-settings-field system-settings-switch">
              <input
                type="checkbox"
                checked={settingsDraft.online_rag_enabled}
                onChange={(event) =>
                  setSettingsDraft((prev) => (prev ? { ...prev, online_rag_enabled: event.target.checked } : prev))
                }
              />
              <span>启用在线 RAG 检索</span>
            </label>
            <label className="system-settings-field system-settings-switch">
              <input
                type="checkbox"
                checked={settingsDraft.multi_agent_enabled}
                onChange={(event) =>
                  setSettingsDraft((prev) => (prev ? { ...prev, multi_agent_enabled: event.target.checked } : prev))
                }
              />
              <span>启用多 Agent 协作</span>
            </label>
            <div className="settings-status">
              <div>配置存储: {settingsData?.db_path || 'N/A'}</div>
              <div>最近更新: {settingsData?.updated_at || 'N/A'}</div>
            </div>
            <div className="system-settings-actions">
              <button type="button" className="ghost-button" onClick={() => void loadSystemSettings()} disabled={settingsSaving}>
                重新加载
              </button>
              <button
                type="button"
                className="primary-button"
                onClick={() => void handleSaveSystemSettings()}
                disabled={settingsSaving || !hasSettingsChanges}
              >
                {settingsSaving ? '保存中...' : '保存设置'}
              </button>
            </div>
          </div>
        ) : null}
        {settingsMessage ? <div className="note-item">{settingsMessage}</div> : null}
      </section>
      <section className="panel">
        <SectionTitle eyebrow="Safe Integration" title="真实数据接入说明" tone="eyebrow-blue" />
        <div className="notes-list">
          <div className="note-item">系统设置已支持持久化到后端数据库，不再是纯静态说明页。</div>
          <div className="note-item">保存后会即时刷新 API 运行参数，规则分页默认值会立刻生效。</div>
          <div className="note-item">模型超时、在线 RAG、多 Agent 开关在下一次任务执行时生效。</div>
        </div>
      </section>
    </section>
  )

  const selectedNav = nav.find((item) => item.id === selectedNavId) ?? nav[1] ?? nav[0]

  return (
    <div key={selectedNavId} className="page-transition-wrap">
      {selectedNav?.id === 'home' ? renderHomePage() : null}
      {selectedNav?.id === 'dashboard' ? renderDashboardPage() : null}
      {selectedNav?.id === 'analysis' ? renderAnalysisPage() : null}
      {selectedNav?.id === 'hunt' ? (
        <section className="single-column-layout">
          <HuntPanel
            hunt={payload.hunt}
            selectedHuntId={selectedHuntId}
            onSelect={setSelectedHuntId}
            ragContext={{
              eventSummary: payload.incident_overview.event_summary,
              topThreat: payload.cards[0]?.value,
              affectedAssets: payload.incident_overview.affected_assets,
              ioc: payload.incident_overview.ioc,
            }}
            graphBridge={huntBridgePayload}
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
