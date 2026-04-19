import type { FrontendPayload } from '../../types/frontendPayload'

interface DashboardMonitorProps {
  payload: FrontendPayload
}

export function DashboardMonitor({ payload }: DashboardMonitorProps) {
  const affectedAssets = payload.incident_overview.affected_assets
  const iocSummary = [
    { label: 'IP', value: payload.incident_overview.ioc.ip.length },
    { label: 'Domain', value: payload.incident_overview.ioc.domain.length },
    { label: 'CVE', value: payload.incident_overview.ioc.cve.length },
    { label: 'Process', value: payload.incident_overview.ioc.process.length },
  ]
  const totalIocCount = iocSummary.reduce((sum, item) => sum + item.value, 0)
  const highSeverityCount = payload.evidence.nodes.filter((node) => node.severity === 'high').length
  const mediumSeverityCount = payload.evidence.nodes.filter((node) => node.severity === 'medium').length
  const totalSignals = payload.evidence.nodes.length + payload.timeline.length + totalIocCount
  const cautionCount = mediumSeverityCount + payload.downgrade.length
  const safeCount = Math.max(totalSignals - highSeverityCount - cautionCount, 0)
  const distributionItems = [
    ...iocSummary,
    { label: 'Assets', value: affectedAssets.length },
    { label: 'Tasks', value: payload.execution.tasks.length },
  ]

  const logs =
    payload.timeline.length > 0
      ? payload.timeline.slice(0, 6).map((item, index) => ({
          id: item.id,
          level: index === 0 ? 'live' : index % 2 === 0 ? 'trace' : 'info',
          levelLabel: index === 0 ? 'ALERT' : index % 2 === 0 ? 'WARN' : 'INFO',
          title: item.label,
          detail: item.value,
        }))
      : [
          {
            id: 'waiting-1',
            level: 'info',
            levelLabel: 'INFO',
            title: '等待后端事件流',
            detail: '实时日志将在 frontend_payload 返回后显示。',
          },
        ]

  const stats = [
    {
      key: 'total',
      label: '监测信号总数',
      value: totalSignals,
      ratio: '100%',
      tone: 'cyan',
    },
    {
      key: 'malicious',
      label: '危险 MALICIOUS',
      value: highSeverityCount,
      ratio: `${totalSignals > 0 ? ((highSeverityCount / totalSignals) * 100).toFixed(2) : '0.00'}%`,
      tone: 'red',
    },
    {
      key: 'caution',
      label: '留意 CAUTION',
      value: cautionCount,
      ratio: `${totalSignals > 0 ? ((cautionCount / totalSignals) * 100).toFixed(2) : '0.00'}%`,
      tone: 'yellow',
    },
    {
      key: 'safe',
      label: '安全 SAFE',
      value: safeCount,
      ratio: `${totalSignals > 0 ? ((safeCount / totalSignals) * 100).toFixed(2) : '0.00'}%`,
      tone: 'green',
    },
  ]

  return (
    <section className="dashboard-monitor hero-animate hero-animate-5">
      <section className="dashboard-stats-row">
        {stats.map((item) => (
          <article key={item.key} className={`dashboard-stat-card dashboard-stat-${item.tone}`}>
            <div className="dashboard-stat-label">{item.label}</div>
            <div className="dashboard-stat-value">{item.value.toLocaleString()}</div>
            <div className="dashboard-stat-ratio">{item.ratio}</div>
          </article>
        ))}
      </section>

      <section className="dashboard-distribution">
        <div className="dashboard-section-top">
          <div>
            <div className="dashboard-section-label">Runtime Distribution</div>
            <h3>类型分布</h3>
          </div>
        </div>
        <div className="dashboard-distribution-grid">
          {distributionItems.map((item) => {
            const percent = totalSignals > 0 ? (item.value / totalSignals) * 100 : 0
            return (
              <div key={item.label} className="dashboard-distribution-item">
                <div className="dashboard-distribution-topline">
                  <span>{item.label}</span>
                  <strong>{percent.toFixed(2)}%</strong>
                </div>
                <div className="dashboard-distribution-value">{item.value}</div>
                <div className="dashboard-distribution-bar">
                  <span style={{ width: `${Math.max(percent, item.value > 0 ? 8 : 0)}%` }} />
                </div>
              </div>
            )
          })}
        </div>
      </section>

      <div className="dashboard-main-grid">
        <div className="dashboard-main-stack">
          <section className="dashboard-log-card dashboard-runtime-block">
            <div className="dashboard-section-top">
              <div>
                <div className="dashboard-section-label">Event Stream</div>
                <h3>实时日志列表</h3>
              </div>
            </div>
            <div className="dashboard-log-list">
              {logs.map((log) => (
                <article key={log.id} className={`dashboard-log-item dashboard-log-item-${log.level}`}>
                  <div className="dashboard-log-prefix">
                    <div className={`dashboard-log-badge dashboard-log-badge-${log.level}`} />
                    <div className="dashboard-log-level">{log.levelLabel}</div>
                    <div className="dashboard-log-prompt">$</div>
                  </div>
                  <div className="dashboard-log-stream">
                    <span className="dashboard-log-title">{log.title}</span>
                    <span className="dashboard-log-detail">{log.detail}</span>
                  </div>
                </article>
              ))}
            </div>
          </section>
        </div>
      </div>
    </section>
  )
}
