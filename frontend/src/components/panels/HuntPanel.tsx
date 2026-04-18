import { SectionTitle } from '../common/SectionTitle'
import type { HuntPanel as HuntPanelType } from '../../types/frontendPayload'

interface HuntPanelProps {
  hunt: HuntPanelType
  selectedHuntId: string
  onSelect: (id: string) => void
  fullHeight?: boolean
}

export function HuntPanel({
  hunt,
  selectedHuntId,
  onSelect,
  fullHeight = false,
}: HuntPanelProps) {
  const selectedHunt = hunt.tabs.find((item) => item.id === selectedHuntId) ?? hunt.tabs[0]

  return (
    <section className="panel">
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
          <div className="query-preview">
            <div className="query-title">{selectedHunt.title}</div>
            <pre className="query-code">{selectedHunt.sql}</pre>
          </div>
        ) : (
          <div className="empty-state">暂无猎捕查询</div>
        )}
      </div>
    </section>
  )
}
