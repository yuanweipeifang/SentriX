import { SidebarIcon } from '../common/SidebarIcon'
import type { DashboardNavItem } from '../../types/frontendPayload'

interface SidebarNavProps {
  nav: DashboardNavItem[]
  selectedNavId: string
  assetCount: number
  ruleCount: number
  navAccentMap: Record<string, string>
  onSelect: (id: string) => void
}

export function SidebarNav({
  nav,
  selectedNavId,
  assetCount,
  ruleCount,
  navAccentMap,
  onSelect,
}: SidebarNavProps) {
  const selectedNavLabel = nav.find((item) => item.id === selectedNavId)?.label || '未选择页面'

  return (
    <aside className="sidebar">
      <div className="brand-card">
        <div className="brand-mark">
          <span className="brand-mark-shield" />
          <span className="brand-mark-network">
            <span className="brand-mark-link brand-mark-link-a" />
            <span className="brand-mark-link brand-mark-link-b" />
            <span className="brand-mark-node brand-mark-node-top" />
            <span className="brand-mark-node brand-mark-node-left" />
            <span className="brand-mark-node brand-mark-node-right" />
            <span className="brand-mark-node brand-mark-node-core" />
          </span>
          <span className="brand-mark-caption">SOC</span>
        </div>
        <div className="brand-copy">
          <div className="brand-title">SentriX</div>
          <div className="brand-badge-row">
            <span className="brand-badge">CORE</span>
            <span className="brand-status">LIVE</span>
          </div>
        </div>
      </div>

      <nav className="nav-list" aria-label="系统导航">
        {nav.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${navAccentMap[item.id] ?? ''} ${selectedNavId === item.id ? 'nav-item-active' : ''}`}
            onClick={() => onSelect(item.id)}
            type="button"
          >
            <span className={`nav-icon ${navAccentMap[item.id] ?? ''}`}>
              <SidebarIcon id={item.id} />
            </span>
            <span className="nav-label">{item.label}</span>
            {item.badge ? <span className="nav-badge">{item.badge}</span> : null}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="side-stat">
          <span>当前页面</span>
          <strong>{selectedNavLabel}</strong>
        </div>
        <div className="side-stat">
          <span>数据概览</span>
          <strong>{`资产 ${assetCount} · 规则 ${ruleCount}`}</strong>
        </div>
      </div>
    </aside>
  )
}
