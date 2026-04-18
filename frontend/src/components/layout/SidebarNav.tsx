import { SidebarIcon } from '../common/SidebarIcon'
import type { DashboardNavItem } from '../../types/frontendPayload'

interface SidebarNavProps {
  nav: DashboardNavItem[]
  selectedNavId: string
  schemaVersion: string
  caseId: string
  navAccentMap: Record<string, string>
  onSelect: (id: string) => void
}

export function SidebarNav({
  nav,
  selectedNavId,
  schemaVersion,
  caseId,
  navAccentMap,
  onSelect,
}: SidebarNavProps) {
  return (
    <aside className="sidebar">
      <div className="brand-card">
        <div className="brand-mark">SX</div>
        <div>
          <div className="brand-title">SentriX</div>
          <div className="brand-subtitle">Threat Response Console</div>
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
          <span>Schema</span>
          <strong>{schemaVersion}</strong>
        </div>
        <div className="side-stat">
          <span>Case</span>
          <strong>{caseId || 'N/A'}</strong>
        </div>
      </div>
    </aside>
  )
}
