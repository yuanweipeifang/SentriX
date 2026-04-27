interface TopBarProps {
  title: string
  subtitle: string
  tone: string
}

const toneLabelMap: Record<string, string> = {
  'tone-danger': '严重',
  'tone-warning': '关注',
  'tone-violet': '研判',
  'tone-primary': '运行',
  'tone-info': '在线',
}

function TopBarIcon({ tone }: { tone: string }) {
  switch (tone) {
    case 'tone-danger':
      return (
        <svg viewBox="0 0 24 24" className="topbar-icon-svg" aria-hidden="true">
          <path d="M12 4v10" />
          <path d="m8 8 4-4 4 4" />
          <path d="M5 19h14" />
        </svg>
      )
    case 'tone-warning':
      return (
        <svg viewBox="0 0 24 24" className="topbar-icon-svg" aria-hidden="true">
          <path d="M12 4 20 19H4z" />
          <path d="M12 9v4" />
          <path d="M12 16h.01" />
        </svg>
      )
    case 'tone-violet':
      return (
        <svg viewBox="0 0 24 24" className="topbar-icon-svg" aria-hidden="true">
          <path d="m12 3 7 4v10l-7 4-7-4V7z" />
          <path d="M12 3v18" />
          <path d="m5 7 7 4 7-4" />
        </svg>
      )
    case 'tone-primary':
      return (
        <svg viewBox="0 0 24 24" className="topbar-icon-svg" aria-hidden="true">
          <rect x="5" y="5" width="14" height="14" rx="2" />
          <path d="M9 12h6" />
          <path d="M12 9v6" />
        </svg>
      )
    default:
      return (
        <svg viewBox="0 0 24 24" className="topbar-icon-svg" aria-hidden="true">
          <circle cx="12" cy="12" r="6" />
          <path d="M12 6v12" />
          <path d="M6 12h12" />
        </svg>
      )
  }
}

export function TopBar({ title, subtitle, tone }: TopBarProps) {
  return (
    <header className={`topbar topbar-${tone}`}>
      <div className="topbar-accent" />
      <div className="topbar-icon-wrap">
        <div className="topbar-icon">
          <TopBarIcon tone={tone} />
        </div>
      </div>
      <div className="topbar-copy">
        <h1>{title}</h1>
        <p className="topbar-summary">{subtitle}</p>
      </div>
      <div className="topbar-status">{toneLabelMap[tone] ?? '在线'}</div>
    </header>
  )
}
