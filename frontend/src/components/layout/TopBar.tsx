interface TopBarProps {
  title: string
  subtitle: string
  tone: string
  source: string
  assetCount: number
}

export function TopBar({ title, subtitle, tone, source, assetCount }: TopBarProps) {
  return (
    <header className="topbar panel">
      <div>
        <div className={`eyebrow ${tone}`}>Dark SOC Workspace</div>
        <h1>{title}</h1>
        <p className="topbar-summary">{subtitle}</p>
      </div>
      <div className="topbar-badges">
        <span className="chip chip-primary">Source {source}</span>
        <span className="chip chip-outline">Assets {assetCount}</span>
      </div>
    </header>
  )
}
