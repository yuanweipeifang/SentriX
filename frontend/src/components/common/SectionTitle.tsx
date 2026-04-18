interface SectionTitleProps {
  eyebrow: string
  title: string
  tone?: string
  badge?: string
}

export function SectionTitle({ eyebrow, title, tone, badge }: SectionTitleProps) {
  return (
    <div className="section-header">
      <div>
        <div className={`eyebrow ${tone ?? ''}`}>{eyebrow}</div>
        <h2>{title}</h2>
      </div>
      {badge ? <span className="chip chip-outline">{badge}</span> : null}
    </div>
  )
}
