import { SectionTitle } from '../common/SectionTitle'
import type { TimelineItem } from '../../types/frontendPayload'

interface TimelinePanelProps {
  timeline: TimelineItem[]
  stageToneMap: Record<string, string>
}

export function TimelinePanel({ timeline, stageToneMap }: TimelinePanelProps) {
  return (
    <section className="panel">
      <SectionTitle eyebrow="Timeline" title="事件流程" tone="eyebrow-orange" />
      <div className="timeline-list">
        {timeline.map((item) => (
          <div key={item.id} className="timeline-item">
            <span className={`timeline-dot ${stageToneMap[item.stage] ?? 'tone-default'}`} />
            <div className="timeline-copy">
              <div className="timeline-label">{item.label}</div>
              <div className="muted">{item.value}</div>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
