import { SectionTitle } from '../common/SectionTitle'
import type { ConfidencePanel as ConfidencePanelType } from '../../types/frontendPayload'

interface ConfidencePanelProps {
  confidence: ConfidencePanelType
}

export function ConfidencePanel({ confidence }: ConfidencePanelProps) {
  return (
    <section className="panel">
      <SectionTitle eyebrow="Confidence" title="置信度面板" tone="eyebrow-blue" />
      <div className="confidence-list">
        {Object.entries(confidence.scores).map(([key, value], index) => (
          <div key={key} className="confidence-item">
            <div className="confidence-label">{key}</div>
            <div className="confidence-bar">
              <span
                className={`confidence-fill confidence-fill-${index % 3}`}
                style={{ width: `${Math.max(6, value * 100)}%` }}
              />
            </div>
            <div className="confidence-value">{value.toFixed(3)}</div>
          </div>
        ))}
      </div>
      <div className="confidence-breakdown">
        {confidence.breakdown.map((item, index) => (
          <div key={item.key} className="breakdown-item">
            <span className={`breakdown-dot breakdown-dot-${index % 3}`} />
            <span className="muted">{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>
    </section>
  )
}
