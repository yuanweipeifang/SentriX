interface MetricRowProps {
  label: string
  value: string
  tone?: string
}

export function MetricRow({ label, value, tone }: MetricRowProps) {
  return (
    <div className="metric-row">
      <span className="metric-label">{label}</span>
      <span className={`metric-value ${tone ?? ''}`}>{value}</span>
    </div>
  )
}
