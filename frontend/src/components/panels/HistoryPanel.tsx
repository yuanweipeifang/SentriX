import { MetricRow } from '../common/MetricRow'
import { SectionTitle } from '../common/SectionTitle'
import type { CaseMemoryPanel as CaseMemoryPanelType } from '../../types/frontendPayload'

interface HistoryPanelProps {
  caseMemory: CaseMemoryPanelType
}

export function HistoryPanel({ caseMemory }: HistoryPanelProps) {
  return (
    <section className="panel">
      <SectionTitle eyebrow="Case Memory" title="历史案例" tone="eyebrow-violet" />
      <div className="case-memory-header">
        <span className="chip chip-outline">Case {caseMemory.case_id || 'N/A'}</span>
        <span className="chip chip-primary">{caseMemory.effective_label || '未标注'}</span>
      </div>
      <div className="metric-grid">
        <MetricRow
          label="误报模式"
          value={caseMemory.historical_panel.has_false_positive_pattern ? '是' : '否'}
          tone="text-orange"
        />
        <MetricRow
          label="良性样本"
          value={String(caseMemory.historical_panel.benign_like_count)}
          tone="text-blue"
        />
        <MetricRow
          label="恶意样本"
          value={String(caseMemory.historical_panel.malicious_like_count)}
          tone="text-violet"
        />
      </div>
      <div className="case-list">
        {caseMemory.historical_panel.cases.length > 0 ? (
          caseMemory.historical_panel.cases.map((item) => (
            <article key={item.case_id} className="case-item">
              <div className="case-title">{item.top_threat || item.case_id}</div>
              <div className="muted">
                {item.effective_label} · score {item.score}
              </div>
              <div className="case-action">{item.best_action}</div>
            </article>
          ))
        ) : (
          <div className="empty-state">暂无历史案例</div>
        )}
      </div>
    </section>
  )
}
