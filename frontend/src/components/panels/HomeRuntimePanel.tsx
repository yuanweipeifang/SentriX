import type { AiPanelMessage, FrontendPayload } from '../../types/frontendPayload'

interface HomeRuntimePanelProps {
  payload: FrontendPayload
  aiMessages: AiPanelMessage[]
}

type RuntimeLine = {
  id: string
  level: 'ok' | 'info' | 'warn'
  prefix: string
  text: string
}

function buildRuntimeLines(payload: FrontendPayload, aiMessages: AiPanelMessage[]): RuntimeLine[] {
  const asyncCv = payload.observability.async_cross_validate
  const enrich = payload.observability.rag_enrichment
  const asyncLines: RuntimeLine[] = [
    {
      id: 'async-xv',
      level: asyncCv.failed > 0 ? 'warn' : asyncCv.running > 0 || asyncCv.queued > 0 ? 'info' : 'ok',
      prefix: '[ASYNC-XV]',
      text: `enabled=${asyncCv.enabled}; q=${asyncCv.queued}; r=${asyncCv.running}; done=${asyncCv.done}; fail=${asyncCv.failed}; scheduled=${asyncCv.scheduled}`,
    },
    {
      id: 'rag-enrich',
      level: enrich.online_cve_field_enriched_count > 0 ? 'ok' : 'info',
      prefix: '[RAG-ENRICH]',
      text: `online=${enrich.online_findings_count}; cve=${enrich.online_cve_enriched_count}; cve_fields=${enrich.online_cve_field_enriched_count}; db_upserted=${enrich.online_db_upserted}`,
    },
  ]

  const timelineLines =
    payload.timeline.length > 0
      ? payload.timeline.slice(0, 6).map((item, index) => ({
          id: item.id,
          level: (index === 0 ? 'ok' : index % 2 === 0 ? 'info' : 'warn') as RuntimeLine['level'],
          prefix: `[${String(item.stage || 'event').toUpperCase()}]`,
          text: `${item.label} ${item.value ? `| ${item.value}` : ''}`.trim(),
        }))
      : []

  const stageLines = Object.entries(payload.observability.stage_elapsed_ms)
    .slice(0, 4)
    .map(([stage, elapsed]) => ({
      id: `stage-${stage}`,
      level: 'info' as const,
      prefix: `[${stage.toUpperCase()}]`,
      text: `elapsed=${elapsed}ms`,
    }))

  const aiLines = aiMessages.slice(0, 3).map((message) => ({
    id: `ai-${message.id}`,
    level: message.role === 'insight' ? ('warn' as const) : ('ok' as const),
    prefix: `[${String(message.meta || 'agent').toUpperCase()}]`,
    text: `${message.title} | ${message.content}`,
  }))

  const fallback = [
    {
      id: 'boot-1',
      level: 'info' as const,
      prefix: '[INIT]',
      text: '等待后端 frontend_payload 返回运行状态。',
    },
  ]

  return [...asyncLines, ...timelineLines, ...stageLines, ...aiLines].slice(0, 10).concat(
    timelineLines.length === 0 && stageLines.length === 0 && aiLines.length === 0 ? fallback : [],
  )
}

export function HomeRuntimePanel({ payload, aiMessages }: HomeRuntimePanelProps) {
  const runtimeLines = buildRuntimeLines(payload, aiMessages)
  const source = payload.incident_overview.source || 'N/A'
  const assets = payload.incident_overview.affected_assets.length
  const caseId = payload.case_memory.case_id || 'pending'
  const topThreat = payload.cards[0]?.value || 'awaiting analysis'

  return (
    <section className="home-runtime">
      <div className="home-runtime-hero">
        <div className="home-runtime-title">SentriX Runtime</div>
        <div className="home-runtime-subtitle">AUTONOMOUS SOC PIPELINE</div>
        <div className="home-runtime-meta">
          <span>source={source}</span>
          <span>assets={assets}</span>
          <span>case={caseId}</span>
        </div>
      </div>

      <section className="home-terminal">
        <div className="home-terminal-topbar">
          <div className="home-terminal-dots">
            <span />
            <span />
            <span />
          </div>
          <div className="home-terminal-path">root@sentrix://runtime</div>
          <div className="home-terminal-live">LIVE</div>
        </div>

        <div className="home-terminal-body">
          {runtimeLines.map((line) => (
            <div key={line.id} className={`home-terminal-line home-terminal-line-${line.level}`}>
              <span className="home-terminal-prompt">$</span>
              <span className="home-terminal-prefix">{line.prefix}</span>
              <span className="home-terminal-text">{line.text}</span>
            </div>
          ))}
        </div>

        <div className="home-terminal-footer">
          <div className="home-terminal-status">SYSTEM READY</div>
          <div className="home-terminal-summary">
            <span>top_threat={topThreat}</span>
            <span>execution={payload.execution.mode || 'pending'}</span>
          </div>
        </div>
      </section>
    </section>
  )
}
