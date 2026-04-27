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
  const runtime = payload.runtime
  const tokenUsage = runtime.token_usage

  const tokenInput = Number(tokenUsage.prompt_tokens ?? tokenUsage.input_tokens ?? 0)
  const tokenOutput = Number(tokenUsage.completion_tokens ?? tokenUsage.output_tokens ?? 0)
  const tokenTotal = Number(tokenUsage.total_tokens ?? tokenInput + tokenOutput)

  const runtimeMetaLines: RuntimeLine[] = [
    {
      id: 'model-runtime',
      level: runtime.model_name ? 'ok' : 'info',
      prefix: '[MODEL]',
      text: `provider=${runtime.model_provider || 'unknown'}; model=${runtime.model_name || 'unknown'}; endpoint=${runtime.model_endpoint || 'n/a'}`,
    },
    {
      id: 'audit-runtime',
      level: runtime.execution_allowed ? 'ok' : runtime.audit_result ? 'warn' : 'info',
      prefix: '[AUDIT]',
      text: `result=${runtime.audit_result || 'unknown'}; execution_allowed=${runtime.execution_allowed}; audit_log=${runtime.audit_log_file || 'n/a'}`,
    },
    {
      id: 'token-runtime',
      level: tokenTotal > 0 ? 'info' : 'warn',
      prefix: '[TOKEN]',
      text: `input=${Number.isFinite(tokenInput) ? tokenInput : 0}; output=${Number.isFinite(tokenOutput) ? tokenOutput : 0}; total=${Number.isFinite(tokenTotal) ? tokenTotal : 0}`,
    },
  ]

  const traceLines: RuntimeLine[] = runtime.skill_trace.slice(0, 4).map((item, index) => ({
    id: `trace-${item.stage}-${item.skill}-${index}`,
    level: item.status.toLowerCase() === 'ok' || item.status.toLowerCase() === 'success' ? 'ok' : 'info',
    prefix: '[TRACE]',
    text: `stage=${item.stage || 'n/a'}; skill=${item.skill || 'n/a'}; status=${item.status || 'n/a'}; elapsed_ms=${item.elapsed_ms}`,
  }))

  const rawLogLines: RuntimeLine[] = payload.runtime_logs.slice(0, 4).map((line, index) => ({
    id: `raw-log-${index}`,
    level: 'info',
    prefix: '[RAWLOG]',
    text: String(line || '').trim(),
  }))

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

  return [...runtimeMetaLines, ...traceLines, ...asyncLines, ...rawLogLines, ...timelineLines, ...stageLines, ...aiLines].slice(0, 16).concat(
    timelineLines.length === 0 && stageLines.length === 0 && aiLines.length === 0 ? fallback : [],
  )
}

export function HomeRuntimePanel({ payload, aiMessages }: HomeRuntimePanelProps) {
  const runtimeLines = buildRuntimeLines(payload, aiMessages)
  const source = payload.incident_overview.source || 'N/A'
  const assets = payload.incident_overview.affected_assets.length
  const caseId = payload.case_memory.case_id || 'pending'
  const topThreat = payload.cards[0]?.value || 'awaiting analysis'
  const attackChain = payload.attack_chain_mapping.slice(0, 8)
  const iocRecords = payload.ioc_indicators.slice(0, 4)
  const exposure = payload.exposure_surface_analysis

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

      <section className="home-intel-grid">
        <article className="home-intel-card">
          <div className="home-intel-card-title">攻击链 ATT&CK 映射</div>
          <div className="home-intel-card-body">
            {attackChain.length > 0 ? (
              attackChain.map((row, index) => (
                <div key={`${row.stage}-${row.technique_id}-${index}`} className="home-intel-row">
                  <span className="home-intel-chip">{row.stage || 'unknown'}</span>
                  <span className="home-intel-text">
                    {row.tactic || 'Unknown'} · {row.technique_id || 'Unknown'} · {row.description || 'N/A'}
                  </span>
                </div>
              ))
            ) : (
              <div className="home-intel-empty">等待后端攻击链数据</div>
            )}
          </div>
        </article>

        <article className="home-intel-card">
          <div className="home-intel-card-title">暴露面分析</div>
          <div className="home-intel-metrics">
            <div className="home-intel-metric">
              <span>风险等级</span>
              <strong>{exposure.risk_level || 'N/A'}</strong>
            </div>
            <div className="home-intel-metric">
              <span>暴露资产</span>
              <strong>{exposure.asset_count}</strong>
            </div>
            <div className="home-intel-metric">
              <span>关键资产</span>
              <strong>{exposure.critical_asset_count}</strong>
            </div>
            <div className="home-intel-metric">
              <span>最高CVE严重度</span>
              <strong>{exposure.max_cve_severity}</strong>
            </div>
          </div>
          <div className="home-intel-note">{exposure.risk_reason || '等待后端暴露面说明'}</div>
        </article>

        <article className="home-intel-card">
          <div className="home-intel-card-title">IOC 指标</div>
          <div className="home-intel-card-body">
            {iocRecords.length > 0 ? (
              iocRecords.map((row) => (
                <div key={`ioc-${row.index}`} className="home-intel-ioc-item">
                  <div className="home-intel-ioc-index">记录 {row.index}</div>
                  <div className="home-intel-ioc-metrics">
                    {row.metrics.slice(0, 5).map((metric, idx) => (
                      <span key={`${metric.name}-${idx}`}>
                        {metric.name}: {metric.value}
                      </span>
                    ))}
                  </div>
                </div>
              ))
            ) : (
              <div className="home-intel-empty">等待后端 IOC 指标数据</div>
            )}
          </div>
        </article>
      </section>
    </section>
  )
}
