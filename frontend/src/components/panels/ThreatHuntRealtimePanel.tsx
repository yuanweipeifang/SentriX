import { useEffect, useMemo, useState } from 'react'
import type { FrontendPayload } from '../../types/frontendPayload'
import type { FrontendPayloadQuery } from '../../services/frontendPayloadApi'
import { fetchDatasetCatalog } from '../../services/datasetCatalogApi'

interface ThreatHuntRealtimePanelProps {
  payload: FrontendPayload
  onRefreshData?: (query?: FrontendPayloadQuery) => Promise<void>
}

type StageTone = 'initial' | 'lateral' | 'privilege' | 'exfil' | 'generic'

function classifyLogTone(line: string): 'ok' | 'warn' | 'danger' | 'info' {
  const text = line.toUpperCase()
  if (text.includes('ERROR') || text.includes('FAIL') || text.includes('BLOCK')) {
    return 'danger'
  }
  if (text.includes('WARN') || text.includes('STOP') || text.includes('DOWNGRADE')) {
    return 'warn'
  }
  if (text.includes('DONE') || text.includes('PASS') || text.includes('SUCCESS')) {
    return 'ok'
  }
  return 'info'
}

function classifyStageTone(stage: string): StageTone {
  const text = stage.toUpperCase()
  if (text.includes('INITIAL')) {
    return 'initial'
  }
  if (text.includes('LATERAL')) {
    return 'lateral'
  }
  if (text.includes('PRIV') || text.includes('ESCAL')) {
    return 'privilege'
  }
  if (text.includes('EXFIL') || text.includes('IMPACT')) {
    return 'exfil'
  }
  return 'generic'
}

export function ThreatHuntRealtimePanel({ payload, onRefreshData }: ThreatHuntRealtimePanelProps) {
  const [sourceType, setSourceType] = useState<'dataset' | 'input' | 'csv'>('dataset')
  const [datasetFile, setDatasetFile] = useState('/home/kali/SentriX/backend/dataset/incident_examples_min.json')
  const [datasetIndex, setDatasetIndex] = useState(0)
  const [inputFile, setInputFile] = useState('/home/kali/SentriX/backend/data/sample_incident.json')
  const [csvFile, setCsvFile] = useState('/home/kali/SentriX/backend/dataset/test_10_no_label.csv')
  const [csvRowIndex, setCsvRowIndex] = useState(0)
  const [datasetRoot, setDatasetRoot] = useState('/home/kali/SentriX/backend/dataset')
  const [datasetOptions, setDatasetOptions] = useState<Array<{ name: string; path: string; sample_count: number }>>([])
  const [csvOptions, setCsvOptions] = useState<Array<{ name: string; path: string; row_count: number }>>([])
  const [catalogLoading, setCatalogLoading] = useState(true)
  const [catalogError, setCatalogError] = useState('')

  const logs = payload.runtime_logs.filter((line) => !line.toUpperCase().includes('HEARTBEAT')).slice(-120).reverse()
  const attackRows = payload.attack_chain_mapping.slice(0, 20)
  const iocRows = payload.ioc_indicators.slice(0, 12)
  const exposure = payload.exposure_surface_analysis
  const selectedDatasetMeta = useMemo(
    () => datasetOptions.find((item) => item.path === datasetFile) ?? null,
    [datasetFile, datasetOptions],
  )
  const selectedCsvMeta = useMemo(
    () => csvOptions.find((item) => item.path === csvFile) ?? null,
    [csvFile, csvOptions],
  )

  useEffect(() => {
    const controller = new AbortController()
    fetchDatasetCatalog(controller.signal)
      .then((data) => {
        const nextDatasetOptions = Array.isArray(data.json_files) ? data.json_files : []
        const nextCsvOptions = Array.isArray(data.csv_files) ? data.csv_files : []
        setDatasetRoot(data.root || datasetRoot)
        setDatasetOptions(nextDatasetOptions)
        setCsvOptions(nextCsvOptions)

        const defaultDataset =
          nextDatasetOptions.find((item) => item.path === data.default_dataset)?.path ??
          nextDatasetOptions[0]?.path ??
          datasetFile
        setDatasetFile(defaultDataset)
        setDatasetIndex(0)

        const defaultCsv = nextCsvOptions[0]?.path ?? csvFile
        setCsvFile(defaultCsv)
        setCsvRowIndex(0)
      })
      .catch((error) => {
        if (controller.signal.aborted) return
        setCatalogError(error instanceof Error ? error.message : '数据目录加载失败')
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setCatalogLoading(false)
        }
      })

    return () => controller.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function buildQuery(): FrontendPayloadQuery {
    if (sourceType === 'input') {
      return {
        inputFile: inputFile.trim(),
      }
    }
    if (sourceType === 'csv') {
      return {
        csvFile: csvFile.trim(),
        csvRowIndex: Math.max(0, csvRowIndex),
      }
    }
    return {
      datasetFile: datasetFile.trim(),
      datasetIndex: Math.max(0, datasetIndex),
    }
  }

  return (
    <section className="threat-hunt-live-page">
      <section className="panel threat-hunt-live-toolbar">
        <div>
          <div className="eyebrow eyebrow-cyan">Threat Hunt</div>
          <h3>实时分析日志与威胁情报</h3>
          <div className="muted">数据目录：{datasetRoot}</div>
        </div>
        <div className="threat-hunt-live-actions">
          <select
            className="threat-hunt-source-select"
            value={sourceType}
            onChange={(event) => setSourceType(event.target.value as 'dataset' | 'input' | 'csv')}
          >
            <option value="dataset">数据集 JSON</option>
            <option value="input">单个日志 JSON</option>
            <option value="csv">CSV 行日志</option>
          </select>
          {sourceType === 'dataset' ? (
            <>
              {datasetOptions.length > 0 ? (
                <select
                  className="threat-hunt-source-select"
                  value={datasetFile}
                  onChange={(event) => {
                    setDatasetFile(event.target.value)
                    setDatasetIndex(0)
                  }}
                >
                  {datasetOptions.map((item) => (
                    <option key={item.path} value={item.path}>
                      {item.name} ({item.sample_count} 条)
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  className="threat-hunt-source-input"
                  value={datasetFile}
                  onChange={(event) => setDatasetFile(event.target.value)}
                  placeholder="dataset file path"
                />
              )}
              <input
                className="threat-hunt-source-number"
                type="number"
                min={0}
                max={selectedDatasetMeta && selectedDatasetMeta.sample_count > 0 ? selectedDatasetMeta.sample_count - 1 : undefined}
                value={datasetIndex}
                onChange={(event) => setDatasetIndex(Math.max(0, Number(event.target.value) || 0))}
                placeholder="样本索引"
              />
            </>
          ) : null}
          {sourceType === 'input' ? (
            <input
              className="threat-hunt-source-input"
              value={inputFile}
              onChange={(event) => setInputFile(event.target.value)}
              placeholder="incident json path"
            />
          ) : null}
          {sourceType === 'csv' ? (
            <>
              {csvOptions.length > 0 ? (
                <select
                  className="threat-hunt-source-select"
                  value={csvFile}
                  onChange={(event) => {
                    setCsvFile(event.target.value)
                    setCsvRowIndex(0)
                  }}
                >
                  {csvOptions.map((item) => (
                    <option key={item.path} value={item.path}>
                      {item.name} ({item.row_count} 行)
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  className="threat-hunt-source-input"
                  value={csvFile}
                  onChange={(event) => setCsvFile(event.target.value)}
                  placeholder="csv file path"
                />
              )}
              <input
                className="threat-hunt-source-number"
                type="number"
                min={0}
                max={selectedCsvMeta && selectedCsvMeta.row_count > 0 ? selectedCsvMeta.row_count - 1 : undefined}
                value={csvRowIndex}
                onChange={(event) => setCsvRowIndex(Math.max(0, Number(event.target.value) || 0))}
                placeholder="CSV 行号"
              />
            </>
          ) : null}
          <button type="button" className="ghost-button" onClick={() => void onRefreshData?.(buildQuery())} disabled={catalogLoading}>
            {catalogLoading ? '加载目录中...' : '按所选源分析'}
          </button>
        </div>
        {catalogError ? <div className="hunt-rag-error">{catalogError}</div> : null}
      </section>

      <section className="threat-hunt-live-layout">
        <article className="panel threat-hunt-live-log-panel">
          <div className="threat-hunt-live-title-row">
            <h4>后端实时分析日志</h4>
            <div className="threat-hunt-live-legend">
              <span className="tone tone-ok">完成/通过</span>
              <span className="tone tone-warn">警告/停止</span>
              <span className="tone tone-danger">失败/阻断</span>
              <span className="tone tone-info">一般信息</span>
            </div>
          </div>
          <div className="threat-hunt-live-log-scroll-shell">
            <div className="threat-hunt-live-log-viewport">
              <div className="threat-hunt-live-log-list">
                {logs.length > 0 ? (
                  logs.map((line, idx) => {
                    const tone = classifyLogTone(line)
                    return (
                      <div key={`${idx}-${line.slice(0, 16)}`} className={`threat-hunt-log-line tone-${tone}`}>
                        <span className="threat-hunt-log-bullet" />
                        <span className="threat-hunt-log-text">{line}</span>
                      </div>
                    )
                  })
                ) : (
                  <div className="threat-hunt-empty">暂无后端分析日志，请先触发一次后端分析。</div>
                )}
              </div>
            </div>
          </div>
        </article>
        <section className="threat-hunt-bottom-grid">
          <article className="panel threat-hunt-card">
            <h4>暴露面分析</h4>
            <div className="threat-hunt-kv-grid">
              <div>
                <span>风险等级</span>
                <strong>{exposure.risk_level || 'N/A'}</strong>
              </div>
              <div>
                <span>暴露资产</span>
                <strong>{exposure.asset_count}</strong>
              </div>
              <div>
                <span>关键资产</span>
                <strong>{exposure.critical_asset_count}</strong>
              </div>
              <div>
                <span>最高CVE严重度</span>
                <strong>{exposure.max_cve_severity}</strong>
              </div>
            </div>
            <p className="threat-hunt-note">{exposure.risk_reason || '等待后端暴露面说明。'}</p>
          </article>

          <article className="panel threat-hunt-card">
            <h4>攻击链 ATT&CK 映射</h4>
            <div className="threat-hunt-chain-list">
              {attackRows.length > 0 ? (
                attackRows.map((row, idx) => (
                  <div
                    key={`${row.stage}-${row.technique_id}-${idx}`}
                    className={`threat-hunt-chain-item tone-${classifyStageTone(row.stage || '')}`}
                  >
                    <div className="threat-hunt-chain-head">
                      <span className="threat-hunt-stage">{row.stage || 'UNKNOWN'}</span>
                      <span className="threat-hunt-tech-id">{row.technique_id || 'TBD'}</span>
                    </div>
                    <div className="threat-hunt-chain-tactic">{row.tactic || 'Unknown Tactic'}</div>
                    <div className="threat-hunt-chain-desc">{row.description || 'N/A'}</div>
                  </div>
                ))
              ) : (
                <div className="threat-hunt-empty">暂无攻击链映射数据。</div>
              )}
            </div>
          </article>

          <article className="panel threat-hunt-card">
            <h4>IOC 指标</h4>
            <div className="threat-hunt-ioc-list">
              {iocRows.length > 0 ? (
                iocRows.map((row) => (
                  <div key={`ioc-${row.index}`} className="threat-hunt-ioc-item">
                    <div className="threat-hunt-ioc-index">记录 {row.index}</div>
                    <div className="threat-hunt-ioc-metrics">
                      {row.metrics.map((metric, idx) => (
                        <span key={`${metric.name}-${idx}`}>
                          <b>{metric.name}</b>: {metric.value}
                        </span>
                      ))}
                    </div>
                  </div>
                ))
              ) : (
                <div className="threat-hunt-empty">暂无 IOC 指标数据。</div>
              )}
            </div>
          </article>
        </section>
      </section>
    </section>
  )
}
