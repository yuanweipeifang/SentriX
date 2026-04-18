import { useEffect, useMemo, useState } from 'react'
import { SectionTitle } from '../common/SectionTitle'
import type { EvidenceGraph } from '../../types/frontendPayload'

interface EvidenceGraphPanelProps {
  evidence: EvidenceGraph
}

export function EvidenceGraphPanel({ evidence }: EvidenceGraphPanelProps) {
  const rootNode = useMemo(
    () => evidence.nodes.find((node) => node.id === evidence.root_id) ?? evidence.nodes[0],
    [evidence.nodes, evidence.root_id],
  )
  const [selectedNodeId, setSelectedNodeId] = useState<string>(rootNode?.id ?? '')
  const [activeType, setActiveType] = useState<string>('all')
  const [zoom, setZoom] = useState<number>(1)

  const selectedNode = useMemo(
    () => evidence.nodes.find((node) => node.id === selectedNodeId) ?? rootNode,
    [evidence.nodes, rootNode, selectedNodeId],
  )

  const filterTypes = useMemo(() => {
    const uniqueTypes = Array.from(new Set(evidence.nodes.map((node) => node.type).filter(Boolean)))
    return ['all', ...uniqueTypes]
  }, [evidence.nodes])

  const visibleNodes = useMemo(
    () =>
      evidence.nodes.filter(
        (node) => node.id === rootNode?.id || activeType === 'all' || node.type === activeType,
      ),
    [activeType, evidence.nodes, rootNode?.id],
  )

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes])
  const visibleEdges = useMemo(
    () => evidence.edges.filter((edge) => visibleNodeIds.has(edge.from) && visibleNodeIds.has(edge.to)),
    [evidence.edges, visibleNodeIds],
  )

  const layout = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {}
    if (!rootNode) return positions

    positions[rootNode.id] = { x: 50, y: 16 }

    const childNodes = visibleNodes.filter((node) => node.id !== rootNode.id)
    const columns = Math.max(1, Math.min(3, childNodes.length))
    const rows = Math.max(1, Math.ceil(childNodes.length / columns))

    childNodes.forEach((node, index) => {
      const row = Math.floor(index / columns)
      const col = index % columns
      const x = columns === 1 ? 50 : 18 + (col * 64) / (columns - 1)
      const y = 48 + row * (rows > 1 ? 22 : 28)
      positions[node.id] = { x, y }
    })

    return positions
  }, [rootNode, visibleNodes])

  const metaEntries = useMemo(
    () => Object.entries(selectedNode?.meta ?? {}).slice(0, 6),
    [selectedNode?.meta],
  )

  useEffect(() => {
    if (!rootNode?.id) return
    setSelectedNodeId((current) => current || rootNode.id)
  }, [rootNode?.id])

  useEffect(() => {
    if (!visibleNodeIds.has(selectedNodeId)) {
      setSelectedNodeId(rootNode?.id ?? visibleNodes[0]?.id ?? '')
    }
  }, [rootNode?.id, selectedNodeId, visibleNodeIds, visibleNodes])

  return (
    <section className="panel">
      <SectionTitle
        eyebrow="Core Analysis"
        title="证据图谱"
        tone="eyebrow-blue"
        badge={`Visible ${visibleNodes.length}/${evidence.nodes.length}`}
      />
      <div className="evidence-graph-shell">
        <div className="graph-toolbar">
          <div className="graph-filter-row">
            {filterTypes.map((type) => (
              <button
                key={type}
                type="button"
                className={`graph-filter-chip ${activeType === type ? 'graph-filter-chip-active' : ''}`}
                onClick={() => setActiveType(type)}
              >
                {type === 'all' ? 'all nodes' : type}
              </button>
            ))}
          </div>
          <div className="graph-zoom-controls">
            <button type="button" className="graph-control-button" onClick={() => setZoom((value) => Math.max(0.85, value - 0.1))}>
              -
            </button>
            <span className="graph-zoom-value">{Math.round(zoom * 100)}%</span>
            <button type="button" className="graph-control-button" onClick={() => setZoom((value) => Math.min(1.45, value + 0.1))}>
              +
            </button>
            <button type="button" className="graph-control-button" onClick={() => setZoom(1)}>
              reset
            </button>
          </div>
        </div>

        <div className="evidence-graph-canvas">
          <div className="graph-stage" style={{ transform: `scale(${zoom})` }}>
            <svg className="graph-link-layer" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
              {visibleEdges.map((edge) => {
                const from = layout[edge.from]
                const to = layout[edge.to]
                if (!from || !to) return null

                return (
                  <g key={`${edge.from}-${edge.to}-${edge.relation}`}>
                    <path
                      className={`graph-link ${
                        selectedNode?.id === edge.from || selectedNode?.id === edge.to ? 'graph-link-active' : ''
                      }`}
                      d={`M ${from.x} ${from.y} C ${from.x} ${(from.y + to.y) / 2}, ${to.x} ${(from.y + to.y) / 2}, ${to.x} ${to.y}`}
                    />
                    <text
                      x={(from.x + to.x) / 2}
                      y={(from.y + to.y) / 2 - 2}
                      className="graph-link-label"
                    >
                      {edge.relation}
                    </text>
                  </g>
                )
              })}
            </svg>

            {visibleNodes.map((node, index) => {
              const position = layout[node.id]
              if (!position) return null

              return (
                <button
                  key={node.id}
                  type="button"
                  className={`graph-node-card graph-selectable ${
                    node.id === rootNode?.id ? 'graph-node-root' : 'graph-node-leaf'
                  } ${selectedNode?.id === node.id ? 'graph-child-active' : ''} ${
                    node.type === 'rule' ? 'tone-violet-soft' : node.type === 'log' ? 'tone-orange-soft' : 'tone-info-soft'
                  }`}
                  style={{ left: `${position.x}%`, top: `${position.y}%` }}
                  onClick={() => setSelectedNodeId(node.id)}
                >
                  <div className="graph-node-topline">
                    <span
                      className={`evidence-type ${
                        node.type === 'log' ? 'text-orange' : node.type === 'rule' ? 'text-violet' : 'text-blue'
                      }`}
                    >
                      {node.type}
                    </span>
                    <span className={`graph-node-index graph-node-index-${index % 3}`}>{String(index + 1).padStart(2, '0')}</span>
                  </div>
                  <div className="evidence-label">{node.label}</div>
                  <div className="evidence-title">{node.title}</div>
                  <div className="graph-node-foot">{node.subtitle || node.severity}</div>
                </button>
              )
            })}
          </div>
        </div>

        <div className="legend-row">
          {Object.entries(evidence.legend).map(([key, value], index) => (
            <div key={key} className="legend-chip">
              <span className={`legend-dot legend-dot-${index % 3}`} />
              <span>{value}</span>
            </div>
          ))}
        </div>
        <div className="graph-detail-panel">
          <div className="mini-title text-violet">Selected Node</div>
          <div className="detail-title">{selectedNode?.label ?? '暂无节点'}</div>
          <div className="muted">{selectedNode?.title ?? '暂无详情'}</div>
          <div className="graph-detail-meta">
            <span className="mini-chip text-blue">{selectedNode?.type ?? 'unknown'}</span>
            <span className="mini-chip text-orange">{selectedNode?.severity ?? 'low'}</span>
          </div>
          {metaEntries.length > 0 ? (
            <div className="graph-meta-grid">
              {metaEntries.map(([key, value]) => (
                <div key={key} className="graph-meta-item">
                  <span className="muted">{key}</span>
                  <strong>{String(value)}</strong>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </section>
  )
}
