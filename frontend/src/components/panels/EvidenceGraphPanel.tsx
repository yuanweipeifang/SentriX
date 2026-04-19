import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
} from 'react'
import { SectionTitle } from '../common/SectionTitle'
import type { EvidenceGraph } from '../../types/frontendPayload'
import type { HuntBridgeAction, HuntBridgePayload } from '../../types/huntBridge'

interface EvidenceGraphPanelProps {
  evidence: EvidenceGraph
  onSendToHunt?: (payload: HuntBridgePayload) => void
}

type Point = {
  x: number
  y: number
}

const CANVAS_WIDTH = 1000
const CANVAS_HEIGHT = 620

function nodeColor(type: string, isRoot: boolean): string {
  if (isRoot) return '#c084fc'
  if (type === 'rule') return '#f472b6'
  if (type === 'log') return '#f87171'
  if (type === 'ioc') return '#60a5fa'
  if (type === 'cve') return '#34d399'
  if (type === 'incident') return '#facc15'
  return '#94a3b8'
}

function shortLabel(text: string, maxLength: number): string {
  if (!text) return 'N/A'
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}...`
}

function uniqueNormalized(values: string[]): string[] {
  const map = new Map<string, string>()
  values.forEach((value) => {
    const normalized = value.trim()
    if (!normalized) return
    const key = normalized.toLowerCase()
    if (!map.has(key)) {
      map.set(key, normalized)
    }
  })
  return Array.from(map.values())
}

function collectMetaStrings(meta: Record<string, unknown>): string[] {
  const result: string[] = []
  Object.values(meta).forEach((value) => {
    if (typeof value === 'string') {
      result.push(value)
      return
    }
    if (Array.isArray(value)) {
      value.forEach((item) => {
        if (typeof item === 'string') {
          result.push(item)
        }
      })
      return
    }
    if (value && typeof value === 'object') {
      Object.values(value as Record<string, unknown>).forEach((child) => {
        if (typeof child === 'string') {
          result.push(child)
        }
      })
    }
  })
  return result
}

function extractNodeIndicators(node: EvidenceGraph['nodes'][number]): HuntBridgePayload['indicators'] {
  const allText = [node.label, node.title, ...collectMetaStrings(node.meta)]
  const allJoined = allText.join(' | ')

  const ipMatches = allJoined.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []
  const cveMatches = allJoined.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []
  const domainMatches = allJoined.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) ?? []

  const hostCandidates = uniqueNormalized(
    Object.entries(node.meta)
      .filter(([key]) => /(host|hostname|asset|endpoint|device|computer)/i.test(key))
      .flatMap(([, value]) => {
        if (typeof value === 'string') return [value]
        if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string')
        return []
      }),
  )

  const processCandidates = uniqueNormalized(
    Object.entries(node.meta)
      .filter(([key]) => /(process|proc|image|exe|command|cmdline)/i.test(key))
      .flatMap(([, value]) => {
        if (typeof value === 'string') return [value]
        if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string')
        return []
      }),
  )

  const cve = uniqueNormalized(cveMatches.map((item) => item.toUpperCase()))
  const ip = uniqueNormalized(ipMatches)
  const domain = uniqueNormalized(domainMatches.filter((item) => !/^CVE-/i.test(item)))
  const ioc = uniqueNormalized([...cve, ...ip, ...domain])

  return {
    ioc,
    cve,
    host: hostCandidates,
    ip,
    domain,
    process: processCandidates,
  }
}

export function EvidenceGraphPanel({ evidence, onSendToHunt }: EvidenceGraphPanelProps) {
  if (evidence.nodes.length === 0) {
    return (
      <section className="panel">
        <SectionTitle eyebrow="Core Analysis" title="证据图谱" tone="eyebrow-blue" badge="Visible 0/0" />
        <div className="empty-state">当前没有可展示的证据节点</div>
      </section>
    )
  }

  const rootNode = useMemo(
    () => evidence.nodes.find((node) => node.id === evidence.root_id) ?? evidence.nodes[0],
    [evidence.nodes, evidence.root_id],
  )

  const [selectedNodeId, setSelectedNodeId] = useState<string>(rootNode?.id ?? '')
  const [activeType, setActiveType] = useState<string>('all')
  const [showDetailPanel, setShowDetailPanel] = useState<boolean>(false)
  const [dragNodeId, setDragNodeId] = useState<string>('')
  const [positions, setPositions] = useState<Record<string, Point>>({})
  const [viewScale, setViewScale] = useState<number>(1)
  const [viewPan, setViewPan] = useState<Point>({ x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState<boolean>(false)

  const stageRef = useRef<SVGSVGElement | null>(null)
  const dragOffsetRef = useRef<{ dx: number; dy: number }>({ dx: 0, dy: 0 })
  const panStartRef = useRef<{ clientX: number; clientY: number; panX: number; panY: number } | null>(null)

  const markerSeed = useId().replace(/:/g, '')
  const arrowId = `${markerSeed}-graph-arrow`
  const arrowActiveId = `${markerSeed}-graph-arrow-active`

  const selectedNode = useMemo(
    () => evidence.nodes.find((node) => node.id === selectedNodeId) ?? rootNode,
    [evidence.nodes, rootNode, selectedNodeId],
  )

  const filterTypes = useMemo(() => {
    const uniqueTypes = Array.from(new Set(evidence.nodes.map((node) => node.type || 'unknown')))
    return ['all', ...uniqueTypes]
  }, [evidence.nodes])

  const visibleNodes = useMemo(
    () =>
      evidence.nodes.filter(
        (node) => node.id === rootNode?.id || activeType === 'all' || (node.type || 'unknown') === activeType,
      ),
    [activeType, evidence.nodes, rootNode?.id],
  )

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes])

  const visibleEdges = useMemo(
    () => evidence.edges.filter((edge) => visibleNodeIds.has(edge.from) && visibleNodeIds.has(edge.to)),
    [evidence.edges, visibleNodeIds],
  )

  const nodeDegreeMap = useMemo(() => {
    const map: Record<string, number> = {}
    visibleNodes.forEach((node) => {
      map[node.id] = 0
    })
    visibleEdges.forEach((edge) => {
      map[edge.from] = (map[edge.from] ?? 0) + 1
      map[edge.to] = (map[edge.to] ?? 0) + 1
    })
    return map
  }, [visibleNodes, visibleEdges])

  const autoLayout = useMemo(() => {
    if (visibleNodes.length === 0) return {} as Record<string, Point>

    const nodeIds = visibleNodes.map((node) => node.id)
    const nodeIndex = new Map(nodeIds.map((id, idx) => [id, idx]))

    const pos = nodeIds.map((id, idx) => {
      if (id === rootNode?.id) {
        return { x: CANVAS_WIDTH * 0.5, y: CANVAS_HEIGHT * 0.5 }
      }
      const angle = (Math.PI * 2 * idx) / Math.max(1, nodeIds.length)
      const radius = Math.min(CANVAS_WIDTH, CANVAS_HEIGHT) * 0.32
      return {
        x: CANVAS_WIDTH * 0.5 + radius * Math.cos(angle),
        y: CANVAS_HEIGHT * 0.5 + radius * Math.sin(angle),
      }
    })

    const velocity = nodeIds.map(() => ({ x: 0, y: 0 }))

    for (let step = 0; step < 220; step += 1) {
      const force = nodeIds.map(() => ({ x: 0, y: 0 }))

      for (let i = 0; i < nodeIds.length; i += 1) {
        for (let j = i + 1; j < nodeIds.length; j += 1) {
          const dx = pos[j].x - pos[i].x
          const dy = pos[j].y - pos[i].y
          const dist2 = Math.max(100, dx * dx + dy * dy)
          const dist = Math.sqrt(dist2)
          const repulsion = 26000 / dist2
          const fx = (dx / dist) * repulsion
          const fy = (dy / dist) * repulsion

          force[i].x -= fx
          force[i].y -= fy
          force[j].x += fx
          force[j].y += fy
        }
      }

      visibleEdges.forEach((edge) => {
        const fromIndex = nodeIndex.get(edge.from)
        const toIndex = nodeIndex.get(edge.to)
        if (fromIndex === undefined || toIndex === undefined) return

        const dx = pos[toIndex].x - pos[fromIndex].x
        const dy = pos[toIndex].y - pos[fromIndex].y
        const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy))
        const ideal = 130
        const spring = (dist - ideal) * 0.014
        const fx = (dx / dist) * spring
        const fy = (dy / dist) * spring

        force[fromIndex].x += fx
        force[fromIndex].y += fy
        force[toIndex].x -= fx
        force[toIndex].y -= fy
      })

      for (let i = 0; i < nodeIds.length; i += 1) {
        const centerDx = CANVAS_WIDTH * 0.5 - pos[i].x
        const centerDy = CANVAS_HEIGHT * 0.5 - pos[i].y
        force[i].x += centerDx * 0.0016
        force[i].y += centerDy * 0.0016

        velocity[i].x = (velocity[i].x + force[i].x) * 0.86
        velocity[i].y = (velocity[i].y + force[i].y) * 0.86
        pos[i].x = Math.max(34, Math.min(CANVAS_WIDTH - 34, pos[i].x + velocity[i].x))
        pos[i].y = Math.max(34, Math.min(CANVAS_HEIGHT - 34, pos[i].y + velocity[i].y))
      }
    }

    return nodeIds.reduce<Record<string, Point>>((acc, id, idx) => {
      acc[id] = pos[idx]
      return acc
    }, {})
  }, [rootNode?.id, visibleEdges, visibleNodes])

  const metaEntries = useMemo(() => Object.entries(selectedNode?.meta ?? {}).slice(0, 6), [selectedNode?.meta])

  const selectedIndicators = useMemo(
    () => (selectedNode ? extractNodeIndicators(selectedNode) : null),
    [selectedNode],
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

  useEffect(() => {
    setPositions(autoLayout)
  }, [autoLayout])

  function clientToSvgPoint(clientX: number, clientY: number): Point | null {
    const stage = stageRef.current
    if (!stage) return null
    const rect = stage.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return null

    return {
      x: ((clientX - rect.left) / rect.width) * CANVAS_WIDTH,
      y: ((clientY - rect.top) / rect.height) * CANVAS_HEIGHT,
    }
  }

  function clientToGraphPoint(clientX: number, clientY: number): Point | null {
    const svgPoint = clientToSvgPoint(clientX, clientY)
    if (!svgPoint) return null

    return {
      x: Math.max(24, Math.min(CANVAS_WIDTH - 24, (svgPoint.x - viewPan.x) / viewScale)),
      y: Math.max(24, Math.min(CANVAS_HEIGHT - 24, (svgPoint.y - viewPan.y) / viewScale)),
    }
  }

  useEffect(() => {
    if (!dragNodeId) return

    function handlePointerMove(event: MouseEvent) {
      const point = clientToGraphPoint(event.clientX, event.clientY)
      if (!point) return

      const nextX = Math.max(24, Math.min(CANVAS_WIDTH - 24, point.x - dragOffsetRef.current.dx))
      const nextY = Math.max(24, Math.min(CANVAS_HEIGHT - 24, point.y - dragOffsetRef.current.dy))
      setPositions((current) => ({ ...current, [dragNodeId]: { x: nextX, y: nextY } }))
    }

    function handlePointerUp() {
      setDragNodeId('')
    }

    window.addEventListener('mousemove', handlePointerMove)
    window.addEventListener('mouseup', handlePointerUp)

    return () => {
      window.removeEventListener('mousemove', handlePointerMove)
      window.removeEventListener('mouseup', handlePointerUp)
    }
  }, [dragNodeId, viewPan.x, viewPan.y, viewScale])

  useEffect(() => {
    if (!isPanning) return

    function handlePanMove(event: MouseEvent) {
      const stage = stageRef.current
      const start = panStartRef.current
      if (!stage || !start) return

      const rect = stage.getBoundingClientRect()
      if (rect.width <= 0 || rect.height <= 0) return

      const dx = ((event.clientX - start.clientX) / rect.width) * CANVAS_WIDTH
      const dy = ((event.clientY - start.clientY) / rect.height) * CANVAS_HEIGHT
      setViewPan({ x: start.panX + dx, y: start.panY + dy })
    }

    function handlePanEnd() {
      setIsPanning(false)
      panStartRef.current = null
    }

    window.addEventListener('mousemove', handlePanMove)
    window.addEventListener('mouseup', handlePanEnd)

    return () => {
      window.removeEventListener('mousemove', handlePanMove)
      window.removeEventListener('mouseup', handlePanEnd)
    }
  }, [isPanning])

  function handleNodeMouseDown(event: ReactMouseEvent<HTMLButtonElement>, nodeId: string) {
    event.preventDefault()
    event.stopPropagation()
    const stage = stageRef.current
    if (!stage) return

    const pointer = clientToGraphPoint(event.clientX, event.clientY)
    if (!pointer) return
    const current = positions[nodeId]
    if (!current) return

    dragOffsetRef.current = {
      dx: pointer.x - current.x,
      dy: pointer.y - current.y,
    }
    setDragNodeId(nodeId)
  }

  function handleStageMouseDown(event: ReactMouseEvent<SVGSVGElement>) {
    const target = event.target as Element | null
    if (target?.closest('.kg-node-hit')) return

    panStartRef.current = {
      clientX: event.clientX,
      clientY: event.clientY,
      panX: viewPan.x,
      panY: viewPan.y,
    }
    setIsPanning(true)
  }

  const applyWheelZoom = useCallback(
    (clientX: number, clientY: number, deltaY: number) => {
      const pointer = clientToSvgPoint(clientX, clientY)
      if (!pointer) return

      const nextScale = Math.max(0.45, Math.min(2.4, viewScale * (deltaY > 0 ? 0.92 : 1.08)))
      const worldX = (pointer.x - viewPan.x) / viewScale
      const worldY = (pointer.y - viewPan.y) / viewScale

      setViewScale(nextScale)
      setViewPan({
        x: pointer.x - worldX * nextScale,
        y: pointer.y - worldY * nextScale,
      })
    },
    [viewPan.x, viewPan.y, viewScale],
  )

  function handleStageWheel(event: React.WheelEvent<SVGSVGElement>) {
    event.preventDefault()
    applyWheelZoom(event.clientX, event.clientY, event.deltaY)
  }

  useEffect(() => {
    const stage = stageRef.current
    if (!stage) return

    const onNativeWheel = (event: WheelEvent) => {
      event.preventDefault()
      applyWheelZoom(event.clientX, event.clientY, event.deltaY)
    }

    stage.addEventListener('wheel', onNativeWheel, { passive: false })
    return () => {
      stage.removeEventListener('wheel', onNativeWheel)
    }
  }, [applyWheelZoom])

  function sendNodeToHunt(action: HuntBridgeAction) {
    if (!selectedNode || !onSendToHunt) return
    onSendToHunt({
      requestId: Date.now(),
      action,
      sourceNodeId: selectedNode.id,
      sourceNodeType: selectedNode.type,
      sourceNodeLabel: selectedNode.label,
      sourceNodeTitle: selectedNode.title,
      indicators: selectedIndicators ?? {
        ioc: [],
        cve: [],
        host: [],
        ip: [],
        domain: [],
        process: [],
      },
    })
  }

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
            <button type="button" className="graph-control-button" onClick={() => setPositions(autoLayout)}>
              自动布局
            </button>
            <button
              type="button"
              className="graph-control-button"
              onClick={() => {
                setViewScale(1)
                setViewPan({ x: 0, y: 0 })
              }}
            >
              视图复位
            </button>
          </div>
        </div>

        <div className="evidence-graph-canvas">
          <svg
            ref={stageRef}
            className={`kg-stage ${isPanning ? 'is-panning' : ''}`}
            viewBox={`0 0 ${CANVAS_WIDTH} ${CANVAS_HEIGHT}`}
            preserveAspectRatio="xMidYMid meet"
            aria-label="knowledge graph"
            onMouseDown={handleStageMouseDown}
            onWheel={handleStageWheel}
          >
            <defs>
              <marker id={arrowId} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 0 L 8 4 L 0 8 z" fill="rgba(142, 162, 203, 0.72)" />
              </marker>
              <marker id={arrowActiveId} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
                <path d="M 0 0 L 8 4 L 0 8 z" fill="rgba(125, 211, 252, 0.96)" />
              </marker>
            </defs>

            <g transform={`matrix(${viewScale} 0 0 ${viewScale} ${viewPan.x} ${viewPan.y})`}>
              {visibleEdges.map((edge) => {
              const from = positions[edge.from]
              const to = positions[edge.to]
              if (!from || !to) return null

              const isActive = selectedNode?.id === edge.from || selectedNode?.id === edge.to

              return (
                <g key={`${edge.from}-${edge.to}-${edge.relation}`}>
                  <line
                    className={`kg-edge ${isActive ? 'kg-edge-active' : ''}`}
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    markerEnd={`url(#${isActive ? arrowActiveId : arrowId})`}
                  />
                  <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 5} className="kg-edge-label">
                    {shortLabel(edge.relation, 10)}
                  </text>
                </g>
              )
              })}

              {visibleNodes.map((node) => {
              const position = positions[node.id]
              if (!position) return null

              const degree = nodeDegreeMap[node.id] ?? 0
              const radius = node.id === rootNode?.id ? 28 : Math.max(18, Math.min(26, 14 + degree * 1.8))
              const isActive = selectedNode?.id === node.id

              return (
                <g key={node.id} transform={`translate(${position.x}, ${position.y})`}>
                  <circle
                    className={`kg-node-circle ${isActive ? 'kg-node-circle-active' : ''}`}
                    r={radius}
                    fill={nodeColor(node.type || 'unknown', node.id === rootNode?.id)}
                  />

                  <foreignObject
                    x={-radius * 0.92}
                    y={-radius * 0.92}
                    width={radius * 1.84}
                    height={radius * 1.84}
                    className="kg-node-label-wrap"
                  >
                    <button
                      type="button"
                      className={`kg-node-hit ${dragNodeId === node.id ? 'kg-node-dragging' : ''}`}
                      onMouseDown={(event) => handleNodeMouseDown(event, node.id)}
                      onClick={() => setSelectedNodeId(node.id)}
                      title={`${node.label} | ${node.title}`}
                      aria-label={node.label}
                    >
                      {node.label || 'N/A'}
                    </button>
                  </foreignObject>
                </g>
              )
              })}
            </g>
          </svg>
        </div>

        <div className="legend-row">
          {Object.entries(evidence.legend).map(([key, value], index) => (
            <div key={key} className="legend-chip">
              <span className={`legend-dot legend-dot-${index % 3}`} />
              <span>{value}</span>
            </div>
          ))}
        </div>

        <div className={`graph-detail-drawer ${showDetailPanel ? 'is-open' : ''}`}>
          <button
            type="button"
            className="graph-detail-toggle"
            onClick={() => setShowDetailPanel((value) => !value)}
            aria-expanded={showDetailPanel}
          >
            <span>节点详细信息</span>
            <span>{showDetailPanel ? '收起' : '展开'}</span>
          </button>

          {showDetailPanel ? (
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

              <div className="graph-detail-actions">
                <button type="button" className="graph-detail-action" onClick={() => sendNodeToHunt('prefill')}>
                  一键带参到猎捕
                </button>
                <button type="button" className="graph-detail-action" onClick={() => sendNodeToHunt('generate')}>
                  基于当前节点生成查询
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </section>
  )
}
