import { useEffect, useMemo, useState } from 'react'
import { SectionTitle } from '../common/SectionTitle'
import type { ExecutionPanel, OrchestrationGraph } from '../../types/frontendPayload'

interface OrchestrationPanelProps {
  execution: ExecutionPanel
  orchestration: OrchestrationGraph
}

export function OrchestrationPanel({ execution, orchestration }: OrchestrationPanelProps) {
  const nodes = useMemo(() => orchestration.nodes.slice(0, 8), [orchestration.nodes])
  const [selectedNodeId, setSelectedNodeId] = useState<string>(String(nodes[0]?.id ?? ''))
  const [zoom, setZoom] = useState<number>(1)
  const selectedNode = useMemo(
    () => nodes.find((node) => String(node.id ?? '') === selectedNodeId) ?? nodes[0],
    [nodes, selectedNodeId],
  )
  const graphEdges = useMemo(() => {
    if (orchestration.edges.length > 0) return orchestration.edges

    return orchestration.execution_order.slice(0, Math.max(0, orchestration.execution_order.length - 1)).map((nodeId, index) => ({
      from: nodeId,
      to: orchestration.execution_order[index + 1],
      relation: 'next',
    }))
  }, [orchestration.edges, orchestration.execution_order])

  const layout = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {}
    const total = Math.max(nodes.length, 1)

    nodes.forEach((node, index) => {
      const id = String(node.id ?? index)
      const x = total === 1 ? 50 : 12 + (index * 76) / Math.max(total - 1, 1)
      const y = String(node.type ?? '').includes('approval') ? 34 : index % 2 === 0 ? 62 : 78
      positions[id] = { x, y }
    })

    return positions
  }, [nodes])

  const selectedTask = useMemo(
    () =>
      execution.tasks.find((task) => task.task_id === String(selectedNode?.id ?? '')) ??
      execution.tasks.find((task) => task.stage === String(selectedNode?.stage ?? '')),
    [execution.tasks, selectedNode],
  )

  useEffect(() => {
    setSelectedNodeId(String(nodes[0]?.id ?? ''))
  }, [nodes])

  return (
    <section className="panel">
      <SectionTitle eyebrow="Response" title="执行编排" tone="eyebrow-violet" badge={execution.mode} />
      <div className="orchestration-grid">
        <div className="orchestration-card tone-info-soft">
          <div className="mini-title text-blue">Playbook</div>
          <div className="mono-line">{String(execution.playbook.title ?? '未定义 playbook')}</div>
          <div className="muted">回滚提示：{String(execution.playbook.rollback_hint ?? '暂无回滚提示')}</div>
        </div>
        <div className="orchestration-card tone-warning-soft">
          <div className="mini-title text-orange">Graph</div>
          <div className="mono-line">{orchestration.graph_id || '暂无图ID'}</div>
          <div className="muted">
            节点 {orchestration.nodes.length} / 审批 {orchestration.approval_nodes.length}
          </div>
        </div>
      </div>

      <div className="graph-toolbar">
        <div className="graph-filter-row">
          <span className="graph-context-chip">strategy: {orchestration.strategy || 'default'}</span>
          <span className="graph-context-chip">tasks: {execution.tasks.length}</span>
          <span className="graph-context-chip">rollback: {Array.isArray(orchestration.rollback_plan.tasks) ? orchestration.rollback_plan.tasks.length : 0}</span>
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

      <div className="orchestration-flow">
        <div className="flow-stage" style={{ transform: `scale(${zoom})` }}>
          <svg className="graph-link-layer" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
            {graphEdges.map((edge, index) => {
              const from = layout[String(edge.from ?? '')]
              const to = layout[String(edge.to ?? '')]
              if (!from || !to) return null

              return (
                <path
                  key={`${String(edge.from ?? index)}-${String(edge.to ?? index)}`}
                  className={`flow-link ${
                    selectedNodeId === String(edge.from ?? '') || selectedNodeId === String(edge.to ?? '') ? 'flow-link-active' : ''
                  }`}
                  d={`M ${from.x} ${from.y} C ${from.x + 8} ${from.y}, ${to.x - 8} ${to.y}, ${to.x} ${to.y}`}
                />
              )
            })}
          </svg>

          {nodes.map((node, index) => {
            const id = String(node.id ?? index)
            const position = layout[id]
            if (!position) return null

            return (
              <button
                key={id}
                type="button"
                className={`flow-node flow-selectable flow-node-${index % 3} ${
                  id === selectedNodeId ? 'flow-node-active' : ''
                }`}
                style={{ left: `${position.x}%`, top: `${position.y}%` }}
                onClick={() => setSelectedNodeId(id)}
              >
                <div className="flow-node-kicker">{String(node.type ?? 'step')}</div>
                <div className="flow-node-title">{String(node.name ?? node.id ?? 'unnamed')}</div>
                <div className="muted">{String(node.stage ?? execution.mode)}</div>
              </button>
            )
          })}
        </div>

        {orchestration.approval_nodes.length > 0 ? (
          <div className="approval-banner">
            审批节点 {orchestration.approval_nodes.length} 个，失败时回滚任务{' '}
            {Array.isArray(orchestration.rollback_plan.tasks) ? orchestration.rollback_plan.tasks.length : 0} 个
          </div>
        ) : null}
      </div>

      <div className="graph-detail-panel">
        <div className="mini-title text-blue">Selected Step</div>
        <div className="detail-title">{String(selectedNode?.name ?? selectedNode?.id ?? '暂无步骤')}</div>
        <div className="muted">{String(selectedNode?.stage ?? execution.mode)}</div>
        <div className="graph-detail-meta">
          <span className="mini-chip text-violet">{String(selectedNode?.type ?? 'node')}</span>
          <span className="mini-chip text-orange">{selectedTask?.requires_approval ? 'requires approval' : 'automation ready'}</span>
        </div>
        {selectedTask ? (
          <div className="graph-meta-grid">
            <div className="graph-meta-item">
              <span className="muted">shell</span>
              <strong>{selectedTask.shell || 'N/A'}</strong>
            </div>
            <div className="graph-meta-item">
              <span className="muted">api</span>
              <strong>{selectedTask.api || 'N/A'}</strong>
            </div>
          </div>
        ) : null}
      </div>

      <div className="task-list">
        {execution.tasks.map((task) => (
          <article key={task.task_id} className="task-item">
            <div className="task-main">
              <div className="task-title">{task.name}</div>
              <div className="task-tags">
                <span className="mini-chip text-blue">{task.stage}</span>
                <span className="mini-chip text-violet">{task.mode}</span>
                <span className="mini-chip text-orange">{task.execution_type}</span>
              </div>
            </div>
            <div className="task-meta">
              <span>{task.estimated_cost_minutes} min</span>
              <span>{task.requires_approval ? '需审批' : '自动化'}</span>
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}
