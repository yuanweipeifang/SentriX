import { useMemo, useState } from 'react'
import { SectionTitle } from '../common/SectionTitle'
import { dispatchCountermeasure } from '../../services/countermeasureApi'
import type {
  CountermeasurePreview,
  ExecutionPanel,
  ExecutionTask,
  IncidentOverview,
  OrchestrationGraph,
} from '../../types/frontendPayload'

interface OrchestrationPanelProps {
  execution: ExecutionPanel
  orchestration: OrchestrationGraph
  incident: IncidentOverview
  caseId: string
  onRefreshData?: () => Promise<void>
}

interface CountermeasureState {
  taskId: string
  status: string
  message: string
  steps: string[]
  safeguards: string[]
  operationId: string
}

const EMPTY_COUNTERMEASURE_STATE: CountermeasureState = {
  taskId: '',
  status: '',
  message: '',
  steps: [],
  safeguards: [],
  operationId: '',
}

function pickCountermeasure(
  countermeasures: CountermeasurePreview[],
  task: ExecutionTask | undefined,
  stage: string,
): CountermeasurePreview | undefined {
  if (!task) {
    return countermeasures.find((item) => item.stage === stage) ?? countermeasures[0]
  }
  return (
    countermeasures.find((item) => item.task_id === task.task_id) ??
    countermeasures.find((item) => item.stage === task.stage) ??
    countermeasures[0]
  )
}

export function OrchestrationPanel({ execution, orchestration, incident, caseId, onRefreshData }: OrchestrationPanelProps) {
  const nodes = useMemo(() => orchestration.nodes.slice(0, 8), [orchestration.nodes])
  const [selectedNodeId, setSelectedNodeId] = useState<string>(String(nodes[0]?.id ?? ''))
  const [countermeasurePending, setCountermeasurePending] = useState(false)
  const [countermeasureError, setCountermeasureError] = useState('')
  const [countermeasureState, setCountermeasureState] = useState<CountermeasureState>(EMPTY_COUNTERMEASURE_STATE)

  const orderedNodes = useMemo(() => {
    const mapped = orchestration.execution_order
      .map((nodeId) => nodes.find((node) => node.id === String(nodeId)))
      .filter((node): node is (typeof nodes)[number] => Boolean(node))
    return mapped.length > 0 ? mapped : nodes
  }, [nodes, orchestration.execution_order])

  const activeNodeId = useMemo(() => {
    const matched = orderedNodes.find((node) => node.id === selectedNodeId)
    return matched ? selectedNodeId : String(orderedNodes[0]?.id ?? '')
  }, [orderedNodes, selectedNodeId])

  const selectedNode = useMemo(
    () => orderedNodes.find((node) => node.id === activeNodeId) ?? orderedNodes[0],
    [activeNodeId, orderedNodes],
  )

  const selectedTask = useMemo(
    () =>
      execution.tasks.find((task) => task.task_id === String(selectedNode?.id ?? '')) ??
      execution.tasks.find((task) => task.stage === String(selectedNode?.stage ?? '')),
    [execution.tasks, selectedNode],
  )

  const selectedCountermeasure = useMemo(
    () => pickCountermeasure(execution.countermeasures, selectedTask, selectedNode?.stage ?? ''),
    [execution.countermeasures, selectedNode?.stage, selectedTask],
  )

  const selectedStepIndex = useMemo(
    () => orderedNodes.findIndex((node) => node.id === String(selectedNode?.id ?? '')),
    [orderedNodes, selectedNode],
  )

  async function handleCountermeasure(apply: boolean) {
    if (!selectedTask) {
      setCountermeasureError('当前动作缺少可执行任务，无法生成反制。')
      return
    }

    setCountermeasurePending(true)
    setCountermeasureError('')

    try {
      const response = await dispatchCountermeasure({
        task: selectedTask,
        case_id: caseId,
        countermeasure: selectedCountermeasure ?? null,
        incident,
        playbook: execution.playbook,
        guardrails: execution.guardrails,
        apply,
      })

      setCountermeasureState({
        taskId: selectedTask.task_id,
        status: response.status,
        message: response.message,
        steps: response.steps,
        safeguards: response.safeguards,
        operationId: response.operation_id,
      })

      if (onRefreshData) {
        await onRefreshData()
      }
    } catch (error) {
      setCountermeasureError(error instanceof Error ? error.message : '反制请求失败。')
      setCountermeasureState((current) =>
        current.taskId === selectedTask.task_id ? EMPTY_COUNTERMEASURE_STATE : current,
      )
    } finally {
      setCountermeasurePending(false)
    }
  }

  const visibleCountermeasureState =
    countermeasureState.taskId === selectedTask?.task_id ? countermeasureState : EMPTY_COUNTERMEASURE_STATE
  const payloadCountermeasureState =
    selectedCountermeasure && visibleCountermeasureState.taskId !== selectedTask?.task_id
      ? {
          status: selectedCountermeasure.status,
          message: selectedCountermeasure.status_message,
          steps: [] as string[],
          safeguards: [] as string[],
          operationId: selectedCountermeasure.operation_id,
        }
      : null
  const resolvedCountermeasureState = payloadCountermeasureState ?? visibleCountermeasureState

  return (
    <section className="panel">
      <SectionTitle eyebrow="Response" title="执行编排" tone="eyebrow-violet" badge={execution.mode} />

      <div className="execution-focus-grid">
        <section className="orchestration-flow execution-step-panel">
          <div className="graph-toolbar execution-step-head">
            <div className="mini-title text-blue">动作步骤</div>
            <div className="muted execution-section-note">
              数据来自后端 `/api/frontend-payload`，执行成功后会自动刷新当前真实状态。
            </div>
          </div>

          <div className="execution-step-list">
            {orderedNodes.map((node, index) => {
              const id = String(node.id ?? index)
              const relatedTask =
                execution.tasks.find((task) => task.task_id === id) ??
                execution.tasks.find((task) => task.stage === String(node.stage ?? ''))

              return (
                <button
                  key={id}
                  type="button"
                  className={`execution-step-item ${id === activeNodeId ? 'is-active' : ''}`}
                  onClick={() => setSelectedNodeId(id)}
                >
                  <div className="execution-step-index">{index + 1}</div>
                  <div className="execution-step-main">
                    <div className="execution-step-top">
                      <div className="execution-step-title">{String(node.name ?? node.id ?? 'unnamed')}</div>
                      <div className="execution-step-meta">
                        <span className="mini-chip text-blue">{String(node.stage ?? execution.mode)}</span>
                        <span className="mini-chip text-violet">{String(node.type ?? 'node')}</span>
                        <span className="mini-chip text-orange">
                          {relatedTask?.requires_approval ? '需审批' : '自动执行'}
                        </span>
                      </div>
                    </div>
                    <div className="execution-step-bottom">
                      <span>{relatedTask?.execution_type || 'unknown'}</span>
                      <span>{relatedTask?.estimated_cost_minutes ?? 0} min</span>
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
        </section>

        <section className="graph-detail-panel execution-detail-panel">
          <div className="mini-title text-blue">当前动作</div>
          <div className="detail-title">{String(selectedNode?.name ?? selectedNode?.id ?? '暂无动作')}</div>
          <div className="muted">
            第 {selectedStepIndex >= 0 ? selectedStepIndex + 1 : 1} 步 / {orderedNodes.length} 步
          </div>
          <div className="graph-detail-meta">
            <span className="mini-chip text-violet">{String(selectedNode?.type ?? 'node')}</span>
            <span className="mini-chip text-blue">{String(selectedNode?.stage ?? execution.mode)}</span>
            <span className="mini-chip text-orange">{selectedTask?.requires_approval ? '需审批' : '可直接执行'}</span>
          </div>
          <div className="muted execution-section-note">
            {selectedTask?.requires_approval ? '该动作进入执行前需要人工审批。' : '该动作可按当前策略直接执行。'}
          </div>
          {selectedTask ? (
            <>
              <div className="graph-meta-grid execution-detail-grid">
                <div className="graph-meta-item">
                  <span className="muted">阶段</span>
                  <strong>{selectedTask.stage || 'N/A'}</strong>
                </div>
                <div className="graph-meta-item">
                  <span className="muted">动作类型</span>
                  <strong>{String(selectedNode?.type ?? 'N/A')}</strong>
                </div>
                <div className="graph-meta-item">
                  <span className="muted">执行方式</span>
                  <strong>{selectedTask.execution_type || 'N/A'}</strong>
                </div>
                <div className="graph-meta-item">
                  <span className="muted">耗时</span>
                  <strong>{selectedTask.estimated_cost_minutes} min</strong>
                </div>
              </div>

              {selectedTask.description ? (
                <div className="muted execution-section-note">{selectedTask.description}</div>
              ) : null}

              <div className="execution-countermeasure-block">
                <div className="execution-countermeasure-head">
                  <div>
                    <div className="mini-title text-orange">威胁反制</div>
                    <div className="muted execution-section-note">
                      {selectedCountermeasure
                        ? `后端可生成 ${selectedCountermeasure.kind || 'generic'} 反制预案，并按开关决定是否允许下发。`
                        : '当前动作缺少反制元数据，后端会退化为通用反制预案。'}
                    </div>
                  </div>
                  <div className="execution-countermeasure-actions">
                    <button
                      type="button"
                      className="hunt-ghost-button"
                      disabled={countermeasurePending}
                      onClick={() => void handleCountermeasure(false)}
                    >
                      {countermeasurePending ? '处理中...' : '反制预演'}
                    </button>
                    <button
                      type="button"
                      className="hunt-rag-button"
                      disabled={countermeasurePending || selectedTask.requires_approval}
                      onClick={() => void handleCountermeasure(true)}
                    >
                      {selectedTask.requires_approval ? '需审批' : '下发反制'}
                    </button>
                  </div>
                </div>

                {selectedCountermeasure ? (
                  <div className="execution-countermeasure-tags">
                    <span className="mini-chip text-orange">{selectedCountermeasure.kind || 'generic'}</span>
                    <span className="mini-chip text-blue">{selectedCountermeasure.mode || execution.mode}</span>
                    <span className="mini-chip text-violet">
                      {selectedCountermeasure.target_assets[0] || '未指定资产'}
                    </span>
                  </div>
                ) : null}

                {countermeasureError ? <div className="hunt-rag-error">{countermeasureError}</div> : null}

                {resolvedCountermeasureState.message ? (
                  <div className="execution-countermeasure-result">
                    <div className="execution-countermeasure-status">
                      <span className="mini-chip text-orange">{resolvedCountermeasureState.status}</span>
                      {selectedCountermeasure?.applied ? <span className="mini-chip text-blue">已同步后端</span> : null}
                      {resolvedCountermeasureState.operationId ? (
                        <span className="muted">operation: {resolvedCountermeasureState.operationId}</span>
                      ) : null}
                    </div>
                    <div className="muted execution-section-note">{resolvedCountermeasureState.message}</div>
                    {selectedCountermeasure?.executed_at ? (
                      <div className="muted execution-section-note">executed_at: {selectedCountermeasure.executed_at}</div>
                    ) : null}
                    {resolvedCountermeasureState.steps.length > 0 ? (
                      <div className="execution-countermeasure-list">
                        {resolvedCountermeasureState.steps.map((item, index) => (
                          <div key={`${item}-${index}`} className="execution-countermeasure-item">
                            {item}
                          </div>
                        ))}
                      </div>
                    ) : null}
                    {resolvedCountermeasureState.safeguards.length > 0 ? (
                      <div className="execution-countermeasure-list">
                        {resolvedCountermeasureState.safeguards.map((item, index) => (
                          <div key={`${item}-${index}`} className="execution-countermeasure-item is-safeguard">
                            {item}
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            </>
          ) : (
            <div className="muted">暂无动作详情。</div>
          )}
        </section>
      </div>
    </section>
  )
}
