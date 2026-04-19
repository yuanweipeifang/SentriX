import type {
  CountermeasurePreview,
  ExecutionTask,
  IncidentOverview,
} from '../types/frontendPayload'

export interface CountermeasureRequest {
  case_id?: string
  task: ExecutionTask
  countermeasure?: CountermeasurePreview | null
  incident: IncidentOverview
  playbook?: Record<string, unknown>
  guardrails?: string[]
  apply?: boolean
}

export interface CountermeasureResponse {
  countermeasure_id: string
  task_id: string
  title: string
  description: string
  kind: string
  stage: string
  mode: string
  status: string
  requires_approval: boolean
  target_assets: string[]
  capability_tags: string[]
  command_preview: string
  api_preview: string
  rollback_hint: string
  incident_summary: string
  primary_indicator: string
  safeguards: string[]
  steps: string[]
  message: string
  applied: boolean
  provider: string
  operation_id: string
  executed_at: string
}

export async function dispatchCountermeasure(
  payload: CountermeasureRequest,
  signal?: AbortSignal,
): Promise<CountermeasureResponse> {
  const response = await fetch('/api/execution/countermeasure', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
    signal,
  })

  const body = (await response.json().catch(() => ({}))) as Partial<CountermeasureResponse> & {
    error?: string
    message?: string
  }

  if (!response.ok) {
    throw new Error(body.message || body.error || `countermeasure request failed: ${response.status}`)
  }

  return body as CountermeasureResponse
}
