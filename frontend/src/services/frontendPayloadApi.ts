export interface FrontendPayloadQuery {
  datasetFile?: string
  datasetIndex?: number
  inputFile?: string
  csvFile?: string
  csvRowIndex?: number
}

export const DEFAULT_FRONTEND_PAYLOAD_QUERY: FrontendPayloadQuery = {
  datasetFile: '/home/kali/SentriX/backend/dataset/incident_examples_min.json',
  datasetIndex: 0,
}

function buildQueryString(query?: FrontendPayloadQuery): string {
  const params = new URLSearchParams()
  if (query?.datasetFile) params.set('dataset_file', query.datasetFile)
  if (typeof query?.datasetIndex === 'number') params.set('dataset_index', String(query.datasetIndex))
  if (query?.inputFile) params.set('input_file', query.inputFile)
  if (query?.csvFile) params.set('csv_file', query.csvFile)
  if (typeof query?.csvRowIndex === 'number') params.set('csv_row_index', String(query.csvRowIndex))
  const text = params.toString()
  return text ? `?${text}` : ''
}

export async function fetchFrontendPayload(query?: FrontendPayloadQuery, signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(`/api/frontend-payload${buildQueryString(query)}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal,
  })
  if (!response.ok) {
    throw new Error(`frontend payload request failed: ${response.status}`)
  }
  return response.json()
}

export interface AsyncCrossValidateRuntimeStatus {
  enabled: boolean
  scheduled: number
  queued: number
  running: number
  done: number
  failed: number
}

export async function fetchAsyncCrossValidateRuntimeStatus(signal?: AbortSignal): Promise<AsyncCrossValidateRuntimeStatus> {
  const response = await fetch('/api/runtime/async-cross-validate', {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal,
  })
  if (!response.ok) {
    throw new Error(`runtime async-cross-validate request failed: ${response.status}`)
  }
  const payload = (await response.json()) as {
    async_cross_validate?: Partial<AsyncCrossValidateRuntimeStatus>
  }
  const stats = payload.async_cross_validate ?? {}
  return {
    enabled: Boolean(stats.enabled ?? false),
    scheduled: Number(stats.scheduled ?? 0),
    queued: Number(stats.queued ?? 0),
    running: Number(stats.running ?? 0),
    done: Number(stats.done ?? 0),
    failed: Number(stats.failed ?? 0),
  }
}
