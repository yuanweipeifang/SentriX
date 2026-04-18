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
