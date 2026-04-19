export interface HuntRagContextPayload {
  eventSummary?: string
  topThreat?: string
  affectedAssets?: string[]
  ioc?: {
    ip?: string[]
    domain?: string[]
    cve?: string[]
    process?: string[]
  }
  additionalTerms?: string[]
}

export interface HuntRagSuggestRequest {
  query_template: string
  param_keys?: string[]
  context?: HuntRagContextPayload
  top_k?: number
}

export interface HuntRagEvidenceItem {
  doc_type: string
  text_key: string
  title: string
  score: number
  source_type: string
}

export interface HuntRagSuggestionItem {
  param_key: string
  param_value: string
  confidence: number
  evidence_ref: HuntRagEvidenceItem
}

export interface HuntRagSuggestResponse {
  query_terms: string[]
  filled_params: Record<string, string>
  suggestions: HuntRagSuggestionItem[]
  evidence: HuntRagEvidenceItem[]
  db_path: string
}

export async function fetchHuntRagSuggest(
  payload: HuntRagSuggestRequest,
  signal?: AbortSignal,
): Promise<HuntRagSuggestResponse> {
  const response = await fetch('/api/hunt/rag-suggest', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
    signal,
  })

  if (!response.ok) {
    const errorPayload = (await response.json().catch(() => ({}))) as { message?: string }
    throw new Error(errorPayload.message || `hunt rag suggest failed: ${response.status}`)
  }

  return response.json() as Promise<HuntRagSuggestResponse>
}
