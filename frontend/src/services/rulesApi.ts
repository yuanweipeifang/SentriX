import type { RulesPanel } from '../types/frontendPayload'

interface SearchRulesParams {
  query?: string
  page?: number
  pageSize?: number
}

export async function searchRules(paramsInput: SearchRulesParams = {}, signal?: AbortSignal): Promise<RulesPanel> {
  const query = paramsInput.query ?? ''
  const page = Math.max(1, paramsInput.page ?? 1)
  const pageSize = Math.max(1, paramsInput.pageSize ?? 100)
  const params = new URLSearchParams()
  if (query.trim()) {
    params.set('q', query.trim())
  }
  params.set('page', String(page))
  params.set('page_size', String(pageSize))

  const response = await fetch(`/api/rules/search?${params.toString()}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal,
  })

  if (!response.ok) {
    throw new Error(`rules search failed: ${response.status}`)
  }

  return (await response.json()) as RulesPanel
}
