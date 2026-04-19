export interface CopilotHistoryItem {
  role: 'user' | 'assistant'
  content: string
}

export interface CopilotContextPayload {
  pageTitle: string
  eventSummary?: string
  topThreat?: string
  recommendedAction?: string
}

export interface CopilotChatRequest {
  message: string
  history?: CopilotHistoryItem[]
  context: CopilotContextPayload
  apiKey?: string
  model?: string
}

export interface CopilotChatResponse {
  reply: string
  provider: string
  model: string
  used_override_key: boolean
  available_models?: string[]
}

export async function sendCopilotChat(
  payload: CopilotChatRequest,
  signal?: AbortSignal,
): Promise<CopilotChatResponse> {
  const response = await fetch('/api/copilot/chat', {
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
    throw new Error(errorPayload.message || `copilot request failed: ${response.status}`)
  }

  return response.json() as Promise<CopilotChatResponse>
}
