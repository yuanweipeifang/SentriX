export interface SystemSettings {
  rules_default_page_size: number
  model_timeout_seconds: number
  online_rag_enabled: boolean
  multi_agent_enabled: boolean
}

export interface SystemSettingsResponse {
  settings: SystemSettings
  db_path: string
  updated_at: string
}

export async function getSystemSettings(signal?: AbortSignal): Promise<SystemSettingsResponse> {
  const response = await fetch('/api/system/settings', {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal,
  })

  if (!response.ok) {
    throw new Error(`system settings load failed: ${response.status}`)
  }

  return (await response.json()) as SystemSettingsResponse
}

export async function updateSystemSettings(
  patch: Partial<SystemSettings>,
  signal?: AbortSignal
): Promise<SystemSettingsResponse> {
  const response = await fetch('/api/system/settings', {
    method: 'PATCH',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(patch),
    signal,
  })

  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as { message?: string }
    throw new Error(payload.message || `system settings update failed: ${response.status}`)
  }

  return (await response.json()) as SystemSettingsResponse
}
