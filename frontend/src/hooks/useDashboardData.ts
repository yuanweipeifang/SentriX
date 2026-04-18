import { useEffect, useMemo, useState } from 'react'
import { createEmptyUiShellData } from '../constants/defaultUi'
import {
  DEFAULT_FRONTEND_PAYLOAD_QUERY,
  fetchFrontendPayload,
} from '../services/frontendPayloadApi'
import type { UiShellData } from '../types/frontendPayload'
import { normalizeFrontendPayload } from '../utils/normalizeFrontendPayload'

export type LoadState = 'loading' | 'success' | 'fallback'

export function useDashboardData() {
  const emptyUi = useMemo(() => createEmptyUiShellData(), [])
  const [ui, setUi] = useState<UiShellData>(emptyUi)
  const [loadState, setLoadState] = useState<LoadState>('loading')
  const [errorMessage, setErrorMessage] = useState('')

  useEffect(() => {
    let active = true

    async function load() {
      setLoadState('loading')
      try {
        const raw = await fetchFrontendPayload(DEFAULT_FRONTEND_PAYLOAD_QUERY)
        if (!active) return
        setUi(normalizeFrontendPayload(raw))
        setLoadState('success')
        setErrorMessage('')
      } catch (error) {
        if (!active) return
        setUi(emptyUi)
        setLoadState('fallback')
        setErrorMessage(error instanceof Error ? error.message : 'unknown error')
      }
    }

    void load()
    return () => {
      active = false
    }
  }, [emptyUi])

  return { ui, loadState, errorMessage }
}
