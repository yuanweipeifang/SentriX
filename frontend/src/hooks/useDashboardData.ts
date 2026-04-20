import { useCallback, useEffect, useMemo, useState } from 'react'
import { createEmptyUiShellData } from '../constants/defaultUi'
import {
  DEFAULT_FRONTEND_PAYLOAD_QUERY,
  fetchAsyncCrossValidateRuntimeStatus,
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

  const refreshUi = useCallback(async () => {
    setLoadState('loading')
    try {
      const raw = await fetchFrontendPayload(DEFAULT_FRONTEND_PAYLOAD_QUERY)
      setUi(normalizeFrontendPayload(raw))
      setLoadState('success')
      setErrorMessage('')
    } catch (error) {
      setUi(emptyUi)
      setLoadState('fallback')
      setErrorMessage(error instanceof Error ? error.message : 'unknown error')
      throw error
    }
  }, [emptyUi])

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

  useEffect(() => {
    let active = true
    let timer: ReturnType<typeof setInterval> | null = null

    async function refreshRuntimeStatus() {
      try {
        const stats = await fetchAsyncCrossValidateRuntimeStatus()
        if (!active) return
        setUi((prev) => ({
          ...prev,
          frontendPayload: {
            ...prev.frontendPayload,
            observability: {
              ...prev.frontendPayload.observability,
              async_cross_validate: {
                ...prev.frontendPayload.observability.async_cross_validate,
                enabled: stats.enabled,
                scheduled: stats.scheduled,
                queued: stats.queued,
                running: stats.running,
                done: stats.done,
                failed: stats.failed,
              },
            },
          },
        }))
      } catch (_error) {
        // ignore transient runtime status errors to avoid interrupting main payload rendering
      }
    }

    void refreshRuntimeStatus()
    timer = setInterval(() => {
      void refreshRuntimeStatus()
    }, 2500)

    return () => {
      active = false
      if (timer) {
        clearInterval(timer)
      }
    }
  }, [])

  return { ui, loadState, errorMessage, refreshUi }
}
