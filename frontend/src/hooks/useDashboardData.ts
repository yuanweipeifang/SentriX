import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createEmptyUiShellData } from '../constants/defaultUi'
import {
  DEFAULT_FRONTEND_PAYLOAD_QUERY,
  type FrontendPayloadQuery,
  fetchAsyncCrossValidateRuntimeStatus,
  fetchFrontendPayload,
  fetchRuntimeAnalysisLogs,
} from '../services/frontendPayloadApi'
import type { UiShellData } from '../types/frontendPayload'
import { normalizeFrontendPayload } from '../utils/normalizeFrontendPayload'

export type LoadState = 'loading' | 'success' | 'fallback'

export function useDashboardData() {
  const emptyUi = useMemo(() => createEmptyUiShellData(), [])
  const [ui, setUi] = useState<UiShellData>(emptyUi)
  const [loadState, setLoadState] = useState<LoadState>('loading')
  const [errorMessage, setErrorMessage] = useState('')
  const latestLogIdRef = useRef(0)
  const activeQueryRef = useRef<FrontendPayloadQuery>({ ...DEFAULT_FRONTEND_PAYLOAD_QUERY })
  const requestSerialRef = useRef(0)
  const payloadAbortRef = useRef<AbortController | null>(null)
  const hasLoadedOnceRef = useRef(false)

  const refreshUi = useCallback(async (query?: FrontendPayloadQuery, options?: { forceLoading?: boolean }) => {
    const nextQuery = query ? { ...activeQueryRef.current, ...query } : activeQueryRef.current
    activeQueryRef.current = nextQuery
    const currentSerial = ++requestSerialRef.current
    payloadAbortRef.current?.abort()
    const controller = new AbortController()
    payloadAbortRef.current = controller
    if (options?.forceLoading ?? !hasLoadedOnceRef.current) {
      setLoadState('loading')
    }
    try {
      const raw = await fetchFrontendPayload(nextQuery, controller.signal)
      if (currentSerial !== requestSerialRef.current) {
        return
      }
      setUi(normalizeFrontendPayload(raw))
      setLoadState('success')
      setErrorMessage('')
      hasLoadedOnceRef.current = true
      latestLogIdRef.current = 0
    } catch (error) {
      if (currentSerial !== requestSerialRef.current) {
        return
      }
      if (error instanceof DOMException && error.name === 'AbortError') {
        return
      }
      if (!hasLoadedOnceRef.current) {
        setUi(emptyUi)
        setLoadState('fallback')
      }
      setErrorMessage(error instanceof Error ? error.message : 'unknown error')
    }
  }, [emptyUi])

  useEffect(() => {
    void refreshUi(undefined, { forceLoading: true })
    return () => {
      payloadAbortRef.current?.abort()
    }
  }, [refreshUi])

  useEffect(() => {
    let active = true
    let timer: ReturnType<typeof setTimeout> | null = null

    async function refreshRuntimeStatusAndLogs() {
      try {
        const [stats, logs] = await Promise.all([
          fetchAsyncCrossValidateRuntimeStatus(),
          fetchRuntimeAnalysisLogs(latestLogIdRef.current, 120),
        ])
        if (!active) return
        latestLogIdRef.current = logs.latestId
        const runtimeActive = stats.running > 0 || stats.queued > 0 || stats.scheduled > 0
        setUi((prev) => ({
          ...prev,
          frontendPayload: {
            ...prev.frontendPayload,
            runtime_logs: (() => {
              const merged = [...prev.frontendPayload.runtime_logs, ...logs.logs.map((item) => item.message)]
              const filtered = merged.filter((line) => !line.toUpperCase().includes('HEARTBEAT'))
              return filtered.slice(-200)
            })(),
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
        timer = setTimeout(
          () => {
            void refreshRuntimeStatusAndLogs()
          },
          runtimeActive ? 1000 : 2500,
        )
      } catch (_error) {
        // ignore transient runtime status errors to avoid interrupting main payload rendering
        if (!active) return
        timer = setTimeout(() => {
          void refreshRuntimeStatusAndLogs()
        }, 2500)
      }
    }

    void refreshRuntimeStatusAndLogs()

    return () => {
      active = false
      if (timer) {
        clearTimeout(timer)
      }
    }
  }, [])

  return { ui, loadState, errorMessage, refreshUi }
}
