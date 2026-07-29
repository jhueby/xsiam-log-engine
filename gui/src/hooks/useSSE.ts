import { useEffect, useRef, useState } from 'react'
import { sseUrl } from '../api/client'

const INITIAL_RECONNECT_DELAY_MS = 1000
const MAX_RECONNECT_DELAY_MS = 30000

export function useSSE(path: string, onMessage: (data: string) => void) {
  const [connected, setConnected] = useState(false)
  const cbRef = useRef(onMessage)
  cbRef.current = onMessage

  useEffect(() => {
    let es: EventSource | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    let reconnectDelay = INITIAL_RECONNECT_DELAY_MS
    let cancelled = false

    const connect = () => {
      const url = sseUrl(path)
      es = new EventSource(url)

      es.onopen = () => {
        setConnected(true)
        reconnectDelay = INITIAL_RECONNECT_DELAY_MS
      }
      es.onmessage = (e) => cbRef.current(e.data)
      es.onerror = () => {
        setConnected(false)
        // Native EventSource auto-retries on a transport-level drop, but
        // permanently stops (readyState === CLOSED) after an HTTP-level
        // failure -- e.g. a 401 from a missing/rotated ENGINE_API_TOKEN.
        // Without a manual reconnect here, the UI is stuck showing
        // "Reconnecting..." forever with no way to recover short of a full
        // page reload.
        if (es && es.readyState === EventSource.CLOSED && !cancelled) {
          es.close()
          reconnectTimer = setTimeout(() => {
            if (!cancelled) connect()
          }, reconnectDelay)
          reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY_MS)
        }
      }
    }

    connect()

    return () => {
      cancelled = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      es?.close()
      setConnected(false)
    }
  }, [path])

  return connected
}
