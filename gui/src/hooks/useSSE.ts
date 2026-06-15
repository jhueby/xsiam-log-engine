import { useEffect, useRef, useState } from 'react'
import { sseUrl } from '../api/client'

export function useSSE(path: string, onMessage: (data: string) => void) {
  const [connected, setConnected] = useState(false)
  const cbRef = useRef(onMessage)
  cbRef.current = onMessage

  useEffect(() => {
    const url = sseUrl(path)
    const es = new EventSource(url)

    es.onopen = () => setConnected(true)
    es.onmessage = (e) => cbRef.current(e.data)
    es.onerror = () => setConnected(false)

    return () => {
      es.close()
      setConnected(false)
    }
  }, [path])

  return connected
}
