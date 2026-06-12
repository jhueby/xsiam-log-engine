import { useEffect, useRef, useState } from 'react'
import { Copy, Check } from 'lucide-react'

interface LogEntry {
  source_id: string
  timestamp: string
  transport: string
  format: string
  raw: string
  success: boolean
  error?: string
}

interface Props {
  filterSource?: string
}

export default function LogViewerComponent({ filterSource }: Props) {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [rawView, setRawView] = useState(true)
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  useEffect(() => {
    const url = filterSource ? `/api/logs/stream?source_id=${filterSource}` : '/api/logs/stream'
    const es = new EventSource(url)
    es.onmessage = (e) => {
      try {
        const entry = JSON.parse(e.data) as LogEntry
        setLogs(prev => [...prev.slice(-199), entry])
      } catch {}
    }
    return () => es.close()
  }, [filterSource])

  useEffect(() => {
    if (autoScroll) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs, autoScroll])

  const copy = (idx: number, text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedIdx(idx)
    setTimeout(() => setCopiedIdx(null), 2000)
  }

  const formatEntry = (raw: string): string => {
    if (!rawView) {
      try { return JSON.stringify(JSON.parse(raw), null, 2) }
      catch {}
    }
    return raw
  }

  const TRANSPORT_COLOR: Record<string, string> = {
    http: 'text-purple-400',
    syslog: 'text-yellow-400',
    wec: 'text-cyan-400',
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-4 p-3 border-b border-gray-800 bg-gray-900">
        <span className="text-xs text-gray-400">{logs.length} events</span>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
          <input type="checkbox" checked={rawView} onChange={e => setRawView(e.target.checked)} className="accent-indigo-500" />
          Raw
        </label>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
          <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} className="accent-indigo-500" />
          Auto-scroll
        </label>
        <button
          onClick={() => setLogs([])}
          className="text-xs text-gray-500 hover:text-gray-300 ml-auto"
        >
          Clear
        </button>
      </div>
      <div className="flex-1 overflow-auto font-mono text-xs p-2 space-y-1">
        {logs.map((log, i) => (
          <div key={i} className={`group flex gap-2 p-2 rounded hover:bg-gray-900 ${!log.success ? 'border-l-2 border-red-700' : ''}`}>
            <div className="flex-shrink-0 text-gray-600 w-24 truncate">{new Date(log.timestamp).toLocaleTimeString()}</div>
            <div className={`flex-shrink-0 w-20 truncate ${TRANSPORT_COLOR[log.transport] || 'text-gray-400'}`}>{log.source_id}</div>
            <div className="flex-1 min-w-0 text-gray-300 whitespace-pre-wrap break-all">{formatEntry(log.raw)}</div>
            <button
              onClick={() => copy(i, log.raw)}
              className="flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
            >
              {copiedIdx === i ? <Check size={12} className="text-green-400" /> : <Copy size={12} className="text-gray-500" />}
            </button>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
