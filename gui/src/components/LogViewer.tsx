import { useCallback, useMemo, useRef, useState } from 'react'
import { Copy, Check, Pause, Play, Download, Search, WifiOff } from 'lucide-react'
import { useSSE } from '../hooks/useSSE'

interface LogEntry {
  source_id: string
  timestamp: string
  transport: string
  format: string
  raw: string
  success: boolean
  error?: string
}

type Filter = 'all' | 'success' | 'errors'

interface Props {
  filterSource?: string
}

export default function LogViewerComponent({ filterSource }: Props) {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [rawView, setRawView] = useState(true)
  const [autoScroll, setAutoScroll] = useState(true)
  const [paused, setPaused] = useState(false)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const pauseBuffer = useRef<LogEntry[]>([])

  const path = filterSource
    ? `/api/logs/stream?source_id=${encodeURIComponent(filterSource)}`
    : '/api/logs/stream'

  const connected = useSSE(path, useCallback((data: string) => {
    try {
      const entry = JSON.parse(data) as LogEntry
      if (paused) {
        pauseBuffer.current.push(entry)
        return
      }
      setLogs(prev => {
        const next = [...prev.slice(-499), entry]
        if (autoScroll) setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 0)
        return next
      })
    } catch {}
  }, [paused, autoScroll]))

  const handlePauseToggle = () => {
    if (paused) {
      // Flush buffer
      setLogs(prev => [...prev, ...pauseBuffer.current].slice(-500))
      pauseBuffer.current = []
    }
    setPaused(v => !v)
  }

  const filtered = useMemo(() => {
    let list = logs
    if (filter === 'success') list = list.filter(l => l.success)
    if (filter === 'errors') list = list.filter(l => !l.success)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(l => l.raw.toLowerCase().includes(q) || l.source_id.includes(q))
    }
    return list
  }, [logs, filter, search])

  const download = () => {
    const ndjson = logs.map(l => JSON.stringify(l)).join('\n')
    const blob = new Blob([ndjson], { type: 'application/x-ndjson' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `log-buffer-${Date.now()}.ndjson`
    a.click()
    URL.revokeObjectURL(url)
  }

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
    http: 'text-purple-600 dark:text-purple-400',
    syslog: 'text-yellow-600 dark:text-yellow-400',
    wec: 'text-cyan-600 dark:text-cyan-400',
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-3 flex-wrap p-3 border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
        <span className="text-xs text-gray-600 dark:text-gray-400 whitespace-nowrap">
          {logs.length} events{filtered.length !== logs.length ? ` (${filtered.length} shown)` : ''}
        </span>

        {/* Search */}
        <div className="relative">
          <Search size={11} className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search…"
            className="pl-6 pr-2 py-1 text-xs bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded focus:outline-none focus:border-indigo-500 w-40"
          />
        </div>

        {/* Filter */}
        <select
          value={filter}
          onChange={e => setFilter(e.target.value as Filter)}
          className="text-xs bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 focus:outline-none"
        >
          <option value="all">All</option>
          <option value="success">Success</option>
          <option value="errors">Errors</option>
        </select>

        <label className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-400 cursor-pointer">
          <input type="checkbox" checked={rawView} onChange={e => setRawView(e.target.checked)} className="accent-indigo-500" />
          Raw
        </label>
        <label className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-400 cursor-pointer">
          <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} className="accent-indigo-500" />
          Auto-scroll
        </label>

        <div className="ml-auto flex items-center gap-2">
          {!connected && (
            <span className="flex items-center gap-1 text-xs text-yellow-600 dark:text-yellow-400">
              <WifiOff size={11} /> Reconnecting…
            </span>
          )}
          {paused && (
            <span className="text-xs text-orange-600 dark:text-orange-400 font-medium">
              {pauseBuffer.current.length} buffered
            </span>
          )}
          <button
            onClick={handlePauseToggle}
            className={`flex items-center gap-1 text-xs px-2 py-1 rounded transition-colors ${
              paused
                ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 hover:bg-orange-200 dark:hover:bg-orange-900/50'
                : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'
            }`}
          >
            {paused ? <><Play size={11} /> Resume</> : <><Pause size={11} /> Pause</>}
          </button>
          <button
            onClick={download}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
            title="Download buffer as NDJSON"
          >
            <Download size={11} />
          </button>
          <button
            onClick={() => setLogs([])}
            className="text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
          >
            Clear
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto font-mono text-xs p-2 space-y-1">
        {filtered.map((log, i) => (
          <div key={i} className={`group flex gap-2 p-2 rounded hover:bg-gray-100 dark:hover:bg-gray-900 ${!log.success ? 'border-l-2 border-red-700' : ''}`}>
            <div className="flex-shrink-0 text-gray-500 dark:text-gray-600 w-20 truncate">
              {new Date(log.timestamp).toLocaleTimeString()}
            </div>
            <div className={`flex-shrink-0 w-20 truncate ${TRANSPORT_COLOR[log.transport] || 'text-gray-600 dark:text-gray-400'}`}>
              {log.source_id}
            </div>
            <div className="flex-1 min-w-0 text-gray-700 dark:text-gray-300 whitespace-pre-wrap break-all">
              {formatEntry(log.raw)}
              {log.error && <div className="text-red-600 dark:text-red-400 mt-0.5">Error: {log.error}</div>}
            </div>
            <button
              onClick={() => copy(i, log.raw)}
              className="flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
            >
              {copiedIdx === i ? <Check size={12} className="text-green-600 dark:text-green-400" /> : <Copy size={12} className="text-gray-500" />}
            </button>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
