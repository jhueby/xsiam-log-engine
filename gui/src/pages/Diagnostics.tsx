import { useEffect, useRef, useState } from 'react'
import { Trash2, WifiOff } from 'lucide-react'
import { DiagEntry, DiagLevel, clearDiagLogs, getDiagLevel, getDiagLogs, setDiagLevel, sseUrl } from '../api/client'
import { useSSE } from '../hooks/useSSE'

const LEVEL_OPTIONS: { value: DiagLevel; label: string; desc: string }[] = [
  { value: 'off', label: 'Off', desc: 'No diagnostic logging' },
  { value: 'errors', label: 'Errors', desc: 'Connection failures and send errors only' },
  { value: 'info', label: 'Informational', desc: 'All engine activity' },
]

const LEVEL_COLOR: Record<string, string> = {
  ERROR: 'text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-950',
  CRITICAL: 'text-red-700 dark:text-red-300 bg-red-100 dark:bg-red-950',
  WARNING: 'text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-950',
  INFO: 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-950',
  DEBUG: 'text-gray-500 bg-white dark:bg-gray-900',
}

function levelBadge(level: string) {
  const cls = LEVEL_COLOR[level] ?? 'text-gray-600 dark:text-gray-400 bg-white dark:bg-gray-900'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-mono font-semibold ${cls}`}>
      {level}
    </span>
  )
}

export default function Diagnostics() {
  const [level, setLevel] = useState<DiagLevel>('errors')
  const [entries, setEntries] = useState<DiagEntry[]>([])
  const [autoScroll, setAutoScroll] = useState(true)
  const [confirmClear, setConfirmClear] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    getDiagLevel().then(r => setLevel(r.data.level)).catch(() => {})
    getDiagLogs(200).then(r => setEntries(r.data)).catch(() => {})
  }, [])

  const connected = useSSE('/api/diagnostics/stream', (data) => {
    try {
      const entry = JSON.parse(data) as DiagEntry
      setEntries(prev => [...prev.slice(-499), entry])
    } catch {}
  })

  useEffect(() => {
    if (autoScroll) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [entries, autoScroll])

  const handleLevelChange = async (next: DiagLevel) => {
    try {
      await setDiagLevel(next)
      setLevel(next)
    } catch {}
  }

  const handleClear = async () => {
    if (!confirmClear) {
      setConfirmClear(true)
      setTimeout(() => setConfirmClear(false), 3000)
      return
    }
    setConfirmClear(false)
    try {
      await clearDiagLogs()
      setEntries([])
    } catch {}
  }

  return (
    <div className="flex flex-col h-screen">
      <div className="flex items-center gap-6 px-6 py-3 border-b border-gray-200 dark:border-gray-800 bg-gray-100 dark:bg-gray-950">
        <h1 className="font-semibold text-gray-900 dark:text-gray-200">Diagnostics</h1>

        <div className="flex items-center gap-1 bg-white dark:bg-gray-900 rounded p-1">
          {LEVEL_OPTIONS.map(opt => (
            <button
              key={opt.value}
              onClick={() => handleLevelChange(opt.value)}
              title={opt.desc}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                level === opt.value
                  ? opt.value === 'off'
                    ? 'bg-gray-300 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
                    : opt.value === 'errors'
                    ? 'bg-red-800 text-red-100'
                    : 'bg-blue-800 text-blue-100'
                  : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <div className="ml-auto flex items-center gap-4">
          {!connected && (
            <span className="flex items-center gap-1 text-xs text-yellow-600 dark:text-yellow-400">
              <WifiOff size={12} /> Reconnecting…
            </span>
          )}
          <label className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={e => setAutoScroll(e.target.checked)}
              className="accent-indigo-500"
            />
            Auto-scroll
          </label>
          <button
            onClick={handleClear}
            className={`flex items-center gap-1.5 text-xs transition-colors ${
              confirmClear
                ? 'text-red-600 dark:text-red-400 font-medium'
                : 'text-gray-500 hover:text-red-600 dark:hover:text-red-400'
            }`}
          >
            <Trash2 size={12} />
            {confirmClear ? 'Confirm Clear?' : 'Clear'}
          </button>
        </div>
      </div>

      {level === 'off' && (
        <div className="px-6 py-2 bg-yellow-100 dark:bg-yellow-950 border-b border-yellow-300 dark:border-yellow-800 text-yellow-800 dark:text-yellow-300 text-xs">
          Diagnostic logging is <strong>Off</strong>. Set level to Errors or Informational to capture engine activity.
        </div>
      )}

      <div className="flex-1 overflow-auto font-mono text-xs p-2 space-y-0.5">
        {entries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500 dark:text-gray-600">
            {level === 'off' ? 'Logging is off — no entries captured.' : 'No diagnostic entries yet.'}
          </div>
        ) : (
          entries.map((entry, i) => (
            <div
              key={i}
              className={`flex gap-3 p-2 rounded hover:bg-gray-100 dark:hover:bg-gray-900 ${
                entry.level === 'ERROR' || entry.level === 'CRITICAL' ? 'border-l-2 border-red-700' : ''
              }`}
            >
              <div className="flex-shrink-0 text-gray-500 dark:text-gray-600 w-24 truncate">
                {new Date(entry.timestamp).toLocaleTimeString()}
              </div>
              <div className="flex-shrink-0 w-6">{levelBadge(entry.level)}</div>
              <div className="flex-shrink-0 text-indigo-600 dark:text-indigo-400 w-28 truncate">{entry.logger}</div>
              <div className="flex-1 min-w-0 text-gray-700 dark:text-gray-300 whitespace-pre-wrap break-all">
                {entry.message}
                {entry.exception && (
                  <pre className="mt-1 text-red-600 dark:text-red-400 text-xs whitespace-pre-wrap">{entry.exception}</pre>
                )}
              </div>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>

      <div className="px-6 py-2 border-t border-gray-200 dark:border-gray-800 bg-gray-100 dark:bg-gray-950 text-xs text-gray-500 dark:text-gray-600">
        {entries.length} entries &nbsp;·&nbsp; capturing: <span className="text-gray-600 dark:text-gray-400">{level}</span>
      </div>
    </div>
  )
}
