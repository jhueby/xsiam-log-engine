import { useState } from 'react'
import { getStats, StatsResponse } from '../api/client'
import { Activity, Send, AlertCircle, Layers, WifiOff } from 'lucide-react'
import { useSSE } from '../hooks/useSSE'

export default function StatsBar() {
  const [stats, setStats] = useState<StatsResponse | null>(null)

  const connected = useSSE('/api/stats/stream', (data) => {
    try { setStats(JSON.parse(data)) } catch {}
  })

  // Fallback poll on first load and when SSE reconnects
  useState(() => { getStats().then(r => setStats(r.data)).catch(() => {}) })

  if (!stats) return <div className="h-14 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 animate-pulse" />

  const cards = [
    { label: 'EPS', value: stats.eps_actual.toFixed(1), icon: Activity, color: 'text-green-600 dark:text-green-400' },
    { label: 'Total Sent', value: stats.total_sent.toLocaleString(), icon: Send, color: 'text-blue-600 dark:text-blue-400' },
    { label: 'Errors', value: stats.total_errors.toLocaleString(), icon: AlertCircle, color: stats.total_errors > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-500' },
    { label: 'Active', value: stats.active_sources.toString(), icon: Layers, color: 'text-indigo-600 dark:text-indigo-400' },
    { label: 'HTTP', value: (stats.per_transport.http || 0).toLocaleString(), icon: null, color: 'text-purple-600 dark:text-purple-400' },
    { label: 'Syslog', value: (stats.per_transport.syslog || 0).toLocaleString(), icon: null, color: 'text-yellow-600 dark:text-yellow-400' },
    { label: 'WEC', value: (stats.per_transport.wec || 0).toLocaleString(), icon: null, color: 'text-cyan-600 dark:text-cyan-400' },
  ]

  return (
    <div className="flex items-center gap-6 px-6 py-3 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 overflow-x-auto">
      {cards.map(({ label, value, icon: Icon, color }) => (
        <div key={label} className="flex items-center gap-2 whitespace-nowrap">
          {Icon && <Icon size={14} className={color} />}
          <span className="text-xs text-gray-500">{label}</span>
          <span className={`text-sm font-bold ${color}`}>{value}</span>
        </div>
      ))}
      {!connected && (
        <div className="ml-auto flex items-center gap-1.5 text-xs text-yellow-600 dark:text-yellow-400 whitespace-nowrap">
          <WifiOff size={12} />
          Reconnecting…
        </div>
      )}
    </div>
  )
}
