import { useEffect, useState } from 'react'
import { getStats, sseUrl, StatsResponse } from '../api/client'
import { Activity, Send, AlertCircle, Layers } from 'lucide-react'

export default function StatsBar() {
  const [stats, setStats] = useState<StatsResponse | null>(null)

  useEffect(() => {
    const es = new EventSource(sseUrl('/api/stats/stream'))
    es.onmessage = (e) => {
      try { setStats(JSON.parse(e.data)) } catch {}
    }
    getStats().then(r => setStats(r.data)).catch(() => {})
    return () => es.close()
  }, [])

  if (!stats) return <div className="h-16 bg-gray-900 border-b border-gray-800 animate-pulse" />

  const cards = [
    { label: 'EPS', value: stats.eps_actual.toFixed(1), icon: Activity, color: 'text-green-400' },
    { label: 'Total Sent', value: stats.total_sent.toLocaleString(), icon: Send, color: 'text-blue-400' },
    { label: 'Errors', value: stats.total_errors.toLocaleString(), icon: AlertCircle, color: stats.total_errors > 0 ? 'text-red-400' : 'text-gray-500' },
    { label: 'Active Sources', value: stats.active_sources.toString(), icon: Layers, color: 'text-indigo-400' },
    { label: 'HTTP Sent', value: (stats.per_transport.http || 0).toLocaleString(), icon: null, color: 'text-purple-400' },
    { label: 'Syslog Sent', value: (stats.per_transport.syslog || 0).toLocaleString(), icon: null, color: 'text-yellow-400' },
    { label: 'WEC Sent', value: (stats.per_transport.wec || 0).toLocaleString(), icon: null, color: 'text-cyan-400' },
  ]

  return (
    <div className="flex items-center gap-6 px-6 py-3 bg-gray-900 border-b border-gray-800 overflow-x-auto">
      {cards.map(({ label, value, icon: Icon, color }) => (
        <div key={label} className="flex items-center gap-2 whitespace-nowrap">
          {Icon && <Icon size={14} className={color} />}
          <span className="text-xs text-gray-500">{label}</span>
          <span className={`text-sm font-bold ${color}`}>{value}</span>
        </div>
      ))}
    </div>
  )
}
