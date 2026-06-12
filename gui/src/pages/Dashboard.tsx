import { useEffect, useState } from 'react'
import { getSources, startAll, stopAll, SourceInfo, getHealth, HealthResponse } from '../api/client'
import StatsBar from '../components/StatsBar'
import SourceGrid from '../components/SourceGrid'
import { Play, Square, RefreshCw } from 'lucide-react'

export default function Dashboard() {
  const [sources, setSources] = useState<SourceInfo[]>([])
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [loading, setLoading] = useState(false)

  const load = () => {
    getSources().then(r => setSources(r.data)).catch(() => {})
    getHealth().then(r => setHealth(r.data)).catch(() => {})
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 3000)
    return () => clearInterval(interval)
  }, [])

  const handleStartAll = async () => {
    setLoading(true)
    await startAll().catch(() => {})
    load()
    setLoading(false)
  }

  const handleStopAll = async () => {
    setLoading(true)
    await stopAll().catch(() => {})
    load()
    setLoading(false)
  }

  const healthDot = (ok: boolean) => (
    <span className={`inline-block w-2 h-2 rounded-full ${ok ? 'bg-green-400' : 'bg-red-400'}`} />
  )

  return (
    <div className="flex flex-col h-full">
      <StatsBar />
      <div className="flex items-center justify-between px-6 py-3 border-b border-gray-200 dark:border-gray-800">
        <h1 className="font-semibold text-gray-900 dark:text-gray-200">Dashboard</h1>
        <div className="flex items-center gap-4">
          {health && (
            <div className="flex items-center gap-3 text-xs text-gray-500">
              {Object.entries(health.transports).map(([name, ok]) => (
                <div key={name} className="flex items-center gap-1">
                  {healthDot(ok)}
                  <span className="capitalize">{name}</span>
                </div>
              ))}
            </div>
          )}
          <button
            onClick={load}
            className="p-1.5 hover:bg-gray-200 dark:hover:bg-gray-800 rounded text-gray-600 dark:text-gray-400"
            title="Refresh"
          >
            <RefreshCw size={14} />
          </button>
          <button
            onClick={handleStartAll}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700 hover:bg-green-600 disabled:opacity-50 rounded text-xs text-white transition-colors"
          >
            <Play size={12} /> Start All
          </button>
          <button
            onClick={handleStopAll}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-800 hover:bg-red-700 disabled:opacity-50 rounded text-xs text-white transition-colors"
          >
            <Square size={12} /> Stop All
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-auto p-6">
        <SourceGrid sources={sources} onUpdate={load} />
      </div>
    </div>
  )
}
