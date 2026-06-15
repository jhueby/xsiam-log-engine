import { useEffect, useState } from 'react'
import { getSources, startAll, stopAll, SourceInfo, getConfig, TransportConfig } from '../api/client'
import StatsBar from '../components/StatsBar'
import SourceGrid from '../components/SourceGrid'
import { Play, Square, RefreshCw, AlertTriangle, X, Settings } from 'lucide-react'
import { useToast } from '../hooks/useToast'
import { useNavigate } from 'react-router-dom'

export default function Dashboard() {
  const [sources, setSources] = useState<SourceInfo[]>([])
  const [config, setConfig] = useState<TransportConfig | null>(null)
  const [loading, setLoading] = useState(false)
  const [confirmStop, setConfirmStop] = useState(false)
  const [dismissedAutoDisabled, setDismissedAutoDisabled] = useState(false)
  const [dismissedFirstRun, setDismissedFirstRun] = useState(false)
  const { show } = useToast()
  const navigate = useNavigate()

  const load = () => {
    getSources().then(r => setSources(r.data)).catch(() => {})
  }

  useEffect(() => {
    load()
    getConfig().then(r => setConfig(r.data)).catch(() => {})
    const interval = setInterval(load, 3000)
    return () => clearInterval(interval)
  }, [])

  const handleStartAll = async () => {
    setLoading(true)
    try {
      await startAll()
      show('All sources started', 'success')
    } catch {
      show('Failed to start all sources', 'error')
    } finally {
      load()
      setLoading(false)
    }
  }

  const handleStopAll = async () => {
    if (!confirmStop) {
      setConfirmStop(true)
      setTimeout(() => setConfirmStop(false), 4000)
      return
    }
    setConfirmStop(false)
    setLoading(true)
    try {
      await stopAll()
      show('All sources stopped', 'success')
    } catch {
      show('Failed to stop all sources', 'error')
    } finally {
      load()
      setLoading(false)
    }
  }

  const autoDisabled = sources.filter(s => s.auto_disabled_reason)

  const isFirstRun = config && (
    !config.xsiam_api_key || config.xsiam_api_key === 'changeme' ||
    config.xsiam_url.includes('YOUR-TENANT')
  )

  return (
    <div className="flex flex-col h-full">
      <StatsBar />

      {/* First-run banner */}
      {isFirstRun && !dismissedFirstRun && (
        <div className="flex items-center gap-3 px-6 py-2.5 bg-amber-50 dark:bg-amber-900/20 border-b border-amber-300 dark:border-amber-700 text-amber-800 dark:text-amber-300 text-sm">
          <Settings size={14} className="flex-shrink-0" />
          <span>XSIAM credentials not configured — no events will be delivered.</span>
          <button
            onClick={() => navigate('/config')}
            className="ml-1 underline font-medium hover:no-underline"
          >
            Open Configuration
          </button>
          <button onClick={() => setDismissedFirstRun(true)} className="ml-auto">
            <X size={14} />
          </button>
        </div>
      )}

      {/* Auto-disabled banner */}
      {autoDisabled.length > 0 && !dismissedAutoDisabled && (
        <div className="flex items-start gap-3 px-6 py-2.5 bg-red-50 dark:bg-red-900/20 border-b border-red-300 dark:border-red-700 text-red-800 dark:text-red-300 text-sm">
          <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-medium">Circuit breaker tripped</span>
            {' — '}
            {autoDisabled.map(s => s.display_name).join(', ')} auto-disabled after consecutive errors.
            Re-enable from the Sources page.
          </div>
          <button onClick={() => setDismissedAutoDisabled(true)} className="ml-auto flex-shrink-0">
            <X size={14} />
          </button>
        </div>
      )}

      <div className="flex items-center justify-between px-6 py-3 border-b border-gray-200 dark:border-gray-800">
        <h1 className="font-semibold text-gray-900 dark:text-gray-200">Dashboard</h1>
        <div className="flex items-center gap-3">
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
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-white transition-colors disabled:opacity-50 ${
              confirmStop
                ? 'bg-red-600 hover:bg-red-500 ring-2 ring-red-400'
                : 'bg-red-800 hover:bg-red-700'
            }`}
          >
            <Square size={12} /> {confirmStop ? 'Confirm Stop' : 'Stop All'}
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-auto p-6">
        <SourceGrid sources={sources} onUpdate={load} />
      </div>
    </div>
  )
}
