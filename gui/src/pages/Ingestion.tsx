import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, CheckCircle, RefreshCw, XCircle } from 'lucide-react'
import { SourceIngestionInfo, getIngestionStatus } from '../api/client'
import { relativeTime, absoluteTime } from '../utils/time'

interface LoadError {
  status: number
  detail: string
}

export default function Ingestion() {
  const [rows, setRows] = useState<SourceIngestionInfo[] | null>(null)
  const [error, setError] = useState<LoadError | null>(null)
  const [loading, setLoading] = useState(false)

  const load = () => {
    setLoading(true)
    setError(null)
    getIngestionStatus()
      .then(r => setRows(r.data))
      .catch(err => {
        const detail = err?.response?.data?.detail
        setError({
          status: err?.response?.status ?? 0,
          detail: typeof detail === 'string' ? detail : 'Could not reach the engine',
        })
        setRows(null)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const missing = rows?.filter(r => !r.exists).length ?? 0

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="font-semibold text-gray-900 dark:text-gray-200">Ingestion</h1>
          <p className="text-xs text-gray-500 mt-0.5 max-w-3xl leading-relaxed">
            What the tenant actually holds, per source. A transport reporting success only means
            XSIAM accepted the request — it says nothing about whether the event was parsed and
            stored. If a dataset is missing, events for that source are landing nowhere.
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 disabled:opacity-50 rounded text-xs transition-colors"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="flex items-start gap-2 bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-700 rounded p-3 text-sm text-red-800 dark:text-red-300 max-w-3xl">
          <AlertTriangle size={16} className="flex-shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div>{error.detail}</div>
            <div className="text-xs">
              {error.status === 400
                ? <>The XSIAM Public API is not configured yet — set it up under <Link to="/config" className="underline">Configuration</Link>.</>
                : <>Use <strong>Test connection</strong> under <Link to="/config" className="underline">Configuration</Link> to pinpoint the problem.</>}
            </div>
          </div>
        </div>
      )}

      {!error && missing > 0 && (
        <div className="flex items-start gap-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded p-3 text-sm text-yellow-800 dark:text-yellow-300 max-w-3xl">
          <AlertTriangle size={16} className="flex-shrink-0 mt-0.5" />
          <div>
            <strong>{missing}</strong> source{missing === 1 ? '' : 's'} target a dataset that doesn't
            exist on the tenant. Add a parsing rule routing <code className="font-mono">simulated_log_source</code>{' '}
            to it (copy the ready-made rule from the source's card), or those events are being discarded.
          </div>
        </div>
      )}

      {!error && rows && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="text-left text-xs text-gray-500 border-b border-gray-200 dark:border-gray-800">
                <th className="py-2 pr-4 font-medium">Source</th>
                <th className="py-2 pr-4 font-medium">Target dataset</th>
                <th className="py-2 pr-4 font-medium">On tenant</th>
                <th className="py-2 pr-4 font-medium text-right">Events (tenant)</th>
                <th className="py-2 pr-4 font-medium text-right">Sent (engine)</th>
                <th className="py-2 font-medium">Dataset updated</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.source_id} className="border-b border-gray-100 dark:border-gray-800/50">
                  <td className="py-2 pr-4">{r.display_name}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{r.dataset}</td>
                  <td className="py-2 pr-4">
                    {r.exists
                      ? <span className="flex items-center gap-1 text-xs text-green-600 dark:text-green-400"><CheckCircle size={12} /> yes</span>
                      : <span className="flex items-center gap-1 text-xs text-red-600 dark:text-red-400"><XCircle size={12} /> missing</span>}
                  </td>
                  <td className="py-2 pr-4 text-right font-mono text-xs">
                    {r.exists ? r.total_events.toLocaleString() : '—'}
                  </td>
                  <td className="py-2 pr-4 text-right font-mono text-xs text-gray-500">
                    {r.sent_by_engine.toLocaleString()}
                  </td>
                  <td
                    className="py-2 text-xs text-gray-500"
                    title={r.last_updated ? absoluteTime(r.last_updated) : undefined}
                  >
                    {r.last_updated ? relativeTime(r.last_updated) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-xs text-gray-500 mt-3 max-w-3xl leading-relaxed">
            <strong>Reading this:</strong> the tenant reports "dataset updated" at day granularity, so it
            can't confirm a batch sent moments ago — watch the tenant event count move instead, allowing
            for ingestion lag. "Sent (engine)" counts what this engine believes it delivered since it
            started, so it won't match a tenant total that predates this run.
          </p>
        </div>
      )}
    </div>
  )
}
