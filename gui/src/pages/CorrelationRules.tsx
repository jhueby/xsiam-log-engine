import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, RefreshCw, Trash2 } from 'lucide-react'
import {
  CorrelationRuleInfo,
  deleteAllCorrelationRules,
  deleteCorrelationRule,
  getCorrelationRules,
} from '../api/client'
import { useToast } from '../hooks/useToast'

interface LoadError {
  status: number
  detail: string
}

export default function CorrelationRules() {
  const [rules, setRules] = useState<CorrelationRuleInfo[] | null>(null)
  const [error, setError] = useState<LoadError | null>(null)
  const [showAll, setShowAll] = useState(false)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [confirmRemoveAll, setConfirmRemoveAll] = useState(false)
  const { show } = useToast()

  const load = (all = showAll) => {
    setLoading(true)
    setError(null)
    getCorrelationRules(all)
      .then(r => setRules(r.data))
      .catch(err => {
        const detail = err?.response?.data?.detail
        setError({
          status: err?.response?.status ?? 0,
          detail: typeof detail === 'string' ? detail : 'Could not reach the engine',
        })
        setRules(null)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [showAll])

  const removeOne = async (rule: CorrelationRuleInfo) => {
    if (!rule.source_id) return
    setBusy(true)
    try {
      await deleteCorrelationRule(rule.source_id)
      show(`Rule '${rule.name}' removed`, 'info')
      load()
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      show(typeof detail === 'string' ? detail : 'Failed to remove rule', 'error')
    } finally {
      setBusy(false)
    }
  }

  const removeAll = async () => {
    setBusy(true)
    setConfirmRemoveAll(false)
    try {
      const r = await deleteAllCorrelationRules()
      show(r.data?.message ?? 'Engine-managed rules removed', 'success')
      load()
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      show(typeof detail === 'string' ? detail : 'Failed to remove rules', 'error')
    } finally {
      setBusy(false)
    }
  }

  const managedCount = rules?.filter(r => r.managed).length ?? 0

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="font-semibold text-gray-900 dark:text-gray-200">Correlation Rules</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Engine-managed rules on the XSIAM tenant (prefixed <code className="font-mono">[LogSim]</code>).
            Push rules from a source's card on the Sources page.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-400 cursor-pointer">
            <input type="checkbox" checked={showAll} onChange={e => setShowAll(e.target.checked)} />
            Show all tenant rules
          </label>
          <button
            onClick={() => load()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 disabled:opacity-50 rounded text-xs transition-colors"
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          {confirmRemoveAll ? (
            <span className="flex items-center gap-2 text-xs text-yellow-700 dark:text-yellow-300">
              Remove {managedCount} engine-managed rule(s)?
              <button
                onClick={removeAll}
                disabled={busy}
                className="px-2 py-1 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded text-white transition-colors"
              >
                Confirm
              </button>
              <button
                onClick={() => setConfirmRemoveAll(false)}
                className="px-2 py-1 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 rounded transition-colors"
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              onClick={() => setConfirmRemoveAll(true)}
              disabled={busy || managedCount === 0}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded text-xs text-white transition-colors"
            >
              <Trash2 size={12} />
              Remove all
            </button>
          )}
        </div>
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

      {!error && rules && rules.length === 0 && (
        <div className="text-sm text-gray-500">
          No {showAll ? '' : 'engine-managed '}correlation rules on the tenant.
        </div>
      )}

      {!error && rules && rules.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="text-left text-xs text-gray-500 border-b border-gray-200 dark:border-gray-800">
                <th className="py-2 pr-4 font-medium">Rule</th>
                <th className="py-2 pr-4 font-medium">Source</th>
                <th className="py-2 pr-4 font-medium">Dataset</th>
                <th className="py-2 pr-4 font-medium">Severity</th>
                <th className="py-2 pr-4 font-medium">Enabled</th>
                <th className="py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.name} className="border-b border-gray-100 dark:border-gray-800/50">
                  <td className="py-2 pr-4 font-mono text-xs" title={rule.xql_query}>{rule.name}</td>
                  <td className="py-2 pr-4 text-xs">{rule.source_id ?? <span className="text-gray-400">user-authored</span>}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{rule.dataset || '—'}</td>
                  <td className="py-2 pr-4 text-xs capitalize">{rule.severity || '—'}</td>
                  <td className="py-2 pr-4 text-xs">{rule.enabled ? 'yes' : 'no'}</td>
                  <td className="py-2 text-right">
                    {rule.managed && (
                      <button
                        onClick={() => removeOne(rule)}
                        disabled={busy}
                        title="Remove from tenant"
                        className="text-gray-400 hover:text-red-500 disabled:opacity-50 transition-colors"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
