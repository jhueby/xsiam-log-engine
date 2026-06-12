import { useEffect, useState } from 'react'
import { KeyRound } from 'lucide-react'
import { getApiToken, getConfig, setApiToken, TransportConfig } from '../api/client'
import ConfigPanel from '../components/ConfigPanel'

export default function Configuration() {
  const [config, setConfig] = useState<TransportConfig | null>(null)
  const [error, setError] = useState('')
  const [token, setToken] = useState(getApiToken())

  const load = () => {
    getConfig()
      .then(r => { setConfig(r.data); setError('') })
      .catch(err => {
        setError(err?.response?.status === 401
          ? 'Authentication required — enter the engine API token below.'
          : 'Failed to load configuration')
      })
  }

  useEffect(() => { load() }, [])

  const applyToken = () => {
    setApiToken(token.trim())
    load()
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="font-semibold text-gray-900 dark:text-gray-200">Configuration</h1>

      {/* Stored in the browser only; sent as X-Engine-Token on every request */}
      <section className="max-w-xl">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 border-b border-gray-200 dark:border-gray-800 pb-2 flex items-center gap-2">
          <KeyRound size={14} /> API Access
        </h3>
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs text-gray-500 mb-1">Engine API Token</label>
            <input
              type="password"
              value={token}
              onChange={e => setToken(e.target.value)}
              placeholder="Leave blank if the engine has no token configured"
              className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
            />
          </div>
          <button
            onClick={applyToken}
            className="px-4 py-2 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 rounded text-sm transition-colors"
          >
            Apply
          </button>
        </div>
      </section>

      {error && <div className="text-red-600 dark:text-red-400 text-sm">{error}</div>}
      {!config && !error && (
        <div className="text-gray-500 text-sm animate-pulse">Loading configuration...</div>
      )}
      {config && <ConfigPanel config={config} onSaved={load} />}
    </div>
  )
}
