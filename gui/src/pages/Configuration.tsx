import { useEffect, useState } from 'react'
import { KeyRound, AlertTriangle } from 'lucide-react'
import { getApiToken, getConfig, setApiToken, TransportConfig } from '../api/client'
import ConfigPanel from '../components/ConfigPanel'

const EMPTY_CONFIG: TransportConfig = {
  xsiam_url: '',
  xsiam_api_key: '',
  xsiam_dataset: 'xsiam_log_engine',
  brokervm_host: '',
  brokervm_syslog_port: 514,
  brokervm_syslog_proto: 'udp',
  brokervm_wec_port: 5985,
  brokervm_wec_use_tls: false,
  brokervm_wec_user: '',
  brokervm_wec_password: '',
  tls_ca_cert_path: '',
  tls_client_cert_path: '',
  tls_client_key_path: '',
}

export default function Configuration() {
  const [config, setConfig] = useState<TransportConfig | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)
  const [authError, setAuthError] = useState(false)
  const [token, setToken] = useState(getApiToken())

  const load = () => {
    setLoadFailed(false)
    setAuthError(false)
    getConfig()
      .then(r => { setConfig(r.data); setLoadFailed(false) })
      .catch(err => {
        if (err?.response?.status === 401) {
          setAuthError(true)
          setConfig(null)
        } else {
          setLoadFailed(true)
          setConfig(EMPTY_CONFIG)
        }
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

      {authError && (
        <div className="text-red-600 dark:text-red-400 text-sm">
          Authentication required — enter the engine API token above.
        </div>
      )}

      {loadFailed && (
        <div className="flex items-start gap-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded p-3 text-sm text-yellow-800 dark:text-yellow-300 max-w-2xl">
          <AlertTriangle size={16} className="flex-shrink-0 mt-0.5" />
          <span>
            Could not reach the engine or no <code className="font-mono text-xs">.env</code> file found.
            Fill in the fields below and click <strong>Save &amp; Reload</strong> — this will create the
            configuration file and apply settings immediately.
          </span>
        </div>
      )}

      {!config && !loadFailed && !authError && (
        <div className="text-gray-500 text-sm animate-pulse">Loading configuration...</div>
      )}

      {config && <ConfigPanel config={config} onSaved={load} />}
    </div>
  )
}
