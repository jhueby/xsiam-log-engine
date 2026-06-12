import { useState } from 'react'
import { HttpCompression, HttpLogType, SourceInfo, patchSource, startSource, stopSource } from '../api/client'
import { ChevronDown, ChevronUp } from 'lucide-react'

const TRANSPORT_COLORS: Record<string, string> = {
  http: 'bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300',
  syslog: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-300',
  wec: 'bg-cyan-100 dark:bg-cyan-900 text-cyan-700 dark:text-cyan-300',
}

const TAG_COLORS: Record<string, string> = {
  windows: 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300',
  linux: 'bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300',
  network: 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300',
  edr: 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300',
  cloud: 'bg-sky-100 dark:bg-sky-900 text-sky-700 dark:text-sky-300',
  identity: 'bg-pink-100 dark:bg-pink-900 text-pink-700 dark:text-pink-300',
  proxy: 'bg-teal-100 dark:bg-teal-900 text-teal-700 dark:text-teal-300',
  default: 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400',
}

interface Props {
  source: SourceInfo
  onUpdate: () => void
}

export default function SourceCard({ source, onUpdate }: Props) {
  const [loading, setLoading] = useState(false)
  const [eps, setEps] = useState(source.eps)
  const [showHttp, setShowHttp] = useState(false)

  const toggle = async () => {
    setLoading(true)
    try {
      if (source.enabled) {
        await stopSource(source.id)
      } else {
        await startSource(source.id)
      }
      onUpdate()
    } finally {
      setLoading(false)
    }
  }

  const handleEpsChange = async (val: number) => {
    setEps(val)
    await patchSource(source.id, { eps: val })
  }

  const tagColor = (tag: string) => TAG_COLORS[tag] || TAG_COLORS.default

  return (
    <div className={`rounded-lg border p-4 flex flex-col gap-3 transition-colors ${
      source.enabled ? 'border-indigo-700 bg-white dark:bg-gray-900' : 'border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900/50'
    }`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="font-semibold text-sm truncate">{source.display_name}</div>
          <div className="text-xs text-gray-500 mt-0.5 truncate">{source.id}</div>
        </div>
        <button
          onClick={toggle}
          disabled={loading}
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none flex-shrink-0 ${
            source.enabled ? 'bg-indigo-600' : 'bg-gray-300 dark:bg-gray-700'
          } ${loading ? 'opacity-50' : ''}`}
          aria-label={source.enabled ? 'Disable source' : 'Enable source'}
        >
          <span
            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
              source.enabled ? 'translate-x-4' : 'translate-x-1'
            }`}
          />
        </button>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-xs px-1.5 py-0.5 rounded ${TRANSPORT_COLORS[source.transport] || 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400'}`}>
          {source.transport}
        </span>
        {source.tags.slice(0, 3).map(tag => (
          <span key={tag} className={`text-xs px-1.5 py-0.5 rounded ${tagColor(tag)}`}>
            {tag}
          </span>
        ))}
      </div>

      <div className="space-y-1">
        <div className="flex justify-between text-xs">
          <span className="text-gray-500">EPS</span>
          <span className="text-gray-700 dark:text-gray-300">{eps.toFixed(1)}</span>
        </div>
        <input
          type="range"
          min={0.1}
          max={1000}
          step={0.1}
          value={eps}
          onChange={e => setEps(parseFloat(e.target.value))}
          onMouseUp={e => handleEpsChange(parseFloat((e.target as HTMLInputElement).value))}
          onTouchEnd={e => handleEpsChange(parseFloat((e.target as HTMLInputElement).value))}
          className="w-full h-1 bg-gray-300 dark:bg-gray-700 rounded appearance-none cursor-pointer accent-indigo-500"
        />
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <div className="text-gray-500">Sent</div>
          <div className="text-green-600 dark:text-green-400 font-mono">{source.total_sent.toLocaleString()}</div>
        </div>
        <div>
          <div className="text-gray-500">Errors</div>
          <div className={`font-mono ${source.total_errors > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-500 dark:text-gray-600'}`}>
            {source.total_errors.toLocaleString()}
          </div>
        </div>
      </div>

      {source.last_event_ts && (
        <div className="text-xs text-gray-500 dark:text-gray-600 truncate">
          Last: {new Date(source.last_event_ts).toLocaleTimeString()}
        </div>
      )}

      {source.transport === 'http' && (
        <div className="border-t border-gray-100 dark:border-gray-800 pt-2">
          <button
            onClick={() => setShowHttp(v => !v)}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 w-full"
          >
            {showHttp ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            HTTP settings
          </button>
          {showHttp && (
            <HttpSettings source={source} onUpdate={onUpdate} />
          )}
        </div>
      )}
    </div>
  )
}

function HttpSettings({ source, onUpdate }: { source: SourceInfo; onUpdate: () => void }) {
  const [logType, setLogType] = useState<HttpLogType>(source.http_log_type)
  const [compression, setCompression] = useState<HttpCompression>(source.http_compression)
  const [apiKey, setApiKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const apply = async () => {
    setSaving(true)
    setSaved(false)
    try {
      const patch: Record<string, string> = { http_log_type: logType, http_compression: compression }
      if (apiKey) patch.http_api_key = apiKey
      await patchSource(source.id, patch as any)
      setSaved(true)
      setApiKey('')
      onUpdate()
      setTimeout(() => setSaved(false), 2500)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="mt-2 space-y-2">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-500 mb-1">Log type</label>
          <select
            value={logType}
            onChange={e => setLogType(e.target.value as HttpLogType)}
            className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-indigo-500"
          >
            <option value="raw">Raw</option>
            <option value="json">JSON</option>
            <option value="cef">CEF</option>
            <option value="leef">LEEF</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">Compression</label>
          <select
            value={compression}
            onChange={e => setCompression(e.target.value as HttpCompression)}
            className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-indigo-500"
          >
            <option value="none">None</option>
            <option value="gzip">Gzip</option>
          </select>
        </div>
      </div>
      <div>
        <label className="block text-xs text-gray-500 mb-1">
          API key {source.http_api_key === '***' ? <span className="text-indigo-400">(custom set)</span> : <span className="text-gray-400">(using global)</span>}
        </label>
        <input
          type="password"
          value={apiKey}
          onChange={e => setApiKey(e.target.value)}
          placeholder="Paste to override global key"
          className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-indigo-500"
        />
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={apply}
          disabled={saving}
          className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded text-xs text-white transition-colors"
        >
          {saving ? 'Applying…' : 'Apply'}
        </button>
        {saved && <span className="text-xs text-green-600 dark:text-green-400">Saved</span>}
      </div>
    </div>
  )
}
