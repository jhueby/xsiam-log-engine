import { useEffect, useState } from 'react'
import {
  CorrelationRuleInfo,
  HttpCompression,
  HttpLogType,
  SourceInfo,
  applyCorrelationRule,
  deleteCorrelationRule,
  patchSource,
  previewCorrelationRule,
  startSource,
  stopSource,
} from '../api/client'
import { ChevronDown, ChevronUp, Copy, Check, AlertTriangle } from 'lucide-react'
import { useToast } from '../hooks/useToast'
import { relativeTime, absoluteTime } from '../utils/time'

const BASE_RULE = '[INGEST:vendor="log", product="sim", target_dataset="log_sim_raw", no_hit=drop]'
function makeParsingRule(sourceId: string) {
  return `${BASE_RULE}filter simulated_log_source = "${sourceId}";`
}

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
  email: 'bg-violet-100 dark:bg-violet-900 text-violet-700 dark:text-violet-300',
  default: 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400',
}

// Log-scale helpers: range 0.1–1000 mapped to slider 0–1000
const EPS_MIN = 0.1
const EPS_MAX = 1000
const LOG_MIN = Math.log10(EPS_MIN)  // -1
const LOG_MAX = Math.log10(EPS_MAX)  //  3

function epsToSlider(eps: number): number {
  return ((Math.log10(Math.max(eps, EPS_MIN)) - LOG_MIN) / (LOG_MAX - LOG_MIN)) * 1000
}

function sliderToEps(v: number): number {
  const raw = Math.pow(10, (v / 1000) * (LOG_MAX - LOG_MIN) + LOG_MIN)
  // Round to 1 decimal for small values, whole numbers above 10
  return raw >= 10 ? Math.round(raw) : Math.round(raw * 10) / 10
}

interface Props {
  source: SourceInfo
  onUpdate: () => void
}

export default function SourceCard({ source, onUpdate }: Props) {
  const [loading, setLoading] = useState(false)
  const [eps, setEps] = useState(source.eps)
  const [showHttp, setShowHttp] = useState(false)
  const { show } = useToast()

  const toggle = async () => {
    setLoading(true)
    try {
      if (source.enabled) {
        await stopSource(source.id)
        show(`${source.display_name} stopped`, 'info')
      } else {
        await startSource(source.id)
        show(`${source.display_name} started`, 'success')
      }
      onUpdate()
    } catch {
      show(`Failed to ${source.enabled ? 'stop' : 'start'} ${source.display_name}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleEpsChange = async (val: number) => {
    setEps(val)
    try {
      await patchSource(source.id, { eps: val })
    } catch {
      show('Failed to update EPS', 'error')
    }
  }

  const handleTransportChange = async (transport: string) => {
    try {
      await patchSource(source.id, { transport })
      show(`${source.display_name} → ${transport}`, 'success')
      onUpdate()
    } catch {
      show('Failed to change transport', 'error')
    }
  }

  const tagColor = (tag: string) => TAG_COLORS[tag] || TAG_COLORS.default

  return (
    <div className={`rounded-lg border p-4 flex flex-col gap-3 transition-colors ${
      source.auto_disabled_reason
        ? 'border-red-400 dark:border-red-700 bg-red-50 dark:bg-red-900/10'
        : source.enabled
        ? 'border-indigo-700 bg-white dark:bg-gray-900'
        : 'border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900/50'
    }`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="font-semibold text-sm truncate">{source.display_name}</div>
          <div className="text-xs text-gray-500 mt-0.5 truncate">{source.id}</div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {source.auto_disabled_reason && (
            <span
              title={source.auto_disabled_reason}
              className="flex items-center gap-1 text-xs px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300"
            >
              <AlertTriangle size={10} />
              Tripped
            </span>
          )}
          <button
            onClick={toggle}
            disabled={loading}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${
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
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        {source.supported_transports.length > 1 ? (
          <select
            value={source.transport}
            onChange={e => handleTransportChange(e.target.value)}
            className={`text-xs px-1.5 py-0.5 rounded border-0 cursor-pointer focus:outline-none focus:ring-1 focus:ring-indigo-500 ${TRANSPORT_COLORS[source.transport] || 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400'}`}
          >
            {source.supported_transports.map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        ) : (
          <span className={`text-xs px-1.5 py-0.5 rounded ${TRANSPORT_COLORS[source.transport] || 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400'}`}>
            {source.transport}
          </span>
        )}
        {source.tags.slice(0, 3).map(tag => (
          <span key={tag} className={`text-xs px-1.5 py-0.5 rounded ${tagColor(tag)}`}>
            {tag}
          </span>
        ))}
      </div>

      {/* EPS slider — log scale */}
      <div className="space-y-1.5">
        <div className="flex justify-between items-center gap-2 text-xs">
          <span className="text-gray-500">EPS</span>
          <input
            type="number"
            min={0.1}
            max={1000}
            step={eps < 1 ? 0.1 : eps < 10 ? 0.5 : 1}
            value={eps}
            onChange={e => {
              const v = parseFloat(e.target.value)
              if (!isNaN(v) && v >= 0.1 && v <= 1000) setEps(v)
            }}
            onBlur={e => {
              const v = parseFloat(e.target.value)
              if (!isNaN(v) && v >= 0.1 && v <= 1000) handleEpsChange(v)
            }}
            className="w-16 text-right bg-transparent border-b border-gray-300 dark:border-gray-700 focus:outline-none focus:border-indigo-500 text-gray-700 dark:text-gray-300"
          />
        </div>
        <input
          type="range"
          min={0}
          max={1000}
          step={1}
          value={epsToSlider(eps)}
          onChange={e => setEps(sliderToEps(parseFloat(e.target.value)))}
          onMouseUp={e => handleEpsChange(sliderToEps(parseFloat((e.target as HTMLInputElement).value)))}
          onTouchEnd={e => handleEpsChange(sliderToEps(parseFloat((e.target as HTMLInputElement).value)))}
          className="w-full h-1 bg-gray-300 dark:bg-gray-700 rounded appearance-none cursor-pointer accent-indigo-500"
        />
        <div className="flex justify-between text-xs text-gray-400 dark:text-gray-600">
          <span>0.1</span><span>1</span><span>10</span><span>100</span><span>1k</span>
        </div>
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
        <div
          className="text-xs text-gray-500 dark:text-gray-600 truncate cursor-default"
          title={absoluteTime(source.last_event_ts)}
        >
          Last: {relativeTime(source.last_event_ts)}
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
  const { show } = useToast()

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
    } catch {
      show('Failed to save HTTP settings', 'error')
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

      <ParsingRuleBlock sourceId={source.id} />
      <CorrelationRuleBlock sourceId={source.id} />
    </div>
  )
}

function CorrelationRuleBlock({ sourceId }: { sourceId: string }) {
  const { show } = useToast()
  const [rule, setRule] = useState<CorrelationRuleInfo | null>(null)
  const [copied, setCopied] = useState(false)
  const [busy, setBusy] = useState(false)
  const [confirmOverwrite, setConfirmOverwrite] = useState(false)

  useEffect(() => {
    previewCorrelationRule(sourceId).then(r => setRule(r.data)).catch(() => {})
  }, [sourceId])

  const errDetail = (err: any, fallback: string) => {
    const d = err?.response?.data?.detail
    return typeof d === 'string' ? d : fallback
  }

  const push = async (overwrite = false) => {
    setBusy(true)
    try {
      const r = await applyCorrelationRule(sourceId, overwrite)
      show(r.data.message, 'success')
      setConfirmOverwrite(false)
    } catch (err: any) {
      if (err?.response?.status === 409) setConfirmOverwrite(true)
      else show(errDetail(err, 'Failed to push correlation rule'), 'error')
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    setBusy(true)
    setConfirmOverwrite(false)
    try {
      const r = await deleteCorrelationRule(sourceId)
      show(r.data?.message ?? 'Correlation rule removed', 'info')
    } catch (err: any) {
      show(errDetail(err, 'Failed to remove correlation rule'), 'error')
    } finally {
      setBusy(false)
    }
  }

  const copy = () => {
    if (!rule) return
    navigator.clipboard.writeText(rule.xql_query)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (!rule) return null

  return (
    <div className="border-t border-gray-100 dark:border-gray-800 pt-2 space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500">XSIAM correlation rule</span>
        <button
          onClick={copy}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
        >
          {copied ? <Check size={11} className="text-green-500" /> : <Copy size={11} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="text-xs font-mono text-gray-600 dark:text-gray-400 whitespace-pre-wrap break-all leading-relaxed bg-gray-50 dark:bg-gray-800/50 rounded p-2">
        {rule.xql_query}
      </pre>
      {confirmOverwrite ? (
        <div className="flex items-center gap-2 text-xs text-yellow-700 dark:text-yellow-300">
          <AlertTriangle size={11} className="flex-shrink-0" />
          <span>Rule exists on tenant — overwrite?</span>
          <button
            onClick={() => push(true)}
            disabled={busy}
            className="px-2 py-0.5 bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 rounded text-white transition-colors"
          >
            Overwrite
          </button>
          <button
            onClick={() => setConfirmOverwrite(false)}
            className="px-2 py-0.5 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 rounded transition-colors"
          >
            Cancel
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <button
            onClick={() => push(false)}
            disabled={busy}
            className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded text-xs text-white transition-colors"
          >
            {busy ? 'Working…' : 'Push to XSIAM'}
          </button>
          <button
            onClick={remove}
            disabled={busy}
            className="px-2.5 py-1 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 disabled:opacity-50 rounded text-xs transition-colors"
          >
            Remove
          </button>
        </div>
      )}
    </div>
  )
}

function ParsingRuleBlock({ sourceId }: { sourceId: string }) {
  const [copied, setCopied] = useState(false)
  const rule = makeParsingRule(sourceId)
  const copy = () => {
    navigator.clipboard.writeText(rule)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div className="border-t border-gray-100 dark:border-gray-800 pt-2 space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500">XSIAM parsing rule</span>
        <button
          onClick={copy}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
        >
          {copied ? <Check size={11} className="text-green-500" /> : <Copy size={11} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="text-xs font-mono text-gray-600 dark:text-gray-400 whitespace-pre-wrap break-all leading-relaxed bg-gray-50 dark:bg-gray-800/50 rounded p-2">
        {rule}
      </pre>
    </div>
  )
}
