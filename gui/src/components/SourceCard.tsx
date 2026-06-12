import { useState } from 'react'
import { SourceInfo, startSource, stopSource, patchSource } from '../api/client'

const TRANSPORT_COLORS: Record<string, string> = {
  http: 'bg-purple-900 text-purple-300',
  syslog: 'bg-yellow-900 text-yellow-300',
  wec: 'bg-cyan-900 text-cyan-300',
}

const TAG_COLORS: Record<string, string> = {
  windows: 'bg-blue-900 text-blue-300',
  linux: 'bg-orange-900 text-orange-300',
  network: 'bg-green-900 text-green-300',
  edr: 'bg-red-900 text-red-300',
  cloud: 'bg-sky-900 text-sky-300',
  identity: 'bg-pink-900 text-pink-300',
  proxy: 'bg-teal-900 text-teal-300',
  default: 'bg-gray-800 text-gray-400',
}

interface Props {
  source: SourceInfo
  onUpdate: () => void
}

export default function SourceCard({ source, onUpdate }: Props) {
  const [loading, setLoading] = useState(false)
  const [eps, setEps] = useState(source.eps)

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
      source.enabled ? 'border-indigo-700 bg-gray-900' : 'border-gray-800 bg-gray-900/50'
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
            source.enabled ? 'bg-indigo-600' : 'bg-gray-700'
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
        <span className={`text-xs px-1.5 py-0.5 rounded ${TRANSPORT_COLORS[source.transport] || 'bg-gray-800 text-gray-400'}`}>
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
          <span className="text-gray-300">{eps.toFixed(1)}</span>
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
          className="w-full h-1 bg-gray-700 rounded appearance-none cursor-pointer accent-indigo-500"
        />
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <div className="text-gray-500">Sent</div>
          <div className="text-green-400 font-mono">{source.total_sent.toLocaleString()}</div>
        </div>
        <div>
          <div className="text-gray-500">Errors</div>
          <div className={`font-mono ${source.total_errors > 0 ? 'text-red-400' : 'text-gray-600'}`}>
            {source.total_errors.toLocaleString()}
          </div>
        </div>
      </div>

      {source.last_event_ts && (
        <div className="text-xs text-gray-600 truncate">
          Last: {new Date(source.last_event_ts).toLocaleTimeString()}
        </div>
      )}
    </div>
  )
}
