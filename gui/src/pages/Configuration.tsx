import { useEffect, useState } from 'react'
import { getConfig, TransportConfig } from '../api/client'
import ConfigPanel from '../components/ConfigPanel'

export default function Configuration() {
  const [config, setConfig] = useState<TransportConfig | null>(null)
  const [error, setError] = useState('')

  const load = () => {
    getConfig()
      .then(r => setConfig(r.data))
      .catch(() => setError('Failed to load configuration'))
  }

  useEffect(() => { load() }, [])

  if (error) return <div className="p-6 text-red-400 text-sm">{error}</div>
  if (!config) return <div className="p-6 text-gray-500 text-sm animate-pulse">Loading configuration...</div>

  return (
    <div className="p-6">
      <h1 className="font-semibold text-gray-200 mb-6">Configuration</h1>
      <ConfigPanel config={config} onSaved={load} />
    </div>
  )
}
