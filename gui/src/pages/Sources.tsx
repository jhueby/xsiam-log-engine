import { useEffect, useState } from 'react'
import { getSources, SourceInfo } from '../api/client'
import SourceCard from '../components/SourceCard'

export default function Sources() {
  const [sources, setSources] = useState<SourceInfo[]>([])

  const load = () => getSources().then(r => setSources(r.data)).catch(() => {})

  useEffect(() => {
    load()
    const interval = setInterval(load, 3000)
    return () => clearInterval(interval)
  }, [])

  const active = sources.filter(s => s.enabled)
  const inactive = sources.filter(s => !s.enabled)

  return (
    <div className="p-6 space-y-6">
      <h1 className="font-semibold text-gray-200">Sources ({sources.length})</h1>

      {active.length > 0 && (
        <section>
          <h2 className="text-xs text-green-400 uppercase tracking-widest mb-3">Active ({active.length})</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {active.map(s => <SourceCard key={s.id} source={s} onUpdate={load} />)}
          </div>
        </section>
      )}

      {inactive.length > 0 && (
        <section>
          <h2 className="text-xs text-gray-500 uppercase tracking-widest mb-3">Inactive ({inactive.length})</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {inactive.map(s => <SourceCard key={s.id} source={s} onUpdate={load} />)}
          </div>
        </section>
      )}
    </div>
  )
}
