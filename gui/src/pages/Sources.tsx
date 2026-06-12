import { useEffect, useState } from 'react'
import { getSources, SourceInfo } from '../api/client'
import SourceCard from '../components/SourceCard'
import ParsingRules from '../components/ParsingRules'

type Tab = 'sources' | 'parsing'

export default function Sources() {
  const [sources, setSources] = useState<SourceInfo[]>([])
  const [tab, setTab] = useState<Tab>('sources')

  const load = () => getSources().then(r => setSources(r.data)).catch(() => {})

  useEffect(() => {
    load()
    const interval = setInterval(load, 3000)
    return () => clearInterval(interval)
  }, [])

  const active = sources.filter(s => s.enabled)
  const inactive = sources.filter(s => !s.enabled)

  return (
    <div className="p-6 space-y-4">
      <h1 className="font-semibold text-gray-900 dark:text-gray-200">Sources ({sources.length})</h1>

      <div className="flex gap-0 border-b border-gray-200 dark:border-gray-800">
        {(['sources', 'parsing'] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t
                ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
            }`}
          >
            {t === 'sources' ? `Sources${active.length ? ` (${active.length} active)` : ''}` : 'Parsing Rules'}
          </button>
        ))}
      </div>

      {tab === 'sources' && (
        <div className="space-y-6">
          {active.length > 0 && (
            <section>
              <h2 className="text-xs text-green-600 dark:text-green-400 uppercase tracking-widest mb-3">Active ({active.length})</h2>
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
      )}

      {tab === 'parsing' && <ParsingRules sources={sources} />}
    </div>
  )
}
