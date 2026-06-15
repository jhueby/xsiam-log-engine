import { useEffect, useState } from 'react'
import { getSources, SourceInfo } from '../api/client'
import SourceCard from '../components/SourceCard'
import { Search, X } from 'lucide-react'

const ALL_TAGS = ['windows', 'linux', 'network', 'edr', 'cloud', 'identity', 'proxy', 'email']

const TAG_COLORS: Record<string, string> = {
  windows: 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-700',
  linux: 'bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300 border-orange-300 dark:border-orange-700',
  network: 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 border-green-300 dark:border-green-700',
  edr: 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 border-red-300 dark:border-red-700',
  cloud: 'bg-sky-100 dark:bg-sky-900 text-sky-700 dark:text-sky-300 border-sky-300 dark:border-sky-700',
  identity: 'bg-pink-100 dark:bg-pink-900 text-pink-700 dark:text-pink-300 border-pink-300 dark:border-pink-700',
  proxy: 'bg-teal-100 dark:bg-teal-900 text-teal-700 dark:text-teal-300 border-teal-300 dark:border-teal-700',
  email: 'bg-violet-100 dark:bg-violet-900 text-violet-700 dark:text-violet-300 border-violet-300 dark:border-violet-700',
  default: 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-600',
}

export default function Sources() {
  const [sources, setSources] = useState<SourceInfo[]>([])
  const [search, setSearch] = useState('')
  const [activeTags, setActiveTags] = useState<Set<string>>(new Set())

  const load = () => getSources().then(r => setSources(r.data)).catch(() => {})

  useEffect(() => {
    load()
    const interval = setInterval(load, 3000)
    return () => clearInterval(interval)
  }, [])

  const toggleTag = (tag: string) => {
    setActiveTags(prev => {
      const next = new Set(prev)
      next.has(tag) ? next.delete(tag) : next.add(tag)
      return next
    })
  }

  const filtered = sources.filter(s => {
    const q = search.toLowerCase()
    const matchSearch = !q || s.display_name.toLowerCase().includes(q) || s.id.includes(q)
    const matchTags = activeTags.size === 0 || [...activeTags].some(t => s.tags.includes(t))
    return matchSearch && matchTags
  })

  const active = filtered.filter(s => s.enabled)
  const inactive = filtered.filter(s => !s.enabled)
  const hasFilter = search.length > 0 || activeTags.size > 0

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <h1 className="font-semibold text-gray-900 dark:text-gray-200">Sources ({sources.length})</h1>

        {/* Search box */}
        <div className="relative flex-1 min-w-48 max-w-64">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter sources…"
            className="w-full pl-7 pr-7 py-1.5 text-xs bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded focus:outline-none focus:border-indigo-500"
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-700 dark:hover:text-gray-300">
              <X size={11} />
            </button>
          )}
        </div>

        {/* Tag chips */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {ALL_TAGS.map(tag => {
            const colors = TAG_COLORS[tag] || TAG_COLORS.default
            const active = activeTags.has(tag)
            return (
              <button
                key={tag}
                onClick={() => toggleTag(tag)}
                className={`text-xs px-2 py-0.5 rounded border transition-opacity ${colors} ${active ? 'opacity-100 ring-1 ring-current' : 'opacity-50 hover:opacity-80'}`}
              >
                {tag}
              </button>
            )
          })}
          {activeTags.size > 0 && (
            <button onClick={() => setActiveTags(new Set())} className="text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 ml-1">
              <X size={11} />
            </button>
          )}
        </div>
      </div>

      {hasFilter && filtered.length === 0 && (
        <div className="text-sm text-gray-500 dark:text-gray-400">No sources match the current filter.</div>
      )}

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
  )
}
