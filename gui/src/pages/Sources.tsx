import { useEffect, useRef, useState } from 'react'
import { getSources, startSource, stopSource, SourceInfo } from '../api/client'
import SourceCard from '../components/SourceCard'
import { Search, X, Play, Square, ArrowDownUp } from 'lucide-react'
import { useToast } from '../hooks/useToast'

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

type SortKey = 'name' | 'eps' | 'sent' | 'errors'

const SORTS: { key: SortKey; label: string }[] = [
  { key: 'name', label: 'Name' },
  { key: 'eps', label: 'EPS' },
  { key: 'sent', label: 'Sent' },
  { key: 'errors', label: 'Errors' },
]

function compare(a: SourceInfo, b: SourceInfo, key: SortKey): number {
  switch (key) {
    case 'name': return a.display_name.localeCompare(b.display_name)
    case 'eps': return a.eps - b.eps
    case 'sent': return a.total_sent - b.total_sent
    case 'errors': return a.total_errors - b.total_errors
  }
}

export default function Sources() {
  const [sources, setSources] = useState<SourceInfo[]>([])
  const [search, setSearch] = useState('')
  const [activeTags, setActiveTags] = useState<Set<string>>(new Set())
  const [sortKey, setSortKey] = useState<SortKey>('name')
  const [sortDesc, setSortDesc] = useState(false)
  const [busy, setBusy] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)
  const { show } = useToast()

  const load = () => getSources().then(r => setSources(r.data)).catch(() => {})

  useEffect(() => {
    load()
    const interval = setInterval(load, 3000)
    return () => clearInterval(interval)
  }, [])

  // Allow the global "/" hotkey to focus the filter box.
  useEffect(() => {
    const focus = () => { searchRef.current?.focus(); searchRef.current?.select() }
    window.addEventListener('focus-source-search', focus)
    return () => window.removeEventListener('focus-source-search', focus)
  }, [])

  const toggleTag = (tag: string) => {
    setActiveTags(prev => {
      const next = new Set(prev)
      next.has(tag) ? next.delete(tag) : next.add(tag)
      return next
    })
  }

  const filtered = sources
    .filter(s => {
      const q = search.toLowerCase()
      const matchSearch = !q || s.display_name.toLowerCase().includes(q) || s.id.includes(q)
      const matchTags = activeTags.size === 0 || [...activeTags].some(t => s.tags.includes(t))
      return matchSearch && matchTags
    })
    .sort((a, b) => (sortDesc ? -1 : 1) * compare(a, b, sortKey))

  const active = filtered.filter(s => s.enabled)
  const inactive = filtered.filter(s => !s.enabled)
  const hasFilter = search.length > 0 || activeTags.size > 0

  const bulk = async (action: 'start' | 'stop') => {
    const targets = action === 'start' ? inactive : active
    if (targets.length === 0) return
    setBusy(true)
    const fn = action === 'start' ? startSource : stopSource
    const results = await Promise.allSettled(targets.map(s => fn(s.id)))
    const failed = results.filter(r => r.status === 'rejected').length
    const ok = targets.length - failed
    if (failed === 0) {
      show(`${action === 'start' ? 'Started' : 'Stopped'} ${ok} source${ok !== 1 ? 's' : ''}`, 'success')
    } else {
      show(`${action === 'start' ? 'Started' : 'Stopped'} ${ok}/${targets.length} — ${failed} failed`, 'error')
    }
    await load()
    setBusy(false)
  }

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <h1 className="font-semibold text-gray-900 dark:text-gray-200">Sources ({sources.length})</h1>

        {/* Search box */}
        <div className="relative flex-1 min-w-48 max-w-64">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            ref={searchRef}
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter sources…  ( / )"
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
            const on = activeTags.has(tag)
            return (
              <button
                key={tag}
                onClick={() => toggleTag(tag)}
                className={`text-xs px-2 py-0.5 rounded border transition-opacity ${colors} ${on ? 'opacity-100 ring-1 ring-current' : 'opacity-50 hover:opacity-80'}`}
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

        {/* Sort */}
        <div className="flex items-center gap-1 ml-auto">
          <select
            value={sortKey}
            onChange={e => setSortKey(e.target.value as SortKey)}
            className="text-xs bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded px-2 py-1.5 focus:outline-none focus:border-indigo-500"
            title="Sort by"
          >
            {SORTS.map(s => <option key={s.key} value={s.key}>Sort: {s.label}</option>)}
          </select>
          <button
            onClick={() => setSortDesc(v => !v)}
            title={sortDesc ? 'Descending' : 'Ascending'}
            className="p-1.5 text-gray-500 hover:text-gray-800 dark:hover:text-gray-200 border border-gray-300 dark:border-gray-700 rounded"
          >
            <ArrowDownUp size={13} />
          </button>
        </div>
      </div>

      {/* Bulk action bar — acts on the current filtered set */}
      <div className="flex items-center gap-3 text-xs">
        <span className="text-gray-500 dark:text-gray-400">
          {hasFilter ? `${filtered.length} matching` : `${sources.length} sources`}
          {' · '}{active.length} active
        </span>
        <button
          onClick={() => bulk('start')}
          disabled={busy || inactive.length === 0}
          className="flex items-center gap-1.5 px-2.5 py-1 bg-green-700 hover:bg-green-600 disabled:opacity-40 disabled:cursor-not-allowed rounded text-white transition-colors"
        >
          <Play size={11} /> Start {inactive.length}
        </button>
        <button
          onClick={() => bulk('stop')}
          disabled={busy || active.length === 0}
          className="flex items-center gap-1.5 px-2.5 py-1 bg-red-800 hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed rounded text-white transition-colors"
        >
          <Square size={11} /> Stop {active.length}
        </button>
        {hasFilter && (
          <span className="text-gray-400 dark:text-gray-600">acts on filtered sources only</span>
        )}
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
