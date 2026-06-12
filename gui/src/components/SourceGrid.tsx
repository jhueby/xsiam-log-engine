import { useState } from 'react'
import { SourceInfo } from '../api/client'
import SourceCard from './SourceCard'

const ALL_TAGS = ['windows', 'linux', 'network', 'edr', 'cloud', 'identity', 'proxy', 'firewall', 'dns', 'auth']

interface Props {
  sources: SourceInfo[]
  onUpdate: () => void
}

export default function SourceGrid({ sources, onUpdate }: Props) {
  const [search, setSearch] = useState('')
  const [activeTag, setActiveTag] = useState<string | null>(null)

  const filtered = sources.filter(s => {
    const matchSearch = !search || s.display_name.toLowerCase().includes(search.toLowerCase()) || s.id.includes(search.toLowerCase())
    const matchTag = !activeTag || s.tags.includes(activeTag)
    return matchSearch && matchTag
  })

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-2 items-center">
        <input
          type="search"
          placeholder="Search sources..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-500 w-48"
        />
        <div className="flex flex-wrap gap-1">
          {ALL_TAGS.map(tag => (
            <button
              key={tag}
              onClick={() => setActiveTag(activeTag === tag ? null : tag)}
              className={`text-xs px-2 py-0.5 rounded transition-colors ${
                activeTag === tag
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-400 dark:hover:bg-gray-700'
              }`}
            >
              {tag}
            </button>
          ))}
        </div>
        <span className="text-xs text-gray-500 ml-auto">{filtered.length} sources</span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {filtered.map(s => (
          <SourceCard key={s.id} source={s} onUpdate={onUpdate} />
        ))}
      </div>
    </div>
  )
}
