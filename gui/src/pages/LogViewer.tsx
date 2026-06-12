import { useEffect, useState } from 'react'
import { getSources, SourceInfo } from '../api/client'
import LogViewerComponent from '../components/LogViewer'

export default function LogViewer() {
  const [sources, setSources] = useState<SourceInfo[]>([])
  const [filterSource, setFilterSource] = useState<string>('')

  useEffect(() => {
    getSources().then(r => setSources(r.data)).catch(() => {})
  }, [])

  return (
    <div className="flex flex-col h-screen">
      <div className="flex items-center gap-4 px-6 py-3 border-b border-gray-200 dark:border-gray-800 bg-gray-100 dark:bg-gray-950">
        <h1 className="font-semibold text-gray-900 dark:text-gray-200">Log Viewer</h1>
        <select
          value={filterSource}
          onChange={e => setFilterSource(e.target.value)}
          className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-500"
        >
          <option value="">All sources</option>
          {sources.map(s => (
            <option key={s.id} value={s.id}>{s.display_name}</option>
          ))}
        </select>
      </div>
      <div className="flex-1 overflow-hidden">
        <LogViewerComponent filterSource={filterSource || undefined} />
      </div>
    </div>
  )
}
