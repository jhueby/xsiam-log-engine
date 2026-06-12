import { useState } from 'react'
import { SourceInfo } from '../api/client'
import { Copy, Check, Info } from 'lucide-react'

interface Props {
  sources: SourceInfo[]
}

const BASE_RULE = '[INGEST:vendor="log", product="sim", target_dataset="log_sim_raw", no_hit=drop]'

function makeRule(sourceId: string): string {
  return `${BASE_RULE}filter simulated_log_source = "${sourceId}";`
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={copy}
      className="flex items-center gap-1.5 px-2.5 py-1 text-xs text-gray-500 hover:text-gray-800 dark:hover:text-gray-200 rounded hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
    >
      {copied ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
      {copied ? 'Copied!' : label}
    </button>
  )
}

export default function ParsingRules({ sources }: Props) {
  const enabled = sources.filter(s => s.enabled)
  const allRules = enabled.map(s => makeRule(s.id)).join('\n\n')

  if (sources.length === 0) {
    return <div className="text-gray-500 text-sm animate-pulse">Loading...</div>
  }

  return (
    <div className="space-y-5 max-w-4xl">
      <div className="flex items-start gap-2 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
        <Info size={13} className="flex-shrink-0 mt-0.5" />
        <div>
          Each rule routes logs from one source to <code className="font-mono">log_sim_raw</code> by
          matching the <code className="font-mono">simulated_log_source</code> field injected into every
          HTTP event. Add these in your XSIAM tenant under{' '}
          <strong>Settings → XDR Data Management → Parsers → New Parser</strong>. Enable at least one
          source to generate its rule.
        </div>
      </div>

      {enabled.length === 0 ? (
        <div className="text-gray-500 dark:text-gray-400 text-sm">
          No sources are currently active. Enable sources to generate parsing rules.
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {enabled.length} rule{enabled.length !== 1 ? 's' : ''} — one per active source
            </span>
            <CopyButton text={allRules} label="Copy All" />
          </div>

          <div className="space-y-2">
            {enabled.map(s => {
              const rule = makeRule(s.id)
              return (
                <div
                  key={s.id}
                  className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded overflow-hidden"
                >
                  <div className="flex items-center justify-between px-3 py-1.5 bg-gray-50 dark:bg-gray-800/50 border-b border-gray-200 dark:border-gray-800">
                    <span className="text-xs font-medium text-gray-600 dark:text-gray-400">
                      {s.display_name}
                      <span className="ml-2 font-normal text-gray-400 dark:text-gray-500">
                        ({s.id})
                      </span>
                    </span>
                    <CopyButton text={rule} />
                  </div>
                  <pre className="px-3 py-2.5 text-xs font-mono text-gray-800 dark:text-gray-200 whitespace-pre-wrap break-all leading-relaxed">
                    {rule}
                  </pre>
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
