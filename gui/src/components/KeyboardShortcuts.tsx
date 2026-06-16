import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { X } from 'lucide-react'

const NAV: Record<string, string> = {
  d: '/',
  s: '/sources',
  c: '/config',
  l: '/logs',
  x: '/diagnostics',
}

const SHORTCUTS: { keys: string[]; desc: string }[] = [
  { keys: ['g', 'd'], desc: 'Go to Dashboard' },
  { keys: ['g', 's'], desc: 'Go to Sources' },
  { keys: ['g', 'c'], desc: 'Go to Configuration' },
  { keys: ['g', 'l'], desc: 'Go to Log Viewer' },
  { keys: ['g', 'x'], desc: 'Go to Diagnostics' },
  { keys: ['/'], desc: 'Focus the Sources filter' },
  { keys: ['?'], desc: 'Toggle this help' },
  { keys: ['Esc'], desc: 'Close help / menus' },
]

function isTyping(el: EventTarget | null): boolean {
  const node = el as HTMLElement | null
  if (!node) return false
  const tag = node.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || node.isContentEditable
}

export default function KeyboardShortcuts() {
  const [helpOpen, setHelpOpen] = useState(false)
  const navigate = useNavigate()
  const pendingG = useRef(false)
  const gTimer = useRef<ReturnType<typeof setTimeout>>()

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return

      // Escape always closes help, even from a field.
      if (e.key === 'Escape') {
        setHelpOpen(false)
        pendingG.current = false
        return
      }
      if (isTyping(e.target)) return

      if (e.key === '?') {
        e.preventDefault()
        setHelpOpen(v => !v)
        return
      }

      if (e.key === '/') {
        e.preventDefault()
        navigate('/sources')
        // Defer so the Sources page is mounted before we focus its input.
        setTimeout(() => window.dispatchEvent(new Event('focus-source-search')), 60)
        return
      }

      if (pendingG.current) {
        pendingG.current = false
        clearTimeout(gTimer.current)
        const dest = NAV[e.key.toLowerCase()]
        if (dest) {
          e.preventDefault()
          navigate(dest)
        }
        return
      }

      if (e.key.toLowerCase() === 'g') {
        pendingG.current = true
        clearTimeout(gTimer.current)
        gTimer.current = setTimeout(() => { pendingG.current = false }, 1000)
      }
    }

    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      clearTimeout(gTimer.current)
    }
  }, [navigate])

  if (!helpOpen) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
      onClick={() => setHelpOpen(false)}
    >
      <div
        className="w-80 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-2xl animate-fade-in"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-800">
          <h2 className="text-sm font-semibold text-gray-900 dark:text-gray-200">Keyboard shortcuts</h2>
          <button onClick={() => setHelpOpen(false)} className="text-gray-400 hover:text-gray-700 dark:hover:text-gray-200">
            <X size={15} />
          </button>
        </div>
        <ul className="p-4 space-y-2">
          {SHORTCUTS.map(({ keys, desc }) => (
            <li key={desc} className="flex items-center justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">{desc}</span>
              <span className="flex items-center gap-1">
                {keys.map((k, i) => (
                  <kbd
                    key={i}
                    className="px-1.5 py-0.5 rounded border border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 text-xs font-mono"
                  >
                    {k}
                  </kbd>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
