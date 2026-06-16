import { useEffect, useRef, useState } from 'react'
import { Check, Palette } from 'lucide-react'
import { applyTheme, currentTheme, THEMES, ThemeId } from '../theme'

export default function ThemeToggle() {
  const [theme, setTheme] = useState<ThemeId>(currentTheme)
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  const select = (id: ThemeId) => {
    applyTheme(id)
    setTheme(id)
    setOpen(false)
  }

  // Close on outside click / Escape
  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const active = THEMES.find(t => t.id === theme) ?? THEMES[1]

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        title="Change theme"
        className="flex items-center gap-2 px-3 py-2 rounded text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-gray-100 transition-colors w-full"
      >
        <Palette size={15} />
        <span className="flex-1 text-left">Theme</span>
        <span className="flex items-center gap-1">
          {active.swatch.map((c, i) => (
            <span
              key={i}
              className="inline-block w-2.5 h-2.5 rounded-full border border-black/10 dark:border-white/10"
              style={{ backgroundColor: c }}
            />
          ))}
        </span>
      </button>

      {open && (
        <div className="absolute bottom-full left-0 mb-2 w-full min-w-44 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-xl overflow-hidden animate-fade-in z-20">
          {THEMES.map(t => (
            <button
              key={t.id}
              onClick={() => select(t.id)}
              className={`flex items-center gap-2.5 w-full px-3 py-2 text-sm transition-colors ${
                t.id === theme
                  ? 'bg-indigo-50 dark:bg-indigo-600/15 text-indigo-700 dark:text-indigo-300'
                  : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'
              }`}
            >
              <span className="flex items-center gap-0.5 flex-shrink-0">
                {t.swatch.map((c, i) => (
                  <span
                    key={i}
                    className="inline-block w-3 h-4 first:rounded-l last:rounded-r border border-black/10 dark:border-white/10"
                    style={{ backgroundColor: c }}
                  />
                ))}
              </span>
              <span className="flex-1 text-left truncate">{t.label}</span>
              {t.id === theme && <Check size={14} className="flex-shrink-0" />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
