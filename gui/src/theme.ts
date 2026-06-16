export type ThemeId = 'light' | 'dark' | 'midnight' | 'nord' | 'solarized'

export interface ThemeMeta {
  id: ThemeId
  label: string
  /** Whether this theme is part of the dark family (adds `.dark`). */
  dark: boolean
  /** Swatch colors for the selector: [background, surface, accent]. */
  swatch: [string, string, string]
}

export const THEMES: ThemeMeta[] = [
  { id: 'light',     label: 'Light',          dark: false, swatch: ['#f3f4f6', '#ffffff', '#6366f1'] },
  { id: 'dark',      label: 'Dark',           dark: true,  swatch: ['#030712', '#111827', '#6366f1'] },
  { id: 'midnight',  label: 'Midnight Cyan',  dark: true,  swatch: ['#0a0e1a', '#131a2b', '#22d3ee'] },
  { id: 'nord',      label: 'Nord',           dark: true,  swatch: ['#2e3440', '#3b4252', '#88c0d0'] },
  { id: 'solarized', label: 'Solarized Dark', dark: true,  swatch: ['#002b36', '#073642', '#268bd2'] },
]

const THEME_CLASS: Record<ThemeId, string> = {
  light: '',
  dark: '',
  midnight: 'theme-midnight',
  nord: 'theme-nord',
  solarized: 'theme-solarized',
}

export function applyTheme(id: ThemeId): void {
  const root = document.documentElement
  root.classList.remove('dark', 'theme-midnight', 'theme-nord', 'theme-solarized')
  const meta = THEMES.find(t => t.id === id) ?? THEMES[1]
  if (meta.dark) root.classList.add('dark')
  const cls = THEME_CLASS[meta.id]
  if (cls) root.classList.add(cls)
  localStorage.setItem('theme', meta.id)
}

export function currentTheme(): ThemeId {
  const stored = localStorage.getItem('theme') as ThemeId | null
  if (stored && THEMES.some(t => t.id === stored)) return stored
  const root = document.documentElement
  if (root.classList.contains('theme-midnight')) return 'midnight'
  if (root.classList.contains('theme-nord')) return 'nord'
  if (root.classList.contains('theme-solarized')) return 'solarized'
  return root.classList.contains('dark') ? 'dark' : 'light'
}
