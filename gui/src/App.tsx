import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { Activity, Settings, List, Eye, Terminal } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Configuration from './pages/Configuration'
import Sources from './pages/Sources'
import LogViewer from './pages/LogViewer'
import Diagnostics from './pages/Diagnostics'
import ErrorBoundary from './components/ErrorBoundary'
import ThemeToggle from './components/ThemeToggle'
import Toasts from './components/Toast'
import { ToastProvider } from './hooks/useToast'
import { getHealth, HealthResponse } from './api/client'

const nav = [
  { to: '/', label: 'Dashboard', icon: Activity },
  { to: '/sources', label: 'Sources', icon: List },
  { to: '/config', label: 'Configuration', icon: Settings },
  { to: '/logs', label: 'Log Viewer', icon: Eye },
  { to: '/diagnostics', label: 'Diagnostics', icon: Terminal },
]

function SidebarHealth() {
  const [health, setHealth] = useState<HealthResponse | null>(null)

  useEffect(() => {
    const load = () => getHealth().then(r => setHealth(r.data)).catch(() => {})
    load()
    const t = setInterval(load, 10_000)
    return () => clearInterval(t)
  }, [])

  if (!health) return null

  return (
    <div className="px-4 pb-2 space-y-1">
      {Object.entries(health.transports).map(([name, ok]) => (
        <div key={name} className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-600">
          <span className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${ok ? 'bg-green-400' : 'bg-red-400'}`} />
          <span className="capitalize">{name}</span>
          <span className={ok ? 'text-green-600 dark:text-green-500' : 'text-red-600 dark:text-red-500'}>
            {ok ? 'up' : 'down'}
          </span>
        </div>
      ))}
    </div>
  )
}

export default function App() {
  return (
    <ToastProvider>
      <BrowserRouter>
        <div className="flex h-screen overflow-hidden">
          <aside className="w-56 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 flex flex-col">
            <div className="p-4 border-b border-gray-200 dark:border-gray-800">
              <div className="text-brand-500 font-bold text-lg tracking-tight">XSIAM</div>
              <div className="text-gray-500 text-xs">Log Engine v1.0</div>
            </div>
            <nav className="flex-1 p-2 space-y-1">
              {nav.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors ${
                      isActive
                        ? 'bg-brand-600 text-white'
                        : 'text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-gray-100'
                    }`
                  }
                >
                  <Icon size={15} />
                  {label}
                </NavLink>
              ))}
            </nav>
            <SidebarHealth />
            <div className="p-2 border-t border-gray-200 dark:border-gray-800">
              <ThemeToggle />
            </div>
            <div className="px-4 pb-4 text-xs text-gray-500 dark:text-gray-600">
              Palo Alto Networks
            </div>
          </aside>
          <main className="flex-1 overflow-auto bg-gray-100 dark:bg-gray-950">
            <ErrorBoundary>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/sources" element={<Sources />} />
                <Route path="/config" element={<Configuration />} />
                <Route path="/logs" element={<LogViewer />} />
                <Route path="/diagnostics" element={<Diagnostics />} />
              </Routes>
            </ErrorBoundary>
          </main>
        </div>
        <Toasts />
      </BrowserRouter>
    </ToastProvider>
  )
}
