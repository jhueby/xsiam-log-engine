import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { Activity, Settings, List, Eye } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Configuration from './pages/Configuration'
import Sources from './pages/Sources'
import LogViewer from './pages/LogViewer'

const nav = [
  { to: '/', label: 'Dashboard', icon: Activity },
  { to: '/sources', label: 'Sources', icon: List },
  { to: '/config', label: 'Configuration', icon: Settings },
  { to: '/logs', label: 'Log Viewer', icon: Eye },
]

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden">
        <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col">
          <div className="p-4 border-b border-gray-800">
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
                      : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
                  }`
                }
              >
                <Icon size={15} />
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="p-4 border-t border-gray-800 text-xs text-gray-600">
            Palo Alto Networks
          </div>
        </aside>
        <main className="flex-1 overflow-auto bg-gray-950">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/sources" element={<Sources />} />
            <Route path="/config" element={<Configuration />} />
            <Route path="/logs" element={<LogViewer />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
