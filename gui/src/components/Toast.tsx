import { X, CheckCircle, AlertCircle, Info } from 'lucide-react'
import { useToast } from '../hooks/useToast'

const ICONS = {
  success: <CheckCircle size={14} className="text-green-400 flex-shrink-0" />,
  error: <AlertCircle size={14} className="text-red-400 flex-shrink-0" />,
  info: <Info size={14} className="text-blue-400 flex-shrink-0" />,
}

const BORDERS = {
  success: 'border-green-600',
  error: 'border-red-600',
  info: 'border-blue-600',
}

export default function Toasts() {
  const { toasts, dismiss } = useToast()
  if (!toasts.length) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`flex items-start gap-2 bg-gray-900 dark:bg-gray-800 border ${BORDERS[t.type]} rounded shadow-lg px-3 py-2.5 text-sm text-gray-100 max-w-xs pointer-events-auto animate-fade-in`}
        >
          {ICONS[t.type]}
          <span className="flex-1 min-w-0 break-words">{t.message}</span>
          <button onClick={() => dismiss(t.id)} className="flex-shrink-0 text-gray-500 hover:text-gray-300">
            <X size={12} />
          </button>
        </div>
      ))}
    </div>
  )
}
