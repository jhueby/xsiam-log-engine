import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Play, Square, CheckCircle, XCircle, Clock } from 'lucide-react'
import {
  ScenarioInfo,
  ScenarioRunInfo,
  cancelScenarioRun,
  getScenarioRuns,
  getScenarios,
  runScenario,
} from '../api/client'
import { useToast } from '../hooks/useToast'

const STATUS_COLORS: Record<string, string> = {
  running: 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300',
  completed: 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300',
  cancelled: 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300',
  failed: 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300',
}

const STEP_ICON: Record<string, JSX.Element> = {
  pending: <Clock size={13} className="text-gray-400" />,
  fired: <CheckCircle size={13} className="text-green-500" />,
  error: <XCircle size={13} className="text-red-500" />,
}

export default function Scenarios() {
  const [scenarios, setScenarios] = useState<ScenarioInfo[] | null>(null)
  const [runs, setRuns] = useState<ScenarioRunInfo[]>([])
  const [starting, setStarting] = useState<string | null>(null)
  const [error, setError] = useState('')
  const { show } = useToast()
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadScenarios = () => {
    getScenarios()
      .then(r => { setScenarios(r.data); setError('') })
      .catch(() => setError('Could not reach the engine'))
  }

  const loadRuns = () => {
    getScenarioRuns().then(r => setRuns(r.data)).catch(() => {})
  }

  useEffect(() => {
    loadScenarios()
    loadRuns()
    pollRef.current = setInterval(loadRuns, 2000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  const start = async (id: string) => {
    setStarting(id)
    try {
      await runScenario(id)
      show('Scenario started', 'success')
      loadRuns()
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      show(typeof detail === 'string' ? detail : 'Failed to start scenario', 'error')
    } finally {
      setStarting(null)
    }
  }

  const cancel = async (runId: string) => {
    try {
      await cancelScenarioRun(runId)
      show('Run cancelled', 'info')
      loadRuns()
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      show(typeof detail === 'string' ? detail : 'Failed to cancel run', 'error')
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="font-semibold text-gray-900 dark:text-gray-200">Attack Scenarios</h1>
        <p className="text-xs text-gray-500 mt-0.5">
          Timed, correlated event sequences across sources — a shared identity/host fires a
          realistic multi-vendor story so correlation rules have something real to detect.
        </p>
      </div>

      {error && (
        <div className="flex items-start gap-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded p-3 text-sm text-yellow-800 dark:text-yellow-300 max-w-2xl">
          <AlertTriangle size={16} className="flex-shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {scenarios && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scenarios.map(s => (
            <div key={s.id} className="rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4 space-y-3">
              <div>
                <div className="font-semibold text-sm">{s.name}</div>
                <div className="text-xs text-gray-500 mt-1 leading-relaxed">{s.description}</div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {s.steps.map((step, i) => (
                  <span key={i} className="text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 font-mono">
                    {step.source}
                  </span>
                ))}
              </div>
              <button
                onClick={() => start(s.id)}
                disabled={starting === s.id}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded text-xs text-white transition-colors"
              >
                <Play size={12} />
                {starting === s.id ? 'Starting…' : 'Run scenario'}
              </button>
            </div>
          ))}
        </div>
      )}

      <div>
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 border-b border-gray-200 dark:border-gray-800 pb-2">
          Recent runs
        </h2>
        {runs.length === 0 && <div className="text-sm text-gray-500">No scenario runs yet.</div>}
        <div className="space-y-3">
          {runs.map(run => (
            <div key={run.run_id} className="rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <span className="font-medium text-sm">{run.scenario_name}</span>
                  <span className={`ml-2 text-xs px-2 py-0.5 rounded ${STATUS_COLORS[run.status]}`}>{run.status}</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-gray-500">
                  <span>entity: <code className="font-mono">{run.entities.username}</code> / <code className="font-mono">{run.entities.host}</code></span>
                  {run.status === 'running' && (
                    <button
                      onClick={() => cancel(run.run_id)}
                      className="flex items-center gap-1 text-red-600 dark:text-red-400 hover:underline"
                    >
                      <Square size={11} /> Cancel
                    </button>
                  )}
                </div>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {run.steps.map(step => (
                  <div
                    key={step.index}
                    title={step.error ?? (step.fired_at ? `fired at ${step.fired_at}` : `+${step.delay}s`)}
                    className="flex items-center gap-1.5 text-xs px-2 py-1 rounded bg-gray-50 dark:bg-gray-800/50 font-mono"
                  >
                    {STEP_ICON[step.status]}
                    {step.source}
                  </div>
                ))}
              </div>
              {run.error && <div className="mt-2 text-xs text-red-600 dark:text-red-400">{run.error}</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
