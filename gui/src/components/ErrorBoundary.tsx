import { Component, ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

interface Props {
  children: ReactNode
  // When this changes (e.g. the route pathname), a previously-tripped
  // boundary resets automatically -- without it, navigating away from a page
  // that threw during render leaves the content pane stuck on the error
  // screen (the nav highlight changes but Routes never gets a chance to
  // re-render its children while state.error is still set).
  resetKey?: unknown
}

interface State {
  error: Error | null
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidUpdate(prevProps: Props) {
    if (this.state.error && prevProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null })
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-4 p-6">
          <AlertTriangle size={32} className="text-yellow-600 dark:text-yellow-400" />
          <div className="text-gray-900 dark:text-gray-200 font-semibold">Something went wrong</div>
          <pre className="text-xs text-red-600 dark:text-red-400 bg-white dark:bg-gray-900 rounded p-4 max-w-xl overflow-auto whitespace-pre-wrap">
            {this.state.error.message}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded text-sm text-white transition-colors"
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
