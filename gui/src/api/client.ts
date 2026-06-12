import axios from 'axios'

const TOKEN_KEY = 'engine_api_token'

export const getApiToken = () => localStorage.getItem(TOKEN_KEY) ?? ''
export const setApiToken = (token: string) => {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

// EventSource cannot set headers, so SSE endpoints take the token as a query param.
export const sseUrl = (path: string) => {
  const token = getApiToken()
  if (!token) return path
  return `${path}${path.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}`
}

export const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
})

api.interceptors.request.use(config => {
  const token = getApiToken()
  if (token) config.headers['X-Engine-Token'] = token
  return config
})

export interface SourceInfo {
  id: string
  display_name: string
  description: string
  default_transport: string
  supported_transports: string[]
  default_eps: number
  tags: string[]
  enabled: boolean
  eps: number
  transport: string
  total_sent: number
  total_errors: number
  last_event_ts: string | null
}

export interface StatsResponse {
  total_sent: number
  total_errors: number
  eps_actual: number
  per_transport: Record<string, number>
  active_sources: number
  timestamp: string
}

export interface TransportConfig {
  xsiam_url: string
  xsiam_api_key: string
  xsiam_dataset: string
  brokervm_host: string
  brokervm_syslog_port: number
  brokervm_syslog_proto: 'udp' | 'tcp' | 'tls'
  brokervm_wec_port: number
  brokervm_wec_use_tls: boolean
  tls_ca_cert_path: string
  tls_client_cert_path: string
  tls_client_key_path: string
}

export interface HealthResponse {
  status: string
  transports: Record<string, boolean>
}

export const getSources = () => api.get<SourceInfo[]>('/sources')
export const startSource = (id: string) => api.post(`/sources/${id}/start`)
export const stopSource = (id: string) => api.post(`/sources/${id}/stop`)
export const patchSource = (id: string, data: Partial<{ eps: number; transport: string; enabled: boolean }>) =>
  api.patch<SourceInfo>(`/sources/${id}/config`, data)

export const getStats = () => api.get<StatsResponse>('/stats')
export const getSourceStats = () => api.get<SourceInfo[]>('/stats/sources')

export const getConfig = () => api.get<TransportConfig>('/config')
export const updateConfig = (data: Partial<TransportConfig>) => api.put<TransportConfig>('/config', data)

export const getHealth = () => api.get<HealthResponse>('/health')

export const startAll = () => api.post('/control/start-all')
export const stopAll = () => api.post('/control/stop-all')
export const reloadConfig = () => api.post('/control/reload')

export type DiagLevel = 'off' | 'errors' | 'info'

export interface DiagEntry {
  timestamp: string
  level: string
  logger: string
  message: string
  exception?: string
}

export const getDiagLogs = (limit = 200) => api.get<DiagEntry[]>('/diagnostics/logs', { params: { limit } })
export const getDiagLevel = () => api.get<{ level: DiagLevel }>('/diagnostics/level')
export const setDiagLevel = (level: DiagLevel) => api.put<{ level: DiagLevel }>('/diagnostics/level', { level })
export const clearDiagLogs = () => api.delete('/diagnostics/logs')
