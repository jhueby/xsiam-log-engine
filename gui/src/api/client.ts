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

export type HttpLogType = 'raw' | 'json' | 'cef' | 'leef'
export type HttpCompression = 'none' | 'gzip'

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
  http_log_type: HttpLogType
  http_compression: HttpCompression
  http_api_key: string  // '***' if set, '' if using global
  auto_disabled_reason: string | null
  xsiam_dataset: string  // effective dataset (source override or global default)
  cribl_emulation: boolean
  cribl_pipe_name: string
  cribl_host_name: string
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
  xsiam_api_key: string   // masked as '***' on GET
  xsiam_dataset: string
  xsiam_api_url: string
  xsiam_api_key_id: string
  xsiam_api_secret: string  // masked as '***' on GET
  brokervm_host: string
  brokervm_syslog_port: number
  brokervm_syslog_proto: 'udp' | 'tcp' | 'tls'
  brokervm_wec_port: number
  wec_subscription_url: string
  tls_client_cert_path: string  // read-only; set by /api/certs/pfx
  tls_client_key_path: string
}

export interface PfxUploadResult {
  cert_path: string
  key_path: string
  subject: string
  expires: string
}

export interface HealthResponse {
  status: string
  transports: Record<string, boolean>
}

export const getSources = () => api.get<SourceInfo[]>('/sources')
export const startSource = (id: string) => api.post(`/sources/${id}/start`)
export const stopSource = (id: string) => api.post(`/sources/${id}/stop`)
export const patchSource = (id: string, data: Partial<{
  eps: number
  transport: string
  enabled: boolean
  http_log_type: HttpLogType
  http_compression: HttpCompression
  http_api_key: string
  cribl_emulation: boolean
  cribl_pipe_name: string
  cribl_host_name: string
}>) => api.patch<SourceInfo>(`/sources/${id}/config`, data)

export const getStats = () => api.get<StatsResponse>('/stats')
export const getSourceStats = () => api.get<SourceInfo[]>('/stats/sources')

export const getConfig = () => api.get<TransportConfig>('/config')
export const updateConfig = (data: Partial<TransportConfig>) => api.put<TransportConfig>('/config', data)

export const uploadPfx = (file: File, passphrase: string) => {
  const form = new FormData()
  form.append('file', file)
  form.append('passphrase', passphrase)
  return api.post<PfxUploadResult>('/certs/pfx', form)
}

export const getHealth = () => api.get<HealthResponse>('/health')

export interface CorrelationRuleInfo {
  name: string
  source_id: string | null  // parsed from the [LogSim] prefix; null for unmanaged
  managed: boolean
  severity: string
  dataset: string
  xql_query: string
  description: string
  enabled: boolean
}

export interface CorrelationApplyResponse {
  ok: boolean
  message: string
  rule: CorrelationRuleInfo
}

export interface ValidationCheck {
  name: 'configured' | 'reachable' | 'authenticated' | 'correlations_access'
  ok: boolean
  detail: string
}

export interface ConfigValidationResponse {
  ok: boolean
  checks: ValidationCheck[]
}

export const getCorrelationRules = (all = false) =>
  api.get<CorrelationRuleInfo[]>('/correlations', { params: { all } })
export const previewCorrelationRule = (id: string) =>
  api.get<CorrelationRuleInfo>(`/correlations/${id}/preview`)
export const applyCorrelationRule = (id: string, overwrite = false) =>
  api.post<CorrelationApplyResponse>(`/correlations/${id}`, null, { params: { overwrite } })
export const deleteCorrelationRule = (id: string) => api.delete(`/correlations/${id}`)
export const deleteAllCorrelationRules = () => api.delete('/correlations')
export const validateConfig = () => api.post<ConfigValidationResponse>('/config/validate')

export interface ScenarioStepInfo {
  source: string
  delay: number
  jitter: number
  overrides: Record<string, unknown>
}

export interface ScenarioInfo {
  id: string
  name: string
  description: string
  steps: ScenarioStepInfo[]
}

export interface ScenarioEntitiesInfo {
  username: string
  domain_user: string
  host: string
  internal_ip: string
  external_ip: string
}

export type ScenarioStepStatus = 'pending' | 'fired' | 'error'
export type ScenarioRunStatus = 'running' | 'completed' | 'cancelled' | 'failed'

export interface ScenarioStepStatusInfo extends ScenarioStepInfo {
  index: number
  status: ScenarioStepStatus
  fired_at: string | null
  error: string | null
}

export interface ScenarioRunInfo {
  run_id: string
  scenario_id: string
  scenario_name: string
  started_at: string
  status: ScenarioRunStatus
  error: string | null
  entities: ScenarioEntitiesInfo
  steps: ScenarioStepStatusInfo[]
}

export const getScenarios = () => api.get<ScenarioInfo[]>('/scenarios')
export const getScenarioRuns = () => api.get<ScenarioRunInfo[]>('/scenarios/runs')
export const getScenarioRun = (runId: string) => api.get<ScenarioRunInfo>(`/scenarios/runs/${runId}`)
export const runScenario = (id: string) => api.post<ScenarioRunInfo>(`/scenarios/${id}/run`)
export const cancelScenarioRun = (runId: string) => api.post<ScenarioRunInfo>(`/scenarios/runs/${runId}/cancel`)

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
