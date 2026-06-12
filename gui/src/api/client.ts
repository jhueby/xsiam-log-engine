import axios from 'axios'

export const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
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
