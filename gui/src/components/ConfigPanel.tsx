import { useState } from 'react'
import { TransportConfig, updateConfig } from '../api/client'
import { Save, RefreshCw } from 'lucide-react'

interface Props {
  config: TransportConfig
  onSaved: () => void
}

export default function ConfigPanel({ config, onSaved }: Props) {
  const [form, setForm] = useState({ ...config, xsiam_api_key: '' })
  const [saving, setSaving] = useState(false)
  const [savedMsg, setSavedMsg] = useState('')
  const [errorMsg, setErrorMsg] = useState('')

  const set = (key: keyof typeof form, value: string | number | boolean) =>
    setForm(prev => ({ ...prev, [key]: value }))

  const save = async () => {
    setSaving(true)
    setErrorMsg('')
    try {
      const payload = { ...form }
      if (!payload.xsiam_api_key) delete (payload as any).xsiam_api_key
      await updateConfig(payload)
      setSavedMsg('Saved & reloaded')
      onSaved()
      setTimeout(() => setSavedMsg(''), 3000)
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      setErrorMsg(typeof detail === 'string' ? detail : 'Failed to save configuration')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <section>
        <h3 className="text-sm font-semibold text-gray-300 mb-3 border-b border-gray-800 pb-2">XSIAM HTTP Ingest</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field label="XSIAM URL" value={form.xsiam_url} onChange={v => set('xsiam_url', v)} />
          <Field label="API Key" value={form.xsiam_api_key} onChange={v => set('xsiam_api_key', v)} type="password" placeholder="Leave blank to keep current" />
          <Field label="Dataset" value={form.xsiam_dataset} onChange={v => set('xsiam_dataset', v)} />
        </div>
      </section>

      <section>
        <h3 className="text-sm font-semibold text-gray-300 mb-3 border-b border-gray-800 pb-2">BrokerVM</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field label="Host" value={form.brokervm_host} onChange={v => set('brokervm_host', v)} />
          <Field label="Syslog Port" value={String(form.brokervm_syslog_port)} onChange={v => set('brokervm_syslog_port', parseInt(v))} type="number" />
          <div>
            <label className="block text-xs text-gray-500 mb-1">Syslog Protocol</label>
            <select
              value={form.brokervm_syslog_proto}
              onChange={e => set('brokervm_syslog_proto', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
            >
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
              <option value="tls">TLS</option>
            </select>
          </div>
          <Field label="WEC Port" value={String(form.brokervm_wec_port)} onChange={v => set('brokervm_wec_port', parseInt(v))} type="number" />
          <div className="flex items-center gap-3">
            <label className="text-xs text-gray-500">WEC Use TLS</label>
            <button
              onClick={() => set('brokervm_wec_use_tls', !form.brokervm_wec_use_tls)}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${form.brokervm_wec_use_tls ? 'bg-indigo-600' : 'bg-gray-700'}`}
            >
              <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${form.brokervm_wec_use_tls ? 'translate-x-4' : 'translate-x-1'}`} />
            </button>
          </div>
        </div>
      </section>

      <section>
        <h3 className="text-sm font-semibold text-gray-300 mb-3 border-b border-gray-800 pb-2">TLS Certificates</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Field label="CA Cert Path" value={form.tls_ca_cert_path} onChange={v => set('tls_ca_cert_path', v)} placeholder="/app/certs/ca.pem" />
          <Field label="Client Cert Path" value={form.tls_client_cert_path} onChange={v => set('tls_client_cert_path', v)} placeholder="/app/certs/client.crt" />
          <Field label="Client Key Path" value={form.tls_client_key_path} onChange={v => set('tls_client_key_path', v)} placeholder="/app/certs/client.key" />
        </div>
      </section>

      <div className="flex items-center gap-3">
        <button
          onClick={save}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded text-sm transition-colors"
        >
          {saving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
          Save & Reload
        </button>
        {savedMsg && <span className="text-xs text-green-400">{savedMsg}</span>}
        {errorMsg && <span className="text-xs text-red-400">{errorMsg}</span>}
      </div>
    </div>
  )
}

function Field({ label, value, onChange, type = 'text', placeholder = '' }: {
  label: string; value: string; onChange: (v: string) => void; type?: string; placeholder?: string
}) {
  return (
    <div>
      <label className="block text-xs text-gray-500 mb-1">{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
      />
    </div>
  )
}
