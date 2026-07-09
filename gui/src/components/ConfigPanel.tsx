import { useRef, useState } from 'react'
import { PfxUploadResult, TransportConfig, ValidationCheck, updateConfig, uploadPfx, validateConfig } from '../api/client'
import { Save, RefreshCw, Upload, ShieldCheck, CheckCircle, XCircle, PlugZap } from 'lucide-react'

interface Props {
  config: TransportConfig
  onSaved: () => void
}

export default function ConfigPanel({ config, onSaved }: Props) {
  const [form, setForm] = useState({
    ...config,
    xsiam_api_key: '',
    xsiam_api_secret: '',
  })
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
      if (!payload.xsiam_api_secret) delete (payload as any).xsiam_api_secret
      // cert paths are read-only; only set via pfx upload endpoint
      delete (payload as any).tls_client_cert_path
      delete (payload as any).tls_client_key_path
      await updateConfig(payload)
      setSavedMsg('Saved & reloaded')
      onSaved()
      setTimeout(() => setSavedMsg(''), 3000)
    } catch (err: any) {
      if (!err?.response) {
        setErrorMsg('Cannot reach engine — check that the engine container is running')
      } else {
        const status = err.response.status
        const detail = err.response.data?.detail
        setErrorMsg(
          typeof detail === 'string'
            ? `HTTP ${status}: ${detail}`
            : `HTTP ${status} — failed to save configuration`
        )
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <section>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 border-b border-gray-200 dark:border-gray-800 pb-2">XSIAM HTTP Ingest</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field label="XSIAM URL" value={form.xsiam_url} onChange={v => set('xsiam_url', v)} />
          <Field label="API Key" value={form.xsiam_api_key} onChange={v => set('xsiam_api_key', v)} type="password" placeholder="Leave blank to keep current" />
          <Field label="Dataset" value={form.xsiam_dataset} onChange={v => set('xsiam_dataset', v)} />
        </div>
      </section>

      <section>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 border-b border-gray-200 dark:border-gray-800 pb-2">XSIAM Public API</h3>
        <p className="text-xs text-gray-500 mb-3">
          Management API used for correlation rules — a different host than the ingest collector.
          Requires a <strong>standard</strong> API key with the Instance Administrator role.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field label="API URL" value={form.xsiam_api_url} onChange={v => set('xsiam_api_url', v)} placeholder="https://api-<tenant>.xdr.us.paloaltonetworks.com" />
          <Field label="API Key ID" value={form.xsiam_api_key_id} onChange={v => set('xsiam_api_key_id', v)} placeholder="e.g. 3" />
          <Field label="API Key" value={form.xsiam_api_secret} onChange={v => set('xsiam_api_secret', v)} type="password" placeholder="Leave blank to keep current" />
        </div>
        <TestConnection />
      </section>

      <section>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 border-b border-gray-200 dark:border-gray-800 pb-2">BrokerVM</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field label="Host" value={form.brokervm_host} onChange={v => set('brokervm_host', v)} />
          <Field label="Syslog Port" value={String(form.brokervm_syslog_port)} onChange={v => set('brokervm_syslog_port', parseInt(v))} type="number" />
          <div>
            <label className="block text-xs text-gray-500 mb-1">Syslog Protocol</label>
            <select
              value={form.brokervm_syslog_proto}
              onChange={e => set('brokervm_syslog_proto', e.target.value)}
              className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
            >
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
              <option value="tls">TLS</option>
            </select>
          </div>
          <Field label="WEC Port" value={String(form.brokervm_wec_port)} onChange={v => set('brokervm_wec_port', parseInt(v))} type="number" />
          <div className="md:col-span-2">
            <Field
              label="WEC Subscription Manager URL"
              value={form.wec_subscription_url}
              onChange={v => set('wec_subscription_url', v)}
              placeholder="Server=HTTPS://bvm.lab:5986/wsman/SubscriptionManager/WEC,Refresh=600,IssuerCA=THUMBPRINT"
            />
          </div>
        </div>
      </section>

      <section>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3 border-b border-gray-200 dark:border-gray-800 pb-2">WEC Client Certificate</h3>
        {(form.tls_client_cert_path) && (
          <div className="flex items-center gap-2 text-xs text-green-600 dark:text-green-400 mb-3">
            <CheckCircle size={13} />
            <span>Certificate active: <code className="font-mono">{form.tls_client_cert_path}</code></span>
          </div>
        )}
        <PfxUpload onUploaded={() => onSaved()} />
      </section>

      <div className="flex items-center gap-3">
        <button
          onClick={save}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded text-sm text-white transition-colors"
        >
          {saving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
          Save & Reload
        </button>
        {savedMsg && <span className="text-xs text-green-600 dark:text-green-400">{savedMsg}</span>}
        {errorMsg && <span className="text-xs text-red-600 dark:text-red-400">{errorMsg}</span>}
      </div>
    </div>
  )
}

const CHECK_LABELS: Record<ValidationCheck['name'], string> = {
  configured: 'Settings present',
  reachable: 'API reachable',
  authenticated: 'API key accepted',
  correlations_access: 'Correlations access',
}

function TestConnection() {
  const [checks, setChecks] = useState<ValidationCheck[] | null>(null)
  const [running, setRunning] = useState(false)
  const [failed, setFailed] = useState('')

  const run = async () => {
    setRunning(true)
    setChecks(null)
    setFailed('')
    try {
      const r = await validateConfig()
      setChecks(r.data.checks)
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      setFailed(typeof detail === 'string' ? detail : 'Validation request failed — is the engine running?')
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="mt-3 space-y-2">
      <div className="flex items-center gap-3">
        <button
          onClick={run}
          disabled={running}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-300 dark:bg-gray-700 hover:bg-gray-400 dark:hover:bg-gray-600 disabled:opacity-50 rounded text-xs transition-colors"
        >
          {running ? <RefreshCw size={12} className="animate-spin" /> : <PlugZap size={12} />}
          Test connection
        </button>
        <span className="text-xs text-gray-500">Tests the saved configuration — click Save &amp; Reload first if you changed fields.</span>
      </div>
      {failed && <div className="text-xs text-red-600 dark:text-red-400">{failed}</div>}
      {checks && (
        <div className="space-y-1">
          {checks.map(c => (
            <div key={c.name} className="flex items-start gap-2 text-xs">
              {c.ok
                ? <CheckCircle size={13} className="text-green-500 flex-shrink-0 mt-0.5" />
                : <XCircle size={13} className="text-red-500 flex-shrink-0 mt-0.5" />}
              <span className="font-medium w-36 flex-shrink-0">{CHECK_LABELS[c.name]}</span>
              <span className={c.ok ? 'text-gray-500' : 'text-red-600 dark:text-red-400'}>{c.detail}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function PfxUpload({ onUploaded }: { onUploaded: (r: PfxUploadResult) => void }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<PfxUploadResult | null>(null)
  const [error, setError] = useState('')

  const upload = async () => {
    if (!file) return
    setUploading(true)
    setError('')
    setResult(null)
    try {
      const r = await uploadPfx(file, passphrase)
      setResult(r.data)
      onUploaded(r.data)
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="border border-dashed border-gray-300 dark:border-gray-700 rounded p-4 space-y-3">
      <div className="flex items-center gap-2 text-xs font-semibold text-gray-600 dark:text-gray-400">
        <ShieldCheck size={13} />
        Upload WEC Certificate (.pfx / PKCS#12)
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <label className="block text-xs text-gray-500 mb-1">Certificate file</label>
          <input
            ref={fileRef}
            type="file"
            accept=".pfx,.p12"
            onChange={e => setFile(e.target.files?.[0] ?? null)}
            className="text-xs text-gray-600 dark:text-gray-400 file:mr-2 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:bg-gray-200 dark:file:bg-gray-700 file:text-gray-700 dark:file:text-gray-300 file:cursor-pointer"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">Passphrase (if any)</label>
          <input
            type="password"
            value={passphrase}
            onChange={e => setPassphrase(e.target.value)}
            placeholder="Optional"
            className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-500 w-44"
          />
        </div>
        <button
          onClick={upload}
          disabled={!file || uploading}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded text-xs text-white transition-colors"
        >
          {uploading ? <RefreshCw size={12} className="animate-spin" /> : <Upload size={12} />}
          Upload
        </button>
      </div>
      {result && (
        <div className="text-xs text-green-600 dark:text-green-400 space-y-0.5">
          <div className="flex items-center gap-1"><ShieldCheck size={11} /> Extracted to {result.cert_path}</div>
          <div className="text-gray-500">Subject: {result.subject} · Expires: {result.expires}</div>
        </div>
      )}
      {error && <div className="text-xs text-red-600 dark:text-red-400">{error}</div>}
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
        className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
      />
    </div>
  )
}
